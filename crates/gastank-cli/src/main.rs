mod convert;
mod gastank;
mod merkle;
mod trace;

use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use convert::{parse_hex_bytes, parse_wei};
use ethrex_common::types::{
    FRAME_TX_RECENT_ROOT_USABLE_WINDOW, Frame, FrameMode, RecentRootReference,
    frame_tx_nonce_manager,
};
use ethrex_common::utils::keccak;
use ethrex_common::{Address, Bytes, H256, U256};
use ethrex_rpc::EthClient;
use ethrex_rpc::types::block_identifier::{BlockIdentifier, BlockTag};
use frame_tx::{
    FrameTxSpec, address_from_secret_key, parse_secret_key, recent_root_frame, self_verify_frame,
    send_frame_tx, sender_frame,
};
use secp256k1::SecretKey;
use url::Url;

/// Execution-gas limits for the frames of a validation prefix. EIP-8141 caps
/// their sum -- the EIP-8272 recent-root verifier frame included -- plus
/// `signature_verification_cost()` (2800 for one secp256k1 signature) at
/// `MAX_VERIFY_GAS`, which ethrex defaults to 100_000.
const SELF_VERIFY_GAS: u64 = 30_000;
const GAS_TANK_VERIFY_GAS: u64 = 85_000;
const RECENT_ROOT_FRAME_GAS: u64 = 8_000;

/// EIP-8037 state gas is a separate dimension from execution gas, charged at
/// `STATE_BYTES_PER_STORAGE_SET * cost_per_state_byte` (64 * 1530 = 97_920) for
/// every storage slot a frame takes from zero to non-zero. Recording a
/// commitment writes the note, the commitments array, the touched Merkle
/// subtrees and the recent-root ring entry, so the first deposit into a fresh
/// tank fills all twenty subtree slots at once.
const DEPOSIT_STATE_GAS: u64 = 3_000_000;
const SETTLE_STATE_GAS: u64 = 1_000_000;

/// EIP-8250: the frame that APPROVEs payment pays, out of its own
/// `limits.state`, one storage set for every keyed nonce the transaction uses
/// for the first time. Spending a note uses a nonce key derived from its leaf,
/// so that slot is always fresh; declaring no state budget there halts the
/// frame and the node rejects the transaction as a reverted validation prefix.
/// Key 0 (`deposit`, `refresh-root`) is the account's own nonce and owes
/// nothing while the account already exists.
const KEYED_NONCE_STATE_GAS: u64 = 97_920;

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// View a note's current balance.
    Balance(BalanceArgs),
    /// Deposit ETH into the GasTank for an owner.
    Deposit(DepositArgs),
    /// Execute an arbitrary call, paid for by the GasTank.
    Execute(ExecuteArgs),
    /// Withdraw a note's full balance from the GasTank.
    Withdraw(WithdrawArgs),
    /// Publish a fresh recent Merkle root, so `execute`/`withdraw` have a
    /// non-stale root to spend against.
    RefreshRoot(RefreshRootArgs),
    /// Summarize a transaction: its frames, their gas, and a call tree.
    Trace(TraceArgs),
}

#[derive(Args)]
struct BalanceArgs {
    #[command(flatten)]
    conn: ConnArgs,
    /// Note owner to check; defaults to the address derived from --private-key
    #[arg(long)]
    owner: Option<Address>,
}

#[derive(Args)]
struct DepositArgs {
    #[command(flatten)]
    conn: ConnArgs,
    /// Amount to deposit, in wei
    #[arg(value_parser = parse_wei)]
    amount_wei: U256,
    /// Note owner; defaults to the address derived from --private-key
    #[arg(long)]
    owner: Option<Address>,
}

#[derive(Args)]
struct ExecuteArgs {
    #[command(flatten)]
    conn: ConnArgs,
    /// Address to call
    #[arg(long)]
    target: Address,
    /// Calldata for `target`, `0x`-prefixed or bare hex
    #[arg(long, value_parser = parse_hex_bytes, default_value = "0x")]
    data: Bytes,
}

#[derive(Args)]
struct WithdrawArgs {
    #[command(flatten)]
    conn: ConnArgs,
    /// Destination for the note's full balance
    #[arg(long)]
    to: Address,
}

#[derive(Args)]
struct RefreshRootArgs {
    #[command(flatten)]
    conn: ConnArgs,
}

#[derive(Args)]
struct ConnArgs {
    /// JSON-RPC endpoint of a frame-tx-capable ethrex node
    #[arg(long, env = "RPC_URL")]
    rpc_url: Url,
    /// Signer private key, `0x`-prefixed or bare hex
    #[arg(long, env = "PRIVATE_KEY", value_parser = parse_secret_key, hide_env_values = true)]
    private_key: SecretKey,
    /// Address of the deployed GasTank contract
    #[arg(long, env = "GAS_TANK_ADDRESS")]
    gas_tank_address: Address,
}

#[derive(Args)]
struct TraceArgs {
    /// JSON-RPC endpoint of a frame-tx-capable ethrex node
    #[arg(long, env = "RPC_URL")]
    rpc_url: Url,
    /// Hash of the transaction to summarize
    tx_hash: H256,
}

/// Everything needed to authorize spending a note: the note itself, its
/// Merkle inclusion proof, and a fresh-enough recent-root reference.
struct SpendContext {
    amount: U256,
    salt: [u8; 32],
    leaf: [u8; 32],
    leaf_index: U256,
    proof: [[u8; 32]; merkle::DEPTH],
    root: [u8; 32],
    slot: u64,
    source_id: [u8; 32],
}

async fn prepare_spend(
    client: &EthClient,
    gas_tank: Address,
    owner: Address,
) -> Result<SpendContext> {
    let (amount, salt) = gastank::read_note(client, gas_tank, owner).await?;
    if amount.is_zero() {
        bail!("no note found for owner {owner:#x} -- deposit first");
    }
    let leaf = gastank::leaf(owner, amount, salt);

    let next_leaf_index = gastank::read_next_leaf_index(client, gas_tank).await?;
    let mut leaves = Vec::new();
    let mut i = U256::zero();
    while i < next_leaf_index {
        leaves.push(gastank::read_commitment(client, gas_tank, i).await?);
        i += U256::one();
    }
    let leaf_index = leaves.iter().position(|l| *l == leaf).with_context(|| {
        format!("leaf for owner {owner:#x} not found in commitments -- state out of sync")
    })?;
    let proof = merkle::proof_for(&leaves, leaf_index);

    let root = gastank::read_root(client, gas_tank).await?;
    let slot = gastank::read_last_root_slot(client, gas_tank).await?;
    let source_id = gastank::read_source_id(client, gas_tank).await?;

    let latest_block = client
        .get_block_by_number(BlockIdentifier::Tag(BlockTag::Latest), false)
        .await
        .context("failed to fetch latest block")?;
    let current_slot = latest_block
        .header
        .slot_number
        .context("node did not report a slot number (EIP-7843 unsupported?)")?;
    let age = current_slot
        .checked_sub(slot)
        .context("stored root slot is ahead of the latest block")?;
    if !(1..=FRAME_TX_RECENT_ROOT_USABLE_WINDOW).contains(&age) {
        bail!("stored recent root is stale ({age} slots old) -- run `refresh-root` first");
    }

    Ok(SpendContext {
        amount,
        salt,
        leaf,
        leaf_index: U256::from(leaf_index),
        proof,
        root,
        slot,
        source_id,
    })
}

/// Reads the EIP-8250 keyed-nonce sequence for `(sender, leaf)` and confirms
/// it's still `0` (i.e. the note hasn't already been consumed under this
/// sender), matching `current_nonce_seq`'s slot formula in ethrex's VM.
async fn ensure_note_unspent(client: &EthClient, sender: Address, leaf: [u8; 32]) -> Result<u64> {
    let mut preimage = [0u8; 64];
    preimage[12..32].copy_from_slice(sender.as_bytes());
    preimage[32..].copy_from_slice(&leaf);
    let slot = keccak(preimage);

    let value = client
        .get_storage_at(
            frame_tx_nonce_manager(),
            U256::from_big_endian(&slot.0),
            BlockIdentifier::Tag(BlockTag::Latest),
        )
        .await
        .context("failed to read nonce_seq from NONCE_MANAGER")?;
    if !value.is_zero() {
        bail!("note already spent (nonce_seq={value} for this leaf)");
    }
    Ok(0)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Balance(args) => cmd_balance(args).await,
        Command::Deposit(args) => cmd_deposit(args).await,
        Command::Execute(args) => cmd_execute(args).await,
        Command::Withdraw(args) => cmd_withdraw(args).await,
        Command::RefreshRoot(args) => cmd_refresh_root(args).await,
        Command::Trace(args) => cmd_trace(args).await,
    }
}

async fn cmd_balance(args: BalanceArgs) -> Result<()> {
    let owner = args
        .owner
        .unwrap_or_else(|| address_from_secret_key(&args.conn.private_key));
    let gas_tank = args.conn.gas_tank_address;

    let client = EthClient::new(args.conn.rpc_url).context("failed to connect to provider")?;
    let (amount, _) = gastank::read_note(&client, gas_tank, owner).await?;

    println!("owner: {owner:#x}");
    println!("balance: {amount} wei");

    Ok(())
}

async fn cmd_deposit(args: DepositArgs) -> Result<()> {
    let secret_key = args.conn.private_key;
    let depositor = address_from_secret_key(&secret_key);
    let owner = args.owner.unwrap_or(depositor);
    let salt: [u8; 32] = rand::random();
    let gas_tank = args.conn.gas_tank_address;

    let client = EthClient::new(args.conn.rpc_url).context("failed to connect to provider")?;
    let nonce = client
        .get_nonce(depositor, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    println!("owner: {owner:#x}");
    println!("salt: 0x{}", hex::encode(salt));

    send_frame_tx(
        &client,
        &secret_key,
        FrameTxSpec {
            sender: depositor,
            nonce_keys: vec![U256::zero()],
            nonce_seq: nonce,
            frames: vec![
                self_verify_frame(depositor, SELF_VERIFY_GAS, 0),
                sender_frame(
                    gas_tank,
                    args.amount_wei,
                    gastank::encode_deposit(owner, salt)?,
                    1_000_000,
                    DEPOSIT_STATE_GAS,
                ),
            ],
        },
        "deposit",
    )
    .await?;

    Ok(())
}

async fn cmd_execute(args: ExecuteArgs) -> Result<()> {
    let secret_key = args.conn.private_key;
    let owner = address_from_secret_key(&secret_key);
    let gas_tank = args.conn.gas_tank_address;
    let new_salt: [u8; 32] = rand::random();

    let client = EthClient::new(args.conn.rpc_url).context("failed to connect to provider")?;

    let spend = prepare_spend(&client, gas_tank, owner).await?;
    let nonce_seq = ensure_note_unspent(&client, gas_tank, spend.leaf).await?;

    // EIP-8272: the roots this transaction may reference are the data of a
    // dedicated VERIFY frame, which must come first. `verify()` reads the
    // tuple back out of frame 0 rather than from the old envelope field.
    let root_frame = recent_root_frame(
        &[RecentRootReference {
            source_id: H256(spend.source_id),
            slot: spend.slot,
            root: H256(spend.root),
        }],
        RECENT_ROOT_FRAME_GAS,
    );
    const ROOT_FRAME_INDEX: u64 = 0;

    let mut verify_frame = self_verify_frame(gas_tank, GAS_TANK_VERIFY_GAS, KEYED_NONCE_STATE_GAS);
    verify_frame.data = gastank::encode_verify(
        owner,
        spend.amount,
        spend.salt,
        spend.leaf_index,
        &spend.proof,
        U256::from(ROOT_FRAME_INDEX),
        U256::zero(),
        U256::zero(),
    )?;

    let settle_frame = Frame {
        mode: FrameMode::Sender as u8,
        flags: 0,
        target: Some(gas_tank),
        gas_limit: 500_000,
        state_gas_limit: SETTLE_STATE_GAS,
        value: U256::zero(),
        data: gastank::encode_settle(new_salt)?,
    };

    let execute_frame = sender_frame(
        gas_tank,
        U256::zero(),
        gastank::encode_execute(args.target, &args.data)?,
        1_500_000,
        500_000,
    );

    send_frame_tx(
        &client,
        &secret_key,
        FrameTxSpec {
            sender: gas_tank,
            nonce_keys: vec![U256::from_big_endian(&spend.leaf)],
            nonce_seq,
            frames: vec![root_frame, verify_frame, settle_frame, execute_frame],
        },
        "execute",
    )
    .await?;

    let (new_amount, _) = gastank::read_note(&client, gas_tank, owner).await?;
    println!(
        "new note: amount={new_amount}, salt=0x{}",
        hex::encode(new_salt)
    );

    Ok(())
}

async fn cmd_withdraw(args: WithdrawArgs) -> Result<()> {
    let secret_key = args.conn.private_key;
    let owner = address_from_secret_key(&secret_key);
    let gas_tank = args.conn.gas_tank_address;

    let client = EthClient::new(args.conn.rpc_url).context("failed to connect to provider")?;

    let spend = prepare_spend(&client, gas_tank, owner).await?;
    let nonce_seq = ensure_note_unspent(&client, owner, spend.leaf).await?;

    let root_frame = recent_root_frame(
        &[RecentRootReference {
            source_id: H256(spend.source_id),
            slot: spend.slot,
            root: H256(spend.root),
        }],
        RECENT_ROOT_FRAME_GAS,
    );
    const ROOT_FRAME_INDEX: u64 = 0;

    let withdraw_frame = Frame {
        mode: FrameMode::Default as u8,
        flags: 0,
        target: Some(gas_tank),
        gas_limit: 3_000_000,
        state_gas_limit: 500_000,
        value: U256::zero(),
        data: gastank::encode_withdraw(
            args.to,
            owner,
            spend.amount,
            spend.salt,
            spend.leaf_index,
            &spend.proof,
            U256::from(ROOT_FRAME_INDEX),
            U256::zero(),
            U256::zero(),
        )?,
    };

    send_frame_tx(
        &client,
        &secret_key,
        FrameTxSpec {
            sender: owner,
            nonce_keys: vec![U256::from_big_endian(&spend.leaf)],
            nonce_seq,
            frames: vec![
                root_frame,
                self_verify_frame(owner, SELF_VERIFY_GAS, KEYED_NONCE_STATE_GAS),
                withdraw_frame,
            ],
        },
        "withdraw",
    )
    .await?;
    println!("withdrew {} wei to {:#x}", spend.amount, args.to);

    Ok(())
}

async fn cmd_refresh_root(args: RefreshRootArgs) -> Result<()> {
    let secret_key = args.conn.private_key;
    let sender = address_from_secret_key(&secret_key);
    let gas_tank = args.conn.gas_tank_address;

    let client = EthClient::new(args.conn.rpc_url).context("failed to connect to provider")?;
    let nonce = client
        .get_nonce(sender, BlockIdentifier::Tag(BlockTag::Latest))
        .await?;

    send_frame_tx(
        &client,
        &secret_key,
        FrameTxSpec {
            sender,
            nonce_keys: vec![U256::zero()],
            nonce_seq: nonce,
            frames: vec![
                self_verify_frame(sender, SELF_VERIFY_GAS, 0),
                sender_frame(
                    gas_tank,
                    U256::zero(),
                    gastank::encode_refresh_root()?,
                    500_000,
                    500_000,
                ),
            ],
        },
        "refresh-root",
    )
    .await?;

    Ok(())
}

async fn cmd_trace(args: TraceArgs) -> Result<()> {
    let client = EthClient::new(args.rpc_url).context("failed to connect to provider")?;
    trace::print_trace(&client, args.tx_hash).await
}
