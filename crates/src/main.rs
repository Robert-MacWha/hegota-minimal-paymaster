use anyhow::{Context, Result, bail};
use clap::{Args, Parser, Subcommand};
use ethrex_common::types::{Frame, FrameMode, RecentRootReference, frame_tx_nonce_manager};
use ethrex_common::utils::keccak;
use ethrex_common::{Address, Bytes, H256, U256};
use ethrex_rpc::EthClient;
use ethrex_rpc::types::block_identifier::{BlockIdentifier, BlockTag};
use hegota_minimal_erc20_paymaster::convert::{parse_hex_bytes, parse_wei};
use hegota_minimal_erc20_paymaster::{
    FrameTxSpec, address_from_secret_key, gastank, merkle, parse_secret_key, self_verify_frame,
    send_frame_tx, sender_frame,
};
use secp256k1::SecretKey;
use url::Url;

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
    if !(1..=8191).contains(&age) {
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
                self_verify_frame(depositor, 300_000),
                sender_frame(
                    gas_tank,
                    args.amount_wei,
                    gastank::encode_deposit(owner, salt)?,
                    8_000_000,
                ),
            ],
            recent_root_references: vec![],
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

    let mut verify_frame = self_verify_frame(gas_tank, 300_000);
    verify_frame.data = gastank::encode_verify(
        owner,
        spend.amount,
        spend.salt,
        spend.leaf_index,
        &spend.proof,
        U256::zero(),
        U256::zero(),
    )?;

    let settle_frame = Frame {
        mode: FrameMode::Sender as u8,
        flags: 0,
        target: Some(gas_tank),
        gas_limit: 8_000_000,
        value: U256::zero(),
        data: gastank::encode_settle(new_salt)?,
    };

    let execute_frame = sender_frame(
        gas_tank,
        U256::zero(),
        gastank::encode_execute(args.target, &args.data)?,
        1_500_000,
    );

    send_frame_tx(
        &client,
        &secret_key,
        FrameTxSpec {
            sender: gas_tank,
            nonce_keys: vec![U256::from_big_endian(&spend.leaf)],
            nonce_seq,
            frames: vec![verify_frame, settle_frame, execute_frame],
            recent_root_references: vec![RecentRootReference {
                source_id: H256(spend.source_id),
                slot: spend.slot,
                root: H256(spend.root),
            }],
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

    let withdraw_frame = Frame {
        mode: FrameMode::Default as u8,
        flags: 0,
        target: Some(gas_tank),
        gas_limit: 3_000_000,
        value: U256::zero(),
        data: gastank::encode_withdraw(
            args.to,
            owner,
            spend.amount,
            spend.salt,
            spend.leaf_index,
            &spend.proof,
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
            frames: vec![self_verify_frame(owner, 300_000), withdraw_frame],
            recent_root_references: vec![RecentRootReference {
                source_id: H256(spend.source_id),
                slot: spend.slot,
                root: H256(spend.root),
            }],
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
                self_verify_frame(sender, 300_000),
                sender_frame(
                    gas_tank,
                    U256::zero(),
                    gastank::encode_refresh_root()?,
                    500_000,
                ),
            ],
            recent_root_references: vec![],
        },
        "refresh-root",
    )
    .await?;

    Ok(())
}
