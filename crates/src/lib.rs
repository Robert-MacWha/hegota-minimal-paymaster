pub mod convert;
pub mod gastank;
pub mod merkle;

use anyhow::{Context, Result};
use ethrex_common::types::{
    APPROVE_EXECUTION_AND_PAYMENT, FRAME_SIG_SCHEME_SECP256K1, Frame, FrameMode, FrameSignature,
    FrameTransaction, RecentRootReference, Transaction,
};
use ethrex_common::utils::keccak;
use ethrex_common::{Address, Bytes, H256, U256};
use ethrex_rpc::EthClient;
use ethrex_rpc::types::receipt::RpcReceipt;
use secp256k1::{Message, SECP256K1, SecretKey};

/// Parses a `0x`-prefixed or bare hex private key into a `SecretKey`.
pub fn parse_secret_key(hex: &str) -> Result<SecretKey> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    SecretKey::from_slice(&hex::decode(hex).context("invalid private key")?)
        .context("invalid private key")
}

/// Derives the Ethereum address controlled by `secret_key`.
pub fn address_from_secret_key(secret_key: &SecretKey) -> Address {
    Address::from(keccak(
        &secret_key.public_key(SECP256K1).serialize_uncompressed()[1..],
    ))
}

pub fn self_verify_frame(sender: Address, gas_limit: u64) -> Frame {
    Frame {
        mode: FrameMode::Verify as u8,
        flags: APPROVE_EXECUTION_AND_PAYMENT,
        target: Some(sender),
        gas_limit,
        value: U256::zero(),
        data: Bytes::new(),
    }
}

pub fn sender_frame(target: Address, value: U256, data: Bytes, gas_limit: u64) -> Frame {
    Frame {
        mode: FrameMode::Sender as u8,
        flags: 0,
        target: Some(target),
        gas_limit,
        value,
        data,
    }
}

/// Signs `hash` with `signer`, returning the raw recovery id (0/1) and the
/// 64-byte `r || s` compact signature.
pub fn sign_recoverable(hash: H256, signer: &SecretKey) -> (u8, [u8; 64]) {
    let msg = Message::from_digest(hash.0);
    let (recovery_id, sig) = SECP256K1
        .sign_ecdsa_recoverable(&msg, signer)
        .serialize_compact();
    (Into::<i32>::into(recovery_id) as u8, sig)
}

/// Signs `tx`'s signature hash and fills in `signatures[sig_index]` with a
/// `v || r || s` SECP256K1 signature, as required by frame-transaction
/// verification (see `validate_frame_signatures` in ethrex's EVM crate).
pub fn sign(tx: &mut FrameTransaction, sig_index: usize, signer: &SecretKey) {
    let (v, sig) = sign_recoverable(tx.compute_sig_hash(), signer);
    let mut raw = Vec::with_capacity(65);
    raw.push(v);
    raw.extend_from_slice(&sig);
    tx.signatures[sig_index].signature = Bytes::from(raw);
}

fn owner_signature(signer: Address) -> FrameSignature {
    FrameSignature {
        scheme: FRAME_SIG_SCHEME_SECP256K1,
        signer: Some(signer),
        msg: Bytes::new(),
        signature: Bytes::new(),
    }
}

/// Everything needed to build a `FrameTransaction` beyond fee/chain-id data,
/// which `send_frame_tx` fills in itself.
pub struct FrameTxSpec {
    pub sender: Address,
    pub nonce_keys: Vec<U256>,
    pub nonce_seq: u64,
    pub frames: Vec<Frame>,
    pub recent_root_references: Vec<RecentRootReference>,
}

/// Builds, signs, sends, and confirms a `FrameTransaction` from `spec`.
///
/// `FrameTransaction`s have no reusable build/sign/send path in `ethrex`'s
/// SDK -- `build_generic_tx` explicitly rejects `TxType::Frame` and the
/// `Signable` trait explicitly refuses to sign frame transactions, since
/// they're authenticated via the outer signatures list rather than ECDSA
/// `sign_inplace` -- so chain-id/fee lookup and signing stay hand-rolled
/// here.
pub async fn send_frame_tx(
    client: &EthClient,
    secret_key: &SecretKey,
    spec: FrameTxSpec,
    label: &str,
) -> Result<RpcReceipt> {
    let signer = address_from_secret_key(secret_key);

    let chain_id = client.get_chain_id().await?.as_u64();
    let max_priority_fee_per_gas = client.get_max_priority_fee().await?.as_u64();
    let max_fee_per_gas = client.get_gas_price().await?.as_u64() + max_priority_fee_per_gas;

    let mut tx = FrameTransaction {
        chain_id,
        nonce_keys: spec.nonce_keys,
        nonce_seq: spec.nonce_seq,
        sender: spec.sender,
        frames: spec.frames,
        signatures: vec![owner_signature(signer)],
        max_priority_fee_per_gas,
        max_fee_per_gas,
        recent_root_references: spec.recent_root_references,
        ..Default::default()
    };
    sign(&mut tx, 0, secret_key);

    let raw = Transaction::FrameTransaction(tx).encode_canonical_to_vec();
    let hash: H256 = client
        .send_raw_transaction(&raw)
        .await
        .with_context(|| format!("failed to send {label} transaction"))?;
    println!("{label} sent: {hash:#x}");

    let receipt = ethrex_l2_sdk::wait_for_transaction_receipt(hash, client, 60)
        .await
        .context("failed to fetch transaction receipt")?;
    println!(
        "status: {}",
        if receipt.receipt.status {
            "success"
        } else {
            "failed"
        }
    );
    Ok(receipt)
}
