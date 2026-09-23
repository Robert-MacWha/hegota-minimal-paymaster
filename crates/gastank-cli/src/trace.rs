use anyhow::{Context, Result};
use ethrex_common::types::{
    FRAME_TX_RECENT_ROOT_TUPLE_BYTES, FrameMode, frame_tx_nonce_manager, frame_tx_recent_root,
};
use ethrex_common::{Address, Bytes, H256, U256};
use ethrex_rpc::EthClient;
use ethrex_rpc::types::receipt::{RpcFrameReceipt, RpcReceipt};
use ethrex_rpc::utils::RpcRequest;
use serde::Deserialize;
use serde_json::json;

/// Prints a frame-by-frame summary of `tx_hash`, then the node's `callTracer`
/// tree.
pub async fn print_trace(client: &EthClient, tx_hash: H256) -> Result<()> {
    let tx: FrameTx = client
        .send_request_parsed(RpcRequest::new(
            "eth_getTransactionByHash",
            Some(vec![json!(format!("{tx_hash:#x}"))]),
        ))
        .await
        .with_context(|| format!("failed to fetch transaction {tx_hash:#x}"))?;
    let receipt = client
        .get_transaction_receipt(tx_hash)
        .await?
        .with_context(|| format!("no receipt for {tx_hash:#x} -- still pending?"))?;

    print_summary(&receipt, &tx.frames);
    print_frames(
        &tx.frames,
        receipt.frame_receipts.as_deref().unwrap_or_default(),
    );
    print_call_tree(client, tx_hash).await;

    Ok(())
}

fn print_summary(receipt: &RpcReceipt, frames: &[FrameInfo]) {
    let used = receipt.tx_info.gas_used;
    let price = receipt.tx_info.effective_gas_price;

    println!("tx      {:#x}", receipt.tx_info.transaction_hash);
    println!(
        "block   {}  status {}",
        receipt.block_info.block_number,
        if receipt.receipt.status {
            "success"
        } else {
            "FAILED"
        }
    );
    println!("sender  {:#x}", receipt.tx_info.from);
    if let Some(payer) = receipt.payer {
        println!("payer   {payer:#x}");
    }
    println!("cost    {} wei @ {price} wei/gas", cost(used, price));

    // What the frames declare is what the payer is quoted: `TXPARAM` `0x06`
    // (max cost) prices the sum of their limits, not the gas the transaction
    // goes on to use. A GasTank note is debited that quote, so slack here is
    // paid for.
    let declared: u64 = frames
        .iter()
        .map(|f| f.gas_limit.saturating_add(f.state_gas_limit))
        .sum();
    if declared == 0 {
        println!("gas     {used} used");
        return;
    }
    println!(
        "gas     {used} used of {declared} declared by frames ({:.0}% slack)",
        (1.0 - used as f64 / declared as f64) * 100.0
    );
}

fn print_frames(frames: &[FrameInfo], receipts: &[RpcFrameReceipt]) {
    if frames.is_empty() {
        return;
    }
    println!("\nframes");
    println!(
        "  {:<2} {:<6} {:<7} {:<26} {:>19} {:>19}",
        "#", "mode", "status", "target", "exec gas", "state gas"
    );
    for (index, frame) in frames.iter().enumerate() {
        let receipt = receipts.get(index);
        println!(
            "  {index:<2} {:<6} {:<7} {:<26} {:>19} {:>19}",
            mode_name(frame.mode),
            receipt.map_or("-", |r| frame_status(r.status)),
            target(frame),
            budget(receipt.map(|r| r.gas_used), frame.gas_limit),
            budget(receipt.map(|r| r.state_gas_used), frame.state_gas_limit),
        );
    }
}

/// Renders the node's `callTracer` output. The `debug` namespace is commonly
/// disabled on public endpoints, in which case the frame table above is all
/// the detail available without running a node.
async fn print_call_tree(client: &EthClient, tx_hash: H256) {
    println!("\ncall tree");
    let request = RpcRequest::new(
        "debug_traceTransaction",
        Some(vec![
            json!(format!("{tx_hash:#x}")),
            json!({ "tracer": "callTracer" }),
        ]),
    );
    match client.send_request_parsed::<CallFrame>(request).await {
        Ok(root) => print_call(&root, 0),
        Err(err) => {
            println!("  unavailable: {err}");
            println!("  (needs an endpoint serving the `debug` namespace)");
        }
    }
}

fn print_call(call: &CallFrame, depth: usize) {
    let indent = "  ".repeat(depth + 1);
    let to = call.to.map_or_else(|| "(create)".to_string(), label);
    let mut line = format!(
        "{indent}{} {to} {} gas {}",
        call.call_type,
        selector(&call.input),
        call.gas_used
    );
    if let Some(value) = call.value.filter(|v| !v.is_zero()) {
        line.push_str(&format!(" value {value}"));
    }
    if let Some(reason) = call.revert_reason.as_ref().or(call.error.as_ref()) {
        line.push_str(&format!("  <- {reason}"));
    }
    println!("{line}");

    for inner in &call.calls {
        print_call(inner, depth + 1);
    }
}

/// The frames of `eth_getTransactionByHash`, decoded directly rather than
/// through `RpcTransaction`: its `Transaction` is serialize-only behind a
/// private serde module, and its required fields run ahead of what a deployed
/// node returns (a node predating `blockTimestamp` fails the whole decode).
/// Taking only these fields keeps the command working across that skew.
#[derive(Deserialize)]
struct FrameTx {
    #[serde(default)]
    frames: Vec<FrameInfo>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct FrameInfo {
    #[serde(with = "ethrex_common::serde_utils::u64::hex_str")]
    mode: u64,
    to: Option<Address>,
    /// `limits.execution` on the wire.
    #[serde(with = "ethrex_common::serde_utils::u64::hex_str")]
    gas_limit: u64,
    #[serde(default, with = "ethrex_common::serde_utils::u64::hex_str")]
    state_gas_limit: u64,
    #[serde(with = "ethrex_common::serde_utils::bytes")]
    data: Bytes,
}

/// The subset of geth's `callTracer` frame this summary prints. ethrex's own
/// `CallTraceFrame` is serialize-only, so it cannot be decoded client-side.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CallFrame {
    #[serde(rename = "type")]
    call_type: String,
    to: Option<Address>,
    value: Option<U256>,
    #[serde(with = "ethrex_common::serde_utils::u64::hex_str")]
    gas_used: u64,
    #[serde(default, with = "ethrex_common::serde_utils::bytes")]
    input: Bytes,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    revert_reason: Option<String>,
    #[serde(default)]
    calls: Vec<CallFrame>,
}

fn mode_name(mode: u64) -> &'static str {
    match u8::try_from(mode).ok().and_then(FrameMode::from_u8) {
        Some(FrameMode::Default) => "DEF",
        Some(FrameMode::Verify) => "VERIFY",
        Some(FrameMode::Sender) => "SENDER",
        None => "?",
    }
}

/// EIP-8141 frame status: 0 = failure, 1 = success, 2 = skipped by an
/// atomic-batch sibling's failure.
fn frame_status(status: u8) -> &'static str {
    match status {
        0 => "FAILED",
        1 => "ok",
        2 => "skipped",
        _ => "?",
    }
}

fn target(frame: &FrameInfo) -> String {
    let target = frame.to.map_or_else(|| "(sender)".to_string(), label);
    // A recent-root verifier frame's data is packed tuples, not a call, so its
    // leading bytes are a source_id rather than a selector.
    if frame.to == Some(frame_tx_recent_root())
        && !frame.data.is_empty()
        && frame
            .data
            .len()
            .is_multiple_of(FRAME_TX_RECENT_ROOT_TUPLE_BYTES)
    {
        return format!(
            "{target} {} root(s)",
            frame.data.len() / FRAME_TX_RECENT_ROOT_TUPLE_BYTES
        );
    }
    format!("{target} {}", selector(&frame.data))
}

/// Abbreviates an address, naming the predeploys a frame transaction routinely
/// touches so they stand out from application contracts.
fn label(address: Address) -> String {
    if address == frame_tx_recent_root() {
        return "RECENT_ROOT".to_string();
    }
    if address == frame_tx_nonce_manager() {
        return "NONCE_MANAGER".to_string();
    }
    let hex = format!("{address:#x}");
    format!("{}..{}", &hex[..8], &hex[hex.len() - 4..])
}

/// The leading 4-byte selector of `data`, or `-` when there is none. Frame data
/// is not always a call: the recent-root verifier frame carries packed tuples.
fn selector(data: &Bytes) -> String {
    match data.get(..4) {
        Some(selector) => format!("0x{}", hex::encode(selector)),
        None => "-".to_string(),
    }
}

fn budget(used: Option<u64>, limit: u64) -> String {
    match used {
        Some(used) => format!("{used}/{limit}"),
        None => format!("?/{limit}"),
    }
}

fn cost(gas: u64, price: u64) -> u128 {
    u128::from(gas).saturating_mul(u128::from(price))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `debug` namespace is off on the public devnet endpoint, so this
    /// pins the `callTracer` decode against the shape ethrex's
    /// `CallTraceFrame` serializes.
    #[test]
    fn decodes_a_nested_call_tracer_response() {
        let json = r#"{
            "type": "CALL",
            "from": "0x0bca60c0742354616c94e9da941cb5802dfe94cf",
            "to": "0x0bca60c0742354616c94e9da941cb5802dfe94cf",
            "value": "0x0",
            "gas": "0x7a120",
            "gasUsed": "0x5e931",
            "input": "0x987757dd00",
            "calls": [
                {
                    "type": "DELEGATECALL",
                    "from": "0x0bca60c0742354616c94e9da941cb5802dfe94cf",
                    "to": "0x31889023a70c8d2154e1a74be6601df6af05203b",
                    "gas": "0x1000",
                    "gasUsed": "0x64",
                    "input": "0x16525c7f"
                },
                {
                    "type": "CALL",
                    "from": "0x0bca60c0742354616c94e9da941cb5802dfe94cf",
                    "to": "0x0000000000000000000000000000000000008272",
                    "gas": "0x2000",
                    "gasUsed": "0x5654",
                    "input": "0xdead",
                    "error": "execution reverted",
                    "revertReason": "GasTank: bad proof"
                }
            ]
        }"#;

        let root: CallFrame = serde_json::from_str(json).expect("callTracer decode");
        assert_eq!(root.call_type, "CALL");
        assert_eq!(root.gas_used, 387_377);
        assert_eq!(selector(&root.input), "0x987757dd");
        assert_eq!(root.calls.len(), 2);

        let predeploy = &root.calls[1];
        assert_eq!(predeploy.to, Some(frame_tx_recent_root()));
        assert_eq!(label(predeploy.to.unwrap()), "RECENT_ROOT");
        assert_eq!(
            predeploy.revert_reason.as_deref(),
            Some("GasTank: bad proof")
        );
    }

    /// `output` and `logs` are present on real responses and must not break the
    /// decode, and a top-level frame carries the EIP-8037 gas fields too.
    #[test]
    fn ignores_fields_the_summary_does_not_print() {
        let json = r#"{
            "type": "CALL",
            "from": "0x0bca60c0742354616c94e9da941cb5802dfe94cf",
            "gas": "0x10",
            "gasUsed": "0x10",
            "input": "0x",
            "output": "0x01",
            "regularGasUsed": "0x20",
            "stateGasUsed": "0x30",
            "gasRefund": "0x0",
            "logs": [],
            "calls": []
        }"#;

        let root: CallFrame = serde_json::from_str(json).expect("callTracer decode");
        assert_eq!(root.to, None);
        assert_eq!(selector(&root.input), "-");
        assert!(root.calls.is_empty());
    }
}
