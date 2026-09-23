use anyhow::{Context, Result};
use ethrex_common::utils::keccak;
use ethrex_common::{Address, Bytes, U256};
use ethrex_l2_common::calldata::Value;
use ethrex_l2_sdk::calldata::{decode_calldata, encode_calldata};
use ethrex_rpc::EthClient;
use ethrex_rpc::clients::eth::Overrides;

use crate::convert::{as_fixed_bytes32, as_uint};

pub fn leaf(owner: Address, amount: U256, salt: [u8; 32]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(84);
    buf.extend_from_slice(owner.as_bytes());
    buf.extend_from_slice(&amount.to_big_endian());
    buf.extend_from_slice(&salt);
    keccak(buf).0
}

fn proof_values(proof: &[[u8; 32]]) -> Vec<Value> {
    proof
        .iter()
        .map(|word| Value::FixedBytes(Bytes::copy_from_slice(word)))
        .collect()
}

pub fn encode_deposit(owner: Address, salt: [u8; 32]) -> Result<Bytes> {
    Ok(encode_calldata(
        "deposit(address,bytes32)",
        &[
            Value::Address(owner),
            Value::FixedBytes(Bytes::copy_from_slice(&salt)),
        ],
    )?
    .into())
}

pub fn encode_settle(new_salt: [u8; 32]) -> Result<Bytes> {
    Ok(encode_calldata(
        "settle(bytes32)",
        &[Value::FixedBytes(Bytes::copy_from_slice(&new_salt))],
    )?
    .into())
}

pub fn encode_execute(target: Address, data: &[u8]) -> Result<Bytes> {
    Ok(encode_calldata(
        "execute(address,bytes)",
        &[
            Value::Address(target),
            Value::Bytes(Bytes::copy_from_slice(data)),
        ],
    )?
    .into())
}

pub fn encode_refresh_root() -> Result<Bytes> {
    Ok(encode_calldata("refreshRoot()", &[])?.into())
}

#[allow(clippy::too_many_arguments)]
pub fn encode_verify(
    owner: Address,
    amount: U256,
    salt: [u8; 32],
    leaf_index: U256,
    proof: &[[u8; 32]],
    root_frame_index: U256,
    root_ref_index: U256,
    sig_index: U256,
) -> Result<Bytes> {
    Ok(encode_calldata(
        "verify(address,uint256,bytes32,uint256,bytes32[],uint256,uint256,uint256)",
        &[
            Value::Address(owner),
            Value::Uint(amount),
            Value::FixedBytes(Bytes::copy_from_slice(&salt)),
            Value::Uint(leaf_index),
            Value::Array(proof_values(proof)),
            Value::Uint(root_frame_index),
            Value::Uint(root_ref_index),
            Value::Uint(sig_index),
        ],
    )?
    .into())
}

#[allow(clippy::too_many_arguments)]
pub fn encode_withdraw(
    to: Address,
    owner: Address,
    amount: U256,
    salt: [u8; 32],
    leaf_index: U256,
    proof: &[[u8; 32]],
    root_frame_index: U256,
    root_ref_index: U256,
    sig_index: U256,
) -> Result<Bytes> {
    Ok(encode_calldata(
        "withdraw(address,address,uint256,bytes32,uint256,bytes32[],uint256,uint256,uint256)",
        &[
            Value::Address(to),
            Value::Address(owner),
            Value::Uint(amount),
            Value::FixedBytes(Bytes::copy_from_slice(&salt)),
            Value::Uint(leaf_index),
            Value::Array(proof_values(proof)),
            Value::Uint(root_frame_index),
            Value::Uint(root_ref_index),
            Value::Uint(sig_index),
        ],
    )?
    .into())
}

pub async fn read_root(client: &EthClient, gas_tank: Address) -> Result<[u8; 32]> {
    let calldata = encode_calldata("root()", &[]).context("failed to encode root() calldata")?;
    let mut values = call_and_decode(client, gas_tank, calldata.into(), "_(bytes32)").await?;
    as_fixed_bytes32(values.remove(0))
}

pub async fn read_next_leaf_index(client: &EthClient, gas_tank: Address) -> Result<U256> {
    let calldata = encode_calldata("nextLeafIndex()", &[])?;
    let mut values = call_and_decode(client, gas_tank, calldata.into(), "_(uint256)").await?;
    as_uint(values.remove(0))
}

pub async fn read_commitment(client: &EthClient, gas_tank: Address, i: U256) -> Result<[u8; 32]> {
    let calldata = encode_calldata("commitments(uint256)", &[Value::Uint(i)])?;
    let mut values = call_and_decode(client, gas_tank, calldata.into(), "_(bytes32)").await?;
    as_fixed_bytes32(values.remove(0))
}

pub async fn read_note(
    client: &EthClient,
    gas_tank: Address,
    owner: Address,
) -> Result<(U256, [u8; 32])> {
    let calldata = encode_calldata("notes(address)", &[Value::Address(owner)])?;
    let mut values =
        call_and_decode(client, gas_tank, calldata.into(), "_(uint256,bytes32)").await?;
    let salt = as_fixed_bytes32(values.remove(1))?;
    let amount = as_uint(values.remove(0))?;
    Ok((amount, salt))
}

pub async fn read_source_id(client: &EthClient, gas_tank: Address) -> Result<[u8; 32]> {
    let calldata = encode_calldata("SOURCE_ID()", &[])?;
    let mut values = call_and_decode(client, gas_tank, calldata.into(), "_(bytes32)").await?;
    as_fixed_bytes32(values.remove(0))
}

pub async fn read_last_root_slot(client: &EthClient, gas_tank: Address) -> Result<u64> {
    let calldata = encode_calldata("lastRootSlot()", &[])?;
    let mut values = call_and_decode(client, gas_tank, calldata.into(), "_(uint256)").await?;
    Ok(as_uint(values.remove(0))?.as_u64())
}

async fn call_and_decode(
    client: &EthClient,
    gas_tank: Address,
    calldata: Bytes,
    return_shape: &str,
) -> Result<Vec<Value>> {
    let raw = client
        .call(gas_tank, calldata, Overrides::default())
        .await?;
    let raw =
        hex::decode(raw.trim_start_matches("0x")).context("invalid hex in eth_call response")?;

    let mut padded = vec![0u8; 4];
    padded.extend_from_slice(&raw);
    decode_calldata(return_shape, padded.into()).context("failed to decode eth_call return value")
}
