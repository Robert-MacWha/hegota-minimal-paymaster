use anyhow::{Result, bail};
use ethrex_common::{Bytes, U256};
use ethrex_l2_common::calldata::Value;

pub fn as_fixed_bytes32(value: Value) -> Result<[u8; 32]> {
    let Value::FixedBytes(bytes) = value else {
        bail!("expected FixedBytes value");
    };
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn as_uint(value: Value) -> Result<U256> {
    let Value::Uint(uint) = value else {
        bail!("expected Uint value");
    };
    Ok(uint)
}

pub fn parse_wei(s: &str) -> Result<U256, String> {
    U256::from_dec_str(s).map_err(|e| e.to_string())
}

pub fn parse_hex_bytes(s: &str) -> Result<Bytes, String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(Bytes::from(hex::decode(s).map_err(|e| e.to_string())?))
}
