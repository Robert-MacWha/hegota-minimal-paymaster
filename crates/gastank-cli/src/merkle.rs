use ethrex_common::utils::keccak;

pub const DEPTH: usize = 20;

/// Generates a merkle proof for a given leaf index in a merkle tree constructed
/// from the provided leaves.
pub fn proof_for(leaves: &[[u8; 32]], index: usize) -> [[u8; 32]; DEPTH] {
    let zeros = zeros();
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    let mut idx = index;
    let mut proof = [[0u8; 32]; DEPTH];

    for (lvl, zero) in zeros.iter().enumerate() {
        let sibling_idx = idx ^ 1;
        proof[lvl] = level.get(sibling_idx).copied().unwrap_or(*zero);

        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            let left = level[i];
            let right = level.get(i + 1).copied().unwrap_or(*zero);
            next.push(hash_pair(left, right));
            i += 2;
        }
        level = next;
        idx /= 2;
    }

    proof
}

/// Precomputes the empty subtree hash at each level, matching
/// `MerkleTree.sol`'s `zeros()`.
///
/// - `zeros[0] = 0`.
/// - `zeros[i] = keccak256(zeros[i-1] || zeros[i-1])`.
fn zeros() -> [[u8; 32]; DEPTH] {
    let mut zeros = [[0u8; 32]; DEPTH];
    for i in 1..DEPTH {
        let prev = zeros[i - 1];
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&prev);
        buf[32..].copy_from_slice(&prev);
        zeros[i] = keccak(buf).0;
    }
    zeros
}

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(&left);
    buf[32..].copy_from_slice(&right);
    keccak(buf).0
}
