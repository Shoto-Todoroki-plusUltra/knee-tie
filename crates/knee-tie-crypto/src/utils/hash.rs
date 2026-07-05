use sha2::{Sha256, Digest};

/// Security parameter: 32 bytes = 256 bits = λ
pub const LAMBDA: usize = 32;

/// Domain separation constants.
/// Every hash call in the library uses one of these prefixes so that
/// H(0x00 ∥ x) ≠ H(0x01 ∥ x) even for identical inputs x.
pub mod domain {
    pub const WOTS_CHAIN: u8 = 0x00;
    pub const MERKLE_NODE: u8 = 0x01;
    pub const MERKLE_LEAF: u8 = 0x02;
    pub const PRF: u8 = 0x03;
    pub const MSG_HASH: u8 = 0x04;
    pub const POS_TAG: u8 = 0x05;
}

/// PRF f: {0,1}^λ × {0,1}^* → {0,1}^λ
///
/// Used in DGMT for all key derivation.
/// Implementation: SHA-256(0x03 ∥ key ∥ input)
pub fn prf(key: &[u8; LAMBDA], input: &[u8]) -> [u8; LAMBDA] {
    let mut h = Sha256::new();
    h.update([domain::PRF]);
    h.update(key);
    h.update(input);
    h.finalize().into()
}

/// PRF with a u64 index input. Convenience wrapper.
pub fn prf_u64(key: &[u8; LAMBDA], index: u64) -> [u8; LAMBDA] {
    prf(key, &index.to_be_bytes())
}

/// PRF with concatenated u32 indices.
/// Used for multi-index lookups: f(SMT1.key, i ∥ j ∥ k)
pub fn prf_indices(key: &[u8; LAMBDA], indices: &[u32]) -> [u8; LAMBDA] {
    let mut input = Vec::with_capacity(indices.len() * 4);
    for idx in indices {
        input.extend_from_slice(&idx.to_be_bytes());
    }
    prf(key, &input)
}

/// One-way function f used in WOTS chains.
///
/// Including the step counter and public seed binds each application
/// to its position, preventing cross-chain attacks.
/// Implementation: SHA-256(0x00 ∥ pub_seed ∥ step_bytes ∥ x)
pub fn wots_chain_step(
    x: &[u8; LAMBDA],
    pub_seed: &[u8; LAMBDA],
    step: u32,
) -> [u8; LAMBDA] {
    let mut h = Sha256::new();
    h.update([domain::WOTS_CHAIN]);
    h.update(pub_seed);
    h.update(step.to_be_bytes());
    h.update(x);
    h.finalize().into()
}

/// Apply the WOTS chain function exactly `steps` times starting from `start`.
/// If steps == 0, returns x unchanged.
pub fn wots_chain(
    x: &[u8; LAMBDA],
    pub_seed: &[u8; LAMBDA],
    start: u32,
    steps: u32,
) -> [u8; LAMBDA] {
    let mut result = *x;
    for step in start..start.saturating_add(steps) {
        result = wots_chain_step(&result, pub_seed, step);
    }
    result
}

/// Merkle tree leaf hash: SHA-256(0x02 ∥ data)
///
/// Domain byte 0x02 prevents leaf hashes colliding with internal
/// node hashes, closing second-preimage attacks on the tree.
pub fn merkle_leaf_hash(data: &[u8]) -> [u8; LAMBDA] {
    let mut h = Sha256::new();
    h.update([domain::MERKLE_LEAF]);
    h.update(data);
    h.finalize().into()
}

/// Merkle tree internal node hash: SHA-256(0x01 ∥ left ∥ right)
///
/// Paper §2.3: yj[i] ← H(yj+1[2i] ∥ yj+1[2i+1])
pub fn merkle_node_hash(left: &[u8; LAMBDA], right: &[u8; LAMBDA]) -> [u8; LAMBDA] {
    let mut h = Sha256::new();
    h.update([domain::MERKLE_NODE]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// DGMT message hash: H(m ∥ μ)
///
/// μ is the depth of fallback node Fn_i in the IMT.
/// Including μ prevents signatures from different depths being
/// interchangeable. Paper §4.3, Algorithm 7, line 3.
pub fn dgmt_message_hash(message: &[u8], fallback_depth: u32) -> [u8; LAMBDA] {
    let mut h = Sha256::new();
    h.update([domain::MSG_HASH]);
    h.update(message);
    h.update(fallback_depth.to_be_bytes());
    h.finalize().into()
}

/// DGMT SMT(2) leaf hash: H(OTS.pk_{i,j,k,l'} ∥ DGMT.pos_{i,j,k,l})
///
/// Embeds the position tag into the leaf so signature opening can
/// verify the correct position tag was used.
/// Paper §4.2.2, Algorithm 3, line 7.
///
/// `ots_pk_bytes`: the full WOTS public key serialised as a byte slice.
///   A WOTS public key is ξ=67 elements × λ=32 bytes = 2144 bytes.
///   We accept &[u8] rather than a fixed-size array because the caller
///   owns a WotsPublicKey([[u8;32]; 67]) and flattens it before calling.
pub fn dgmt_leaf_hash(ots_pk_bytes: &[u8], dgmt_pos: &[u8; LAMBDA]) -> [u8; LAMBDA] {
    let mut h = Sha256::new();
    h.update([domain::MERKLE_LEAF]);
    h.update(ots_pk_bytes);
    h.update(dgmt_pos);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_is_deterministic() {
        let key = [1u8; LAMBDA];
        assert_eq!(prf_u64(&key, 42), prf_u64(&key, 42));
    }

    #[test]
    fn prf_different_inputs_give_different_outputs() {
        let key = [1u8; LAMBDA];
        assert_ne!(prf_u64(&key, 1), prf_u64(&key, 2));
    }

    #[test]
    fn prf_different_keys_give_different_outputs() {
        let key1 = [1u8; LAMBDA];
        let key2 = [2u8; LAMBDA];
        assert_ne!(prf_u64(&key1, 1), prf_u64(&key2, 1));
    }

    #[test]
    fn domain_separation_works() {
        let key = [0u8; LAMBDA];
        let data = b"test_input";
        let prf_out  = prf(&key, data);
        let leaf_out = merkle_leaf_hash(data);
        assert_ne!(prf_out, leaf_out,
            "Domain separation failed: PRF and leaf hash must differ");
    }

    #[test]
    fn wots_chain_zero_steps_is_identity() {
        let x = [42u8; LAMBDA];
        let pub_seed = [0u8; LAMBDA];
        assert_eq!(wots_chain(&x, &pub_seed, 0, 0), x);
    }

    #[test]
    fn wots_chain_is_sequential() {
        // chain(x, 0, 3) must equal chain(chain(x, 0, 1), 1, 2)
        let x = [7u8; LAMBDA];
        let pub_seed = [3u8; LAMBDA];
        let full  = wots_chain(&x, &pub_seed, 0, 3);
        let step1 = wots_chain(&x, &pub_seed, 0, 1);
        let step2 = wots_chain(&step1, &pub_seed, 1, 2);
        assert_eq!(full, step2,
            "Chain must be composable: chain(x,0,3) != chain(chain(x,0,1),1,2)");
    }

    #[test]
    fn merkle_leaf_and_node_hashes_differ() {
        let data = [5u8; LAMBDA];
        let leaf = merkle_leaf_hash(&data);
        let node = merkle_node_hash(&data, &data);
        assert_ne!(&leaf[..], &node[..],
            "Leaf and node hashes must differ (different domain bytes)");
    }
}
