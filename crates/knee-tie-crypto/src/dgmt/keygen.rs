//! DGMT Key Generation
//!
//! Paper 1, Algorithms 1 and 4.

use zeroize::ZeroizeOnDrop;
use crate::utils::hash::{LAMBDA, prf_u64, prf_indices, merkle_leaf_hash};
use crate::utils::sprp::sprp_eval;
use crate::wots::wots_keygen;
use crate::merkle::MerkleTree;
use crate::dgmt::params::DgmtParams;
use crate::error::Result;

// ─── Secret Keys ─────────────────────────────────────────────────────────────

/// DGMT manager secret key: DGMT.SK
///
/// DGMT.SK = (msk, IMT.key, SMT1.key, SMT2.key, shuffle.key)
///
/// All fields are λ=256 bits. ZeroizeOnDrop wipes key material
/// from memory when this struct is dropped.
///
/// Paper §4.3, Algorithm 4.
#[derive(ZeroizeOnDrop)]
pub struct DgmtSecretKey {
    /// Master secret key for SPRP g2.
    /// Used to compute DGMT.pos tags and to open signatures.
    pub msk: [u8; LAMBDA],

    /// PRF key for IMT leaf generation.
    /// IMT leaf i = f(imt_key, i) for i = 1..2^hI.
    pub imt_key: [u8; LAMBDA],

    /// PRF key for SMT(1) OTS derivation.
    /// OTS.sk_{i,j,k} ← f(smt1_key, i ∥ j ∥ k)
    pub smt1_key: [u8; LAMBDA],

    /// PRF key for SMT(2) OTS derivation.
    /// OTS.sk_{i,j,k,l'} ← f(smt2_key, i ∥ j ∥ k ∥ l')
    pub smt2_key: [u8; LAMBDA],

    /// SPRP g1 key for shuffling SMT(2) leaves and computing fallback keys.
    pub shuffle_key: [u8; LAMBDA],
}

impl DgmtSecretKey {
    /// Generate fresh random secret keys.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut key = Self {
            msk:         [0u8; LAMBDA],
            imt_key:     [0u8; LAMBDA],
            smt1_key:    [0u8; LAMBDA],
            smt2_key:    [0u8; LAMBDA],
            shuffle_key: [0u8; LAMBDA],
        };
        rng.fill_bytes(&mut key.msk);
        rng.fill_bytes(&mut key.imt_key);
        rng.fill_bytes(&mut key.smt1_key);
        rng.fill_bytes(&mut key.smt2_key);
        rng.fill_bytes(&mut key.shuffle_key);
        key
    }

    /// Generate deterministic keys from a master seed.
    /// For testing only — not for production use.
    pub fn from_seed(seed: &[u8; LAMBDA]) -> Self {
        Self {
            msk:         prf_indices(seed, &[0]),
            imt_key:     prf_indices(seed, &[1]),
            smt1_key:    prf_indices(seed, &[2]),
            smt2_key:    prf_indices(seed, &[3]),
            shuffle_key: prf_indices(seed, &[4]),
        }
    }
}

// ─── Public Parameters ───────────────────────────────────────────────────────

/// DGMT public parameters: DGMT.PubPr = (DGMT.gpk, FK, RL)
///
/// Paper §4.3.
#[derive(Clone, Debug)]
pub struct DgmtPublicParams {
    /// Group public key: root of the IMT.
    /// Paper: "DGMT.gpk = rIMT"
    pub gpk: [u8; LAMBDA],

    /// Fallback key list FK.
    ///
    /// FK[(i-1)*γ + (j-1)] = Fk_{i,j}  (0-indexed here)
    /// where i = fallback node index (1..=num_fallback_nodes)
    ///       j = SMTMT index         (1..=γ)
    ///
    /// Paper §4.2.1: |FK| = γ × (2^(hI+1) - 2).
    pub fk: Vec<[u8; LAMBDA]>,

    /// Revocation list RL. Initially empty.
    /// Entries are DGMT.pos values of revoked OTS keys.
    pub rl: Vec<[u8; LAMBDA]>,

    /// Public seed for WOTS chains.
    ///
    /// This is a public value — every verifier needs it to run
    /// WOTS chain computations during signature verification.
    /// It is derived deterministically from the IMT key during
    /// setup and included in the public parameters.
    pub pub_seed: [u8; LAMBDA],

    /// All IMT node values in 1-indexed BFS layout.
    /// Needed to produce A.path_i (authentication path from
    /// a fallback node to the root) during signing.
    /// Not published directly — gpk is the public summary.
    pub(crate) imt_nodes: Vec<[u8; LAMBDA]>,

    /// IMT height, stored for auth path computation.
    ///
    /// Not yet read anywhere in this crate (callers currently pass
    /// `DgmtParams.h_i` separately to every function that needs it).
    /// Retained here because knee-tie-server (Phase 2) will need to
    /// reconstruct a full DgmtPublicParams from storage without also
    /// persisting a separate DgmtParams record, at which point this
    /// becomes the source of truth for IMT height.
    #[allow(dead_code)]
    pub(crate) h_i: u32,
}

impl DgmtPublicParams {
    /// Return true if `dgmt_pos` appears in the revocation list.
    /// Uses constant-time comparison to prevent timing side-channels.
    pub fn is_revoked(&self, dgmt_pos: &[u8; LAMBDA]) -> bool {
        self.rl.iter().any(|entry| {
            let mut differs = 0u8;
            for i in 0..LAMBDA { differs |= entry[i] ^ dgmt_pos[i]; }
            differs == 0
        })
    }

    /// Authentication path from fallback node `fallback_idx` to the root.
    ///
    /// This is A.path_i in the DGMT signature (Algorithm 7).
    /// `fallback_idx` is 1-indexed (1..=num_fallback_nodes).
    pub fn imt_auth_path(&self, fallback_idx: u32) -> Result<Vec<[u8; LAMBDA]>> {
        // Fallback node i (1-indexed) is at BFS position i+1
        // (root occupies BFS position 1).
        let bfs_start = (fallback_idx + 1) as usize;
        let mut path  = Vec::new();
        let mut current = bfs_start;

        while current > 1 {
            let sibling = if current % 2 == 0 { current + 1 } else { current - 1 };
            if sibling < self.imt_nodes.len() {
                path.push(self.imt_nodes[sibling]);
            }
            current /= 2;
        }
        Ok(path)
    }

    /// Value of IMT fallback node `fallback_idx` (1-indexed).
    /// This is Fn_i in the paper.
    pub fn fallback_node_value(&self, fallback_idx: u32) -> &[u8; LAMBDA] {
        &self.imt_nodes[(fallback_idx + 1) as usize]
    }
}

// ─── Helper Functions ─────────────────────────────────────────────────────────

/// Compute DGMT.pos_{i,j,k,l} ← g2(msk, i ∥ j ∥ k ∥ l)
///
/// Encodes (i,j,k,l) as 16 bytes padded to 32 bytes, then applies
/// SPRP g2 keyed with msk.
///
/// Paper §4.1, Table 5.
pub fn compute_dgmt_pos(
    msk: &[u8; LAMBDA],
    i: u32, j: u32, k: u32, l: u32,
) -> [u8; LAMBDA] {
    let mut input = [0u8; LAMBDA];
    input[0..4].copy_from_slice(&i.to_be_bytes());
    input[4..8].copy_from_slice(&j.to_be_bytes());
    input[8..12].copy_from_slice(&k.to_be_bytes());
    input[12..16].copy_from_slice(&l.to_be_bytes());
    // input[16..32] = 0 (padding)
    sprp_eval(msk, &input)
}

/// Compute the shuffle permutation for SMT(2)_{i,j,k} — Algorithm 2, Paper 1.
///
/// Generates a random permutation of leaf indices 0..α by:
///   1. Computing g1(shuffle_key, i∥j∥k∥l) for each l in 0..α
///   2. Sorting by those pseudo-random values
///   3. The sort order defines the permutation
///
/// Returns `shuffle` where shuffle[l] = l' (permuted position of leaf l).
pub fn compute_shuffle(
    shuffle_key: &[u8; LAMBDA],
    i: u32, j: u32, k: u32,
    alpha: u32,
) -> Vec<u32> {
    let mut sort_keys: Vec<(u64, u32)> = (0..alpha)
        .map(|l| {
            let mut input = [0u8; LAMBDA];
            input[0..4].copy_from_slice(&i.to_be_bytes());
            input[4..8].copy_from_slice(&j.to_be_bytes());
            input[8..12].copy_from_slice(&k.to_be_bytes());
            input[12..16].copy_from_slice(&l.to_be_bytes());
            let out      = sprp_eval(shuffle_key, &input);
            let sort_val = u64::from_be_bytes(out[..8].try_into().unwrap());
            (sort_val, l)
        })
        .collect();

    sort_keys.sort_by_key(|&(sort_val, _)| sort_val);

    let mut shuffle = vec![0u32; alpha as usize];
    for (position, &(_, original_l)) in sort_keys.iter().enumerate() {
        shuffle[original_l as usize] = position as u32;
    }
    shuffle
}

// ─── Key Generation ──────────────────────────────────────────────────────────

/// Internal: construct public parameters from secret key and parameters.
///
/// Implements Algorithm 1 (DGMT.PubPrCons) and Algorithm 4 (DGMT.KG)
/// from Paper 1.
fn build_public_params(sk: &DgmtSecretKey, params: &DgmtParams) -> DgmtPublicParams {
    let n_imt        = 1usize << params.h_i;
    let num_fallback = params.num_fallback_nodes() as usize;
    let alpha        = params.alpha() as usize;

    // Public seed for WOTS chains, derived from imt_key.
    let pub_seed: [u8; LAMBDA] = prf_indices(&sk.imt_key, &[0xFFFF_FFFFu32]);

    // ── Step 1: Build IMT ────────────────────────────────────────────────
    //
    // Leaf i = f(IMT.key, i) for i = 1..2^hI.
    // Algorithm 1, lines 3-7.

    let imt_leaves: Vec<[u8; LAMBDA]> = (1..=(n_imt as u64))
        .map(|i| prf_u64(&sk.imt_key, i))
        .collect();

    let imt   = MerkleTree::build(imt_leaves);
    let gpk   = *imt.root();
    // Copy the node array for later auth path computation.
    // imt.nodes uses 1-indexed BFS; nodes[0] is unused padding.
    let imt_nodes = imt.nodes.clone();

    // ── Step 2: Build all SMT(1)s and compute fallback keys ─────────────
    //
    // For each fallback node i (1..=num_fallback_nodes):
    //   For each SMTMT j (1..=γ):
    //     Build SMT(1)_{i,j} from WOTS public keys
    //     Fk_{i,j} ← g1(r_{i,j}, Fn_i)   Algorithm 1, line 16.

    let total_fk = params.num_fallback_keys() as usize;
    let mut fk   = vec![[0u8; LAMBDA]; total_fk];

    for i in 1..=(num_fallback as u32) {
        // Fn_i: the value stored at BFS position i+1 in the IMT.
        let fn_i = imt_nodes[(i + 1) as usize];

        for j in 1..=(params.gamma) {
            // Generate SMT(1)_{i,j}: Merkle tree over WOTS public keys.
            // Algorithm 1, lines 11-15.
            let smt1_leaves: Vec<[u8; LAMBDA]> = (0..alpha as u32)
                .map(|k| {
                    // OTS.sk_{i,j,k} ← f(SMT1.key, i ∥ j ∥ k)
                    let ots_sk_seed = prf_indices(&sk.smt1_key, &[i, j, k]);

                    // Expand seed into WOTS key pair.
                    let (_, ots_pk) = wots_keygen(&ots_sk_seed, &pub_seed, &[i, j, k]);

                    // SMT(1) leaf = H(OTS.pk_{i,j,k})
                    // Concatenate all ξ elements of the WOTS public key
                    // then hash them together as one leaf value.
                    let pk_bytes: Vec<u8> = ots_pk.0.iter().flatten().copied().collect();
                    merkle_leaf_hash(&pk_bytes)
                })
                .collect();

            let smt1 = MerkleTree::build(smt1_leaves);
            let r_ij = *smt1.root();

            // Fk_{i,j} ← g1(r_{i,j}, Fn_i)
            // g1 is our SPRP with key=r_{i,j} and input=Fn_i.
            // Algorithm 1, line 16.
            let fk_ij  = sprp_eval(&r_ij, &fn_i);
            let fk_idx = ((i - 1) * params.gamma + (j - 1)) as usize;
            fk[fk_idx] = fk_ij;
        }
    }

    DgmtPublicParams {
        gpk,
        fk,
        rl: Vec::new(),
        pub_seed,
        imt_nodes,
        h_i: params.h_i,
    }
}

/// DGMT.KG: generate all secret and public keys. (Algorithm 4, Paper 1)
///
/// Run once by the community founder at setup time.
///
/// Returns (DgmtSecretKey, DgmtPublicParams).
///
/// Publish: pub_params.gpk and pub_params.fk
/// Keep secret: sk and pub_params.imt_nodes
pub fn dgmt_keygen(params: &DgmtParams) -> (DgmtSecretKey, DgmtPublicParams) {
    let sk         = DgmtSecretKey::generate();
    let pub_params = build_public_params(&sk, params);
    (sk, pub_params)
}

/// Deterministic key generation from a seed — for testing only.
pub fn dgmt_keygen_from_seed(
    params: &DgmtParams,
    seed: &[u8; LAMBDA],
) -> (DgmtSecretKey, DgmtPublicParams) {
    let sk         = DgmtSecretKey::from_seed(seed);
    let pub_params = build_public_params(&sk, params);
    (sk, pub_params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::sprp::sprp_inv;

    fn test_params() -> DgmtParams {
        DgmtParams::for_testing()
        // hI=2, hS=2, γ=1, Nmax=2, β=2
        // num_fallback_nodes=6, |FK|=6
    }

    #[test]
    fn keygen_produces_correct_fk_count() {
        let params = test_params();
        let (_, pp) = dgmt_keygen_from_seed(&params, &[1u8; LAMBDA]);
        assert_eq!(
            pp.fk.len(),
            params.num_fallback_keys() as usize,
            "FK must have γ × (2^(hI+1) - 2) entries"
        );
    }

    #[test]
    fn keygen_is_deterministic() {
        let params = test_params();
        let (_, pp1) = dgmt_keygen_from_seed(&params, &[42u8; LAMBDA]);
        let (_, pp2) = dgmt_keygen_from_seed(&params, &[42u8; LAMBDA]);
        assert_eq!(pp1.gpk, pp2.gpk, "Same seed must give same gpk");
        assert_eq!(pp1.fk,  pp2.fk,  "Same seed must give same FK");
    }

    #[test]
    fn different_seeds_give_different_gpk() {
        let params = test_params();
        let (_, pp1) = dgmt_keygen_from_seed(&params, &[1u8; LAMBDA]);
        let (_, pp2) = dgmt_keygen_from_seed(&params, &[2u8; LAMBDA]);
        assert_ne!(pp1.gpk, pp2.gpk);
    }

    #[test]
    fn revocation_list_is_initially_empty() {
        let (_, pp) = dgmt_keygen_from_seed(&test_params(), &[1u8; LAMBDA]);
        assert!(pp.rl.is_empty());
    }

    #[test]
    fn dgmt_pos_is_invertible() {
        let msk = [99u8; LAMBDA];
        let (i, j, k, l) = (3u32, 2u32, 1u32, 0u32);
        let pos      = compute_dgmt_pos(&msk, i, j, k, l);
        let recovered = sprp_inv(&msk, &pos);

        let ri = u32::from_be_bytes(recovered[0..4].try_into().unwrap());
        let rj = u32::from_be_bytes(recovered[4..8].try_into().unwrap());
        let rk = u32::from_be_bytes(recovered[8..12].try_into().unwrap());
        let rl = u32::from_be_bytes(recovered[12..16].try_into().unwrap());
        assert_eq!((ri, rj, rk, rl), (i, j, k, l),
            "SPRP inversion must recover original (i,j,k,l)");
    }

    #[test]
    fn fallback_node_values_differ() {
        let params = test_params();
        let (_, pp) = dgmt_keygen_from_seed(&params, &[5u8; LAMBDA]);
        let n = params.num_fallback_nodes();
        for i in 1..=n {
            for j in (i + 1)..=n {
                assert_ne!(
                    pp.fallback_node_value(i),
                    pp.fallback_node_value(j),
                    "Fallback nodes {} and {} must have different values", i, j
                );
            }
        }
    }

    #[test]
    fn shuffle_is_a_permutation() {
        let key   = [77u8; LAMBDA];
        let alpha = 8u32;
        let shuffle = compute_shuffle(&key, 1, 1, 0, alpha);

        assert_eq!(shuffle.len(), alpha as usize);

        let mut seen = vec![false; alpha as usize];
        for &pos in &shuffle {
            assert!((pos as usize) < alpha as usize, "Position out of range");
            assert!(!seen[pos as usize], "Position {} appears twice", pos);
            seen[pos as usize] = true;
        }
        assert!(seen.iter().all(|&s| s), "Not all positions appear in shuffle");
    }

    #[test]
    fn is_revoked_works() {
        let mut pp = dgmt_keygen_from_seed(&test_params(), &[1u8; LAMBDA]).1;
        let pos = [0xAAu8; LAMBDA];

        assert!(!pp.is_revoked(&pos));
        pp.rl.push(pos);
        assert!(pp.is_revoked(&pos));
        assert!(!pp.is_revoked(&[0xBBu8; LAMBDA]));
    }
}
