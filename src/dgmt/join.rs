//! DGMT.Join and DGMT.OTSReq
//!
//! Paper 1, Algorithms 5 and 6.
//!
//! DGMT.Join:    Manager issues (id, c_id) credentials to a new member.
//! DGMT.OTSReq:  Member requests OTS key pairs from the manager.
//! DGMT.KeyDist: Manager allocates the next available key pairs.

use crate::utils::hash::{LAMBDA, dgmt_leaf_hash, prf_indices};
use crate::wots::{wots_keygen, WotsSecretKey, WotsPublicKey};
use crate::merkle::MerkleTree;
use crate::dgmt::params::DgmtParams;
use crate::dgmt::keygen::{
    DgmtSecretKey, DgmtPublicParams, compute_dgmt_pos, compute_shuffle,
};
use crate::error::{Result, KneeTieError};
use rand::RngCore;

// ─── Member Record (Manager Side) ────────────────────────────────────────────

/// Status of a member in the manager's private list PLM.
#[derive(Clone, Debug, PartialEq)]
pub enum MemberStatus {
    Active,
    Revoked,
}

/// One entry in the manager's private list PLM.
///
/// Paper §3: "M stores (id, cid, Active) in a private list PLM"
#[derive(Clone, Debug)]
pub struct MemberRecord {
    /// Sequential member identifier (1..=Nmax).
    pub id: u32,
    /// Secret credential shared only between manager and this member.
    pub c_id: [u8; LAMBDA],
    /// Whether this member is active or revoked.
    pub status: MemberStatus,
    /// The last key index allocated to this member for each fallback
    /// node i. Tracks position in the key allocation sequence.
    ///
    /// index_state[i-1] = (j, k, l) meaning the last SMT(2)_{i,j,k}
    /// leaf allocated to this member was leaf l.
    pub index_state: Vec<(u32, u32, u32)>,
}

// ─── Member Credential (Member Side) ─────────────────────────────────────────

/// Credentials held by a group member.
///
/// Received from the manager over a secure channel during DGMT.Join.
/// Stored encrypted on the member's device.
#[derive(Clone, Debug)]
pub struct MemberCredential {
    pub id:   u32,
    pub c_id: [u8; LAMBDA],
}

// ─── Signing Key (Given to Member) ───────────────────────────────────────────

/// A single OTS signing key, as distributed to a member by DGMT.KeyDist.
///
/// This is gsk^id_{i,j,k,l'} from Paper §4.3, equation (2).
///
/// The member uses OTS.sk to sign exactly ONE message.
/// Everything else in this struct is pre-computed by the manager
/// and sent to the member so that signing is lightweight.
#[derive(Clone, Debug)]
pub struct SigningKey {
    // ── Index ──────────────────────────────────────────────────────────
    /// Fallback node index i (1-indexed).
    pub i: u32,
    /// SMTMT index j within fallback node i (1-indexed).
    pub j: u32,
    /// SMT(2) index k within SMT(1)_{i,j} (0-indexed leaf of SMT(1)).
    pub k: u32,
    /// Permuted leaf index l' in SMT(2)_{i,j,k} (0-indexed).
    pub l_prime: u32,

    // ── Signing material (member uses this) ────────────────────────────
    /// OTS secret key for leaf (i,j,k,l'). Used to sign ONE message.
    pub ots_sk: WotsSecretKey,
    /// Corresponding OTS public key.
    pub ots_pk: WotsPublicKey,
    /// DGMT position tag for leaf (i,j,k,l).
    /// Used in revocation and signature opening.
    pub dgmt_pos: [u8; LAMBDA],

    // ── Authentication paths (pre-computed by manager) ─────────────────
    /// Auth path from leaf l' in SMT(2)_{i,j,k} to root r_{i,j,k}.
    pub auth_path_smt2: Vec<[u8; LAMBDA]>,
    /// OTS secret key for the SMT(1) leaf at index k.
    /// Used to sign r_{i,j,k} and bind SMT(2) into SMT(1).
    pub smt1_ots_sk: WotsSecretKey,
    /// Corresponding SMT(1) OTS public key.
    pub smt1_ots_pk: WotsPublicKey,
    /// Auth path from leaf k in SMT(1)_{i,j} to root r_{i,j}.
    pub auth_path_smt1: Vec<[u8; LAMBDA]>,
    /// Auth path from fallback node Fn_i to the IMT root (DGMT.gpk).
    pub auth_path_imt: Vec<[u8; LAMBDA]>,

    /// Public seed for WOTS chains (same value used throughout a community).
    pub pub_seed: [u8; LAMBDA],
}

// ─── DGMT.Join ───────────────────────────────────────────────────────────────

/// DGMT.Join: manager issues credentials to a new member.
///
/// Paper §4.3, Algorithm 5.
///
/// # Arguments
/// * `next_id`  - The next unassigned id (1..=Nmax). Caller tracks this.
/// * `n_max`    - Maximum group size. Rejects if next_id > n_max.
/// * `num_fn`   - Number of IMT fallback nodes = 2^(hI+1) - 2.
///
/// Returns (MemberRecord, MemberCredential) on success.
/// MemberRecord is stored by the manager in PLM.
/// MemberCredential is sent to the new member.
pub fn dgmt_join(
    next_id: u32,
    n_max: u32,
    num_fn: u32,
) -> Result<(MemberRecord, MemberCredential)> {
    if next_id > n_max {
        return Err(KneeTieError::InvalidParameter(format!(
            "Group is full: next_id {} > n_max {}", next_id, n_max
        )));
    }

    // Generate a random λ-bit secret credential c_id.
    // Shared only between manager and this member.
    let mut c_id = [0u8; LAMBDA];
    rand::thread_rng().fill_bytes(&mut c_id);

    // Initialise index_state: for each fallback node, start at (j=1, k=0, l=0).
    // This means: "no keys allocated yet from SMTMT_{i,1} for this member."
    let index_state = vec![(1u32, 0u32, 0u32); num_fn as usize];

    let record = MemberRecord {
        id: next_id,
        c_id,
        status: MemberStatus::Active,
        index_state,
    };

    let credential = MemberCredential {
        id: next_id,
        c_id,
    };

    Ok((record, credential))
}

// ─── DGMT.KeyDist ────────────────────────────────────────────────────────────

/// DGMT.KeyDist: allocate B new signing key pairs for member `id`.
///
/// Paper §4.3, Algorithm 6 (DGMT.KeyDist subroutine).
///
/// The manager:
///   1. Selects B fallback nodes randomly (one per key).
///   2. Advances the key allocation pointer for each selected node.
///   3. Constructs SMT(2)s on demand if needed.
///   4. Returns the full signing key structs to the member.
///
/// # Arguments
/// * `sk`         - Manager's secret key.
/// * `pp`         - Community public parameters.
/// * `params`     - DGMT setup parameters.
/// * `record`     - Mutable member record (index_state is updated).
/// * `b`          - Number of keys to allocate.
pub fn dgmt_key_dist(
    sk: &DgmtSecretKey,
    pp: &DgmtPublicParams,
    params: &DgmtParams,
    record: &mut MemberRecord,
    b: u32,
) -> Result<Vec<SigningKey>> {
    if record.status == MemberStatus::Revoked {
        return Err(KneeTieError::CredentialsRevoked);
    }

    let num_fn = params.num_fallback_nodes();
    let alpha  = params.alpha();
    let beta   = params.beta;
    let gamma  = params.gamma;
    let id     = record.id;

    // Public seed — taken from the community's public parameters.
    // It was derived from sk.imt_key during setup and stored in pp.
    // Using pp.pub_seed here ensures verify.rs and join.rs are consistent
    // without either needing the secret key.
    let pub_seed = pp.pub_seed;

    let mut keys = Vec::with_capacity(b as usize);
    let mut allocated = 0u32;

    // We iterate until we have allocated b keys or exhausted all positions.
    // To avoid infinite loops, track attempts.
    let max_attempts = b * num_fn * 2;
    let mut attempts = 0u32;

    while allocated < b {
        attempts += 1;
        if attempts > max_attempts {
            return Err(KneeTieError::NoKeysRemaining);
        }

        // Randomly select a fallback node index i (1..=num_fn).
        // In Algorithm 6, line 3: "Randomly choose an internal node Fni".
        let i = (rand_u32() % num_fn) + 1;

        // Retrieve current allocation state for node i.
        let (mut j, mut k, mut l) = record.index_state[(i - 1) as usize];

        // Advance the pointer — Algorithm 6, lines 5-8.
        if l < beta - 2 {
            l += 1;
        } else if l == beta - 2 && k < alpha - 1 {
            k += 1;
            l = 0;
        } else if l == beta - 2 && k == alpha - 1 && j < gamma {
            j += 1;
            k = 0;
            l = 0;
        } else {
            // This fallback node is exhausted for this member.
            // Try another node.
            continue;
        }

        // Update the member's index state.
        record.index_state[(i - 1) as usize] = (j, k, l);

        // Compute the permuted leaf index l' for this member.
        // shuffle[l + (id-1)*beta] gives the actual position in SMT(2).
        // Algorithm 6, line 14: l' ← L_{i,j,k}[l + (id-1)*β]
        let shuffle = compute_shuffle(&sk.shuffle_key, i, j, k, alpha);
        let l_prime = shuffle[(l + (id - 1) * beta) as usize];

        // Compute DGMT.pos_{i,j,k,l} — the position tag for this leaf.
        // Algorithm 6, line 19: DGMT.pos_{i,j,k,l} = g2(msk, i∥j∥k∥l)
        let l_absolute = l + (id - 1) * beta; // l in global SMT(2) terms
        let dgmt_pos   = compute_dgmt_pos(&sk.msk, i, j, k, l_absolute);

        // ── Build SMT(2)_{i,j,k} and retrieve the signing key ──────────

        let signing_key = build_signing_key(
            sk, pp, params,
            i, j, k, l_prime, dgmt_pos, &pub_seed,
        )?;

        keys.push(signing_key);
        allocated += 1;
    }

    Ok(keys)
}

/// Build a complete SigningKey for leaf l' in SMT(2)_{i,j,k}.
///
/// This constructs:
///   - The SMT(2) tree, extracting the OTS key at l' and its auth path
///   - The SMT(1) tree, extracting the OTS key at k and its auth path
///   - The IMT auth path from Fn_i to the root
fn build_signing_key(
    sk: &DgmtSecretKey,
    pp: &DgmtPublicParams,
    params: &DgmtParams,
    i: u32, j: u32, k: u32,
    l_prime: u32,
    dgmt_pos: [u8; LAMBDA],
    pub_seed: &[u8; LAMBDA],
) -> Result<SigningKey> {
    let alpha = params.alpha() as usize;

    // ── SMT(2)_{i,j,k}: Merkle tree over WOTS public keys ───────────────
    //
    // Each leaf l' = H(OTS.pk_{i,j,k,l'} ∥ DGMT.pos_{i,j,k,l})
    // Paper §4.2.2, Algorithm 3.

    // Generate all WOTS key pairs for SMT(2)_{i,j,k}.
    let mut smt2_ots_sks: Vec<WotsSecretKey> = Vec::with_capacity(alpha);
    let mut smt2_ots_pks: Vec<WotsPublicKey> = Vec::with_capacity(alpha);

    // We also need DGMT.pos for each l' to construct the leaf hashes.
    // The mapping from l' to l is via the shuffle; we build it here.
    let shuffle     = compute_shuffle(&sk.shuffle_key, i, j, k, alpha as u32);
    let mut inv_shuffle = vec![0u32; alpha]; // inv_shuffle[l'] = l
    for (l_idx, &lp) in shuffle.iter().enumerate() {
        inv_shuffle[lp as usize] = l_idx as u32;
    }

    for lp in 0..alpha as u32 {
        // Derive OTS secret key: f(SMT2.key, i ∥ j ∥ k ∥ l')
        let ots_sk_seed = prf_indices(&sk.smt2_key, &[i, j, k, lp]);
        let (ots_sk, ots_pk) = wots_keygen(&ots_sk_seed, pub_seed, &[i, j, k, lp]);
        smt2_ots_sks.push(ots_sk);
        smt2_ots_pks.push(ots_pk);
    }

    // Build SMT(2) leaf nodes.
    // Leaf at position l' = H(OTS.pk_{i,j,k,l'} ∥ DGMT.pos_{i,j,k,l})
    // where l = inv_shuffle[l'] is the original (pre-shuffle) index.
    // The full WOTS public key (ξ=67 elements × λ=32 bytes = 2144 bytes)
    // is serialised as a flat byte slice before hashing.
    // Paper §4.2.2, Algorithm 3, lines 3-7.
    let smt2_leaves: Vec<[u8; LAMBDA]> = (0..alpha as u32)
        .map(|lp| {
            let l_orig  = inv_shuffle[lp as usize];
            let pos_tag = compute_dgmt_pos(&sk.msk, i, j, k, l_orig);
            let pk_bytes: Vec<u8> = smt2_ots_pks[lp as usize]
                .0.iter().flatten().copied().collect();
            dgmt_leaf_hash(&pk_bytes, &pos_tag)
        })
        .collect();

    let smt2         = MerkleTree::build(smt2_leaves);
    let auth_path_l  = smt2.auth_path(l_prime as usize)?;

    // ── SMT(1)_{i,j}: Merkle tree over WOTS public keys ─────────────────
    //
    // Each SMT(1) leaf k = H(OTS.pk_{i,j,k})
    // These OTS keys sign the roots of SMT(2) trees.

    let mut smt1_ots_sks: Vec<WotsSecretKey> = Vec::with_capacity(alpha);
    let mut smt1_ots_pks: Vec<WotsPublicKey> = Vec::with_capacity(alpha);

    for k_idx in 0..alpha as u32 {
        let ots_sk_seed = prf_indices(&sk.smt1_key, &[i, j, k_idx]);
        let (ots_sk, ots_pk) = wots_keygen(&ots_sk_seed, pub_seed, &[i, j, k_idx]);
        smt1_ots_sks.push(ots_sk);
        smt1_ots_pks.push(ots_pk);
    }

    let smt1_leaves: Vec<[u8; LAMBDA]> = smt1_ots_pks
        .iter()
        .map(|pk| {
            let pk_bytes: Vec<u8> = pk.0.iter().flatten().copied().collect();
            crate::utils::hash::merkle_leaf_hash(&pk_bytes)
        })
        .collect();

    let smt1        = MerkleTree::build(smt1_leaves);
    let auth_path_k = smt1.auth_path(k as usize)?;

    // ── IMT auth path from Fn_i to DGMT.gpk ─────────────────────────────

    let auth_path_i = pp.imt_auth_path(i)?;

    Ok(SigningKey {
        i,
        j,
        k,
        l_prime,
        ots_sk:         smt2_ots_sks.into_iter().nth(l_prime as usize).unwrap(),
        ots_pk:         smt2_ots_pks.into_iter().nth(l_prime as usize).unwrap(),
        dgmt_pos,
        auth_path_smt2: auth_path_l,
        smt1_ots_sk:    smt1_ots_sks.into_iter().nth(k as usize).unwrap(),
        smt1_ots_pk:    smt1_ots_pks.into_iter().nth(k as usize).unwrap(),
        auth_path_smt1: auth_path_k,
        auth_path_imt:  auth_path_i,
        pub_seed:       *pub_seed,
    })
}

/// Generate a pseudo-random u32 using the thread RNG.
fn rand_u32() -> u32 {
    let mut buf = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut buf);
    u32::from_be_bytes(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dgmt::keygen::dgmt_keygen_from_seed;

    fn setup() -> (DgmtParams, DgmtSecretKey, DgmtPublicParams) {
        let params = DgmtParams::for_testing();
        let seed   = [1u8; LAMBDA];
        let (sk, pp) = dgmt_keygen_from_seed(&params, &seed);
        (params, sk, pp)
    }

    #[test]
    fn join_assigns_sequential_ids() {
        let params = DgmtParams::for_testing();
        let num_fn = params.num_fallback_nodes();

        let (r1, c1) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let (r2, c2) = dgmt_join(2, params.n_max, num_fn).unwrap();

        assert_eq!(r1.id, 1);
        assert_eq!(r2.id, 2);
        assert_eq!(c1.id, 1);
        assert_eq!(c2.id, 2);
        // Credentials must differ
        assert_ne!(c1.c_id, c2.c_id);
    }

    #[test]
    fn join_fails_when_group_is_full() {
        let params = DgmtParams::for_testing(); // n_max = 2
        let num_fn = params.num_fallback_nodes();
        assert!(dgmt_join(3, params.n_max, num_fn).is_err(),
            "Joining with id > n_max must fail");
    }

    #[test]
    fn join_initial_index_state_is_correct() {
        let params = DgmtParams::for_testing();
        let num_fn = params.num_fallback_nodes();
        let (record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();

        assert_eq!(record.index_state.len(), num_fn as usize,
            "index_state must have one entry per fallback node");
        for &(j, k, l) in &record.index_state {
            assert_eq!((j, k, l), (1, 0, 0),
                "All initial states must be (j=1, k=0, l=0)");
        }
    }

    #[test]
    fn revoked_member_cannot_receive_keys() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();

        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        record.status = MemberStatus::Revoked;

        assert!(
            dgmt_key_dist(&sk, &pp, &params, &mut record, 1).is_err(),
            "Revoked member must not receive keys"
        );
    }

    #[test]
    fn key_dist_returns_b_keys() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();
        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();

        let keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 3).unwrap();
        assert_eq!(keys.len(), 3, "Must return exactly B=3 signing keys");
    }

    #[test]
    fn keys_have_valid_indices() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();
        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();

        let keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 4).unwrap();

        for key in &keys {
            assert!(key.i >= 1 && key.i <= num_fn,
                "i={} out of range [1,{}]", key.i, num_fn);
            assert!(key.j >= 1 && key.j <= params.gamma,
                "j={} out of range [1,{}]", key.j, params.gamma);
            assert!((key.k as usize) < params.alpha() as usize,
                "k={} out of range [0,{})", key.k, params.alpha());
            assert!((key.l_prime as usize) < params.alpha() as usize,
                "l'={} out of range [0,{})", key.l_prime, params.alpha());
        }
    }

    #[test]
    fn auth_path_lengths_are_correct() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();
        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();

        let keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 2).unwrap();

        for key in &keys {
            assert_eq!(key.auth_path_smt2.len(), params.h_s as usize,
                "SMT(2) auth path must have hS={} elements", params.h_s);
            assert_eq!(key.auth_path_smt1.len(), params.h_s as usize,
                "SMT(1) auth path must have hS={} elements", params.h_s);
            // IMT auth path length = depth of Fn_i
            let expected_imt_len = params.fallback_node_depth(key.i) as usize;
            assert_eq!(key.auth_path_imt.len(), expected_imt_len,
                "IMT auth path for node i={} must have depth={} elements",
                key.i, expected_imt_len);
        }
    }
}
