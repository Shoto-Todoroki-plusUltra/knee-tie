//! DGMT.Sig — Group Signature Generation
//!
//! Paper 1, Algorithm 7.
//!
//! A member signs a message anonymously on behalf of the group.
//! The signature proves the signer is a valid group member without
//! revealing which member.

use crate::utils::hash::{LAMBDA, dgmt_message_hash};
use crate::wots::{wots_sign, WotsSignature};
use crate::dgmt::params::DgmtParams;
use crate::dgmt::join::SigningKey;
use crate::error::Result;

// ─── Signature Structure ─────────────────────────────────────────────────────

/// A DGMT group signature.
///
/// Paper §4.3, equation (3):
///   σDGMT = ((i,j,k,l'), σ_{i,j,k,l'}, DGMT.pos_{i,j,k,l},
///             A.path_{i,j,k,l'}, σ_{i,j,k}, A.path_{i,j,k}, A.path_i)
///
/// When using WOTS (Remark 1), OTS public keys are NOT included in the
/// signature — they are recovered during verification from the WOTS
/// signature itself.
#[derive(Clone, Debug)]
pub struct DgmtSignature {
    // ── Index ───────────────────────────────────────────────────────────
    /// Fallback node index i (1-indexed).
    pub i: u32,
    /// SMTMT index j within fallback node i (1-indexed).
    pub j: u32,
    /// SMT(1) leaf index k (0-indexed).
    pub k: u32,
    /// Permuted SMT(2) leaf index l' (0-indexed).
    pub l_prime: u32,

    // ── Layer 2: message signature ──────────────────────────────────────
    /// σ_{i,j,k,l'} = WOTS.Sig(OTS.sk_{i,j,k,l'}, H(m ∥ μ))
    /// The actual signature on the message. Computed by the member.
    pub sig_message: WotsSignature,

    // ── Position tag ────────────────────────────────────────────────────
    /// DGMT.pos_{i,j,k,l}: encrypted position tag.
    /// Allows manager to open (identify signer) and revoke.
    pub dgmt_pos: [u8; LAMBDA],

    // ── Layer 2: SMT(2) authentication path ────────────────────────────
    /// Auth path from leaf l' in SMT(2)_{i,j,k} to root r_{i,j,k}.
    pub auth_path_smt2: Vec<[u8; LAMBDA]>,

    // ── Layer 1: SMT(2) root signature ─────────────────────────────────
    /// σ_{i,j,k} = WOTS.Sig(OTS.sk_{i,j,k}, r_{i,j,k})
    /// Signs the SMT(2) root, binding it into SMT(1).
    pub sig_smt2_root: WotsSignature,

    // ── Layer 1: SMT(1) authentication path ────────────────────────────
    /// Auth path from leaf k in SMT(1)_{i,j} to root r_{i,j}.
    pub auth_path_smt1: Vec<[u8; LAMBDA]>,

    // ── IMT authentication path ─────────────────────────────────────────
    /// Auth path from fallback node Fn_i to DGMT.gpk.
    pub auth_path_imt: Vec<[u8; LAMBDA]>,
}

// ─── Signing ─────────────────────────────────────────────────────────────────

/// DGMT.Sig: sign a message with an unused signing key.
///
/// Paper §4.3, Algorithm 7.
///
/// # Arguments
/// * `message`  - The message to sign (arbitrary bytes).
/// * `key`      - An unused SigningKey received from the manager.
/// * `params`   - Community setup parameters (needed for fallback depth μ).
///
/// # Returns
/// A DgmtSignature that:
/// - Proves the signer is a valid group member (verifiable by anyone).
/// - Hides which member signed (anonymous to all except manager).
///
/// # IMPORTANT
/// Each SigningKey contains a WOTS secret key that must be used AT MOST ONCE.
/// Reusing a signing key breaks WOTS security and may reveal the secret key.
/// The caller must mark the key as used after calling this function.
pub fn dgmt_sign(
    message: &[u8],
    key: &SigningKey,
    params: &DgmtParams,
) -> Result<DgmtSignature> {
    // Step 1: Compute the depth μ of fallback node Fn_i in the IMT.
    // μ is included in the message hash to bind the signature to
    // a specific tree level, preventing cross-level forgeries.
    // Algorithm 7, line 2.
    let mu = params.fallback_node_depth(key.i);

    // Step 2: Hash the message together with μ.
    // m' = H(m ∥ μ)    Algorithm 7, line 3.
    let m_prime = dgmt_message_hash(message, mu);

    // Step 3: Sign m' with the SMT(2) OTS secret key.
    // σ_{i,j,k,l'} ← WOTS.Sig(OTS.sk_{i,j,k,l'}, m')
    // Algorithm 7, line 4.
    let sig_message = wots_sign(&key.ots_sk, &m_prime, &key.pub_seed);

    // Step 4: The SMT(2) root r_{i,j,k} was pre-computed by the manager
    // and implicitly encoded in auth_path_smt2.
    // We need to sign it with the SMT(1) OTS key.
    //
    // First, recover r_{i,j,k} from the auth path and the leaf value.
    // Leaf at l' = H(OTS.pk_{i,j,k,l'} ∥ DGMT.pos_{i,j,k,l}).
    // The full WOTS public key is serialised the same way it was in join.rs.
    let pk_bytes: Vec<u8> = key.ots_pk.0.iter().flatten().copied().collect();
    let leaf_val = crate::utils::hash::dgmt_leaf_hash(
        &pk_bytes,
        &key.dgmt_pos,
    );
    let r_ijk = crate::merkle::compute_root(
        &leaf_val,
        key.l_prime as usize,
        &key.auth_path_smt2,
        params.h_s,
    )?;

    // Step 5: Sign r_{i,j,k} with the SMT(1) OTS key.
    // σ_{i,j,k} ← WOTS.Sig(OTS.sk_{i,j,k}, r_{i,j,k})
    let sig_smt2_root = wots_sign(&key.smt1_ots_sk, &r_ijk, &key.pub_seed);

    // Assemble the full DGMT signature.
    // Algorithm 7, line 5 (equation 3).
    Ok(DgmtSignature {
        i: key.i,
        j: key.j,
        k: key.k,
        l_prime: key.l_prime,
        sig_message,
        dgmt_pos: key.dgmt_pos,
        auth_path_smt2: key.auth_path_smt2.clone(),
        sig_smt2_root,
        auth_path_smt1: key.auth_path_smt1.clone(),
        auth_path_imt:  key.auth_path_imt.clone(),
    })
}

/// Serialise a DgmtSignature to bytes.
///
/// Layout (all fixed-width fields, variable-length auth paths
/// preceded by a u32 length):
///   [i: 4][j: 4][k: 4][l': 4]
///   [sig_message: XI*LAMBDA]
///   [dgmt_pos: LAMBDA]
///   [auth_path_smt2 len: 4][auth_path_smt2: len*LAMBDA]
///   [sig_smt2_root: XI*LAMBDA]
///   [auth_path_smt1 len: 4][auth_path_smt1: len*LAMBDA]
///   [auth_path_imt len: 4][auth_path_imt: len*LAMBDA]
pub fn dgmt_sig_to_bytes(sig: &DgmtSignature) -> Vec<u8> {
    let mut out = Vec::new();

    out.extend_from_slice(&sig.i.to_be_bytes());
    out.extend_from_slice(&sig.j.to_be_bytes());
    out.extend_from_slice(&sig.k.to_be_bytes());
    out.extend_from_slice(&sig.l_prime.to_be_bytes());

    for elem in &sig.sig_message.0 {
        out.extend_from_slice(elem);
    }

    out.extend_from_slice(&sig.dgmt_pos);

    out.extend_from_slice(&(sig.auth_path_smt2.len() as u32).to_be_bytes());
    for node in &sig.auth_path_smt2 { out.extend_from_slice(node); }

    for elem in &sig.sig_smt2_root.0 {
        out.extend_from_slice(elem);
    }

    out.extend_from_slice(&(sig.auth_path_smt1.len() as u32).to_be_bytes());
    for node in &sig.auth_path_smt1 { out.extend_from_slice(node); }

    out.extend_from_slice(&(sig.auth_path_imt.len() as u32).to_be_bytes());
    for node in &sig.auth_path_imt { out.extend_from_slice(node); }

    out
}

/// Compute the approximate signature size in bytes for given parameters.
///
/// Formula from Paper §4.4:
///   (hI + hSM + 2 + 2ξ) × λ  bits
///
/// This matches Table 6: for hI=16, hSM=32, ξ=67, λ=32 bytes → 5.75 KB.
pub fn signature_size_bytes(params: &DgmtParams) -> usize {
    use crate::wots::XI;
    // Index (i,j,k,l'): 4 × 4 = 16 bytes — not in paper's formula but real overhead
    let index_bytes      = 4 * 4;
    // Two WOTS signatures: 2 × ξ × λ bytes
    let wots_bytes       = 2 * XI * LAMBDA;
    // DGMT.pos: λ bytes
    let pos_bytes        = LAMBDA;
    // Three auth paths: (hI + hSM) × λ bytes total
    // hSM here is split as hS (SMT2) + hS (SMT1)
    let auth_path_bytes  = (params.h_i as usize + params.h_sm() as usize) * LAMBDA;

    index_bytes + wots_bytes + pos_bytes + auth_path_bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dgmt::keygen::dgmt_keygen_from_seed;
    use crate::dgmt::join::{dgmt_join, dgmt_key_dist};

    fn setup() -> (DgmtParams, crate::dgmt::keygen::DgmtSecretKey, DgmtPublicParams) {
        let params = DgmtParams::for_testing();
        let (sk, pp) = dgmt_keygen_from_seed(&params, &[1u8; LAMBDA]);
        (params, sk, pp)
    }

    use crate::dgmt::keygen::DgmtPublicParams;

    #[test]
    fn sign_produces_signature() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();
        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let mut keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 1).unwrap();
        let key = keys.remove(0);

        let sig = dgmt_sign(b"hello knee tie", &key, &params);
        assert!(sig.is_ok(), "Signing must succeed: {:?}", sig.err());
    }

    #[test]
    fn signature_indices_match_key_indices() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();
        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let mut keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 1).unwrap();
        let key = keys.remove(0);

        let (i, j, k, l_prime) = (key.i, key.j, key.k, key.l_prime);
        let sig = dgmt_sign(b"test", &key, &params).unwrap();

        assert_eq!(sig.i, i);
        assert_eq!(sig.j, j);
        assert_eq!(sig.k, k);
        assert_eq!(sig.l_prime, l_prime);
    }

    #[test]
    fn signature_size_matches_paper_formula() {
        // Paper §4.4, eq (4): |σDGMT| = (hI + hSM + 2 + 2ξ) × λ bits
        // For hI=16, hSM=32 (hS=16), ξ=67, λ=32 bytes (256 bits):
        //   (16+32+2+2×67) × 32 = 184 × 32 = 5888 bytes ≈ 5.75 KB   (Table 6)
        let params = DgmtParams::new(16, 16, 1 << 16, 1 << 12, 16).unwrap();
        let size   = signature_size_bytes(&params);

        let paper_formula_bytes = (params.h_i as usize
            + params.h_sm() as usize
            + 2
            + 2 * crate::wots::XI) * LAMBDA;

        assert_eq!(paper_formula_bytes, 5888,
            "Paper formula must reproduce Table 6's reported 5888 bytes (5.75 KB)");

        // Our implementation packs the index (i,j,k,l') as 4×u32 = 16 bytes,
        // whereas the paper's formula treats the index as a single λ=32-byte
        // placeholder. The two must differ by exactly that 16-byte saving.
        let expected_diff = LAMBDA - 16; // 32 - 16 = 16
        assert_eq!(paper_formula_bytes - size, expected_diff,
            "Compact index encoding should save exactly {} bytes vs. the paper's λ-byte placeholder",
            expected_diff);

        println!("Computed signature size: {} bytes ({:.2} KB)", size, size as f64 / 1024.0);
        assert!(size > 5000 && size < 7000,
            "Signature size {} is far from expected ~5.75 KB", size);
    }

    #[test]
    fn serialisation_produces_nonzero_bytes() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();
        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let mut keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 1).unwrap();
        let key = keys.remove(0);
        let sig   = dgmt_sign(b"test message", &key, &params).unwrap();
        let bytes = dgmt_sig_to_bytes(&sig);
        assert!(!bytes.is_empty());
        assert!(bytes.iter().any(|&b| b != 0),
            "Serialised signature should not be all zeros");
    }
}
