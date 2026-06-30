//! DGMT.Vf — Non-Interactive Signature Verification
//!
//! Paper 1, Algorithm 8.
//!
//! Verification requires only the public parameters (gpk, FK, RL).
//! No interaction with the manager is needed — this is the key
//! improvement over DGM.

use crate::utils::hash::{LAMBDA, dgmt_message_hash, dgmt_leaf_hash, merkle_leaf_hash};
use crate::utils::sprp::sprp_inv;
use crate::wots::wots_pk_from_sig;
use crate::merkle::compute_root;
use crate::dgmt::params::DgmtParams;
use crate::dgmt::keygen::DgmtPublicParams;
use crate::dgmt::sign::DgmtSignature;
use crate::error::{Result, KneeTieError};

/// DGMT.Vf: verify a group signature.
///
/// Paper §4.3, Algorithm 8.
///
/// Returns Ok(()) if the signature is valid, Err otherwise.
///
/// Verification steps:
///   1. Check DGMT.pos ∉ RL (not revoked).
///   2. Verify σ_{i,j,k,l'} on H(m ∥ μ) using recovered pk_{i,j,k,l'}.
///   3. Reconstruct r_{i,j,k} from the SMT(2) leaf and auth path.
///   4. Verify σ_{i,j,k} on r_{i,j,k} using recovered pk_{i,j,k}.
///   5. Reconstruct r_{i,j} from the SMT(1) leaf and auth path.
///   6. Recover Fn_i ← g1^{-1}(r'_{i,j}, FK[γ(i-1)+j]).
///   7. Reconstruct the IMT root from Fn_i and auth_path_i.
///   8. Check reconstructed root == DGMT.gpk.
pub fn dgmt_verify(
    message: &[u8],
    sig: &DgmtSignature,
    pp: &DgmtPublicParams,
    params: &DgmtParams,
) -> Result<()> {
    // ── Step 1: Revocation check ──────────────────────────────────────
    // Algorithm 8, line 2.
    if pp.is_revoked(&sig.dgmt_pos) {
        return Err(KneeTieError::DgmtVerificationFailed);
    }

    // ── Step 2: Compute message hash m' = H(m ∥ μ) ───────────────────
    // μ = depth of fallback node Fn_i in the IMT.
    // Algorithm 8, lines 4-5.
    let mu      = params.fallback_node_depth(sig.i);
    let m_prime = dgmt_message_hash(message, mu);

    // Public seed from the community's public parameters.
    // Every verifier has access to pp.pub_seed — it was published
    // during setup alongside gpk and FK.
    let pub_seed = pp.pub_seed;

    // ── Step 3: Verify message signature σ_{i,j,k,l'} ────────────────
    // Recover pk_{i,j,k,l'} from the WOTS signature.
    // Algorithm 8, line 6.
    let recovered_pk_smt2 = wots_pk_from_sig(&sig.sig_message, &m_prime, &pub_seed);

    // ── Step 4: Reconstruct SMT(2) leaf and root r'_{i,j,k} ──────────
    // SMT(2) leaf at l' = H(OTS.pk_{i,j,k,l'} ∥ DGMT.pos_{i,j,k,l})
    // The full WOTS pk (67×32=2144 bytes) is serialised flat then hashed.
    // Algorithm 8, lines 8-9.
    let pk_bytes_smt2: Vec<u8> = recovered_pk_smt2.0.iter().flatten().copied().collect();
    let smt2_leaf = dgmt_leaf_hash(&pk_bytes_smt2, &sig.dgmt_pos);

    let r_ijk = compute_root(
        &smt2_leaf,
        sig.l_prime as usize,
        &sig.auth_path_smt2,
        params.h_s,
    )?;

    // ── Step 5: Verify σ_{i,j,k} on r_{i,j,k} ───────────────────────
    // Recover pk_{i,j,k} from the WOTS signature on the SMT(2) root.
    // Algorithm 8, line 10.
    let recovered_pk_smt1 = wots_pk_from_sig(&sig.sig_smt2_root, &r_ijk, &pub_seed);

    // ── Step 6: Reconstruct SMT(1) leaf and root r'_{i,j} ────────────
    // SMT(1) leaf at k = H(OTS.pk_{i,j,k})
    // Algorithm 8, lines 12.
    let pk_smt1_bytes: Vec<u8> = recovered_pk_smt1.0.iter().flatten().copied().collect();
    let smt1_leaf = merkle_leaf_hash(&pk_smt1_bytes);

    let r_ij = compute_root(
        &smt1_leaf,
        sig.k as usize,
        &sig.auth_path_smt1,
        params.h_s,
    )?;

    // ── Step 7: Recover fallback node Fn_i ───────────────────────────
    // Fn_i ← g1^{-1}(r'_{i,j}, FK[γ(i-1)+j])
    // where FK[...] is the fallback key Fk_{i,j}.
    // Algorithm 8, line 13.
    let fk_idx = ((sig.i - 1) * params.gamma + (sig.j - 1)) as usize;
    if fk_idx >= pp.fk.len() {
        return Err(KneeTieError::InvalidParameter(format!(
            "Fallback key index {} out of range (|FK|={})", fk_idx, pp.fk.len()
        )));
    }
    let fk_ij  = &pp.fk[fk_idx];
    let fn_i   = sprp_inv(&r_ij, fk_ij);

    // ── Step 8: Reconstruct IMT root from Fn_i and auth path ─────────
    // Compute the IMT root by walking from Fn_i to the root using
    // the authentication path.
    // Algorithm 8, line 14.
    //
    // Fn_i is at BFS position (i+1) in the IMT.
    // Its 0-based position among its level's nodes is computed from BFS index.
    let bfs_idx  = sig.i + 1; // BFS position of Fn_i (root=1, skipped)
    let depth    = params.fallback_node_depth(sig.i);
    // Within its level, 0-based index = bfs_idx - 2^depth
    let level_offset = bfs_idx - (1u32 << depth);

    let computed_root = compute_root(
        &fn_i,
        level_offset as usize,
        &sig.auth_path_imt,
        depth,
    )?;

    // ── Step 9: Compare to group public key ───────────────────────────
    // Algorithm 8, lines 15-16.
    let mut differs = 0u8;
    for i in 0..LAMBDA {
        differs |= computed_root[i] ^ pp.gpk[i];
    }

    if differs == 0 {
        Ok(())
    } else {
        Err(KneeTieError::DgmtVerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dgmt::keygen::dgmt_keygen_from_seed;
    use crate::dgmt::join::{dgmt_join, dgmt_key_dist};
    use crate::dgmt::sign::dgmt_sign;

    fn setup() -> (
        DgmtParams,
        crate::dgmt::keygen::DgmtSecretKey,
        DgmtPublicParams,
    ) {
        let params = DgmtParams::for_testing();
        let (sk, pp) = dgmt_keygen_from_seed(&params, &[1u8; LAMBDA]);
        (params, sk, pp)
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();
        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let mut keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 1).unwrap();
        let key = keys.remove(0);

        let sig = dgmt_sign(b"test message", &key, &params).unwrap();
        let result = dgmt_verify(b"test message", &sig, &pp, &params);

        assert!(result.is_ok(),
            "Valid signature must verify: {:?}", result.err());
    }

    #[test]
    fn wrong_message_fails_verification() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();
        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let mut keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 1).unwrap();
        let key = keys.remove(0);

        let sig = dgmt_sign(b"real message", &key, &params).unwrap();
        assert!(
            dgmt_verify(b"different message", &sig, &pp, &params).is_err(),
            "Wrong message must fail verification"
        );
    }

    #[test]
    fn revoked_signature_fails_verification() {
        let (params, sk, mut pp) = setup();
        let num_fn = params.num_fallback_nodes();
        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let mut keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 1).unwrap();
        let key = keys.remove(0);

        let sig = dgmt_sign(b"test", &key, &params).unwrap();

        // Add this signature's position tag to the revocation list
        pp.rl.push(sig.dgmt_pos);

        assert!(
            dgmt_verify(b"test", &sig, &pp, &params).is_err(),
            "Revoked signature must fail verification"
        );
    }

    #[test]
    fn multiple_members_can_sign_and_verify() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();

        let (mut record1, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let (mut record2, _) = dgmt_join(2, params.n_max, num_fn).unwrap();

        let mut keys1 = dgmt_key_dist(&sk, &pp, &params, &mut record1, 1).unwrap();
        let mut keys2 = dgmt_key_dist(&sk, &pp, &params, &mut record2, 1).unwrap();

        let sig1 = dgmt_sign(b"from member 1", &keys1.remove(0), &params).unwrap();
        let sig2 = dgmt_sign(b"from member 2", &keys2.remove(0), &params).unwrap();

        assert!(dgmt_verify(b"from member 1", &sig1, &pp, &params).is_ok(),
            "Member 1 signature must verify");
        assert!(dgmt_verify(b"from member 2", &sig2, &pp, &params).is_ok(),
            "Member 2 signature must verify");
    }

    #[test]
    fn signature_does_not_verify_against_wrong_community() {
        let params = DgmtParams::for_testing();

        // Two separate communities with different keys
        let (sk1, pp1) = dgmt_keygen_from_seed(&params, &[1u8; LAMBDA]);
        let (_sk2, pp2) = dgmt_keygen_from_seed(&params, &[2u8; LAMBDA]);

        let num_fn = params.num_fallback_nodes();
        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let mut keys = dgmt_key_dist(&sk1, &pp1, &params, &mut record, 1).unwrap();
        let sig = dgmt_sign(b"community 1 message", &keys.remove(0), &params).unwrap();

        // Signature from community 1 must not verify in community 2
        assert!(
            dgmt_verify(b"community 1 message", &sig, &pp2, &params).is_err(),
            "Signature from community 1 must not verify in community 2"
        );
    }
}
