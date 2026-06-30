//! DGMT.Rev — Member Revocation
//!
//! Paper 1, Algorithm 9.
//!
//! Revocation adds all of a member's assigned DGMT.pos values to the
//! public revocation list RL. Future signatures from the revoked member
//! will then fail verification at step 1 (revocation check).
//!
//! DGMT's interval-based allocation (each member owns a contiguous
//! interval of leaf indices) makes revocation efficient: the manager
//! computes positions on demand rather than storing them all in advance.

use crate::utils::hash::LAMBDA;
use crate::dgmt::params::DgmtParams;
use crate::dgmt::keygen::{DgmtSecretKey, DgmtPublicParams, compute_dgmt_pos};
use crate::dgmt::join::{MemberRecord, MemberStatus};
use crate::error::Result;

/// DGMT.Rev: revoke a set of members.
///
/// Paper §4.3, Algorithm 9.
///
/// For each member id in `revoke_ids`:
///   1. Mark the member as Revoked in PLM (their private list entry).
///   2. For each fallback node i and each key (j, k, l) that was
///      allocated to this member up to their last received key,
///      compute DGMT.pos_{i,j,k,l+(id-1)*β} and add it to RL.
///
/// After this call, DGMT.PubPr.rl is updated.
/// Verifiers downloading the updated RL will reject all past and future
/// signatures from revoked members.
///
/// # Arguments
/// * `sk`          - Manager's secret key (needed for g2 to compute positions).
/// * `pp`          - Public parameters (RL is updated in place).
/// * `params`      - Community setup parameters.
/// * `records`     - Manager's private member list PLM (updated in place).
/// * `revoke_ids`  - Set of member ids to revoke.
pub fn dgmt_revoke(
    sk: &DgmtSecretKey,
    pp: &mut DgmtPublicParams,
    params: &DgmtParams,
    records: &mut Vec<MemberRecord>,
    revoke_ids: &[u32],
) -> Result<()> {
    let beta = params.beta;

    for &target_id in revoke_ids {
        // Find the member record.
        let record = match records.iter_mut().find(|r| r.id == target_id) {
            Some(r) => r,
            None => continue, // Skip unknown ids silently.
        };

        // Mark as revoked so future OTSReq calls are rejected.
        record.status = MemberStatus::Revoked;

        // For each fallback node i, compute all DGMT.pos values for
        // keys that were allocated to this member.
        //
        // The member's allocated leaves in SMT(2)_{i,j,k} are at
        // original indices l ∈ [(id-1)*β, id*β - 1], giving global
        // positions l + (id-1)*β relative to the leaf sequence.
        //
        // But we track allocation state as (j, k, l) where l is the
        // local offset within the member's β-slot interval.
        // The global l passed to compute_dgmt_pos is (id-1)*β + l_local.
        //
        // Algorithm 9, line 5:
        // RL = RL ∪ { g2(msk, i∥j∥k∥l + (id-1)β)
        //             for all (j,k,l) ≤ (ji,ki,li) }

        let index_state = record.index_state.clone();

        for (i_idx, &(ji, ki, li)) in index_state.iter().enumerate() {
            let i = (i_idx + 1) as u32; // 1-indexed fallback node

            // Walk all (j, k, l) tuples from (1, 0, 0) to (ji, ki, li).
            // Order: j is outermost, then k, then l.
            let mut j = 1u32;
            let mut k = 0u32;
            let mut l = 0u32;

            loop {
                // Compute the global l index for this member.
                // Paper §4.2.2: member id gets interval I_id = [(id-1)β, idβ-1]
                // The position tag uses the global l = l_local + (id-1)*β.
                let l_global = l + (target_id - 1) * beta;
                let dgmt_pos = compute_dgmt_pos(&sk.msk, i, j, k, l_global);

                // Add to revocation list if not already present.
                if !pp.rl.iter().any(|entry| {
                    let mut eq = 0u8;
                    for idx in 0..LAMBDA { eq |= entry[idx] ^ dgmt_pos[idx]; }
                    eq == 0
                }) {
                    pp.rl.push(dgmt_pos);
                }

                // Check if we have reached the last allocated tuple.
                if j == ji && k == ki && l == li {
                    break;
                }

                // Advance to next tuple — same ordering as Algorithm 6.
                if l < beta - 2 {
                    l += 1;
                } else if k < params.alpha() - 1 {
                    l = 0;
                    k += 1;
                } else if j < params.gamma {
                    l = 0;
                    k = 0;
                    j += 1;
                } else {
                    // Should not happen if record is consistent.
                    break;
                }
            }
        }
    }

    Ok(())
}

/// Count the number of DGMT.pos entries that would be added to RL
/// for a member, given their current allocation state.
///
/// Useful for estimating revocation cost before executing it.
pub fn revocation_entry_count(record: &MemberRecord, params: &DgmtParams) -> u64 {
    let beta  = params.beta as u64;
    let alpha = params.alpha() as u64;

    let mut total = 0u64;
    for &(ji, ki, li) in &record.index_state {
        // Count tuples from (j=1,k=0,l=0) up to and including (ji,ki,li),
        // walking j outermost, then k, then l — the same order DGMT.KeyDist
        // (Algorithm 6) uses to advance the allocation pointer.
        let pos = (ji as u64 - 1) * alpha * beta
            + ki as u64 * beta
            + li as u64 + 1;
        total += pos;
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dgmt::keygen::dgmt_keygen_from_seed;
    use crate::dgmt::join::{dgmt_join, dgmt_key_dist};
    use crate::dgmt::sign::dgmt_sign;
    use crate::dgmt::verify::dgmt_verify;

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
    fn revoked_member_signatures_fail_verification() {
        let (params, sk, mut pp) = setup();
        let num_fn = params.num_fallback_nodes();

        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let mut keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 2).unwrap();

        // Sign a message before revocation
        let key  = keys.remove(0);
        let sig  = dgmt_sign(b"before revoke", &key, &params).unwrap();

        // Verify before revocation — must succeed
        assert!(dgmt_verify(b"before revoke", &sig, &pp, &params).is_ok(),
            "Signature before revocation must verify");

        // Revoke the member
        let mut records = vec![record];
        dgmt_revoke(&sk, &mut pp, &params, &mut records, &[1]).unwrap();

        // Verify after revocation — must fail
        assert!(dgmt_verify(b"before revoke", &sig, &pp, &params).is_err(),
            "Signature after revocation must fail");
    }

    #[test]
    fn revocation_marks_member_status_revoked() {
        let (params, sk, mut pp) = setup();
        let num_fn = params.num_fallback_nodes();
        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let _ = dgmt_key_dist(&sk, &pp, &params, &mut record, 1).unwrap();

        let mut records = vec![record];
        dgmt_revoke(&sk, &mut pp, &params, &mut records, &[1]).unwrap();

        assert_eq!(records[0].status, MemberStatus::Revoked,
            "Revoked member must be marked Revoked in PLM");
    }

    #[test]
    fn non_revoked_member_unaffected() {
        let (params, sk, mut pp) = setup();
        let num_fn = params.num_fallback_nodes();

        let (mut record1, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let (mut record2, _) = dgmt_join(2, params.n_max, num_fn).unwrap();

        // Allocate keys for member 1 too (unused directly below), so that
        // revoking member 1 actually populates the revocation list — this
        // is the realistic scenario the test is checking.
        let _keys1 = dgmt_key_dist(&sk, &pp, &params, &mut record1, 1).unwrap();
        let mut keys2 = dgmt_key_dist(&sk, &pp, &params, &mut record2, 1).unwrap();

        let sig2 = dgmt_sign(b"member 2 msg", &keys2.remove(0), &params).unwrap();

        // Revoke only member 1
        let mut records = vec![record1, record2];
        dgmt_revoke(&sk, &mut pp, &params, &mut records, &[1]).unwrap();

        // Member 2's signature must still verify
        assert!(dgmt_verify(b"member 2 msg", &sig2, &pp, &params).is_ok(),
            "Non-revoked member 2 signature must still verify after revoking member 1");
    }

    #[test]
    fn revoking_unknown_id_is_harmless() {
        let (params, sk, mut pp) = setup();
        let mut records = vec![];
        // Should not panic or error
        let result = dgmt_revoke(&sk, &mut pp, &params, &mut records, &[99]);
        assert!(result.is_ok(), "Revoking unknown id must not error");
    }

    #[test]
    fn revocation_list_grows_after_revoke() {
        let (params, sk, mut pp) = setup();
        let num_fn = params.num_fallback_nodes();
        let initial_rl_size = pp.rl.len();

        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let _ = dgmt_key_dist(&sk, &pp, &params, &mut record, 3).unwrap();

        let mut records = vec![record];
        dgmt_revoke(&sk, &mut pp, &params, &mut records, &[1]).unwrap();

        assert!(pp.rl.len() > initial_rl_size,
            "Revocation list must grow after revoking a member with allocated keys");
    }
}
