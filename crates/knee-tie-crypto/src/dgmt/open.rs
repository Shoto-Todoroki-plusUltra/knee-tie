//! DGMT.Op — Signature Opening
//!
//! Paper 1, Algorithm 10.
//!
//! The manager opens a valid signature to reveal the signer's identifier.
//! This is the accountability mechanism — anonymity holds for all parties
//! except the manager who holds msk.
//!
//! NOTE: In Knee Tie we removed the identity-opening action from the
//! moderation flow. This module is retained because:
//!   a) The paper requires it for completeness.
//!   b) It may be re-enabled in future under strict governance rules.
//!   c) The revocation algorithm depends on the same g2^{-1} inversion.

use crate::utils::sprp::sprp_inv;
use crate::dgmt::params::DgmtParams;
use crate::dgmt::keygen::DgmtSecretKey;
use crate::dgmt::sign::DgmtSignature;
use crate::error::{Result, KneeTieError};

/// Result of opening a group signature.
#[derive(Debug, Clone, PartialEq)]
pub struct OpenResult {
    /// The member identifier (1..=Nmax).
    pub id: u32,
    /// Raw indices recovered from the position tag.
    pub i: u32,
    pub j: u32,
    pub k: u32,
    /// The global leaf index l (before interval mapping).
    pub l_global: u32,
}

/// DGMT.Op: open a signature to recover the signer's identifier.
///
/// Paper §4.3, Algorithm 10.
///
/// # How it works
///
/// DGMT.pos_{i,j,k,l} = g2(msk, i∥j∥k∥l)
///
/// Given msk and DGMT.pos, we compute:
///   i∥j∥k∥l ← g2^{-1}(msk, DGMT.pos)
///
/// Then recover the member id from l:
///   id = ⌈(l + 0.5) / β⌉
///
/// Because each member id owns the interval [β(id-1), βid-1],
/// l ∈ Iid iff (id-1)β ≤ l ≤ idβ-1, giving id = ⌈(l+0.5)/β⌉.
///
/// Paper §4.3, Algorithm 10, line 3.
///
/// # Arguments
/// * `sig`    - A valid DGMT group signature.
/// * `sk`     - Manager's secret key (msk).
/// * `params` - Community setup parameters (needed for β and bounds).
///
/// # Returns
/// `Ok(OpenResult)` on success.
/// `Err` if the recovered indices are out of valid range.
pub fn dgmt_open(
    sig: &DgmtSignature,
    sk: &DgmtSecretKey,
    params: &DgmtParams,
) -> Result<OpenResult> {
    // Step 1: recover i∥j∥k∥l from the position tag.
    // i∥j∥k∥l ← g2^{-1}(msk, DGMT.pos_{i,j,k,l})
    // Algorithm 10, line 2.
    let recovered = sprp_inv(&sk.msk, &sig.dgmt_pos);

    // Decode the 4-tuple from the first 16 bytes (big-endian u32 each).
    // The remaining bytes are zero padding (see compute_dgmt_pos in keygen.rs).
    let i = u32::from_be_bytes(recovered[0..4].try_into().unwrap());
    let j = u32::from_be_bytes(recovered[4..8].try_into().unwrap());
    let k = u32::from_be_bytes(recovered[8..12].try_into().unwrap());
    let l = u32::from_be_bytes(recovered[12..16].try_into().unwrap());

    // Step 2: validate recovered indices against known parameter bounds.
    // Algorithm 10, line 3 condition check.
    let num_fn = params.num_fallback_nodes();
    let alpha  = params.alpha();

    if i < 1 || i > num_fn {
        return Err(KneeTieError::CryptoError(format!(
            "Recovered i={} out of valid range [1,{}]", i, num_fn
        )));
    }
    if j < 1 || j > params.gamma {
        return Err(KneeTieError::CryptoError(format!(
            "Recovered j={} out of valid range [1,{}]", j, params.gamma
        )));
    }
    if k >= alpha {
        return Err(KneeTieError::CryptoError(format!(
            "Recovered k={} out of valid range [0,{})", k, alpha
        )));
    }
    if l >= alpha {
        return Err(KneeTieError::CryptoError(format!(
            "Recovered l={} out of valid range [0,{})", l, alpha
        )));
    }

    // Step 3: recover member id from l using the interval formula.
    // id = ⌈(l + 0.5) / β⌉
    //
    // In integer arithmetic: id = (l / β) + 1
    // Because l ∈ [(id-1)β, idβ-1]:
    //   l / β (integer division) = id - 1
    //   so id = l / β + 1
    let beta = params.beta;
    let id   = l / beta + 1;

    // Verify id is in valid range.
    if id < 1 || id > params.n_max {
        return Err(KneeTieError::CryptoError(format!(
            "Recovered id={} out of valid range [1,{}]", id, params.n_max
        )));
    }

    Ok(OpenResult { id, i, j, k, l_global: l })
}

/// Verify that an OpenResult is consistent with the signature's index fields.
///
/// A valid opening must satisfy:
///   recovered.i == sig.i
///   recovered.j == sig.j
///   recovered.k == sig.k
///   recovered.l_global maps to sig.l_prime via the shuffle
///
/// This check does not require the secret key — it uses only the
/// public index fields of the signature. It is a sanity check that
/// the opening is internally consistent.
pub fn verify_open_consistency(
    open_result: &OpenResult,
    sig: &DgmtSignature,
) -> bool {
    open_result.i == sig.i
        && open_result.j == sig.j
        && open_result.k == sig.k
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::hash::LAMBDA;
    use crate::dgmt::keygen::dgmt_keygen_from_seed;
    use crate::dgmt::join::{dgmt_join, dgmt_key_dist};
    use crate::dgmt::sign::dgmt_sign;

    fn setup() -> (
        DgmtParams,
        crate::dgmt::keygen::DgmtSecretKey,
        crate::dgmt::keygen::DgmtPublicParams,
    ) {
        let params = DgmtParams::for_testing();
        let (sk, pp) = dgmt_keygen_from_seed(&params, &[1u8; LAMBDA]);
        (params, sk, pp)
    }

    #[test]
    fn open_recovers_correct_member_id() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();

        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let mut keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 1).unwrap();
        let key = keys.remove(0);

        let sig    = dgmt_sign(b"member 1 message", &key, &params).unwrap();
        let result = dgmt_open(&sig, &sk, &params).unwrap();

        assert_eq!(result.id, 1, "Opened signature must identify member 1");
    }

    #[test]
    fn open_distinguishes_between_members() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();

        let (mut r1, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let (mut r2, _) = dgmt_join(2, params.n_max, num_fn).unwrap();

        let mut keys1 = dgmt_key_dist(&sk, &pp, &params, &mut r1, 1).unwrap();
        let mut keys2 = dgmt_key_dist(&sk, &pp, &params, &mut r2, 1).unwrap();

        let sig1 = dgmt_sign(b"msg", &keys1.remove(0), &params).unwrap();
        let sig2 = dgmt_sign(b"msg", &keys2.remove(0), &params).unwrap();

        let open1 = dgmt_open(&sig1, &sk, &params).unwrap();
        let open2 = dgmt_open(&sig2, &sk, &params).unwrap();

        assert_eq!(open1.id, 1, "sig1 must open to member 1");
        assert_eq!(open2.id, 2, "sig2 must open to member 2");
        assert_ne!(open1.id, open2.id, "Different members must open to different ids");
    }

    #[test]
    fn open_is_consistent_with_signature_indices() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();

        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let mut keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 1).unwrap();
        let key = keys.remove(0);

        let sig    = dgmt_sign(b"test", &key, &params).unwrap();
        let result = dgmt_open(&sig, &sk, &params).unwrap();

        assert!(verify_open_consistency(&result, &sig),
            "Opened (i,j,k) must match signature (i,j,k)");
    }

    #[test]
    fn open_multiple_keys_same_member() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();

        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 3).unwrap();

        for key in keys {
            let sig    = dgmt_sign(b"repeated member", &key, &params).unwrap();
            let result = dgmt_open(&sig, &sk, &params).unwrap();
            assert_eq!(result.id, 1,
                "All keys for member 1 must open to id=1");
        }
    }

    #[test]
    fn open_result_indices_are_in_range() {
        let (params, sk, pp) = setup();
        let num_fn = params.num_fallback_nodes();

        let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
        let keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 2).unwrap();

        for key in keys {
            let sig    = dgmt_sign(b"range check", &key, &params).unwrap();
            let result = dgmt_open(&sig, &sk, &params).unwrap();

            assert!(result.i >= 1 && result.i <= num_fn,
                "i={} out of range", result.i);
            assert!(result.j >= 1 && result.j <= params.gamma,
                "j={} out of range", result.j);
            assert!(result.k < params.alpha(),
                "k={} out of range", result.k);
            assert!(result.id >= 1 && result.id <= params.n_max,
                "id={} out of range", result.id);
        }
    }
}
