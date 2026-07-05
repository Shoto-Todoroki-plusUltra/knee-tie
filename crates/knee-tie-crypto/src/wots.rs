//! Winternitz One-Time Signature (WOTS)
//!
//! Paper 1, Section 2.2. Parameters for our instantiation:
//!   λ = 256 bits (32 bytes)
//!   w = 4 (Winternitz parameter)
//!
//! Derived quantities (fixed at compile time, verified in tests):
//!   ξ1 = ⌈λ/w⌉ = ⌈256/4⌉ = 64   (message digits in base 2^w)
//!   ξ2 = ⌊log2(ξ1(2^w-1))/w⌋+1  = 3   (checksum digits)
//!   ξ  = ξ1 + ξ2 = 67             (total signature elements)
//!   W_MAX = 2^w - 1 = 15           (maximum chain length)

use std::fmt;
use zeroize::ZeroizeOnDrop;
use crate::utils::hash::{LAMBDA, prf_indices, wots_chain};
use crate::error::{Result, KneeTieError};

// ─── Parameters ──────────────────────────────────────────────────────────────

/// Winternitz parameter w. Chain length = 2^W = 16.
pub const W: u32 = 4;

/// ξ1 = ⌈λ/w⌉ = 64. Message digits in base 2^w.
pub const XI1: usize = 64;

/// ξ2 = 3. Checksum digits in base 2^w.
pub const XI2: usize = 3;

/// ξ = ξ1 + ξ2 = 67. Total WOTS signature/key elements.
pub const XI: usize = XI1 + XI2;

/// W_MAX = 2^w - 1 = 15. Maximum index in a single chain.
pub const W_MAX: u32 = (1u32 << W) - 1;

// ─── Types ───────────────────────────────────────────────────────────────────

/// WOTS secret key: ξ elements of λ bytes each.
/// Wiped from memory when dropped (ZeroizeOnDrop).
#[derive(Clone, ZeroizeOnDrop)]
pub struct WotsSecretKey(pub [[u8; LAMBDA]; XI]);

/// Manually implemented (never derived) so secret key material is never
/// printed. `SigningKey` (dgmt/join.rs) derives `Debug` and embeds two
/// `WotsSecretKey` fields — without this redacted impl, an accidental
/// `{:?}` on a SigningKey would leak one-time signing secrets into logs,
/// defeating the purpose of `ZeroizeOnDrop` above.
impl fmt::Debug for WotsSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "WotsSecretKey(REDACTED)")
    }
}

/// WOTS public key: ξ elements of λ bytes each.
#[derive(Clone, Debug, PartialEq)]
pub struct WotsPublicKey(pub [[u8; LAMBDA]; XI]);

/// WOTS signature: ξ elements of λ bytes each.
#[derive(Clone, Debug)]
pub struct WotsSignature(pub [[u8; LAMBDA]; XI]);

// ─── Key Generation ──────────────────────────────────────────────────────────

/// Generate a WOTS key pair from a seed and public seed.
///
/// In DGMT the seed for OTS_{i,j,k} at SMT(1) level is:
///   OTS.sk_{i,j,k} ← f(SMT1.key, i ∥ j ∥ k)
///
/// This function takes that derived seed and expands it into
/// the full WOTS key pair.
///
/// Paper §2.2, WOTS.KG
pub fn wots_keygen(
    sk_seed: &[u8; LAMBDA],
    pub_seed: &[u8; LAMBDA],
    position: &[u32],
) -> (WotsSecretKey, WotsPublicKey) {
    let mut sk = [[0u8; LAMBDA]; XI];
    let mut pk = [[0u8; LAMBDA]; XI];

    for t in 0..XI {
        // Append element index t to position to get a unique input per element.
        let mut indices = position.to_vec();
        indices.push(t as u32);
        sk[t] = prf_indices(sk_seed, &indices);

        // pk[t] = f^{W_MAX}(sk[t])  (Paper §2.2)
        pk[t] = wots_chain(&sk[t], pub_seed, 0, W_MAX);
    }

    (WotsSecretKey(sk), WotsPublicKey(pk))
}

// ─── Message Decomposition ───────────────────────────────────────────────────

/// Decompose a message hash into ξ base-2^w digits with checksum.
///
/// Paper §2.2, WOTS.Sig:
///   1. (d)_{2^w}: represent H(m) as ξ1 digits in base 2^w
///   2. c = Σ(W_MAX - b_i) for i = 0..ξ1-1
///   3. Append (c)_{2^w} → ξ2 more digits
///   4. B = d_digits ∥ c_digits (total ξ digits)
pub fn message_to_basew(msg_hash: &[u8; LAMBDA]) -> [u32; XI] {
    let mut digits = [0u32; XI];

    // Step 1: extract ξ1 = 64 nibbles (4-bit values) from 32 bytes.
    for i in 0..XI1 {
        let byte = msg_hash[i / 2];
        digits[i] = if i % 2 == 0 {
            ((byte >> 4) & 0x0F) as u32   // high nibble
        } else {
            (byte & 0x0F) as u32           // low nibble
        };
    }

    // Step 2: checksum c = Σ(W_MAX - b_i)
    // Maximum: 64 × 15 = 960, fits in u32.
    let checksum: u32 = digits[..XI1].iter().map(|&b| W_MAX - b).sum();

    // Step 3: encode checksum as ξ2 = 3 base-16 digits (most significant first).
    for i in 0..XI2 {
        let shift = (XI2 - 1 - i) * (W as usize);
        digits[XI1 + i] = (checksum >> shift) & W_MAX;
    }

    digits
}

// ─── Signing ─────────────────────────────────────────────────────────────────

/// Sign a message hash with a WOTS secret key.
///
/// σ_t = f^{b_t}(sk_t) for each position t.
///
/// Note: WOTS is one-time — never reuse a secret key.
///
/// Paper §2.2, WOTS.Sig
pub fn wots_sign(
    sk: &WotsSecretKey,
    msg_hash: &[u8; LAMBDA],
    pub_seed: &[u8; LAMBDA],
) -> WotsSignature {
    let digits = message_to_basew(msg_hash);
    let mut sig = [[0u8; LAMBDA]; XI];
    for t in 0..XI {
        sig[t] = wots_chain(&sk.0[t], pub_seed, 0, digits[t]);
    }
    WotsSignature(sig)
}

// ─── Verification / Public Key Recovery ──────────────────────────────────────

/// Recover the WOTS public key from a signature and message hash.
///
/// pk_t = f^{W_MAX - b_t}(σ_t)
///       = f^{W_MAX - b_t}(f^{b_t}(sk_t))
///       = f^{W_MAX}(sk_t)   ✓
///
/// Paper §2.2, WOTS.Vf and Remark 1
pub fn wots_pk_from_sig(
    sig: &WotsSignature,
    msg_hash: &[u8; LAMBDA],
    pub_seed: &[u8; LAMBDA],
) -> WotsPublicKey {
    let digits = message_to_basew(msg_hash);
    let mut pk = [[0u8; LAMBDA]; XI];
    for t in 0..XI {
        let remaining = W_MAX - digits[t];
        pk[t] = wots_chain(&sig.0[t], pub_seed, digits[t], remaining);
    }
    WotsPublicKey(pk)
}

/// Verify a WOTS signature against a known public key.
/// Uses constant-time comparison to prevent timing attacks.
pub fn wots_verify(
    sig: &WotsSignature,
    msg_hash: &[u8; LAMBDA],
    pk: &WotsPublicKey,
    pub_seed: &[u8; LAMBDA],
) -> Result<()> {
    let recovered = wots_pk_from_sig(sig, msg_hash, pub_seed);

    let mut all_equal = 1u8;
    for t in 0..XI {
        let mut differs = 0u8;
        for i in 0..LAMBDA {
            differs |= recovered.0[t][i] ^ pk.0[t][i];
        }
        all_equal &= (differs == 0) as u8;
    }

    if all_equal == 1 { Ok(()) } else { Err(KneeTieError::WotsVerificationFailed) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seeds() -> ([u8; LAMBDA], [u8; LAMBDA]) {
        ([0x11u8; LAMBDA], [0x22u8; LAMBDA])
    }

    #[test]
    fn parameter_sanity_check() {
        assert_eq!(W,     4,  "Winternitz parameter w");
        assert_eq!(XI1,   64, "ξ1 = ⌈256/4⌉");
        assert_eq!(XI2,   3,  "ξ2 = ⌊log2(64×15)/4⌋+1");
        assert_eq!(XI,    67, "ξ = ξ1 + ξ2");
        assert_eq!(W_MAX, 15, "W_MAX = 2^4 - 1");

        // Max checksum 960 must fit in XI2 = 3 base-16 digits
        let max_cs = XI1 as u32 * W_MAX; // 960
        assert!(max_cs < (1u32 << (XI2 as u32 * W)),
            "Checksum {} must fit in {} base-2^w digits", max_cs, XI2);
    }

    #[test]
    fn message_to_basew_all_zeros() {
        let hash   = [0u8; LAMBDA];
        let digits = message_to_basew(&hash);
        for i in 0..XI1 {
            assert_eq!(digits[i], 0, "digit {} should be 0", i);
        }
        // Checksum = 64 × 15 = 960 = [3, 12, 0] in base-16
        assert_eq!(digits[XI1],     3,  "checksum high digit");
        assert_eq!(digits[XI1 + 1], 12, "checksum mid digit");
        assert_eq!(digits[XI1 + 2], 0,  "checksum low digit");
    }

    #[test]
    fn message_to_basew_all_ones() {
        let hash   = [0xFFu8; LAMBDA];
        let digits = message_to_basew(&hash);
        for i in 0..XI1 {
            assert_eq!(digits[i], 15, "digit {} should be 15", i);
        }
        // Checksum = 0
        assert_eq!(digits[XI1],     0);
        assert_eq!(digits[XI1 + 1], 0);
        assert_eq!(digits[XI1 + 2], 0);
    }

    #[test]
    fn sign_then_verify_succeeds() {
        let (sk_seed, pub_seed) = test_seeds();
        let (sk, pk) = wots_keygen(&sk_seed, &pub_seed, &[0, 1, 2]);
        let msg_hash = [0x42u8; LAMBDA];
        let sig      = wots_sign(&sk, &msg_hash, &pub_seed);
        assert!(wots_verify(&sig, &msg_hash, &pk, &pub_seed).is_ok(),
            "Valid signature must verify");
    }

    #[test]
    fn wrong_message_fails_verification() {
        let (sk_seed, pub_seed) = test_seeds();
        let (sk, pk) = wots_keygen(&sk_seed, &pub_seed, &[0, 0, 0]);
        let sig = wots_sign(&sk, &[0x01u8; LAMBDA], &pub_seed);
        assert!(wots_verify(&sig, &[0x02u8; LAMBDA], &pk, &pub_seed).is_err(),
            "Wrong message must fail verification");
    }

    #[test]
    fn wrong_public_key_fails_verification() {
        let (sk_seed, pub_seed) = test_seeds();
        let (sk, _) = wots_keygen(&sk_seed, &pub_seed, &[0, 0, 0]);
        let (_, wrong_pk) = wots_keygen(&[0x99u8; LAMBDA], &pub_seed, &[0, 0, 0]);
        let msg_hash = [0x42u8; LAMBDA];
        let sig      = wots_sign(&sk, &msg_hash, &pub_seed);
        assert!(wots_verify(&sig, &msg_hash, &wrong_pk, &pub_seed).is_err(),
            "Wrong public key must fail verification");
    }

    #[test]
    fn different_positions_give_different_keys() {
        let (sk_seed, pub_seed) = test_seeds();
        let (_, pk1) = wots_keygen(&sk_seed, &pub_seed, &[1, 1, 0]);
        let (_, pk2) = wots_keygen(&sk_seed, &pub_seed, &[1, 1, 1]);
        assert_ne!(pk1.0[0], pk2.0[0],
            "Different positions must produce different keys");
    }

    #[test]
    fn pk_recovery_from_sig_matches_original() {
        let (sk_seed, pub_seed) = test_seeds();
        let (sk, pk) = wots_keygen(&sk_seed, &pub_seed, &[0, 0, 0]);
        let msg_hash = [0x55u8; LAMBDA];
        let sig      = wots_sign(&sk, &msg_hash, &pub_seed);
        let recovered = wots_pk_from_sig(&sig, &msg_hash, &pub_seed);
        assert_eq!(pk.0, recovered.0,
            "Public key recovered from signature must match original");
    }
}
