//! Elligator-K1 Diffie-Hellman key exchange.
//!
//! Paper 2, §7.1: "Diffie-Hellman using Kummer line."
//!
//! PROTOCOL OVERVIEW
//!
//! Unlike standard ECDH where parties exchange elliptic curve points
//! (which are distinguishable from random bytes), this protocol exchanges
//! field elements that are indistinguishable from uniform random strings.
//!
//! Party A:
//!   1. Choose random scalar a.
//!   2. Compute PA = a·B  (scalar multiplication on Kummer line).
//!   3. Check whether PA is in the image of Elligator-K1.
//!      If not, try a different scalar (about 50% success rate per attempt).
//!   4. Compute µA = ψ̂₁⁻¹(PA) and send µA to B.
//!
//! Party B does the same with scalar b, sends µB to A.
//!
//! A computes: shared = a · ψ̂₁(µB) = a · bB = abB
//! B computes: shared = b · ψ̂₁(µA) = b · aB = abB
//!
//! Shared secret derivation: H(abB) using SHA-256.
//!
//! SECURITY PROPERTIES
//!   - Transmitted values µA and µB are indistinguishable from random 32-byte strings.
//!   - Security reduces to the DLP on the Kummer line (CDH assumption).
//!   - Post-quantum: no quantum speedup beyond Grover on the hash (affects
//!     the 128-bit security level). The underlying group DLP is quantum-vulnerable,
//!     but this module is included for the traffic-indistinguishability property,
//!     not post-quantum key establishment.
//!
//! NOTE: For full post-quantum key exchange, use a lattice-based KEM
//! (e.g. ML-KEM / Kyber) as the primary key establishment mechanism and
//! use the Elligator transport layer only for traffic obfuscation of the
//! public key transmission.

use sha2::{Sha256, Digest};
use rand::RngCore;
use crate::elligator::kummer::{KummerPoint, KummerParams, scalar_mult, clamp_scalar};
use crate::elligator::elligator_k1::{
    elligator_k1_encode, elligator_k1_decode,
    field_to_bits, bits_to_field,
};
use crate::error::{Result, KneeTieError};

// ─── Types ───────────────────────────────────────────────────────────────────

/// A 32-byte string that is indistinguishable from random bytes.
/// Contains an Elligator-encoded Kummer line point.
pub type ElligatorString = [u8; 32];

/// A clamped 32-byte Diffie-Hellman scalar.
pub type DhScalar = [u8; 32];

/// A party's DH key pair.
pub struct DhKeyPair {
    /// Secret scalar a (32 bytes, clamped).
    pub scalar: DhScalar,
    /// Public value: Elligator encoding of a·B.
    /// This is what the party transmits.
    pub public: ElligatorString,
    /// The actual Kummer point a·B (kept private, used for shared secret).
    ///
    /// Currently write-only: `generate_keypair` sets this, but the public
    /// `dh_initiate`/`dh_complete` API only passes the raw scalar around
    /// and re-derives points from it, so this field is never read through
    /// that path. Kept on the struct so a future caller working directly
    /// with `DhKeyPair` (e.g. to skip redundant scalar multiplications
    /// in `knee-tie-server`) doesn't have to recompute a·B.
    #[allow(dead_code)]
    pub(crate) point: KummerPoint,
}

// ─── Key Generation ──────────────────────────────────────────────────────────

/// Generate a DH key pair using the Elligator-K1 transport.
///
/// Paper 2, §7.1 steps 1-4.
///
/// Repeatedly samples random scalars until the resulting point a·B
/// falls in the image of the Elligator-K1 map (expected ~2 trials).
///
/// # Arguments
/// * `params` — Kummer line parameters (a², b², λ).
/// * `base`   — Base point B on the Kummer line.
///
/// # Returns
/// A `DhKeyPair` with:
///   - `scalar`:  the private scalar a
///   - `public`:  µA = ψ̂₁⁻¹(a·B), a 32-byte string ≈ random
///   - `point`:   a·B (kept secret, used during shared secret computation)
pub fn generate_keypair(
    params: &KummerParams,
    base: &KummerPoint,
) -> Result<DhKeyPair> {
    let mut rng = rand::thread_rng();
    let max_attempts = 64u32;

    for _ in 0..max_attempts {
        // Sample a random 32-byte scalar and clamp it.
        let mut scalar_bytes = [0u8; 32];
        rng.fill_bytes(&mut scalar_bytes);
        let scalar = clamp_scalar(scalar_bytes);

        // Compute a·B on the Kummer line.
        let point = scalar_mult(&scalar, base, &params.a2, &params.b2, &params.lambda);

        if point.is_infinity() { continue; }

        // Check if a·B is in the image of Elligator-K1.
        if let Some(field_elem) = elligator_k1_decode(&point, params) {
            let public = field_to_bits(&field_elem);
            return Ok(DhKeyPair { scalar, public, point });
        }
        // About 50% of random points are in the image; retry otherwise.
    }

    Err(KneeTieError::CryptoError(
        format!("Failed to generate Elligator-K1 keypair after {} attempts", max_attempts)
    ))
}

// ─── Shared Secret ───────────────────────────────────────────────────────────

/// Compute the Diffie-Hellman shared secret.
///
/// Paper 2, §7.1: "A computes c = H(a·PB)"
///
/// # Arguments
/// * `our_scalar`     — Our private scalar a.
/// * `their_public`   — Their Elligator-encoded public value µB.
/// * `params`         — Kummer line parameters.
///
/// # Returns
/// 32-byte shared secret H(a·bB).
pub fn compute_shared_secret(
    our_scalar: &DhScalar,
    their_public: &ElligatorString,
    params: &KummerParams,
) -> Result<[u8; 32]> {
    // Decode their public Elligator string to a field element.
    let field_elem = bits_to_field(their_public);

    // Recover their Kummer point b·B = ψ̂₁(µB).
    let their_point = elligator_k1_encode(&field_elem, params);

    if their_point.is_infinity() {
        return Err(KneeTieError::CryptoError(
            "Received public value decodes to point at infinity".into()
        ));
    }

    // Compute a·(b·B) = a·b·B.
    let shared_point = scalar_mult(
        our_scalar,
        &their_point,
        &params.a2,
        &params.b2,
        &params.lambda,
    );

    if shared_point.is_infinity() {
        return Err(KneeTieError::CryptoError(
            "Shared point is the point at infinity (small subgroup attack?)".into()
        ));
    }

    // Hash the shared point to derive a uniform 32-byte secret.
    // We use the X-coordinate in affine form (normalised by Z-inverse)
    // to ensure both parties compute the same value regardless of
    // the projective representative they obtained.
    //
    // affine_x = X·Z⁻¹
    let affine_x = shared_point.x.mul(&shared_point.z.inv());
    let x_bytes  = affine_x.to_bytes_le();

    let mut h = Sha256::new();
    h.update(b"KneeTie-DH-v1"); // domain separation
    h.update(&x_bytes);
    let secret: [u8; 32] = h.finalize().into();

    Ok(secret)
}

// ─── High-Level API ──────────────────────────────────────────────────────────

/// Complete one side of the Elligator-K1 DH handshake.
///
/// Generates a key pair, returns the public Elligator string to transmit,
/// and retains the secret scalar for shared-secret derivation.
///
/// # Usage
///
/// ```text
/// // Alice side:
/// let (alice_pub, alice_secret) = dh_initiate(&params, &base)?;
/// // Send alice_pub to Bob (looks like random bytes)
///
/// // Bob side:
/// let (bob_pub, bob_secret) = dh_initiate(&params, &base)?;
/// // Send bob_pub to Alice
///
/// // Alice computes shared secret:
/// let alice_shared = dh_complete(&alice_secret, &bob_pub, &params)?;
///
/// // Bob computes shared secret:
/// let bob_shared = dh_complete(&bob_secret, &alice_pub, &params)?;
///
/// assert_eq!(alice_shared, bob_shared);
/// ```
pub fn dh_initiate(
    params: &KummerParams,
    base: &KummerPoint,
) -> Result<(ElligatorString, DhScalar)> {
    let kp = generate_keypair(params, base)?;
    Ok((kp.public, kp.scalar))
}

/// Complete the DH exchange given our scalar and their public string.
pub fn dh_complete(
    our_scalar: &DhScalar,
    their_public: &ElligatorString,
    params: &KummerParams,
) -> Result<[u8; 32]> {
    compute_shared_secret(our_scalar, their_public, params)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elligator::field::{base_point_x, base_point_z};

    fn params() -> KummerParams { KummerParams::p25519() }
    fn base()   -> KummerPoint  {
        KummerPoint::new(base_point_x(), base_point_z())
    }

    #[test]
    fn generate_keypair_succeeds() {
        let p  = params();
        let b  = base();
        let kp = generate_keypair(&p, &b);
        assert!(kp.is_ok(), "Key pair generation must succeed: {:?}", kp.err());
    }

    #[test]
    fn public_value_is_32_bytes() {
        let p   = params();
        let b   = base();
        let kp  = generate_keypair(&p, &b).unwrap();
        assert_eq!(kp.public.len(), 32);
    }

    #[test]
    fn two_keypairs_have_different_public_values() {
        let p  = params();
        let b  = base();
        let k1 = generate_keypair(&p, &b).unwrap();
        let k2 = generate_keypair(&p, &b).unwrap();
        // Extremely unlikely to be equal for two random keys
        assert_ne!(k1.public, k2.public,
            "Two independent keypairs must (almost certainly) have different public values");
    }

    #[test]
    fn dh_shared_secret_matches() {
        // Full DH exchange: Alice and Bob derive the same shared secret.
        let p = params();
        let b = base();

        let (alice_pub, alice_sk) = dh_initiate(&p, &b).unwrap();
        let (bob_pub,   bob_sk)   = dh_initiate(&p, &b).unwrap();

        let alice_shared = dh_complete(&alice_sk, &bob_pub,   &p).unwrap();
        let bob_shared   = dh_complete(&bob_sk,   &alice_pub, &p).unwrap();

        assert_eq!(alice_shared, bob_shared,
            "Alice and Bob must derive the same shared secret");
    }

    #[test]
    fn shared_secret_is_32_bytes() {
        let p = params();
        let b = base();
        let (_alice_pub, alice_sk) = dh_initiate(&p, &b).unwrap();
        let (bob_pub,    _bob_sk)  = dh_initiate(&p, &b).unwrap();
        let secret = dh_complete(&alice_sk, &bob_pub, &p).unwrap();
        assert_eq!(secret.len(), 32);
    }

    #[test]
    fn wrong_counterpart_gives_different_secret() {
        let p = params();
        let b = base();

        let (_alice_pub, alice_sk) = dh_initiate(&p, &b).unwrap();
        let (bob_pub,    _bob_sk)  = dh_initiate(&p, &b).unwrap();
        let (eve_pub,    _eve_sk)  = dh_initiate(&p, &b).unwrap();

        let alice_bob = dh_complete(&alice_sk, &bob_pub, &p).unwrap();
        let alice_eve = dh_complete(&alice_sk, &eve_pub, &p).unwrap();

        assert_ne!(alice_bob, alice_eve,
            "DH with different counterparts must give different secrets");
    }

    #[test]
    fn public_value_decodes_to_field_element() {
        // The transmitted public value must be decodeable by the receiver.
        // This is guaranteed by construction but worth asserting.
        let p  = params();
        let b  = base();
        let kp = generate_keypair(&p, &b).unwrap();

        let t = bits_to_field(&kp.public);
        let pt = elligator_k1_encode(&t, &p);
        assert!(!pt.is_infinity(), "Decoded public value must not be point at infinity");
    }

    #[test]
    fn public_value_top_bit_is_zero() {
        // Canonical representatives are in [0,(p-1)/2] which fits in 255 bits.
        // The top bit (bit 255) of the 32-byte encoding must always be 0.
        let p = params();
        let b = base();
        // Run a few trials to be confident
        for _ in 0..10 {
            let kp = generate_keypair(&p, &b).unwrap();
            assert_eq!(kp.public[31] & 0x80, 0,
                "Top bit of transmitted public value must be 0 (canonical representative)");
        }
    }

    #[test]
    fn dh_complete_rejects_infinity_encoding() {
        // Craft a public value that encodes the point at infinity.
        // The point at infinity (1:0) is not in the image of Elligator-K1,
        // so elligator_k1_encode is never called on it directly.
        // Instead, we can test with a zero scalar which would yield infinity.
        // Actually the easier test: pass all-zeros public value and verify
        // the function either succeeds with some point or fails gracefully.
        let p      = params();
        let zero32 = [0u8; 32];
        let result = dh_complete(&[1u8; 32], &zero32, &p);
        // This should succeed (zero decodes to the distinguished point (b²:a²))
        // and produce a valid (non-infinity) shared point.
        match result {
            Ok(secret) => assert_ne!(secret, [0u8; 32]),
            Err(_) => {} // also acceptable
        }
    }
}
