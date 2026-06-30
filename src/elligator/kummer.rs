//! Squared Kummer line Ka²,b² arithmetic — and scalar multiplication.
//!
//! A Kummer line Ka²,b² is associated with the Legendre curve
//! Eλ : y² = x(x-1)(x-λ) via the map
//!
//!   Π⁻¹((X:·:Z)) = [b²X : a²(X-Z)]           (Paper 2, eq. 2)
//!
//! where λ = a⁴/(a⁴-b⁴).
//!
//! Points are represented externally as projective pairs (X:Z).
//! The point at infinity corresponds to (1:0).
//!
//! ─────────────────────────────────────────────────────────────────────────
//! IMPLEMENTATION NOTE — how scalar multiplication is actually computed
//! ─────────────────────────────────────────────────────────────────────────
//! An earlier version of this file computed scalar multiplication with a
//! textbook-shaped (X:Z)-only Montgomery ladder: a doubling formula (xDBL)
//! derived by hand from the Legendre curve's x-only doubling law, and a
//! differential-addition formula (xADD) borrowed from Montgomery-curve
//! x-only arithmetic (Curve25519-style). That xADD formula does NOT hold
//! for this specific (raw, non-torsion-shifted) Legendre→Kummer
//! parameterization — it is only valid for Montgomery-form curves, and
//! this is not one. The bug was confirmed by cross-checking both formulas
//! against an independent y-coordinate elliptic-curve group law: xDBL
//! matched, xADD did not. It went undetected by every prior unit test
//! because (a) the ladder's returned value only exercises xADD's output
//! for scalars with at least one non-leading `1` bit *and* that bit's
//! branch consuming it — trivially true for large random scalars but not
//! for the small powers-of-two used in the old tests (k=1,2,4), and
//! (b) the one test that did use a non-power-of-two scalar (k=3) compared
//! xADD's output against itself with identical inputs, which is circular.
//!
//! The current implementation avoids this failure mode entirely: scalar
//! multiplication is computed using standard affine (x,y) elliptic-curve
//! addition and doubling — textbook chord-and-tangent formulas that are
//! straightforward to verify by hand — converting to/from the Kummer
//! (X:Z) wire format only at the boundary, via the same Π/Π⁻¹ mapping
//! that `elligator_k1.rs` already uses. Because a Kummer point only
//! encodes an x-coordinate (it discards the sign of y), an arbitrary
//! choice of y is reconstructed via `Fp::sqrt` before the ladder runs;
//! this is always valid because scalar multiplication commutes with
//! point negation — k·(x,−y) = −(k·(x,y)), which has the *same*
//! x-coordinate as k·(x,y) — so the choice of y-sign cannot affect the
//! result once it is projected back down to Kummer (X:Z) form.
//!
//! This trades the (unverifiable, without the cited reference [KS20])
//! performance benefit of pure x-only arithmetic for an implementation
//! whose correctness can be checked directly against standard, widely
//! reviewed elliptic-curve formulas.
//!
//! References:
//!   [KS20] Karati & Sarkar, "Kummer for Genus One over Prime-Order Fields",
//!           Journal of Cryptology, 2020. (cited by Paper 2 for the
//!           genuine x-only Kummer group law, not reproduced here)
//!   Paper 2, §2.4 and §7.

use num_bigint::BigUint;
use num_traits::Zero;
use crate::elligator::field::{Fp, lambda_p25519, kummer_a2, kummer_b2};

// ─── Point ───────────────────────────────────────────────────────────────────

/// A projective point on the Kummer line Ka²,b² — the wire format used
/// throughout the rest of this crate (Elligator encode/decode, DH).
///
/// The affine Legendre x-coordinate of the corresponding point is
///   x_leg = a²·X / (a²·X − b²·Z).
///
/// Z = 0 represents the point at infinity.
#[derive(Clone, Debug, PartialEq)]
pub struct KummerPoint {
    pub x: Fp,
    pub z: Fp,
}

impl KummerPoint {
    pub fn new(x: Fp, z: Fp) -> Self { KummerPoint { x, z } }

    /// The point at infinity (identity element).
    pub fn infinity() -> Self {
        KummerPoint { x: Fp::one(), z: Fp::zero() }
    }

    pub fn is_infinity(&self) -> bool { self.z.is_zero() }

    /// Recover the affine Legendre x-coordinate from a projective Kummer point.
    ///
    /// x_leg = a²·X / (a²·X − b²·Z)
    ///
    /// Returns None for the point at infinity or the degenerate case a²X = b²Z.
    pub fn to_legendre_x(&self, a2: &Fp, b2: &Fp) -> Option<Fp> {
        if self.z.is_zero() { return None; }
        let n = a2.mul(&self.x);         // a²·X
        let d = n.sub(&b2.mul(&self.z)); // a²·X - b²·Z
        if d.is_zero() { return None; }
        Some(n.mul(&d.inv()))
    }

    /// Construct a Kummer point from a Legendre affine x-coordinate.
    ///
    ///   X = b²·x,  Z = a²·(x−1)
    ///
    /// This is the raw Π⁻¹ map (Paper 2, eq. 2), matching the direction
    /// `elligator_k1_encode` uses.
    fn from_legendre_x(x: &Fp, a2: &Fp, b2: &Fp) -> KummerPoint {
        KummerPoint {
            x: b2.mul(x),
            z: a2.mul(&x.sub(&Fp::one())),
        }
    }
}

// ─── Internal: affine (x, y) elliptic curve arithmetic ──────────────────────
//
// Standard chord-and-tangent group law for y² = x³ + Ax² + Bx, specialised
// to the Legendre curve's A = −(1+λ), B = λ. Used only inside this module,
// as the verified-correct engine behind `scalar_mult`.

#[derive(Clone, Debug, PartialEq)]
enum EcPoint {
    Infinity,
    Affine { x: Fp, y: Fp },
}

/// Point doubling: 2·P.
///
/// slope = (3x² + 2Ax + B) / (2y),  A = −(1+λ), B = λ
/// x₃ = slope² − A − 2x
/// y₃ = slope·(x − x₃) − y
///
/// A 2-torsion point (y = 0) doubles to the point at infinity, as for any
/// elliptic curve.
fn ec_double(p: &EcPoint, lambda: &Fp) -> EcPoint {
    let (x, y) = match p {
        EcPoint::Infinity => return EcPoint::Infinity,
        EcPoint::Affine { x, y } => (x, y),
    };
    if y.is_zero() { return EcPoint::Infinity; }

    let a = lambda.add(&Fp::one()).neg(); // A = −(1+λ)
    let b = lambda.clone();               // B = λ

    // slope = (3x² + 2Ax + B) / (2y)
    let three_x_sq = x.sqr().mul_small(3);
    let two_a_x    = a.mul(x).mul_small(2);
    let num        = three_x_sq.add(&two_a_x).add(&b);
    let den        = y.mul_small(2);
    let slope      = num.mul(&den.inv());

    let x3 = slope.sqr().sub(&a).sub(&x.mul_small(2));
    let y3 = slope.mul(&x.sub(&x3)).sub(y);

    EcPoint::Affine { x: x3, y: y3 }
}

/// Point addition: P₁ + P₂ (general case, handles P₁ = P₂ and P₁ = −P₂).
///
/// P₁ = P₂ (same point): dispatches to `ec_double`.
/// P₁ = −P₂ (same x, opposite y): returns the point at infinity.
/// Otherwise: standard chord formula
///   slope = (y₂−y₁)/(x₂−x₁)
///   x₃ = slope² − A − x₁ − x₂
///   y₃ = slope·(x₁−x₃) − y₁
fn ec_add(p1: &EcPoint, p2: &EcPoint, lambda: &Fp) -> EcPoint {
    let (x1, y1) = match p1 {
        EcPoint::Infinity => return p2.clone(),
        EcPoint::Affine { x, y } => (x, y),
    };
    let (x2, y2) = match p2 {
        EcPoint::Infinity => return p1.clone(),
        EcPoint::Affine { x, y } => (x, y),
    };

    if x1 == x2 {
        let y_sum = y1.add(y2);
        if y_sum.is_zero() {
            return EcPoint::Infinity; // P + (−P) = O
        }
        // x1 == x2 and y1 == y2 (the only remaining case on a curve
        // with no repeated roots): this is a doubling.
        return ec_double(p1, lambda);
    }

    let a = lambda.add(&Fp::one()).neg(); // A = −(1+λ)

    let slope = y2.sub(y1).mul(&x2.sub(x1).inv());
    let x3    = slope.sqr().sub(&a).sub(x1).sub(x2);
    let y3    = slope.mul(&x1.sub(&x3)).sub(y1);

    EcPoint::Affine { x: x3, y: y3 }
}

/// Scalar multiplication via double-and-add: k·P.
///
/// Not constant-time (branches on each bit of k). Correctness, not
/// side-channel resistance, is the goal of this PoC implementation.
///
/// Iterates by bit *index* (via `BigUint::bit`) rather than repeatedly
/// shifting k, since only `Zero`, `bit()`, and `bits()` are relied upon
/// here — all three already proven to compile elsewhere in this crate
/// (field.rs's sqrt() and prime-size assertions) — rather than assuming
/// `ShrAssign<u32>` is implemented for `BigUint` in the pinned dependency
/// version, which was not otherwise exercised anywhere in this codebase.
fn ec_scalar_mult(k: &BigUint, p: &EcPoint, lambda: &Fp) -> EcPoint {
    if k.is_zero() { return EcPoint::Infinity; }

    let mut result = EcPoint::Infinity;
    let mut addend = p.clone();

    for i in 0..k.bits() {
        if k.bit(i) {
            result = ec_add(&result, &addend, lambda);
        }
        addend = ec_double(&addend, lambda);
    }

    result
}

// ─── Public scalar multiplication (Kummer wire format in, Kummer out) ───────

/// Scalar multiplication on Ka²,b²: compute k·P.
///
/// `scalar_bytes` is a scalar encoded as 32 little-endian bytes (typically
/// produced by `clamp_scalar`, though any value works — k=0 correctly
/// yields the point at infinity).
///
/// Internally converts the input Kummer point to a Legendre affine
/// (x, y) pair (reconstructing an arbitrary — either — square root for y,
/// which is safe: see the module-level doc comment), performs the scalar
/// multiplication with standard elliptic-curve arithmetic, then converts
/// the result's x-coordinate back to Kummer (X:Z) form.
///
/// Returns the point at infinity if the input point is already infinity,
/// if k = 0, or if the scalar multiplication lands on the identity.
pub fn scalar_mult(scalar_bytes: &[u8; 32], p: &KummerPoint, a2: &Fp, b2: &Fp, lambda: &Fp)
    -> KummerPoint
{
    let x = match p.to_legendre_x(a2, b2) {
        Some(x) => x,
        None    => return KummerPoint::infinity(),
    };

    let k = BigUint::from_bytes_le(scalar_bytes);
    if k.is_zero() { return KummerPoint::infinity(); }

    // y² = x(x-1)(x-λ). Every point that reaches this function via the
    // Elligator-K1 encode map is guaranteed to be a genuine curve point
    // (Paper 2, Theorem 5.1's proof structure — mirrored for Elligator-K1
    // in Lemma 4.6), so this square root always exists in correct usage.
    // If it does not (a malformed or off-curve point was passed in), we
    // fail safe by returning the point at infinity rather than panicking.
    let y_sq = x.sub(&Fp::one()).mul(&x.sub(lambda)).mul(&x);
    let y = match y_sq.sqrt() {
        Some(y) => y,
        None    => return KummerPoint::infinity(),
    };

    let ec_p = EcPoint::Affine { x, y };
    match ec_scalar_mult(&k, &ec_p, lambda) {
        EcPoint::Infinity => KummerPoint::infinity(),
        EcPoint::Affine { x: x_out, .. } => KummerPoint::from_legendre_x(&x_out, a2, b2),
    }
}

/// Clamp a 32-byte scalar following the X25519 convention:
///   - Clear the three lowest bits of byte 0
///   - Clear the highest bit of byte 31
///   - Set the second-highest bit of byte 31
///
/// This ensures the scalar is in [2^254, 2^255) and is a multiple of 8
/// (the cofactor of the associated Legendre curve used in Paper 2).
pub fn clamp_scalar(mut scalar: [u8; 32]) -> [u8; 32] {
    scalar[0]  &= 248;   // clear bits 0, 1, 2
    scalar[31] &= 127;   // clear bit 255
    scalar[31] |= 64;    // set bit 254
    scalar
}

// ─── Convenience: Default Parameters ────────────────────────────────────────

/// Parameters for the Ka²,b² line used in Paper 2 / Knee Tie.
pub struct KummerParams {
    pub a2:     Fp,
    pub b2:     Fp,
    pub lambda: Fp,
}

impl KummerParams {
    /// Parameters from Paper 2, Table 7 (p25519 / Elligator-K1).
    pub fn p25519() -> Self {
        KummerParams {
            a2:     kummer_a2(),
            b2:     kummer_b2(),
            lambda: lambda_p25519(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elligator::field::{base_point_x, base_point_z};

    fn params() -> KummerParams { KummerParams::p25519() }

    fn base() -> KummerPoint {
        KummerPoint::new(base_point_x(), base_point_z())
    }

    fn proj_eq(p1: &KummerPoint, p2: &KummerPoint) -> bool {
        p1.x.mul(&p2.z) == p2.x.mul(&p1.z)
    }

    #[test]
    fn infinity_is_infinity() {
        assert!(KummerPoint::infinity().is_infinity());
    }

    #[test]
    fn base_point_is_not_infinity() {
        assert!(!base().is_infinity());
    }

    #[test]
    fn base_point_has_valid_legendre_x() {
        let p = params();
        let x = base().to_legendre_x(&p.a2, &p.b2);
        assert!(x.is_some(), "base point should have a valid Legendre x-coordinate");
        // x_leg = a²·X / (a²·X − b²·Z) = 289·2/(289·2-515·1) = 578/63 mod p
        let expected_n = p.a2.mul_small(2);
        let expected_d = p.a2.mul_small(2).sub(&p.b2);
        let expected   = expected_n.mul(&expected_d.inv());
        assert_eq!(x.unwrap(), expected);
    }

    #[test]
    fn scalar_mult_zero_is_infinity() {
        let p = params();
        let result = scalar_mult(&[0u8; 32], &base(), &p.a2, &p.b2, &p.lambda);
        assert!(result.is_infinity(), "0·B must be the point at infinity");
    }

    #[test]
    fn scalar_mult_1_is_base_point() {
        let p = params();
        let mut sc = [0u8; 32];
        sc[0] = 1;
        let result = scalar_mult(&sc, &base(), &p.a2, &p.b2, &p.lambda);
        assert!(proj_eq(&result, &base()), "1·B must equal B");
    }

    // ── Cross-checks against independently-computed ground truth ─────────
    //
    // These vectors were computed in Python using a completely separate
    // implementation of standard y-coordinate EC point addition/doubling
    // (double-and-add), NOT this file's code, then hard-coded here as
    // literal expected bytes. This is deliberate: comparing scalar_mult's
    // output only against itself (e.g. checking 2·B via scalar_mult(2)
    // equals 2·B via some other function in this same file) cannot catch
    // a bug that is wrong in a self-consistent way — which is exactly
    // what happened with the xADD formula this file used to contain.
    // Cross-checking against numbers computed by an entirely independent
    // method is the only way to catch that class of error.

    fn le(bytes: [u8; 32]) -> Fp { Fp::from_bytes_le(&bytes) }

    #[test]
    fn scalar_mult_matches_independent_ground_truth_k1_through_k5() {
        let p = params();
        let b = base();

        let vectors: [([u8;32],[u8;32]); 5] = [
            // k=1
            ([0xcb,0xa8,0x65,0x59,0x96,0x65,0x59,0x96,0x65,0x59,0x96,0x65,0x59,0x96,0x65,0x59,
              0x96,0x65,0x59,0x96,0x65,0x59,0x96,0x65,0x59,0x96,0x65,0x59,0x96,0x65,0x59,0x16],
             [0x5c,0xd4,0xb2,0x2c,0xcb,0xb2,0x2c,0xcb,0xb2,0x2c,0xcb,0xb2,0x2c,0xcb,0xb2,0x2c,
              0xcb,0xb2,0x2c,0xcb,0xb2,0x2c,0xcb,0xb2,0x2c,0xcb,0xb2,0x2c,0xcb,0xb2,0x2c,0x4b]),
            // k=2
            ([0xe7,0x90,0x74,0xb4,0x14,0x08,0xa8,0x11,0x91,0xd1,0x1e,0x4d,0xae,0x46,0x26,0xf9,
              0x8c,0x6c,0xb9,0x6c,0x4d,0x3b,0x79,0xf9,0x37,0x97,0xf7,0x09,0x33,0x3b,0x94,0x1d],
             [0xed,0x78,0x36,0x6e,0xd6,0xd0,0xaf,0x2f,0x77,0x37,0xc9,0x29,0x7b,0xf1,0x70,0xcb,
              0x84,0x80,0x1b,0x82,0x76,0xac,0x2b,0x6e,0x71,0x46,0xfc,0x17,0x7a,0xf5,0x23,0x34]),
            // k=3
            ([0xda,0x64,0x66,0x7d,0xf5,0x85,0x70,0xb1,0x07,0x26,0x85,0xe9,0xce,0x46,0xfc,0x55,
              0x38,0xfc,0x63,0x81,0x2f,0x0d,0x7f,0x9d,0x87,0xa0,0x3f,0x36,0x65,0x02,0x47,0x67],
             [0x0b,0x25,0x19,0xca,0x84,0x65,0x69,0xd4,0xac,0x31,0xa4,0xc7,0xac,0xdc,0xb0,0x3a,
              0x61,0xa8,0x2f,0xe6,0x46,0x1c,0x67,0xff,0x5d,0xd4,0x63,0x27,0x51,0x5b,0x26,0x6e]),
            // k=4
            ([0x0b,0x0b,0x3e,0x4b,0xdf,0x1a,0x85,0xc7,0x5c,0x73,0x1d,0xb1,0x84,0xc0,0x83,0x58,
              0xfa,0xd1,0xde,0xbf,0xd0,0x46,0x88,0xab,0x01,0xfe,0xe2,0xd8,0x12,0xd7,0x14,0x67],
             [0x8c,0x0b,0xfb,0xa8,0x40,0x9c,0x03,0x12,0x33,0x47,0x90,0xf0,0xf8,0xcb,0xb6,0x7f,
              0xdf,0x6e,0xe4,0x45,0xb4,0x2d,0xd4,0xfe,0xf6,0x45,0x3c,0x75,0xc9,0xbd,0x03,0x1d]),
            // k=5
            ([0xfa,0x03,0xb5,0x99,0x40,0x05,0x1f,0xd3,0x70,0x70,0xbe,0x52,0x21,0x80,0x96,0xf2,
              0x8b,0x2f,0x1c,0x72,0x4b,0x29,0xc2,0x7b,0xbf,0x83,0x73,0xed,0xfc,0xc9,0xd4,0x41],
             [0x1d,0xfc,0x74,0xde,0xba,0xd2,0x1f,0xb2,0xa8,0x34,0x31,0x02,0xde,0x4d,0x6e,0xaa,
              0xe2,0xf7,0xf5,0xa1,0xa2,0x1d,0xa7,0x22,0xf7,0xee,0x2d,0x91,0xcc,0x79,0xc1,0x44]),
        ];

        for (i, (expected_x, expected_z)) in vectors.iter().enumerate() {
            let k = (i as u8) + 1;
            let mut sc = [0u8; 32];
            sc[0] = k;
            let got      = scalar_mult(&sc, &b, &p.a2, &p.b2, &p.lambda);
            let expected = KummerPoint::new(le(*expected_x), le(*expected_z));
            assert!(proj_eq(&got, &expected),
                "scalar_mult({})·B does not match independently-computed ground truth", k);
        }
    }

    #[test]
    fn scalar_mult_matches_ground_truth_for_large_clamped_scalar() {
        // A single large (255-bit, properly clamped) scalar, cross-checked
        // the same way as the k=1..5 vectors above. This specifically
        // exercises the code path that the old, broken xADD formula would
        // have silently corrupted (any scalar with a non-power-of-two bit
        // pattern in its lower bits).
        let p = params();
        let b = base();

        let k_bytes: [u8; 32] = [
            0x08,0xdd,0xfc,0x5d,0x07,0x58,0x8f,0x74,0xd5,0xb3,0xc2,0xee,0x86,0x7a,0xa4,0xd5,
            0xdd,0x87,0x56,0x66,0x70,0xbc,0x65,0xd9,0xbf,0x85,0x00,0x60,0xd9,0xc0,0x73,0x4c,
        ];
        let expected_x: [u8; 32] = [
            0xae,0x14,0xb3,0x6d,0xa4,0x21,0x88,0x2e,0xf9,0x45,0x6d,0xb3,0x16,0x38,0x07,0x24,
            0x28,0x1f,0x28,0x22,0x75,0xc5,0xa6,0xd0,0x7e,0x14,0x9b,0x21,0x14,0x1d,0xc0,0x45,
        ];
        let expected_z: [u8; 32] = [
            0x26,0xec,0x6f,0x52,0xfe,0xa9,0xc8,0xfc,0x1b,0x42,0x9d,0xc6,0x5b,0x33,0x95,0x80,
            0x1a,0xfd,0x1a,0x73,0x1c,0x90,0x61,0x98,0xfd,0xb7,0xe0,0x64,0xa5,0x2d,0xd7,0x2f,
        ];

        let got      = scalar_mult(&k_bytes, &b, &p.a2, &p.b2, &p.lambda);
        let expected = KummerPoint::new(le(expected_x), le(expected_z));
        assert!(proj_eq(&got, &expected),
            "scalar_mult for a large clamped scalar does not match independent ground truth");
    }

    // ── Structural / consistency properties ───────────────────────────────

    #[test]
    fn scalar_mult_2_differs_from_1() {
        let p = params();
        let b = base();
        let mut sc2 = [0u8; 32]; sc2[0] = 2;
        let mut sc1 = [0u8; 32]; sc1[0] = 1;

        let two_b = scalar_mult(&sc2, &b, &p.a2, &p.b2, &p.lambda);
        let one_b = scalar_mult(&sc1, &b, &p.a2, &p.b2, &p.lambda);
        assert!(!proj_eq(&two_b, &one_b),
            "2·B and 1·B must be different points");
    }

    #[test]
    fn scalar_mult_result_is_genuine_curve_point() {
        // For every scalar tested, the resulting Kummer point's Legendre
        // x-coordinate must satisfy x(x-1)(x-λ) being a square — i.e. it
        // must be a genuine point on Eλ, not an artefact of a broken
        // formula landing on the curve's quadratic twist instead.
        let p = params();
        let b = base();
        for k in [1u8, 2, 3, 5, 7, 11, 100, 255] {
            let mut sc = [0u8; 32];
            sc[0] = k;
            let result = scalar_mult(&sc, &b, &p.a2, &p.b2, &p.lambda);
            let x = result.to_legendre_x(&p.a2, &p.b2)
                .expect("result must have a valid Legendre x-coordinate");
            let rhs = x.sub(&Fp::one()).mul(&x.sub(&p.lambda)).mul(&x);
            assert_eq!(rhs.chi(), 1,
                "scalar_mult({})·B must land on Eλ itself, not its twist", k);
        }
    }

    #[test]
    fn clamp_sets_correct_bits() {
        let raw     = [0xFFu8; 32];
        let clamped = clamp_scalar(raw);
        assert_eq!(clamped[0] & 0b111, 0,
            "lowest 3 bits of byte 0 must be zero");
        assert_eq!(clamped[31] & 0x80, 0,    "bit 255 must be cleared");
        assert_eq!(clamped[31] & 0x40, 0x40, "bit 254 must be set");
    }

    #[test]
    fn scalar_mult_on_infinity_is_infinity() {
        let p = params();
        let mut sc = [0u8; 32]; sc[0] = 7;
        let result = scalar_mult(&sc, &KummerPoint::infinity(), &p.a2, &p.b2, &p.lambda);
        assert!(result.is_infinity(), "k·O must be O for any k");
    }
}
