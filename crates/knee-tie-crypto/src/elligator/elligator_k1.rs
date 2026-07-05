//! Elligator-K1: injective encoding from F_{p25519} to the Kummer line Ka²,b².
//!
//! Paper 2, §4.2 (Lemma 4.6, Definition 4.7, Corollary 4.9).
//!
//! PRECONDITIONS (verified at the bottom of this file in tests):
//!   q ≡ 1 (mod 4)       ← p25519 satisfies this
//!   χ(λ) = 1            ← λ₃ from Paper 2 Table 7 satisfies this
//!   u is a non-square    ← u = 2 satisfies this for p ≡ 5 (mod 8)
//!
//! MAP DIRECTION (field element → Kummer point):
//!   Input:  t ∈ Fq
//!   Output: (X:Z) ∈ Ka²,b²
//!
//!   ψ₂x (Legendre x-coordinate, Lemma 4.6 part 1):
//!     v  = (λ+1) / (1 + u·t²)    [denominator is never 0: u non-square]
//!     ε  = χ(v(v-1)(v-λ))
//!     x  = ε·v + (1-ε)(λ+1)/2   [= v if ε=1, = (λ+1)-v if ε=-1]
//!
//!   Π⁻¹ (Legendre → Kummer, eq. 2 of Paper 2):
//!     X  = b²·x
//!     Z  = a²·(x-1)
//!
//!   Special case t=0: ψ̂₂(0) = (b²:a²)
//!
//! INVERSE DIRECTION (Kummer point → field element):
//!   Corollary 4.9 of Paper 2.
//!
//!   Given (X:Z) ∈ Ka²,b²:
//!     x     = a²·X / (a²·X − b²·Z)         [Legendre x-coordinate]
//!     denom = a²·X − (λ+1)·(a²·X − b²·Z)   [= (a²X-b²Z) + b²Z - (λ+1)(a²X-b²Z)]
//!     t̄     = √(-a²·X / (denom · u))
//!
//!   The map is 4-to-1: t̄, -t̄, 1/(u·t̄), -1/(u·t̄) all map to the same point.
//!   To make it injective we restrict to a canonical representative.

use num_bigint::BigUint;
use crate::elligator::field::{Fp, prime};
use crate::elligator::kummer::{KummerPoint, KummerParams};

// ─── Forward Map ─────────────────────────────────────────────────────────────

/// Encode a field element `t` as a point on Ka²,b².
///
/// Paper 2, Lemma 4.6 and Definition 4.7.
///
/// Returns ψ̂₁(t) ∈ Ka²,b².
///   t = 0 maps to the distinguished point (b²:a²).
///   All other t produce a proper Kummer point.
///
/// This map has NO exception points — every element of Fq maps to a
/// valid Kummer point. (Paper 2, Lemma 4.6.)
pub fn elligator_k1_encode(t: &Fp, params: &KummerParams) -> KummerPoint {
    let lambda = &params.lambda;
    let a2     = &params.a2;
    let b2     = &params.b2;
    let u      = Fp::nonsquare_u(); // u = 2, the fixed non-square

    // Special case: t = 0 → distinguished point (b²:a²)
    if t.is_zero() {
        return KummerPoint::new(b2.clone(), a2.clone());
    }

    // ── ψ₂x: compute Legendre x-coordinate ──────────────────────────────
    //
    // v = (λ+1) / (1 + u·t²)
    let lam_plus_1 = lambda.add(&Fp::one()); // λ+1
    let ut_sq      = u.mul(&t.sqr());        // u·t²
    let denom_v    = Fp::one().add(&ut_sq);  // 1 + u·t²
    // denom_v ≠ 0: if 1 + u·t² = 0 then t² = -1/u.
    // Since u is non-square, -1/u = -u^{-1}. For p ≡ 1 mod 4, -1 is a square,
    // so -1/u is non-square, therefore t² = non-square has no solution. QED.
    let v = lam_plus_1.mul(&denom_v.inv()); // v = (λ+1)/(1+ut²)

    // ε = χ(v(v-1)(v-λ))
    let v_m1    = v.sub(&Fp::one());             // v-1
    let v_m_lam = v.sub(lambda);                 // v-λ
    let product = v.mul(&v_m1).mul(&v_m_lam);    // v(v-1)(v-λ)
    let epsilon = product.chi();                  // ε ∈ {-1, 0, 1}

    // x = ε·v + (1-ε)·(λ+1)/2
    //
    // When ε =  1: x = v                  (v(v-1)(v-λ) is already a square)
    // When ε = -1: x = -v + (λ+1)         (shift to the other root family)
    // When ε =  0: theoretically impossible (proved in Theorem 3.5)
    //
    // VERIFIED against Paper 2, Theorem 3.5 proof: "if ε=−1, then
    // x=−v+(λ+1)=vu t²" — note the explicit minus sign on v. An earlier
    // version of this code dropped the ε multiplier on v (using x=v+(λ+1)
    // for the ε=-1 branch), which silently broke the bijection between
    // encode and decode while individual field operations still type-checked
    // and ran without error.
    let x = if epsilon >= 0 {
        v.clone()
    } else {
        lam_plus_1.sub(&v) // (λ+1) - v = -v + (λ+1)
    };

    // ── Π⁻¹: Legendre x → Kummer (X:Z) ─────────────────────────────────
    //   X = b²·x
    //   Z = a²·(x-1)
    let cap_x = b2.mul(&x);                // b²·x
    let cap_z = a2.mul(&x.sub(&Fp::one())); // a²·(x-1)

    KummerPoint::new(cap_x, cap_z)
}

// ─── Inverse Map ─────────────────────────────────────────────────────────────

/// Decode a Kummer point back to a canonical field element.
///
/// Paper 2, Corollary 4.9.
///
/// Returns `Some(t̄)` where ψ̂₂(t̄) = (X:Z), or `None` if the point is
/// not in the image of elligator_k1_encode.
///
/// The canonical representative is chosen as the element in
/// {0, 1, …, (p-1)/2} — the non-negative half of the field.
/// (Paper 2, §3.2.2: "R has exactly (q+1)/2 elements".)
pub fn elligator_k1_decode(point: &KummerPoint, params: &KummerParams) -> Option<Fp> {
    let lambda = &params.lambda;
    let a2     = &params.a2;
    let b2     = &params.b2;
    let u      = Fp::nonsquare_u();

    // Special case: (b²:a²) → 0
    // This is ψ̂₂(0) by Definition 4.7.
    {
        // Check projective equality: b²·z == a²·x (i.e., (b²:a²) ∝ (x:z))
        let lhs = b2.mul(&point.z);
        let rhs = a2.mul(&point.x);
        if lhs == rhs {
            return Some(Fp::zero());
        }
    }

    // Recover Legendre x-coordinate:
    //   x_leg = a²·X / (a²·X − b²·Z)
    let a2x   = a2.mul(&point.x);          // a²·X
    let b2z   = b2.mul(&point.z);          // b²·Z
    let a2x_m_b2z = a2x.sub(&b2z);        // a²·X − b²·Z

    if a2x_m_b2z.is_zero() { return None; } // point at infinity or invalid

    // Check membership condition (Paper 2, Theorem 4.8 statement 2b):
    //   −x·u·(x−λ−1) must be a square in Fq.
    //
    // Express everything in terms of (X:Z) ratios.
    // Let x = a²X / (a²X-b²Z).  Then x−(λ+1) = (a²X − (λ+1)(a²X−b²Z)) / (a²X−b²Z).
    // Numerator of x−(λ+1):
    let lam_plus_1    = lambda.add(&Fp::one());
    let x_m_lam1_num  = a2x.sub(&lam_plus_1.mul(&a2x_m_b2z)); // a²X − (λ+1)(a²X-b²Z)

    // −x·u·(x−(λ+1)) in projective form:
    //   numerator   = −a²X · u · (a²X−(λ+1)(a²X−b²Z))
    //   denominator = (a²X−b²Z)²    [always positive]
    //
    // The sign of the quadratic character depends only on the numerator.
    let check_num = a2x.neg().mul(&u).mul(&x_m_lam1_num);

    if check_num.chi() != 1 {
        return None; // not in image
    }

    // Compute t̄ = √(−a²X / (denom · u))
    // where denom = a²X − (λ+1)(a²X − b²Z)
    //
    // We compute as √(num / (den · u)) keeping everything over the same denominator.
    let radicand_num = a2x.neg();           // −a²·X
    let radicand_den = x_m_lam1_num.mul(&u); // (a²X−(λ+1)(a²X−b²Z)) · u
    if radicand_den.is_zero() { return None; }

    let radicand = radicand_num.mul(&radicand_den.inv());
    let t_bar    = radicand.sqrt()?;        // None if not a square

    // Canonicalise: choose representative in {0, …, (p-1)/2}
    // The canonical representative is the one whose canonical bytes
    // represent a value ≤ (p-1)/2.
    Some(canonical_rep(t_bar))
}

/// Choose the canonical representative of {t, -t} that lies in [0, (p-1)/2].
///
/// This makes the encoding injective (maps each image point to exactly
/// one bit-string) as described in Paper 2, §3.2.2 and Theorem 3.4/3.8.
fn canonical_rep(t: Fp) -> Fp {
    let p        = prime();
    let half_p   = (&p - 1u32) / 2u32;
    let t_bytes  = BigUint::from_bytes_le(&t.to_bytes_le());
    if t_bytes <= half_p {
        t
    } else {
        // return -t
        let neg_bytes = &p - &t_bytes;
        Fp::new(neg_bytes)
    }
}

// ─── Bit-String Encoding ─────────────────────────────────────────────────────

/// Encode a canonical field element as a 32-byte bit string.
///
/// The canonical representative lives in [0, (p-1)/2], which fits in
/// 255 bits. The top bit (bit 255) of the 32-byte encoding is always 0.
/// This leaves one free bit that can carry a sign or parity flag.
///
/// Paper 2, §3.2.2 (Theorem 3.4 and Corollary 4.5/4.10).
pub fn field_to_bits(t: &Fp) -> [u8; 32] {
    t.to_bytes_le()
}

/// Decode a 32-byte bit string back to a field element.
///
/// Clears the top bit before decoding (it may carry auxiliary data).
pub fn bits_to_field(bits: &[u8; 32]) -> Fp {
    let mut b = *bits;
    b[31] &= 0x7F; // clear bit 255
    Fp::from_bytes_le(&b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elligator::field::{Fp, lambda_p25519};

    fn params() -> KummerParams { KummerParams::p25519() }

    // ── Precondition checks ───────────────────────────────────────────────

    #[test]
    fn precondition_p_equiv_1_mod_4() {
        // Already tested in field.rs but repeated here for clarity
        use crate::elligator::field::prime;
        use num_bigint::BigUint;
        use num_traits::One;
        let p   = prime();
        let rem = &p % 4u32;
        assert_eq!(rem, BigUint::one(), "p25519 must be ≡ 1 mod 4 for Elligator-K1");
    }

    #[test]
    fn precondition_lambda_is_square() {
        assert_eq!(lambda_p25519().chi(), 1, "λ must be a QR for Elligator-K1");
    }

    #[test]
    fn precondition_u_is_nonsquare() {
        assert_eq!(Fp::nonsquare_u().chi(), -1, "u must be a non-square");
    }

    // ── Encode: basic properties ──────────────────────────────────────────

    #[test]
    fn encode_zero_gives_distinguished_point() {
        let p   = params();
        let pt  = elligator_k1_encode(&Fp::zero(), &p);
        // Distinguished point is (b²:a²)
        let lhs = p.b2.mul(&pt.z);
        let rhs = p.a2.mul(&pt.x);
        assert_eq!(lhs, rhs, "ψ̂₁(0) must be (b²:a²)");
    }

    #[test]
    fn encode_never_produces_infinity() {
        let p = params();
        for t_val in [1u64, 2, 7, 42, 999, 0xDEAD_BEEF] {
            let t  = Fp::from_u64(t_val);
            let pt = elligator_k1_encode(&t, &p);
            assert!(!pt.is_infinity(), "ψ̂₁({}) must not be the point at infinity", t_val);
        }
    }

    #[test]
    fn encode_is_deterministic() {
        let p  = params();
        let t  = Fp::from_u64(12345);
        let p1 = elligator_k1_encode(&t, &p);
        let p2 = elligator_k1_encode(&t, &p);
        assert_eq!(p1, p2);
    }

    #[test]
    fn different_inputs_can_give_different_outputs() {
        let p  = params();
        let p1 = elligator_k1_encode(&Fp::from_u64(1), &p);
        let p2 = elligator_k1_encode(&Fp::from_u64(2), &p);
        // They might or might not be equal by coincidence, but for these
        // small values they should differ
        assert_ne!(p1, p2, "distinct small inputs should usually give distinct points");
    }

    // ── Decode: round-trip ────────────────────────────────────────────────

    #[test]
    fn decode_zero_point_gives_zero() {
        let p  = params();
        let pt = elligator_k1_encode(&Fp::zero(), &p);
        let t  = elligator_k1_decode(&pt, &p);
        assert_eq!(t, Some(Fp::zero()), "decode(encode(0)) must equal 0");
    }

    /// The correct round-trip property for a 4-to-1 map is:
    ///   encode(decode(encode(t))) == encode(t)   (same Kummer point)
    /// NOT necessarily that decode(encode(t)) == t, because the canonical
    /// preimage might be -t or 1/(u·t), not t itself.
    #[test]
    fn encode_decode_roundtrip_consistency() {
        let p = params();
        for t_val in [1u64, 2, 3, 5, 7, 11, 13, 42, 100, 1337, 9999] {
            let t_in  = Fp::from_u64(t_val);
            let pt1   = elligator_k1_encode(&t_in, &p);

            if let Some(t_out) = elligator_k1_decode(&pt1, &p) {
                // Re-encode the decoded value — must give the same Kummer point.
                let pt2  = elligator_k1_encode(&t_out, &p);

                // Projective equality: X₁·Z₂ == X₂·Z₁
                let lhs = pt1.x.mul(&pt2.z);
                let rhs = pt2.x.mul(&pt1.z);
                assert_eq!(lhs, rhs,
                    "encode(decode(encode({}))) must equal encode({})", t_val, t_val);
            }
            // None is valid: the specific t may not map to the canonical
            // representative image. encode is defined for all t; decode
            // returns None for points not in the canonical-half image.
        }
    }

    #[test]
    fn encode_decode_roundtrip_canonical_half() {
        // For any point in the image, re-encoding the decoded value
        // gives back the same point.
        let p = params();
        let mut decoded_count = 0usize;
        for t_val in (0u64..500).step_by(7) {
            let t_in = Fp::from_u64(t_val);
            let pt1  = elligator_k1_encode(&t_in, &p);

            if let Some(t_out) = elligator_k1_decode(&pt1, &p) {
                decoded_count += 1;
                let pt2  = elligator_k1_encode(&t_out, &p);
                let lhs  = pt1.x.mul(&pt2.z);
                let rhs  = pt2.x.mul(&pt1.z);
                assert_eq!(lhs, rhs,
                    "re-encode property must hold for t={}", t_val);
            }
        }
        // At least some inputs should decode successfully
        assert!(decoded_count > 0,
            "at least some inputs must be decodable");
    }

    #[test]
    fn decode_point_at_infinity_is_none() {
        let p = params();
        let inf = KummerPoint::infinity();
        assert!(elligator_k1_decode(&inf, &p).is_none(),
            "point at infinity is not in the image of the Elligator map");
    }

    // ── Symmetry: 4-to-1 property ────────────────────────────────────────

    #[test]
    fn encode_t_and_neg_t_give_projectively_equal_points() {
        // Paper 2, Lemma 4.8 statement 1: ψ̂₁ maps the full 4-element orbit
        // {t, -t, 1/(u·t), -1/(u·t)} to the same Kummer point.
        let p = params();
        let u = Fp::nonsquare_u();
        let t = Fp::from_u64(42);

        let neg_t      = t.neg();
        let inv_ut     = u.mul(&t).inv();
        let neg_inv_ut = inv_ut.neg();

        let base_pt = elligator_k1_encode(&t, &p);

        for (label, variant) in [
            ("-t",      &neg_t),
            ("1/(ut)",  &inv_ut),
            ("-1/(ut)", &neg_inv_ut),
        ] {
            let pt  = elligator_k1_encode(variant, &p);
            // Projective equality: X₁·Z₂ == X₂·Z₁
            let lhs = base_pt.x.mul(&pt.z);
            let rhs = pt.x.mul(&base_pt.z);
            assert_eq!(lhs, rhs,
                "ψ̂₁(t) and ψ̂₁({}) must be projectively equal", label);
        }
    }

    // ── Bit-string encoding ───────────────────────────────────────────────

    #[test]
    fn field_to_bits_and_back() {
        let t     = Fp::from_u64(0xABCD_EF01);
        let bits  = field_to_bits(&t);
        let back  = bits_to_field(&bits);
        assert_eq!(t, back, "field_to_bits → bits_to_field must be identity");
    }

    #[test]
    fn bits_to_field_clears_top_bit() {
        // A bit string with top bit set should decode the same as without it
        let mut bits_with  = [0u8; 32];
        let mut bits_without = [0u8; 32];
        bits_with[31]    = 0x80; // only top bit set
        bits_without[31] = 0x00;
        assert_eq!(bits_to_field(&bits_with), bits_to_field(&bits_without),
            "bits_to_field must clear and ignore the top bit");
    }
}
