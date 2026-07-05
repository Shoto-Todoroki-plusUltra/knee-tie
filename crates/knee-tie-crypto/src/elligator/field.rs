//! Prime field arithmetic for F_{p25519} where p = 2^255 - 19.
//!
//! p25519 ≡ 1 (mod 4) and ≡ 5 (mod 8), which enables:
//!   - Elligator-K1 (requires q ≡ 1 mod 4, Paper 2 §3.2)
//!   - Efficient square root via the p ≡ 5 mod 8 formula
//!   - u = 2 as a non-square (χ(2) = -1 for p ≡ 5 mod 8)
//!
//! This module uses `num-bigint` for arbitrary-precision arithmetic.
//! For production use, replace with a constant-time 256-bit field
//! implementation (e.g. `fiat-crypto` or hand-rolled 4×u64 limbs).

use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::fmt;

// ─── Prime ───────────────────────────────────────────────────────────────────

/// Return p = 2^255 - 19 as a BigUint.
/// Called on every operation; fast enough for a PoC.
#[inline]
pub fn prime() -> BigUint {
    (BigUint::one() << 255u32) - 19u32
}

// ─── Field Element ───────────────────────────────────────────────────────────

/// An element of F_{p25519}.
///
/// Invariant: `0 ≤ val < p`.
#[derive(Clone, PartialEq, Eq)]
pub struct Fp {
    val: BigUint,
}

impl fmt::Debug for Fp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fp(0x{})", self.val.to_str_radix(16))
    }
}

impl Fp {
    // ── Constructors ─────────────────────────────────────────────────────

    /// Construct from an arbitrary BigUint, reducing mod p.
    pub fn new(val: BigUint) -> Self {
        Fp { val: val % prime() }
    }

    pub fn zero() -> Self { Fp { val: BigUint::zero() } }
    pub fn one()  -> Self { Fp { val: BigUint::one()  } }

    pub fn from_u64(n: u64) -> Self { Fp::new(BigUint::from(n)) }

    /// Decode a field element from 32 little-endian bytes.
    /// Reduces mod p if the value is out of range.
    pub fn from_bytes_le(bytes: &[u8; 32]) -> Self {
        Fp::new(BigUint::from_bytes_le(bytes))
    }

    /// Encode as 32 little-endian bytes (canonical representative).
    pub fn to_bytes_le(&self) -> [u8; 32] {
        let mut b = self.val.to_bytes_le();
        b.resize(32, 0);
        b.try_into().expect("exactly 32 bytes")
    }

    /// Parse from hex string (big-endian, as written in papers/specs).
    pub fn from_hex(s: &str) -> Self {
        let s = s.trim_start_matches("0x");
        let val = BigUint::parse_bytes(s.as_bytes(), 16)
            .expect("invalid hex string");
        Fp::new(val)
    }

    // ── Predicates ───────────────────────────────────────────────────────

    pub fn is_zero(&self) -> bool { self.val.is_zero() }

    // ── Arithmetic ───────────────────────────────────────────────────────

    pub fn neg(&self) -> Self {
        if self.val.is_zero() { return self.clone(); }
        Fp::new(prime() - &self.val)
    }

    pub fn add(&self, rhs: &Fp) -> Fp {
        Fp::new(&self.val + &rhs.val)
    }

    pub fn sub(&self, rhs: &Fp) -> Fp {
        let p = prime();
        Fp::new(
            if self.val >= rhs.val {
                &self.val - &rhs.val
            } else {
                &p + &self.val - &rhs.val
            }
        )
    }

    pub fn mul(&self, rhs: &Fp) -> Fp {
        Fp::new(&self.val * &rhs.val)
    }

    /// Multiply by a small integer constant (avoids constructing an Fp).
    pub fn mul_small(&self, n: u64) -> Fp {
        Fp::new(&self.val * n)
    }

    pub fn sqr(&self) -> Fp { self.mul(self) }

    pub fn pow(&self, exp: &BigUint) -> Fp {
        Fp::new(self.val.modpow(exp, &prime()))
    }

    /// Multiplicative inverse via Fermat: a^{p-2} mod p.
    /// Panics on zero input.
    pub fn inv(&self) -> Fp {
        assert!(!self.is_zero(), "cannot invert the field zero element");
        let p = prime();
        let exp = &p - 2u32;
        Fp::new(self.val.modpow(&exp, &p))
    }

    // ── Quadratic character and square root ──────────────────────────────

    /// χ(a) = a^{(p-1)/2} mod p.
    ///   Returns  0 if a = 0
    ///   Returns  1 if a is a non-zero square
    ///   Returns -1 if a is a non-square
    ///
    /// For p ≡ 1 (mod 4) as is the case for p25519.
    pub fn chi(&self) -> i8 {
        if self.val.is_zero() { return 0; }
        let p = prime();
        let exp = (&p - 1u32) / 2u32;
        let r = self.val.modpow(&exp, &p);
        if r.is_one() { 1 } else { -1 }
    }

    /// Square root for p ≡ 5 (mod 8), using the standard square-root
    /// algorithm for this case (as used in Ed25519 / RFC 8032, adapted
    /// to a single-argument sqrt rather than the curve's u/v-decompression
    /// form).
    ///
    /// Returns `Some(r)` where r² = self, choosing the canonical root
    /// (the one whose least significant bit is 0), or `None` if self is
    /// not a quadratic residue.
    ///
    /// Formula:
    ///   v = (2a)^{(p-5)/8} mod p
    ///   i = 2a·v² mod p
    ///   r = a·v·(i-1) mod p
    ///
    /// DERIVATION: for p ≡ 5 (mod 8), 2 is always a quadratic non-residue
    /// (verified by `u_eq_2_is_nonsquare` test). If `a` is a residue, then
    /// 2a is a non-residue, so by Euler's criterion (2a)^((p-1)/2) ≡ -1.
    /// Since i = 2a·v² = (2a)^(1+(p-5)/4) = (2a)^((p-1)/4), squaring gives
    /// i² = (2a)^((p-1)/2) ≡ -1 — i.e. i is *itself* a square root of -1,
    /// with no separate sqrt(-1) computation needed. Then:
    ///   r² = a²v²(i-1)² = a²v²(i²-2i+1) = a²v²(-2i) = -2i·a·(av²)
    ///      = -2i·a·(i/2) = -i²·a = a.                              ✓
    /// (Hand-verified numerically against p=13: a=4 → v=8, i=5,
    /// 5²=25≡-1 (mod 13) ✓, r=11, 11²=121≡4 (mod 13) ✓.)
    pub fn sqrt(&self) -> Option<Fp> {
        if self.val.is_zero() { return Some(Self::zero()); }
        if self.chi() != 1    { return None; }

        let p = prime();
        let a = &self.val;

        // v = (2a)^{(p-5)/8} mod p
        let two_a = (BigUint::from(2u32) * a) % &p;
        let exp   = (&p - 5u32) / 8u32;
        let v     = two_a.modpow(&exp, &p);

        // i = 2a·v² mod p — automatically a square root of -1 here,
        // because 2a is always a non-residue whenever a is a residue.
        let v_sq = (&v * &v) % &p;
        let i    = (&two_a * &v_sq) % &p;

        // r = a·v·(i-1) mod p
        let i_minus_1 = (&i + &p - 1u32) % &p; // modular i-1, no underflow
        let av        = (a * &v) % &p;
        let root_val  = (&av * &i_minus_1) % &p;

        // Canonicalise: choose the root whose value has LSB = 0
        let root_val = if root_val.bit(0) {
            (&p - &root_val) % &p
        } else {
            root_val
        };

        Some(Fp { val: root_val })
    }

    /// A fixed non-square in F_{p25519}.
    ///
    /// For p ≡ 5 (mod 8): the Legendre symbol (2/p) = (-1)^{(p²-1)/8}.
    /// With p = 2^255-19 ≡ 5 (mod 8): (p²-1)/8 is odd, so χ(2) = -1.
    /// Therefore u = 2 is a non-square.
    ///
    /// Required by Elligator-K1 (Paper 2, §3.2).
    pub fn nonsquare_u() -> Fp { Fp::from_u64(2) }
}

// ─── Constants ────────────────────────────────────────────────────────────────

/// λ₃ from Paper 2, Table 7 — Legendre curve parameter for p25519/Elligator-K1.
///
/// This value satisfies χ(λ₃) = 1 (λ₃ is a quadratic residue in F_{p25519}),
/// which is required for the Elligator-K1 map to be well-defined.
pub fn lambda_p25519() -> Fp {
    Fp::from_hex("12cadb5b93d7bd5d89e6d2067837a2509694e414dfc0e1c840d4cc46eae96c8a")
}

/// Kummer line parameter a² = 289 (from Paper 2, Table 7).
pub fn kummer_a2() -> Fp { Fp::from_u64(289) }

/// Kummer line parameter b² = 515 (from Paper 2, Table 7).
pub fn kummer_b2() -> Fp { Fp::from_u64(515) }

/// Base point X-coordinate on Ka²,b² for p25519 (Paper 2, Table 7).
pub fn base_point_x() -> Fp { Fp::from_u64(2) }

/// Base point Z-coordinate on Ka²,b² (affine, so Z=1).
pub fn base_point_z() -> Fp { Fp::one() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p25519_is_correct_size() {
        let p = prime();
        // p should have 255 bits, i.e. 2^254 ≤ p < 2^255
        assert!(p.bits() == 255, "p25519 should be 255 bits, got {}", p.bits());
    }

    #[test]
    fn p25519_mod_4_is_1() {
        let p   = prime();
        let rem = &p % 4u32;
        assert_eq!(rem, BigUint::one(), "p25519 must be ≡ 1 (mod 4) for Elligator-K1");
    }

    #[test]
    fn p25519_mod_8_is_5() {
        let p   = prime();
        let rem = &p % 8u32;
        assert_eq!(rem, BigUint::from(5u32), "p25519 must be ≡ 5 (mod 8) for sqrt formula");
    }

    #[test]
    fn zero_and_one() {
        let z = Fp::zero();
        let o = Fp::one();
        assert!(z.is_zero());
        assert!(!o.is_zero());
        assert_eq!(z.add(&o), o);
    }

    #[test]
    fn add_sub_roundtrip() {
        let a = Fp::from_u64(1234567890);
        let b = Fp::from_u64(9876543210);
        let c = a.add(&b);
        assert_eq!(c.sub(&b), a);
        assert_eq!(c.sub(&a), b);
    }

    #[test]
    fn mul_by_zero_is_zero() {
        let a = Fp::from_u64(999);
        assert_eq!(a.mul(&Fp::zero()), Fp::zero());
    }

    #[test]
    fn mul_by_one_is_identity() {
        let a = Fp::from_u64(42);
        assert_eq!(a.mul(&Fp::one()), a);
    }

    #[test]
    fn negation_adds_to_zero() {
        let a = Fp::from_u64(123);
        assert_eq!(a.add(&a.neg()), Fp::zero());
    }

    #[test]
    fn inversion_roundtrip() {
        let a   = Fp::from_u64(7);
        let inv = a.inv();
        assert_eq!(a.mul(&inv), Fp::one(), "a × a⁻¹ must equal 1");
    }

    #[test]
    fn chi_of_one_is_positive() {
        assert_eq!(Fp::one().chi(), 1, "1 is always a quadratic residue");
    }

    #[test]
    fn chi_of_zero_is_zero() {
        assert_eq!(Fp::zero().chi(), 0);
    }

    #[test]
    fn u_eq_2_is_nonsquare() {
        assert_eq!(Fp::nonsquare_u().chi(), -1,
            "u=2 must be a non-square for p25519 ≡ 5 (mod 8)");
    }

    #[test]
    fn sqrt_of_square_roundtrips() {
        // 4 = 2² is a square
        let four  = Fp::from_u64(4);
        let root  = four.sqrt().expect("4 must have a square root");
        assert_eq!(root.sqr(), four, "root² must equal 4");
    }

    #[test]
    fn sqrt_of_nonsquare_is_none() {
        // u=2 is a non-square for p25519
        assert!(Fp::nonsquare_u().sqrt().is_none(),
            "non-square element must have no sqrt");
    }

    #[test]
    fn bytes_roundtrip() {
        let a     = Fp::from_u64(0xDEADBEEF_CAFEBABE);
        let bytes = a.to_bytes_le();
        let back  = Fp::from_bytes_le(&bytes);
        assert_eq!(a, back);
    }

    #[test]
    fn lambda_p25519_is_square() {
        assert_eq!(lambda_p25519().chi(), 1,
            "λ₃ must be a quadratic residue for Elligator-K1 to work");
    }

    #[test]
    fn kummer_params_are_nonzero() {
        assert!(!kummer_a2().is_zero());
        assert!(!kummer_b2().is_zero());
    }

    #[test]
    fn from_hex_parses_correctly() {
        // 0x01 in little-endian is just 1
        let one = Fp::from_hex("01");
        assert_eq!(one, Fp::one());
    }

    #[test]
    fn sub_wraps_correctly() {
        // 0 - 1 should equal p - 1 (field wrap)
        let result = Fp::zero().sub(&Fp::one());
        let expected = Fp::new(prime() - 1u32);
        assert_eq!(result, expected);
    }
}
