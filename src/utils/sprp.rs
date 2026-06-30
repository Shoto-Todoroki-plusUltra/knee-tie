use aes::{Aes128, cipher::{BlockEncrypt, KeyInit, generic_array::GenericArray}};
use super::hash::LAMBDA;

/// SPRP g1 and g2: {0,1}^256 × {0,1}^256 → {0,1}^256
///
/// Used in DGMT (Paper 1) for two distinct purposes:
///   g1: compute fallback keys    Fk_{i,j} ← g1(r_{i,j}, Fn_i)
///   g2: compute position tags    DGMT.pos  ← g2(msk, i∥j∥k∥l)
///
/// Both must be invertible:
///   g1^{-1}: recover Fn_i during verification   (Algorithm 8, line 13)
///   g2^{-1}: recover i∥j∥k∥l during opening     (Algorithm 10, line 2)
///
/// CONSTRUCTION: 2-round Feistel network with AES-128 round functions.
///
///   Keys:    k1 = key[0..16],  k2 = key[16..32]
///   Split:   x_L = x[0..16],   x_R = x[16..32]
///   Round 1: y_L = x_R ⊕ AES-128(k1, x_L)
///   Round 2: y_R = x_L ⊕ AES-128(k2, y_L)
///   Output:  [y_L || y_R]
///
/// INVERSION:
///   Given y = [y_L || y_R]:
///   x_L = y_R ⊕ AES-128(k2, y_L)
///   x_R = y_L ⊕ AES-128(k1, x_L)
///
/// NOTE: A 2-round Feistel is not a strong PRP for production use.
/// Minimum 4 rounds recommended for cryptographic strength.
/// This is sufficient for a proof-of-concept implementation.

fn aes128_encrypt(key_bytes: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    let key    = GenericArray::from_slice(key_bytes);
    let cipher = Aes128::new(key);
    let mut b  = GenericArray::clone_from_slice(block);
    cipher.encrypt_block(&mut b);
    b.into()
}

fn xor_blocks(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut result = [0u8; 16];
    for i in 0..16 {
        result[i] = a[i] ^ b[i];
    }
    result
}

/// SPRP forward: g(key, x) → y
///
/// key: 32 bytes (r_{i,j} for g1, or msk for g2)
/// x:   32 bytes (the input to permute)
pub fn sprp_eval(key: &[u8; LAMBDA], x: &[u8; LAMBDA]) -> [u8; LAMBDA] {
    // Split key and input into 128-bit halves
    let k1: [u8; 16] = key[..16].try_into().unwrap();
    let k2: [u8; 16] = key[16..].try_into().unwrap();
    let x_l: [u8; 16] = x[..16].try_into().unwrap();
    let x_r: [u8; 16] = x[16..].try_into().unwrap();

    // Round 1: y_L = x_R ⊕ AES-128(k1, x_L)
    let y_l = xor_blocks(&x_r, &aes128_encrypt(&k1, &x_l));

    // Round 2: y_R = x_L ⊕ AES-128(k2, y_L)
    let y_r = xor_blocks(&x_l, &aes128_encrypt(&k2, &y_l));

    let mut output = [0u8; LAMBDA];
    output[..16].copy_from_slice(&y_l);
    output[16..].copy_from_slice(&y_r);
    output
}

/// SPRP inverse: g^{-1}(key, y) → x
pub fn sprp_inv(key: &[u8; LAMBDA], y: &[u8; LAMBDA]) -> [u8; LAMBDA] {
    let k1: [u8; 16] = key[..16].try_into().unwrap();
    let k2: [u8; 16] = key[16..].try_into().unwrap();
    let y_l: [u8; 16] = y[..16].try_into().unwrap();
    let y_r: [u8; 16] = y[16..].try_into().unwrap();

    // Invert round 2: x_L = y_R ⊕ AES-128(k2, y_L)
    let x_l = xor_blocks(&y_r, &aes128_encrypt(&k2, &y_l));

    // Invert round 1: x_R = y_L ⊕ AES-128(k1, x_L)
    let x_r = xor_blocks(&y_l, &aes128_encrypt(&k1, &x_l));

    let mut output = [0u8; LAMBDA];
    output[..16].copy_from_slice(&x_l);
    output[16..].copy_from_slice(&x_r);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sprp_forward_inverse_roundtrip() {
        let key = [0xABu8; LAMBDA];
        let x   = [0x42u8; LAMBDA];
        let y   = sprp_eval(&key, &x);
        assert_eq!(sprp_inv(&key, &y), x,
            "g^{{-1}}(g(x)) must equal x");
    }

    #[test]
    fn sprp_inverse_forward_roundtrip() {
        let key = [0xCCu8; LAMBDA];
        let y   = [0xDDu8; LAMBDA];
        let x   = sprp_inv(&key, &y);
        assert_eq!(sprp_eval(&key, &x), y,
            "g(g^{{-1}}(y)) must equal y");
    }

    #[test]
    fn sprp_is_not_identity() {
        let key = [1u8; LAMBDA];
        let x   = [2u8; LAMBDA];
        assert_ne!(sprp_eval(&key, &x), x,
            "SPRP must not return the input unchanged");
    }

    #[test]
    fn different_keys_give_different_outputs() {
        let x = [3u8; LAMBDA];
        assert_ne!(
            sprp_eval(&[1u8; LAMBDA], &x),
            sprp_eval(&[2u8; LAMBDA], &x)
        );
    }

    #[test]
    fn sprp_is_deterministic() {
        let key = [7u8; LAMBDA];
        let x   = [9u8; LAMBDA];
        assert_eq!(sprp_eval(&key, &x), sprp_eval(&key, &x));
    }
}
