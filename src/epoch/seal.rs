//! Sealing epoch keys for specific members using Kummer-line DH.
//!
//! An "epoch-access keypair" is a long-term Kummer DH keypair each
//! member holds (distinct from their per-post Ed25519 signing key —
//! see identity::pseudonym). To grant a member access to an epoch, the
//! manager performs an ephemeral-static ECIES-style exchange with the
//! member's static public value, derives a symmetric key via HKDF, and
//! encrypts the epoch key under it.
//!
//! Reuses the Elligator-K1 / Kummer DH primitive validated in
//! elligator::dh, rather than introducing a second DH construction
//! (e.g. X25519) purely for this purpose — this keeps every member's
//! long-term public value traffic-indistinguishable too, consistent
//! with the rest of the system's design.

use hkdf::Hkdf;
use sha2::Sha256;
use crate::elligator::{KummerParams, KummerPoint, ElligatorString, DhScalar, dh_initiate, dh_complete};
use crate::epoch::key::EpochKey;
use crate::utils::aead::{self, KEY_LEN, NONCE_LEN};
use crate::error::{Result, KneeTieError};

/// Domain-separation string for HKDF, ensuring epoch-key-sealing keys
/// can never collide with keys derived from the same DH shared secret
/// for any other purpose.
const HKDF_INFO: &[u8] = b"knee-tie-epoch-key-seal-v1";

/// An epoch key, encrypted so that only the holder of the matching
/// static DH scalar can recover it. This is what actually gets stored
/// (by the future server) and transmitted to members.
pub struct SealedEpochKey {
    pub epoch_number: u64,
    /// One-time ephemeral DH public value used for this specific seal.
    pub ephemeral_pub: ElligatorString,
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

/// Seal an epoch key so that only `recipient_pub`'s holder can open it.
pub fn seal_epoch_key(
    epoch_key: &EpochKey,
    recipient_pub: &ElligatorString,
    params: &KummerParams,
    base: &KummerPoint,
) -> Result<SealedEpochKey> {
    let (ephemeral_pub, ephemeral_sk) = dh_initiate(params, base)?;
    let shared = dh_complete(&ephemeral_sk, recipient_pub, params)?;

    let sym_key = derive_sym_key(&shared)?;

    let nonce = aead::random_nonce();
    let ciphertext = aead::encrypt(&sym_key, &nonce, &epoch_key.key)?;

    Ok(SealedEpochKey {
        epoch_number: epoch_key.epoch_number,
        ephemeral_pub,
        nonce,
        ciphertext,
    })
}

/// Open a sealed epoch key using the recipient's static DH scalar.
pub fn open_sealed_epoch_key(
    sealed: &SealedEpochKey,
    my_scalar: &DhScalar,
    params: &KummerParams,
) -> Result<EpochKey> {
    let shared = dh_complete(my_scalar, &sealed.ephemeral_pub, params)?;
    let sym_key = derive_sym_key(&shared)?;

    let plaintext = aead::decrypt(&sym_key, &sealed.nonce, &sealed.ciphertext)?;

    if plaintext.len() != KEY_LEN {
        return Err(KneeTieError::CryptoError(
            "decrypted epoch key has unexpected length".into()
        ));
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&plaintext);

    Ok(EpochKey { epoch_number: sealed.epoch_number, key })
}

fn derive_sym_key(shared_secret: &[u8; 32]) -> Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(None, shared_secret);
    let mut sym_key = [0u8; KEY_LEN];
    hk.expand(HKDF_INFO, &mut sym_key)
        .map_err(|_| KneeTieError::CryptoError("HKDF expand failed".into()))?;
    Ok(sym_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::elligator::field::{base_point_x, base_point_z};

    fn params() -> KummerParams { KummerParams::p25519() }
    fn base() -> KummerPoint { KummerPoint::new(base_point_x(), base_point_z()) }

    #[test]
    fn seal_then_open_roundtrips() {
        let p = params();
        let b = base();
        let (recipient_pub, recipient_sk) = dh_initiate(&p, &b).unwrap();

        let epoch_key = EpochKey::generate(3);
        let sealed = seal_epoch_key(&epoch_key, &recipient_pub, &p, &b).unwrap();

        let opened = open_sealed_epoch_key(&sealed, &recipient_sk, &p).unwrap();
        assert_eq!(opened.epoch_number, 3);
        assert_eq!(opened.key, epoch_key.key);
    }

    #[test]
    fn wrong_recipient_cannot_open() {
        let p = params();
        let b = base();
        let (recipient_pub, _recipient_sk) = dh_initiate(&p, &b).unwrap();
        let (_eve_pub, eve_sk) = dh_initiate(&p, &b).unwrap();

        let epoch_key = EpochKey::generate(0);
        let sealed = seal_epoch_key(&epoch_key, &recipient_pub, &p, &b).unwrap();

        assert!(open_sealed_epoch_key(&sealed, &eve_sk, &p).is_err(),
            "a different member's scalar must not be able to open the seal");
    }

    #[test]
    fn each_seal_uses_a_fresh_ephemeral_key() {
        let p = params();
        let b = base();
        let (recipient_pub, _) = dh_initiate(&p, &b).unwrap();
        let epoch_key = EpochKey::generate(0);

        let sealed1 = seal_epoch_key(&epoch_key, &recipient_pub, &p, &b).unwrap();
        let sealed2 = seal_epoch_key(&epoch_key, &recipient_pub, &p, &b).unwrap();

        assert_ne!(sealed1.ephemeral_pub, sealed2.ephemeral_pub,
            "each seal operation must use a fresh ephemeral keypair");
    }

    #[test]
    fn epoch_number_is_preserved() {
        let p = params();
        let b = base();
        let (recipient_pub, recipient_sk) = dh_initiate(&p, &b).unwrap();
        let epoch_key = EpochKey::generate(42);
        let sealed = seal_epoch_key(&epoch_key, &recipient_pub, &p, &b).unwrap();
        assert_eq!(sealed.epoch_number, 42);
        let opened = open_sealed_epoch_key(&sealed, &recipient_sk, &p).unwrap();
        assert_eq!(opened.epoch_number, 42);
    }
}
