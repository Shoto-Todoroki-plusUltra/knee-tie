//! Integration tests for knee-tie-crypto.
//!
//! These tests exercise the full pipeline:
//!   Paper 1 (DGMT): key generation → join → sign → verify → revoke → open
//!   Paper 2 (Elligator-K1): DH key exchange with indistinguishable public values
//!   Combined: DGMT group signature transported over an Elligator-K1 DH channel

use knee_tie_crypto::{
    // DGMT
    DgmtParams,
    dgmt_keygen,
    // Elligator / Kummer DH
    KummerPoint, KummerParams,
    dh_initiate, dh_complete,
};
use knee_tie_crypto::dgmt::join::{dgmt_join, dgmt_key_dist, MemberStatus};
use knee_tie_crypto::dgmt::sign::dgmt_sign;
use knee_tie_crypto::dgmt::verify::dgmt_verify;
use knee_tie_crypto::dgmt::revoke::dgmt_revoke;
use knee_tie_crypto::dgmt::open::dgmt_open;
use knee_tie_crypto::elligator::field::{base_point_x, base_point_z};

// ─── DGMT End-to-End ─────────────────────────────────────────────────────────

/// Full lifecycle: setup → join → sign → verify → revoke → open.
#[test]
fn dgmt_full_lifecycle() {
    // ── Setup ────────────────────────────────────────────────────────────
    let params  = DgmtParams::for_testing();
    let (sk, pp) = dgmt_keygen(&params);
    let num_fn  = params.num_fallback_nodes();

    // ── Join two members ──────────────────────────────────────────────────
    let (mut record1, cred1) = dgmt_join(1, params.n_max, num_fn).unwrap();
    let (mut record2, cred2) = dgmt_join(2, params.n_max, num_fn).unwrap();

    assert_eq!(cred1.id, 1);
    assert_eq!(cred2.id, 2);
    assert_ne!(cred1.c_id, cred2.c_id, "members must receive distinct credentials");

    // ── Request signing keys ──────────────────────────────────────────────
    let mut keys1 = dgmt_key_dist(&sk, &pp, &params, &mut record1, 2).unwrap();
    let mut keys2 = dgmt_key_dist(&sk, &pp, &params, &mut record2, 2).unwrap();

    assert_eq!(keys1.len(), 2);
    assert_eq!(keys2.len(), 2);

    // ── Sign messages ─────────────────────────────────────────────────────
    let msg1 = b"Member 1 reporting anonymously";
    let msg2 = b"Member 2 reporting anonymously";

    let sig1a = dgmt_sign(msg1, &keys1.remove(0), &params).unwrap();
    let sig1b = dgmt_sign(msg1, &keys1.remove(0), &params).unwrap();
    let sig2  = dgmt_sign(msg2, &keys2.remove(0), &params).unwrap();

    // ── Verify signatures ─────────────────────────────────────────────────
    assert!(dgmt_verify(msg1, &sig1a, &pp, &params).is_ok(),
        "sig1a must verify");
    assert!(dgmt_verify(msg1, &sig1b, &pp, &params).is_ok(),
        "sig1b must verify");
    assert!(dgmt_verify(msg2, &sig2,  &pp, &params).is_ok(),
        "sig2 must verify");

    // Wrong message must fail
    assert!(dgmt_verify(b"tampered", &sig1a, &pp, &params).is_err(),
        "wrong message must fail verification");

    // ── Open signatures (identify signer) ─────────────────────────────────
    let open1a = dgmt_open(&sig1a, &sk, &params).unwrap();
    let open2  = dgmt_open(&sig2,  &sk, &params).unwrap();

    assert_eq!(open1a.id, 1, "sig1a must open to member 1");
    assert_eq!(open2.id,  2, "sig2 must open to member 2");

    // ── Revoke member 1 ───────────────────────────────────────────────────
    let mut records  = vec![record1, record2.clone()];
    let mut pp_mut   = pp.clone();
    dgmt_revoke(&sk, &mut pp_mut, &params, &mut records, &[1]).unwrap();

    // Member 1's record is now Revoked
    assert_eq!(records[0].status, MemberStatus::Revoked);
    // Member 2's record is still Active
    assert_eq!(records[1].status, MemberStatus::Active);

    // ── Post-revocation verification ──────────────────────────────────────
    // sig1a was signed before revocation but its position is now in RL
    assert!(dgmt_verify(msg1, &sig1a, &pp_mut, &params).is_err(),
        "revoked member's signature must fail verification");
    assert!(dgmt_verify(msg1, &sig1b, &pp_mut, &params).is_err(),
        "all of member 1's signatures must fail after revocation");

    // Member 2's signature must still verify
    assert!(dgmt_verify(msg2, &sig2, &pp_mut, &params).is_ok(),
        "non-revoked member 2 signature must still verify");

    // ── Revoked member cannot receive new keys ────────────────────────────
    let (revoked_record, _) = records.into_iter()
        .partition::<Vec<_>, _>(|r| r.id == 1);
    let mut r1 = revoked_record.into_iter().next().unwrap();
    assert!(dgmt_key_dist(&sk, &pp_mut, &params, &mut r1, 1).is_err(),
        "revoked member must not receive new signing keys");
}

/// Group full-capacity test: all Nmax members sign and are independently verifiable.
#[test]
fn dgmt_all_members_can_sign() {
    let params  = DgmtParams::for_testing(); // Nmax = 2
    let (sk, pp) = dgmt_keygen(&params);
    let num_fn  = params.num_fallback_nodes();

    let mut all_sigs = Vec::new();

    for id in 1..=params.n_max {
        let (mut record, _) = dgmt_join(id, params.n_max, num_fn).unwrap();
        let mut keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 1).unwrap();
        let msg      = format!("message from member {}", id);
        let sig      = dgmt_sign(msg.as_bytes(), &keys.remove(0), &params).unwrap();
        all_sigs.push((id, msg, sig));
    }

    for (id, msg, sig) in &all_sigs {
        assert!(dgmt_verify(msg.as_bytes(), sig, &pp, &params).is_ok(),
            "member {} signature must verify", id);

        let opened = dgmt_open(sig, &sk, &params).unwrap();
        assert_eq!(opened.id, *id,
            "opened signature must identify member {}", id);
    }
}

/// Cross-community isolation: signatures from one community fail in another.
#[test]
fn dgmt_signatures_are_community_specific() {
    let params = DgmtParams::for_testing();
    let (sk1, pp1) = dgmt_keygen(&params);
    let (_sk2, pp2) = dgmt_keygen(&params);

    let num_fn = params.num_fallback_nodes();
    let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
    let mut keys = dgmt_key_dist(&sk1, &pp1, &params, &mut record, 1).unwrap();
    let sig = dgmt_sign(b"test", &keys.remove(0), &params).unwrap();

    assert!(dgmt_verify(b"test", &sig, &pp1, &params).is_ok(),
        "must verify in community 1");
    assert!(dgmt_verify(b"test", &sig, &pp2, &params).is_err(),
        "must NOT verify in community 2");
}

/// Unforgeability property: constructing a fake signature fails verification.
#[test]
fn dgmt_forged_signature_fails() {
    let params  = DgmtParams::for_testing();
    let (sk, pp) = dgmt_keygen(&params);
    let num_fn  = params.num_fallback_nodes();

    let (mut record, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
    let mut keys = dgmt_key_dist(&sk, &pp, &params, &mut record, 1).unwrap();

    let real_sig = dgmt_sign(b"real", &keys.remove(0), &params).unwrap();

    // Tamper: flip all bytes of the message signature part
    let mut forged = real_sig.clone();
    for byte in forged.sig_message.0[0].iter_mut() {
        *byte ^= 0xFF;
    }

    assert!(dgmt_verify(b"real", &forged, &pp, &params).is_err(),
        "tampered signature must fail verification");
}

// ─── Elligator-K1 / Kummer DH End-to-End ───────────────────────────────────

/// DH key exchange produces matching shared secrets.
#[test]
fn elligator_dh_shared_secret_agreement() {
    let params = KummerParams::p25519();
    let base   = KummerPoint::new(base_point_x(), base_point_z());

    let (alice_pub, alice_sk) = dh_initiate(&params, &base).unwrap();
    let (bob_pub,   bob_sk)   = dh_initiate(&params, &base).unwrap();

    let alice_secret = dh_complete(&alice_sk, &bob_pub,   &params).unwrap();
    let bob_secret   = dh_complete(&bob_sk,   &alice_pub, &params).unwrap();

    assert_eq!(alice_secret, bob_secret,
        "Alice and Bob must derive the same shared secret");
    assert_ne!(alice_secret, [0u8; 32],
        "Shared secret must not be all zeros");
}

/// Multiple independent exchanges produce distinct secrets.
#[test]
fn elligator_dh_each_exchange_is_unique() {
    let params = KummerParams::p25519();
    let base   = KummerPoint::new(base_point_x(), base_point_z());

    let mut secrets = Vec::new();
    for _ in 0..3 {
        let (_pub1, sk1) = dh_initiate(&params, &base).unwrap();
        let (pub2, _sk2) = dh_initiate(&params, &base).unwrap();
        let secret       = dh_complete(&sk1, &pub2, &params).unwrap();
        secrets.push(secret);
    }

    // All three secrets should be distinct (with overwhelming probability)
    assert_ne!(secrets[0], secrets[1]);
    assert_ne!(secrets[1], secrets[2]);
    assert_ne!(secrets[0], secrets[2]);
}

/// Public values are 32 bytes with top bit clear (canonical representative).
#[test]
fn elligator_public_values_are_uniform_looking() {
    let params = KummerParams::p25519();
    let base   = KummerPoint::new(base_point_x(), base_point_z());

    for _ in 0..5 {
        let (pub_val, _) = dh_initiate(&params, &base).unwrap();
        // Top bit must be 0 (canonical representative in [0,(p-1)/2])
        assert_eq!(pub_val[31] & 0x80, 0,
            "Top bit of public value must be 0");
        // Must be exactly 32 bytes
        assert_eq!(pub_val.len(), 32);
    }
}

// ─── Combined: DGMT + Elligator Transport ───────────────────────────────────

/// Simulate the complete Knee Tie join flow:
///   1. Client and server establish an Elligator-K1 DH channel.
///   2. Server issues DGMT credentials to client over that channel.
///   3. Client produces a DGMT group signature.
///   4. Verifier checks the signature using only public params.
///
/// This is a logical simulation — actual encryption of channel data
/// is not implemented here (that belongs in the protocol layer).
/// What we verify: both cryptographic subsystems work correctly together.
#[test]
fn knee_tie_join_and_sign_simulation() {
    // ── 1. Establish Elligator-K1 DH channel ─────────────────────────────
    let kummer_params = KummerParams::p25519();
    let base          = KummerPoint::new(base_point_x(), base_point_z());

    // Client generates ephemeral DH key pair
    let (client_pub, client_sk) = dh_initiate(&kummer_params, &base).unwrap();
    // Server generates ephemeral DH key pair
    let (server_pub, server_sk) = dh_initiate(&kummer_params, &base).unwrap();

    // Both derive the same channel key
    let client_channel_key = dh_complete(&client_sk, &server_pub, &kummer_params).unwrap();
    let server_channel_key = dh_complete(&server_sk, &client_pub, &kummer_params).unwrap();
    assert_eq!(client_channel_key, server_channel_key,
        "Channel key must match on both sides");

    // ── 2. Server (manager) sets up DGMT community ───────────────────────
    let dgmt_params = DgmtParams::for_testing();
    let (sk, pp)    = dgmt_keygen(&dgmt_params);
    let num_fn      = dgmt_params.num_fallback_nodes();

    // Server issues DGMT credentials to client (transmitted over the DH channel,
    // which we simulate here as a direct function call)
    let (mut record, credential) = dgmt_join(1, dgmt_params.n_max, num_fn).unwrap();
    // In the real protocol, credential would be encrypted with client_channel_key
    // before sending. Here we just verify the credential is valid.
    assert_eq!(credential.id, 1);

    // Client requests OTS keys (also over the authenticated channel)
    let mut signing_keys = dgmt_key_dist(&sk, &pp, &dgmt_params, &mut record, 1).unwrap();

    // ── 3. Client signs a message anonymously ────────────────────────────
    let message = b"Anonymous report: important finding #42";
    let key     = signing_keys.remove(0);
    let sig     = dgmt_sign(message, &key, &dgmt_params).unwrap();

    // ── 4. Verifier checks the signature using only public params ─────────
    // The verifier does NOT have sk, does NOT know who signed,
    // and does NOT need the manager to be online.
    assert!(dgmt_verify(message, &sig, &pp, &dgmt_params).is_ok(),
        "Group signature must verify using only public parameters");

    // The verifier can also confirm the signature is NOT revoked
    assert!(!pp.is_revoked(&sig.dgmt_pos),
        "Signature must not be on the revocation list");

    // If the verifier tampers with the message, verification must fail
    assert!(dgmt_verify(b"tampered message", &sig, &pp, &dgmt_params).is_err(),
        "Tampered message must fail verification");
}

/// Demonstrates the manager can open a signature to identify the signer,
/// while the verifier cannot (without manager cooperation).
#[test]
fn accountability_without_anonymity_loss() {
    let params  = DgmtParams::for_testing();
    let (sk, pp) = dgmt_keygen(&params);
    let num_fn  = params.num_fallback_nodes();

    // Two members sign messages
    let (mut r1, _) = dgmt_join(1, params.n_max, num_fn).unwrap();
    let (mut r2, _) = dgmt_join(2, params.n_max, num_fn).unwrap();

    let mut keys1 = dgmt_key_dist(&sk, &pp, &params, &mut r1, 1).unwrap();
    let mut keys2 = dgmt_key_dist(&sk, &pp, &params, &mut r2, 1).unwrap();

    let sig1 = dgmt_sign(b"from member 1", &keys1.remove(0), &params).unwrap();
    let sig2 = dgmt_sign(b"from member 2", &keys2.remove(0), &params).unwrap();

    // Both signatures verify — verifier cannot tell which member signed
    assert!(dgmt_verify(b"from member 1", &sig1, &pp, &params).is_ok());
    assert!(dgmt_verify(b"from member 2", &sig2, &pp, &params).is_ok());

    // The signatures look anonymous — their DGMT.pos values are different
    assert_ne!(sig1.dgmt_pos, sig2.dgmt_pos,
        "Different members' position tags must differ");

    // Manager can open both signatures to identify the signers
    let open1 = dgmt_open(&sig1, &sk, &params).unwrap();
    let open2 = dgmt_open(&sig2, &sk, &params).unwrap();

    // Each signature opens to the correct member
    assert_eq!(open1.id, 1, "sig1 must be attributable to member 1");
    assert_eq!(open2.id, 2, "sig2 must be attributable to member 2");

    // Opening one signature does not affect the other's anonymity
    // (we cannot learn anything about who signed sig2 from opening sig1)
    assert_ne!(open1.id, open2.id, "Different members must have different ids");
}
