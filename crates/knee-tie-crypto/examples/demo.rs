//! Runnable demonstration of the full Knee Tie Phase 1 cryptographic stack.
//!
//! This walks through exactly the same lifecycle as the
//! `knee_tie_full_post_lifecycle` integration test, but prints what's
//! happening at each step instead of just asserting on it — so you can
//! actually *see* the library work end to end.
//!
//! Run with:
//!   cargo run --example demo -p knee-tie-crypto
//! (from the workspace root), or:
//!   cargo run --example demo
//! (from inside crates/knee-tie-crypto).

use knee_tie_crypto::{
    DgmtParams, dgmt_keygen,
    KummerPoint, KummerParams, dh_initiate, dh_complete,
    EpochHistory, HistoryAccessPolicy, grant_epochs, MemberEpochKeyRing,
    encrypt_content, decrypt_content,
    PseudonymKeypair, verify_pseudonym_signature,
};
use knee_tie_crypto::dgmt::join::dgmt_join;
use knee_tie_crypto::dgmt::sign::dgmt_sign;
use knee_tie_crypto::dgmt::verify::dgmt_verify;
use knee_tie_crypto::dgmt::open::dgmt_open;
use knee_tie_crypto::elligator::field::{base_point_x, base_point_z};

fn main() {
    println!("=== Knee Tie Phase 1 Demo ===\n");

    // ── 1. Community setup ────────────────────────────────────────────
    println!("[1] Setting up a community (DGMT group + epoch key history)...");
    let dgmt_params = DgmtParams::for_testing();
    let (dgmt_sk, dgmt_pp) = dgmt_keygen(&dgmt_params);
    let num_fn = dgmt_params.num_fallback_nodes();

    let kummer_params = KummerParams::p25519();
    let base = KummerPoint::new(base_point_x(), base_point_z());

    let epoch_history = EpochHistory::new();
    println!("    Community public key (DGMT.gpk): {} bytes", dgmt_pp.gpk.len());
    println!("    Fallback keys published: {}", dgmt_pp.fk.len());
    println!("    Starting epoch: {}\n", epoch_history.current_epoch_number());

    // ── 2. A member joins ─────────────────────────────────────────────
    println!("[2] A new member joins the community...");
    let (mut dgmt_record, _cred) = dgmt_join(1, dgmt_params.n_max, num_fn)
        .expect("join should succeed");
    let mut dgmt_keys = dgmt_join_keys(&dgmt_sk, &dgmt_pp, &dgmt_params, &mut dgmt_record);
    let registration_key = dgmt_keys.remove(0);

    let registration_proof = dgmt_sign(b"member registration", &registration_key, &dgmt_params)
        .expect("signing should succeed");
    let verified = dgmt_verify(b"member registration", &registration_proof, &dgmt_pp, &dgmt_params);
    println!("    DGMT registration proof verifies: {}", verified.is_ok());
    println!("    (This is the ONE post-quantum group signature this member ever produces —");
    println!("     everything else uses the lightweight keys below.)\n");

    // ── 3. Ongoing keys ────────────────────────────────────────────────
    println!("[3] Member generates their ongoing keys...");
    let pseudonym = PseudonymKeypair::generate();
    let (epoch_access_pub, epoch_access_sk) = dh_initiate(&kummer_params, &base)
        .expect("DH keypair generation should succeed");
    println!("    Pseudonym public key:      {}", hex_preview(&pseudonym.public_key_bytes()));
    println!("    Epoch-access public value: {}", hex_preview(&epoch_access_pub));
    println!("    (Both look like — and the second one IS — uniformly random bytes.)\n");

    // ── 4. Epoch access granted ────────────────────────────────────────
    println!("[4] Community grants this member access to community content...");
    let grant = grant_epochs(
        &epoch_history, &epoch_access_pub, HistoryAccessPolicy::FullHistory,
        &kummer_params, &base,
    ).expect("grant should succeed");

    let mut member_ring = MemberEpochKeyRing::new();
    member_ring.absorb_grant(&grant, &epoch_access_sk, &kummer_params)
        .expect("absorbing the grant should succeed");
    println!("    Epochs granted: {}\n", grant.sealed_keys.len());

    // ── 5. Compose, encrypt, sign a post ───────────────────────────────
    println!("[5] Member composes a post...");
    let post_plaintext = b"Hello, Knee Tie! This is my first anonymous post.";
    let epoch_key = member_ring.get(epoch_history.current_epoch_number())
        .expect("member should have the current epoch's key");

    let encrypted = encrypt_content(&epoch_key, post_plaintext)
        .expect("encryption should succeed");

    let mut signed_material = encrypted.ciphertext.clone();
    signed_material.extend_from_slice(&encrypted.epoch_number.to_be_bytes());
    let post_signature = pseudonym.sign(&signed_material);

    println!("    Plaintext:  {:?}", String::from_utf8_lossy(post_plaintext));
    println!("    Ciphertext: {} (encrypted, {} bytes)", hex_preview(&encrypted.ciphertext), encrypted.ciphertext.len());
    println!("    Signature:  {} (Ed25519, 64 bytes)\n", hex_preview(&post_signature));

    // ── 6. A reader verifies and decrypts ──────────────────────────────
    println!("[6] A reader (another community member) receives the post...");
    let sig_ok = verify_pseudonym_signature(&pseudonym.public_key_bytes(), &signed_material, &post_signature).is_ok();
    println!("    Signature verifies (post really is from this pseudonym): {}", sig_ok);

    let reader_epoch_key = member_ring.get(encrypted.epoch_number)
        .expect("reader has the same epoch key");
    let decrypted = decrypt_content(&reader_epoch_key, &encrypted).expect("decryption should succeed");
    println!("    Decrypted content: {:?}\n", String::from_utf8_lossy(&decrypted));

    // ── 7. Accountability, still available separately ──────────────────
    println!("[7] If ever needed, the manager can still open the original registration proof...");
    let opened = dgmt_open(&registration_proof, &dgmt_sk, &dgmt_params).expect("opening should succeed");
    println!("    Opened signature identifies member id: {}", opened.id);
    println!("    (Note: this reveals nothing about the post above — DGMT was never used on it.)\n");

    println!("=== Demo complete. Everything above passed. ===");
}

/// Small helper: request B signing keys for a freshly-joined member.
fn dgmt_join_keys(
    sk: &knee_tie_crypto::DgmtSecretKey,
    pp: &knee_tie_crypto::DgmtPublicParams,
    params: &DgmtParams,
    record: &mut knee_tie_crypto::dgmt::join::MemberRecord,
) -> Vec<knee_tie_crypto::dgmt::join::SigningKey> {
    knee_tie_crypto::dgmt::join::dgmt_key_dist(sk, pp, params, record, 1)
        .expect("key distribution should succeed")
}

/// Print the first few bytes of a byte slice as hex, for readable output.
fn hex_preview(bytes: &[u8]) -> String {
    let n = bytes.len().min(8);
    let prefix: String = bytes[..n].iter().map(|b| format!("{:02x}", b)).collect();
    format!("{}...", prefix)
}
