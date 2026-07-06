# Knee Tie — Project Specification & Roadmap

---

## 1. What Knee Tie Is

Knee Tie is an open-source, self-hosted community platform. Each community on Knee Tie is:

- **Fully independent** from every other community — no cross-community discovery, no shared identity, no federation. Each community is its own isolated space, closer to a standalone forum than to a subreddit within a larger site.
- **Pseudonymous, not merely anonymous.** Members choose a persistent handle within a community. Posts under that handle are visibly linked to each other (consistent voice, reputation, history) but the handle cannot be linked to a real-world identity by anyone — not other members, not the server operator, not a government with server access.
- **Self-governing.** A founder and promoted senior members make moderation decisions through weighted voting, recorded on a public transparency log. There is no platform-level moderation layer above individual communities.
- **Post-quantum secure** at the membership layer. Anonymity is designed to hold even against an adversary with a cryptographically relevant quantum computer, via a hash-based group signature scheme (no elliptic-curve or factoring-based assumptions at that layer).
- **Not growth-oriented.** The project is explicitly not trying to compete with Reddit-scale platforms. Communities are expected to be small to medium, quality-of-discourse over quantity-of-users.

What Knee Tie explicitly is **not**, at least in this version:

- Not peer-to-peer. Communities run on a server — either self-hosted by the community, or on a centralized instance the project operates as a lower-barrier fallback for people who cannot self-host. True P2P storage (gossip protocols, IPFS, etc.) was deliberately deferred: it conflicts with the moderation model (content must be genuinely removable when a community votes to remove it, which P2P storage makes very difficult), and it adds substantial protocol complexity before the core cryptography has been proven.
- Not a general anonymous social network. The design deliberately avoids the "anonymous Twitter" failure mode: public, unbounded-scale, virally-spreading, unmoderated anonymous content has a fundamentally different (and much harder to defend) harm profile than small, invite-gated or vouched communities with real internal accountability. See §12.

---

## 2. Foundational Research

Knee Tie's cryptographic core combines two independent research papers, plus original design work specific to this project.

### 2.1 Paper 1 — DGMT (Fadavi, Karati, Erfanian, Safavi-Naini; *Cryptography* 2025)

*"DGMT: A Fully Dynamic Group Signature from Symmetric-Key Primitives"*

A **group signature scheme**: any member of a group can sign a message anonymously on behalf of the group. A verifier can confirm the signature came from *some* valid member, but not which one. A trusted manager can, if needed, "open" a signature to reveal the signer's identity, and can revoke a member's signing ability going forward.

What makes DGMT specifically valuable for Knee Tie:

- **Post-quantum.** Security rests entirely on hash functions and symmetric-key primitives (via a Winternitz One-Time Signature / Merkle tree construction), not on discrete log or factoring assumptions that Shor's algorithm breaks.
- **Fully dynamic.** Members can join and be revoked throughout the group's lifetime — not just at a fixed setup time.
- **Non-interactive verification.** Unlike its predecessor (DGM), verifying a DGMT signature requires no communication with the group manager. This is essential for Knee Tie: a verifier (any community member's client) must be able to check a post's validity offline, without querying a manager that may not be running.
- **Practical storage.** DGMT's key innovation over DGM is an interval-based key assignment scheme that keeps the manager's storage proportional to the number of members (Nmax), not the total number of signatures ever issued (Ttot) — DGM's approach would require ~108.7 TB of manager storage to support 2⁶⁴ signatures; DGMT does not.
- **Shortest known signature size** among post-quantum group signature schemes at the same security level (~5.75 KB at 128-bit security).

**Role in Knee Tie:** DGMT is used exactly **once**, at community registration — to produce a single, permanent proof that a given pseudonym belongs to a legitimate, vetted member of the community. It is deliberately *not* used on every post (see §5).

### 2.2 Paper 2 — Elligator-K1 / Kummer Line (Saha & Karati; *Advances in Mathematics of Communications*, 2026)

*"Encoding to Legendre Curve, Kummer Line and Twisted Edwards Curve"*

Solves a different problem: elliptic curve traffic is normally distinguishable from random bytes (a network observer, or firewall doing deep packet inspection, can detect that a given connection is doing ECC key exchange). Elligator maps let field elements and curve points be converted into each other bijectively, so what's actually transmitted over the wire is indistinguishable from uniformly random data.

The paper introduces new Elligator-style maps (Elligator-L1/L3, Elligator-K1/K3, Elligator-T/Ty) covering cases the original Elligator-1/Elligator-2 constructions (Bernstein et al.) did not — specifically, prime fields of the form q ≡ 1 (mod 4) mapping onto Legendre curves and their associated (squared) Kummer lines.

**Role in Knee Tie:** Elligator-K1, applied to a squared Kummer line over the p25519 prime field, is used for:

1. **Traffic-obfuscated key exchange** — establishing an encrypted channel to a Knee Tie server (join requests, application submissions, and eventually all traffic) using a Diffie-Hellman handshake whose public values are indistinguishable from random bytes.
2. **Epoch-key sealing** — see §5.3. This is an original application of the primitive: rather than introduce a second DH construction (e.g. X25519) purely to encrypt symmetric keys for specific members, Knee Tie reuses the same validated Kummer-line DH for that purpose, so that even long-term member public keys used for content-key distribution remain traffic-indistinguishable.

### 2.3 Why These Two Papers Together

They solve non-overlapping problems and were chosen specifically because they compose without conflict: DGMT provides anonymous-but-accountable *membership*; Elligator-K1 provides *transport-level* indistinguishability. Neither paper's authors proposed this combination or this application — it is original design work for this project. (Earlier project-scoping discussion considered several other applications — anonymous peer review, anonymous voting, a general community-governance platform — before converging on the present pseudonymous-forum design as the best balance of novelty, buildability, and adoption viability.)

---

## 3. Threat Model & Security Properties

Precision matters here — "anonymous" is not one property, it's several, and Knee Tie makes different guarantees at different layers.

### 3.1 What "Anonymous" Means in This System

A member's **real-life identity** (legal name, physical location, device, IP address, behavioral fingerprint linking them to other accounts) cannot be linked to their pseudonym by:

- The server operator (whether self-hosted or the project's centralized instance)
- Other community members, including senior members and the founder
- A network observer performing traffic analysis
- Law enforcement or a state actor with full access to the server's stored data

A member's **pseudonym**, once chosen, *is* intentionally persistent and visible within a community — posts under "ghost_orchid" are recognizably from the same participant, building reputation and enabling normal forum dynamics. This is a deliberate design choice, not a limitation: pure per-post anonymity (no persistent identity at all) was considered and rejected early in the design process, because it destroys the social coordination and accountability that make forums functional.

### 3.2 Layered Identity Stack

| Layer | Mechanism | Protects against |
|---|---|---|
| Network | Tor | Server/observer learning the member's real IP |
| Protocol | Elligator-K1 DH handshake | A network observer identifying that Knee Tie's protocol is in use at all |
| Membership | DGMT (once, at registration) | Anyone determining which vetted member a given pseudonym corresponds to |
| Authorship | Ed25519 (per post) | Forgery of posts under someone else's pseudonym |
| Confidentiality | Epoch keys (per community) | Non-members (and the server) reading post content |

### 3.3 Explicit Non-Goals / Known Limitations

- **Revoked members retain read access to content from before their revocation.** This is a deliberate, documented tradeoff of the epoch-key design (§5.3), not an oversight — the alternative (retroactively re-encrypting all history on every revocation) makes the "past posts become unreadable after any membership change" problem worse, not better.
- **A network observer with global traffic-analysis capability** (timing correlation across the whole network, not just packet content) is not fully defended against. Tor provides probabilistic protection against this; Knee Tie does not attempt to improve on Tor's guarantees here.
- **Sybil resistance is best-effort, not absolute.** Depending on which membership model (§6) a community chooses, a sufficiently motivated single person can obtain multiple pseudonyms. This is an open problem for anonymous systems generally; Knee Tie's mitigations (invite/vouching models creating social cost) reduce but do not eliminate it.
- **The founder is a real trust bottleneck for community founding and dispute-of-last-resort**, though moderation power is deliberately *not* concentrated in the founder alone (§7).

---

## 4. System Architecture

### 4.1 Community Independence

Each community is a self-contained cryptographic and social unit:

- Its own DGMT group (separate group public key, separate manager secret key).
- Its own epoch-key history.
- Its own membership roll, governance configuration, and transparency log.
- A member's pseudonym in Community A has **no cryptographic link** to any pseudonym the same person might hold in Community B — including no shared name requirement. There is no cross-community identity layer at all, by design.

### 4.2 Deployment Modes

1. **Self-hosted.** Anyone downloads the open-source server and runs their own instance for their community. Full control, no dependency on the project.
2. **Centralized fallback (project-operated).** For communities/founders who cannot self-host. Free tier with defined storage/post/member limits; paid tier via Monero (chosen specifically to keep payment itself from creating an identity-linkage the rest of the system avoids). Yet to come.

### 4.3 What the Server Can and Cannot Do

By design, a Knee Tie server (self-hosted or centralized) is a **blind storage layer**:

- **Can:** store encrypted content blobs; store sealed epoch-key bundles; verify DGMT/Ed25519 signatures on submissions (to reject malformed or unauthorized posts without needing to read them); serve the community's public parameters and transparency log; enforce storage/rate limits.
- **Cannot:** read any post content (encrypted); identify any member (all traffic Tor + Elligator-K1); link a pseudonym to a real identity (no such data is ever collected); perform moderation (that's the community's job, not the platform's).

---

## 5. Cryptographic Design

### 5.1 The Three-Key Model

An earlier design iteration considered a single shared community content-encryption key (CEK) for everyone. This was identified as flawed during design review: it cannot distinguish who authored a post (everyone shares the same key), and if the key leaks, anyone on the internet can forge posts and read all content — a single point of total compromise. The current design separates three concerns into three distinct key types:

| Key | Purpose | Scope / lifetime | Used |
|---|---|---|---|
| **DGMT credential** | Prove valid, vetted membership | Once, at join | Once (produces a permanent registration proof) |
| **Ed25519 pseudonym keypair** | Prove authorship of a specific post | Persistent per pseudonym | Every post |
| **Epoch key** | Content confidentiality (who can read) | Rotates on revocation | Every post (to encrypt/decrypt) |

Leaking one key type does not compromise the others: a leaked epoch key lets an attacker *read* that epoch's content, but not forge posts (no Ed25519 private key) and not gain DGMT-proven membership. A leaked Ed25519 key compromises one pseudonym's authorship integrity, not the community's confidentiality or anyone else's identity.

### 5.2 Why DGMT Isn't on Every Post

DGMT signatures are ~5.75 KB each and take on the order of 1 second to verify (per the paper's own benchmarks). Verifying a 100-post feed at that cost is impractical for an interactive UI. Since Knee Tie uses *persistent pseudonyms* (not per-post anonymity), the correct design is:

1. DGMT proves, **once**, "this Ed25519 public key belongs to a legitimately admitted member." This proof is stored in the member's public profile.
2. Every subsequent post is signed with the (cheap, ~64-byte, microsecond-verify) Ed25519 key.
3. A revocation check is a simple lookup against the community's public revocation list — not a fresh signature verification.

### 5.3 Epoch Keys — Solving the "History Becomes Unreadable" Problem

The naive approach — rotate a single shared key on every membership change — makes old posts unreadable to current members after any change, which is unacceptable for a forum where history has value. The chosen design ("Solution 3" in project design discussion):

- The community starts at **epoch 0** with a fresh random key.
- **New epochs are created only on revocation events**, not on every join. This keeps the epoch count proportional to moderation activity, not membership growth.
- Each post is tagged with the epoch active when it was created and encrypted under that epoch's key.
- A new member is granted access to epochs per a **founder-configured policy**: `FullHistory` (sealed keys for every epoch since founding) or `FromJoinDate` (only the current epoch onward).
- On revocation: the epoch rotates; the new epoch key is sealed and distributed to every *remaining active* member; the revoked member receives nothing for the new epoch and so cannot decrypt future content — but retains whatever epoch keys they already held. This is the accepted tradeoff from §3.3.

**Sealing mechanism:** each member holds a long-term Kummer-line DH keypair (distinct from their Ed25519 pseudonym key) used only to receive epoch keys. To grant epoch access, the community performs an ephemeral-static Elligator-K1 DH exchange with the member's static public key, derives a symmetric key via HKDF-SHA256, and encrypts the epoch key with ChaCha20-Poly1305. This reuses the already-validated Kummer DH primitive from Paper 2 rather than introducing a second DH construction.

### 5.4 Local Identity Storage

A member's local device stores their Ed25519 pseudonym seed, DGMT credential, and epoch-access DH scalar, encrypted at rest. The encryption key is derived from a user passphrase via Argon2id (OWASP-recommended default parameters), and the blob is sealed with ChaCha20-Poly1305. This is implemented as a storage-agnostic primitive in the crypto library; on-disk format and passphrase-prompting UX are Phase 4 (TUI client) concerns.

---

## 6. Membership Models

Each community configures one membership model at founding:

- **Invite-only.** An existing member issues a one-time, DGMT-signed invite token (proving it came from *some* valid member, without revealing which) shared out-of-band. Highest barrier, highest trust.
- **Application.** A prospective member submits a pseudonym choice and a written statement — no real-identity information at all. Senior members review and vote (weighted, threshold-based) to admit.
- **Vouching.** Existing members (optionally restricted to seniors) issue DGMT-signed vouches for an applicant. Once *k* vouches are collected, credentials are issued automatically — no moderator review needed.
- **Proof-of-work.** A computational puzzle (hashcash-style) with a founder-configured difficulty, as a low-friction spam barrier with no social trust or review requirement.

The founder chooses per-community which model(s) apply; this was an explicit requirement ("each community is different, therefore everyone will have different needs").

---

## 7. Governance & Moderation

### 7.1 Roles

- **Founder** — creates the community, holds the highest vote weight, can promote members to Senior.
- **Senior member** — promoted by the founder (or by threshold vote of existing seniors, if so configured); has weighted voting rights on moderation actions.
- **Member** — can post, comment, and flag content for senior review; no moderation voting rights.

### 7.2 The Moderation Key Problem, and Why It's Solved by *Not* Using DGMT's Master Key

An early design question: since the number of senior members changes over time, how can a single cryptographic key be "distributed" among a dynamic set of people for moderation decisions? The resolution was to **not** use DGMT's master secret key (`msk`) for this at all — that key is reserved for the founder alone, for issuing/revoking credentials. Moderation instead uses a **separate, simple mechanism**: every moderation action (remove a post, warn, suspend, ban) is a Ed25519-signed proposal, voted on by senior members with individually signed votes, executed automatically once a founder-configured weight threshold is met. No secret-sharing, no key reconstruction — adding or removing a senior member is just adding or removing a public key from the voting roster, which requires no cryptographic ceremony.

**Explicitly removed from scope:** an original design included a "nuclear option" (threshold-gated real-identity opening of a DGMT signature for extreme cases). This was removed at the user's request — Knee Tie's moderation model does not include any mechanism to de-anonymize a member, full stop. Moderation acts on content and pseudonym standing only.

### 7.3 Founder Succession

Configured entirely by the founder at community creation, all parameters optional:

- Whether succession is enabled at all.
- An inactivity threshold (days of no signed founder activity — post, vote, credential issuance, or an explicit heartbeat) before a succession vote becomes eligible.
- Vote requirements: **100% of senior members** must approve, plus **90% of participating members** (with a configurable minimum participation quorum), over a configurable voting window.
- Who becomes the new founder: automatically the most senior member by tenure, or a separate senior vote.

### 7.4 Community Deletion

The founder can dissolve a community; a 48-hour delay (giving members time to archive content they want to keep) precedes permanent deletion of all content, followed by a 30-day tombstone period before the community record itself is removed. On a self-hosted server, the founder can of course simply stop the server at any time regardless of this protocol — that is an accepted, inherent property of self-hosting.

---

## 8. Content Model

- **Text posts and comments.**
- **Polls**, with anonymous voting via cryptographic nullifiers (each vote includes `SHA-256(voter_private_key ∥ poll_id)` to prevent double-voting without revealing who voted; results are tallied client-side from downloaded votes, never by the server).
- **No upvote/downvote system** (explicitly decided against, to avoid an additional anonymous-voting subsystem where it isn't needed).
- **Client-side full-text search.** Indexed locally on the member's device from decrypted content; no search query ever reaches the server. Communities with large histories will see a real indexing-time cost on first load — the client surfaces this to the user as an explicit warning rather than hiding the latency.

---

## 9. Implementation Status

A pure Rust library (AGPL-3.0, edition 2021), no networking, no application logic. 120+ unit/integration tests, all passing.

| Module | Contents | Status |
|---|---|---|
| `utils::hash` | Domain-separated PRF, WOTS chain function, Merkle leaf/node hashes | Done |
| `utils::sprp` | Strong pseudorandom permutations g1, g2 (2-round AES Feistel) | Done — *see §10 for hardening note* |
| `utils::aead` | Shared ChaCha20-Poly1305 helpers | Done |
| `wots` | Winternitz One-Time Signature (keygen, sign, verify, pk recovery) | Done |
| `merkle` | Merkle tree construction, authentication paths, root verification | Done |
| `dgmt::params` | Setup parameter validation | Done |
| `dgmt::keygen` | DGMT.KG — IMT/SMT(1) construction, fallback keys (Algorithms 1, 4) | Done |
| `dgmt::join` | DGMT.Join, DGMT.OTSReq / KeyDist (Algorithms 5, 6) | Done |
| `dgmt::sign` | DGMT.Sig (Algorithm 7) | Done |
| `dgmt::verify` | DGMT.Vf — fully non-interactive (Algorithm 8) | Done |
| `dgmt::revoke` | DGMT.Rev (Algorithm 9) | Done |
| `dgmt::open` | DGMT.Op — signature opening (Algorithm 10) | Done |
| `elligator::field` | F_p25519 arithmetic (add/sub/mul/inv/sqrt/quadratic character) | Done — *corrected mid-project, see §10* |
| `elligator::kummer` | Squared Kummer line arithmetic, scalar multiplication | Done — *rewritten mid-project, see §10* |
| `elligator::elligator_k1` | Elligator-K1 encode/decode | Done — *corrected mid-project, see §10* |
| `elligator::dh` | Diffie-Hellman key exchange over the Kummer line | Done |
| `epoch::key` | EpochKey, EpochHistory, content encrypt/decrypt | Done |
| `epoch::seal` | Sealing/opening epoch keys for specific members via Kummer DH | Done |
| `epoch::grant` | History access policy, member epoch key ring | Done |
| `identity::pseudonym` | Ed25519 keypair generation, signing, verification | Done |
| `identity::store` | Argon2id + AEAD local encrypted storage primitive | Done |

**Test coverage highlights:** full DGMT lifecycle (join → key distribution → sign → verify → revoke → open); cross-community signature isolation; forged-signature rejection; DH shared-secret agreement between independent parties; a full combined-stack test exercising DGMT registration + Ed25519 authorship + epoch-key encryption + Elligator-K1 sealing together, matching the real intended usage pattern; an epoch-revocation end-to-end test confirming a revoked member loses future access while retaining past access; identity-store roundtrip with wrong-passphrase rejection.


Self-hosting documentation, protocol specification (so third parties can build interoperable clients/servers), security-model document, and launch of the project-operated centralized fallback instance.

---

## 10. Known Limitations & Technical Debt

Recorded honestly, for future hardening passes — none of these invalidate what's built, but all should be addressed before any real deployment:

1. **The SPRP (g1, g2 in `utils::sprp`) is only a 2-round AES-based Feistel network.** It is correctly invertible (tested) but not established as a cryptographically strong pseudorandom permutation. Needs 4+ rounds, or replacement with a proper wide-block cipher construction, before production use.
2. **`pub_seed` (WOTS chain binding) is currently derived from the DGMT manager's secret `imt_key`.** This is a design smell — a public value should not be derived from secret key material, even indirectly. Should become an independently-generated random public value stored in `DgmtPublicParams`.
3. **All field arithmetic (`num-bigint`-based) is variable-time**, including the elliptic-curve arithmetic added to fix the Kummer-line scalar multiplication bug (§10.1). A timing side-channel attacker could potentially learn information about secret scalars. Acceptable for a proof-of-concept; not acceptable before any real deployment. A constant-time fixed-limb field implementation is a prerequisite for production use.
4. **`ec_scalar_mult` (the corrected Kummer-line scalar multiplication) is a plain double-and-add, not constant-time**, for the same reason as above — correctness was prioritized over side-channel resistance given the constraints of not having a compiler available during development (see §10.1).

### 10.1 A Note on How Two Real Bugs Were Found and Fixed

During Phase 1 development, without direct compiler access, code was written, manually traced for type/borrow correctness, and delivered for the user to compile and test — an iterative loop across several rounds. Two genuine cryptographic bugs were caught this way and are worth recording:

- **A `sqrt()` formula bug** (`elligator::field`): two different known square-root algorithms for primes ≡ 5 (mod 8) had been conflated into a hybrid matching neither. Re-derived from first principles, verified algebraically, then numerically confirmed against every quadratic residue of a small test prime before shipping the fix.
- **A Kummer-line differential-addition (`xADD`) bug**: the original implementation borrowed a formula from Montgomery-curve (Curve25519-style) x-only arithmetic, which does not hold for this project's specific Legendre-curve-derived Kummer parameterization. It went undetected by initial unit tests because those tests were *circular* — they checked the implementation's output against itself, rather than against an independent reference. The bug was found by cross-checking against an independently-implemented y-coordinate elliptic-curve group law (standard textbook chord-and-tangent formulas), which is verifiable by hand. The fix replaced the unverifiable x-only Kummer ladder entirely with scalar multiplication routed through that same verified y-coordinate arithmetic, converting to/from the Kummer wire format only at the boundary.

This episode is the reason several test suites in this codebase specifically favor hard-coded, independently-computed test vectors over self-referential "does function X agree with function X" checks — the latter cannot catch a bug that is wrong in a self-consistent way.

---

## 11. Naming & Licensing

**Name:** Knee Tie.

**License:** AGPL-3.0. Chosen specifically for the Affero clause: anyone who runs a *modified* Knee Tie server must publish their modifications. Without this, a self-hosted or centralized operator could silently alter server behavior (e.g. secretly logging identifying data) while still appearing to run the trusted open-source code — which would undermine the entire privacy premise of the project. Plain GPL or a permissive license (MIT/Apache) would not close this gap.

---

## 12. Ethical Considerations (Summary)

Strong-anonymity systems have a documented history of enabling serious harm (CSAM, non-consensual intimate imagery, coordinated harassment, extremist coordination), and this was treated as a first-order design constraint, not an afterthought. Key conclusions from that design discussion:

- The **marginal uplift Knee Tie provides to a bad actor is low**: everything it offers (anonymity, encrypted transport) is already more accessible via existing tools (Tor, Signal, existing dark-web forums). Knee Tie does not meaningfully expand bad-actor capability.
- The **community-governance model is itself a harm mitigant, not just a feature**: invite/vouching-gated communities with internal weighted-vote moderation are structurally hostile to the kind of open, unmoderated space bad actors generally seek out. This is a property of the design, not a policy bolted on top.
- A separate, larger-scale "anonymous Twitter" concept was explicitly considered and **rejected** during scoping: the combination of public reach, viral spread, and no community-level accountability structure changes the harm calculus in a way that Knee Tie's small-community design specifically avoids.
- The project maintains a clear line between **the open-source protocol** (usable by anyone, no content policy attached) and **any centralized instance the project operates** (which will have rules and will act on credible reports by removing communities — without needing to read their content, since community-level removal doesn't require content access).
- CSAM reporting-law compliance for any project-operated instance is treated as non-negotiable and outside the scope of "privacy tradeoffs" — it has no legitimate-use defense and no free-expression dimension.
