# Knee Tie

A pseudonymous, self-governing community platform, built on post-quantum
group signatures and traffic-indistinguishable key exchange.

> **⚠️ Research / proof-of-concept stage. Not production-ready. Not audited.**
> Do not rely on this software for real anonymity or safety needs yet.
> See [Current Status](#current-status) and [`SECURITY.md`](SECURITY.md)
> for exactly what is and is not implemented and hardened so far.

---

## What this is

Each community on Knee Tie is a fully independent, self-contained space;
closer to a standalone forum than to a subreddit within a larger site.
Members hold a **persistent pseudonym** within a community (so reputation
and normal forum dynamics work) that **cannot be linked to their real-world
identity** by anyone: not other members, not the server operator, not a
state actor with full access to the server.

The cryptographic core combines two research papers with original design
work specific to this project:

- **[DGMT](https://doi.org/10.3390/cryptography9010012)** (Fadavi, Karati,
  Erfanian, Safavi-Naini — *Cryptography*, 2025) — a fully dynamic,
  post-quantum group signature scheme. Used once, at community
  registration, to prove a pseudonym belongs to a legitimately admitted
  member, without revealing which member.
- **Elligator-K1 / Kummer line** (Saha & Karati — *Advances in Mathematics
  of Communications*, 2026) — encodes Diffie-Hellman key-exchange values
  so they are indistinguishable from uniformly random bytes, defeating
  traffic-analysis fingerprinting of the protocol itself.

Full design rationale, threat model, and every architectural decision
behind these choices: **[`docs/SPECIFICATION.md`](docs/SPECIFICATION.md)**.

## Current Status

```
Phase 1 — Cryptographic library (crates/knee-tie-crypto)   ✅ complete
Phase 2 — Server                                            ⬜ not started
Phase 3 — Protocol library                                  ⬜ not started
Phase 4 — TUI client                                         ⬜ not started
Phase 5 — Packaging & launch                                 ⬜ not started
```

Phase 1 has 120+ passing tests covering the full DGMT lifecycle
(join → sign → verify → revoke → open), Elligator-K1 encode/decode,
Diffie-Hellman shared-secret agreement, epoch-key content confidentiality,
and pseudonym signing, including a combined test exercising all of these
together in one realistic post lifecycle.

**Known limitations that must be addressed before any real deployment**
(see `docs/SPECIFICATION.md` §10 for full detail):

- The strong pseudorandom permutation used internally (`utils::sprp`) is
  only a 2-round Feistel network: correctly invertible, but not
  established as cryptographically strong. Needs hardening.
- A public value (`pub_seed`) is currently derived indirectly from secret
  key material. Should become an independent random value.
- Field and elliptic-curve arithmetic is variable-time (not constant-time),
  which is a real timing side-channel exposure for an anonymity system.
- No external security audit has been performed.

Two genuine cryptographic bugs were found and fixed during Phase 1
development; see §10.1 of the specification for what they were and, more
importantly, *why the original tests didn't catch them*. That history is
kept in the specification deliberately, as a record of what to watch for
in future work on this codebase.

## Repository Layout

```
knee-tie/
├── crates/
│   └── knee-tie-crypto/   Phase 1: DGMT, Elligator-K1/Kummer DH, epoch
│                          keys, pseudonym identity. Pure library, no
│                          networking, no application logic.
├── docs/
│   └── SPECIFICATION.md   Full project specification: threat model,
│                          architecture, every design decision and why,
│                          implementation status, roadmap.
├── SECURITY.md            Vulnerability reporting + current limitations.
├── CONTRIBUTING.md        How to contribute, code conventions.
└── LICENSE                AGPL-3.0.
```

## Building & Testing

```bash
git clone https://github.com/Shoto-Todoroki-plusUltra/knee-tie.git
cd knee-tie
cargo test --workspace
```

Requires a current stable Rust toolchain. No other setup needed for
Phase 1. The crypto library has no external service dependencies.

## Why AGPL-3.0

Anyone who runs a *modified* Knee Tie server, whether self-hosted or as part of
a hosted instance, must publish their modifications. Without this
requirement, an operator could silently alter server behavior (for
example, secretly logging identifying data) while still appearing to run
the trusted open-source code, which would undermine the project's entire
privacy premise. A permissive license, or the plain GPL (which does not
cover network-only use), would not close this gap.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Given the security-sensitive
nature of this project, independent review of the cryptographic code is
especially welcome. See [`SECURITY.md`](SECURITY.md) for how to report
issues responsibly.

## License

[AGPL-3.0](LICENSE).
