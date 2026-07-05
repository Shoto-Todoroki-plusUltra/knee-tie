# Security Policy

## Project Maturity — Read This First

Knee Tie is a **research / proof-of-concept implementation**. It has not
been independently audited. Do not use it to protect anyone's real
anonymity, safety, or legal interests yet. This applies to every
component in this repository, without exception, until this notice is
updated to say otherwise.

If you are evaluating this project for a use case where someone's safety
depends on the anonymity guarantees holding — an activist, a journalist's
source, an abuse survivor, anyone facing real consequences from exposure —
**do not deploy this yet.** Watch the repository for a version that has
been through independent cryptographic review, and use established,
audited tools (Tor, Signal, SecureDrop) in the meantime.

## Known Limitations (Current)

These are tracked openly, not hidden in an audit report, because the
people best positioned to evaluate whether they matter for a given use
case are exactly the people reading this file.

1. **`utils::sprp` (the strong pseudorandom permutation used for DGMT
   fallback-key derivation) is only a 2-round AES-based Feistel network.**
   It is correctly invertible (tested) but has not been established as a
   cryptographically strong PRP. An adversary able to query it extensively
   might find weaknesses a properly-rounds Feistel construction would not
   have. **Needs hardening before production use.**

2. **`pub_seed` (used to bind WOTS hash chains) is currently derived from
   the DGMT manager's secret `imt_key`.** A public value should never be
   derived — even indirectly, even if the derivation is one-way — from
   secret key material if it can instead be independent. This is a design
   smell that should be fixed (making `pub_seed` an independently
   generated random value) before relying on this for real membership
   anonymity guarantees.

3. **All field and elliptic-curve arithmetic is variable-time**, not
   constant-time. This includes both the Elligator-K1/Kummer-line
   arithmetic and the DGMT/WOTS hash-chain computations. An adversary
   with the ability to measure execution timing precisely (e.g. a
   co-located process, or in some network conditions) could potentially
   learn information about secret key material. **A constant-time,
   fixed-limb field implementation is a prerequisite for any production
   deployment.**

4. **No external security audit has been performed on any part of this
   codebase.**

See [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md) §10 for the full,
current list, kept up to date as the project progresses.

## Reporting a Vulnerability

If you find a security issue — in the cryptographic design, in the
implementation, or in how they're combined — please report it privately
rather than opening a public issue, so there's time to assess and (if
needed) coordinate a fix before public disclosure.

**Preferred:** open a
[GitHub Security Advisory](../../security/advisories/new) on this
repository (private by default, visible only to maintainers until
published).

**Alternative:** `<add a maintainer contact email here before publishing
this repository — a security-relevant project should not ship without
one>`.

Please include:

- What you found and why you believe it's a security issue (not just a
  correctness bug — though correctness bugs affecting the security
  properties described in `docs/SPECIFICATION.md` §3 are absolutely in
  scope too).
- Which module/file, and ideally a minimal reproduction or a concrete
  attack scenario.
- Your assessment of severity, if you have one — but don't let
  uncertainty about severity stop you from reporting.

There is no bug bounty program at this stage. Reports are still very
welcome and will be credited (with permission) once addressed.

## Scope

In scope: anything in `crates/` and any code that will be added for
Phase 2 onward (server, protocol library, client).

Out of scope: the underlying research papers themselves (DGMT; the
Elligator-K1/Kummer-line construction) — if you find an issue with the
*published cryptographic scheme* rather than this implementation of it,
please contact the papers' authors directly; this repository can only fix
implementation-level issues.
