# Contributing to Knee Tie

Thank you for considering contributing. This is a security-sensitive
project at an early, actively-changing stage — please read
[`docs/SPECIFICATION.md`](docs/SPECIFICATION.md) first to understand the
overall design before proposing changes, and [`SECURITY.md`](SECURITY.md)
for how to report vulnerabilities privately rather than as public issues.

## Where to Start

- The specification's [Roadmap](docs/SPECIFICATION.md#13-roadmap) and
  [Open Questions](docs/SPECIFICATION.md#14-open-questions) sections list
  what's planned and undecided.
- The [Known Limitations](docs/SPECIFICATION.md#10-known-limitations--technical-debt)
  section lists hardening work that doesn't depend on new features being
  built first — good entry points for a first contribution.

## Code Conventions

This codebase follows a few conventions worth knowing before you dive in:

**Cite the source for cryptographic code.** Every function implementing
an algorithm from DGMT or the Elligator-K1 paper includes a doc comment
citing the specific paper section and algorithm/theorem number (e.g.
"Paper 1, Algorithm 7" or "Paper 2, Theorem 3.5"). If you're implementing
or modifying cryptographic logic, do the same — it makes review against
the source material tractable, and it's how two real bugs were caught
during Phase 1 (see the specification, §10.1).

**Don't trust self-referential tests for cryptographic correctness.** A
test that checks `f(x)` against another call to `f` (or against a
different function built from the same internals) can pass even when
both are wrong in the same way. This project was bitten by exactly this
once already (§10.1 of the specification). Prefer either:
- hard-coded test vectors computed independently (a different
  implementation, a different language, or hand computation) of the code
  under test, or
- cross-checks against a genuinely independent method (e.g. the y-coordinate
  elliptic-curve arithmetic used to verify the Kummer-line scalar
  multiplication).

**Verify unfamiliar crate APIs before depending on them**, especially for
anything security-relevant. Check current documentation (docs.rs) rather
than relying on training data or memory, particularly for crates whose
APIs have changed across major versions.

**Zero secret material on drop.** Types holding private keys or other
secrets should derive or implement `ZeroizeOnDrop` (see `zeroize` crate
usage throughout `knee-tie-crypto`), and should never derive `Debug` in a
way that could print secret bytes — see `WotsSecretKey`'s manual,
redacted `Debug` impl for the pattern to follow when a type must be
printable for some reason but shouldn't leak.

## Running Tests

```bash
cargo test --workspace
```

## Pull Requests

- Keep cryptographic changes and non-cryptographic changes (docs, CI,
  tooling) in separate PRs where reasonably possible — it keeps review
  focused.
- New cryptographic functionality should come with tests that would have
  caught the kind of self-referential-test failure described above.
- Please don't add new dependencies without checking their current API
  documentation and noting in the PR description what you verified.

## Reporting Issues

Non-security bugs, feature requests, and design discussion: open a
regular GitHub issue.

Security vulnerabilities: see [`SECURITY.md`](SECURITY.md) — please do
not open a public issue for these.
