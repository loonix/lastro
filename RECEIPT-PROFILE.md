# Receipt Profile — what a Lastro receipt is and is not

**Status:** normative for this repo · **Wire format:** Bolina SPEC §7.1, unmodified ·
**Conformance:** `wire/testdata/vectors.json` (frozen, provenance recorded)

A receipt is a **Bolina Span**: a signed record that a specific observation was actually
made by a specific executor. The wire bytes are SPEC bytes — a Lastro receipt parses in any
conformant Bolina implementation and vice versa. This document defines the *profile*: how
spans are used detached from a mesh, what `lastro run` captures, and what a verified receipt
does and does not prove.

## 1. The single deviation: detached origin

SPEC §7.1 defines `origin` as the hash of the Effect envelope that published the span — its
anchor in a channel's causal order. A CI run has no channel and no ledger, so a detached
receipt carries:

```
origin = 32 zero bytes    meaning: "no causal anchor"
```

That is the **only** deviation this profile permits, and it is a value convention, not a
format change. Consequences, stated honestly:

- No causal ordering between receipts. Freshness comes from `resource_id` embedding the
  commit SHA (§3): a receipt about commit X never claims anything about commit Y.
- No supersession (BE-EVID-05): a detached receipt is never invalidated by a later
  observation. Point-in-time evidence, permanently.
- A detached receipt fed into a real Bolina mesh resolves as *Unresolved/unsupportable*
  under BE-EVID-09b — by design, since its origin resolves to nothing. Detached receipts
  are for detached verification (`lastro verify`), not for raising claim ceilings in-mesh.

**Any second deviation from SPEC bytes requires a written decision entry in this repo
(PREMORTEM item 3). There are currently zero others.**

## 2. Capture contract (`lastro run`)

`lastro run [flags] -- command args...` executes the command and observes it:

- **What is captured:** stdout and stderr, byte-exact, merged in the order this process
  observed them. Output is streamed through to the terminal unchanged — wrapping a CI step
  never hides its logs. The exit code is folded into the observed stream as a canonical
  trailer line (`[lastro] exit-status=N`): a Span carries no exit field (in-mesh that is
  `Effect.exit_code`'s job), so detached receipts cover the exit code with the digest, and
  it is readable whenever the output is saved (`--save-output`; recommended as a CI
  artifact next to the receipt).
- **The digest** (`Span.digest`) is BLAKE2s-256 of the captured byte stream. It proves
  *what was observed at this run*. It is **not** a reproducibility claim: interleaving of
  the two streams and any nondeterminism in the command's own output (timestamps, ordering)
  legitimately vary between runs. The stable, comparable fields are the exit code and the
  resource_id.
- **Size cap:** captured output above the cap (default 8 MiB, `--max-output`) produces
  **no receipt** — never a receipt of a truncation. An observation that was not fully
  captured is not an observation (BE-EVID-14, imported). `lastro run` then exits 125.
- **method_id is 1 (subprocess), always.** There is no flag to choose it: the method is a
  compile-time constant of the code path (BE-EVID-11 — no interface accepts a method,
  class, or confidence). Likewise `volatility` is fixed at `volatile`: a command's outcome
  is state that can change under us, and fail-closed is the profile's default posture.
- **Exit code contract:** `lastro run` exits with the child's exit code when the receipt was
  written (red and green runs both get receipts — PREMORTEM item 7); **125** when the
  child ran but no receipt could be produced (cap exceeded, key unreadable, disk error) —
  loudly, so a missing receipt can never look like a passing step; **127** when the child
  could not be started.

## 3. Resource identity

`resource_id` follows the canonical grammar (SPEC §8.4):

```
bol:<executor_fp>/<namespace>/<path>
executor_fp = BLAKE2s-256(sig_pubkey)[0..8], 16 lowercase hex chars (BE-RES-06)
namespace   = 1..32 chars of [a-z0-9-]
path        = 1..180 chars of [a-z0-9-._/], no empty/"."/".." segment
```

The fingerprint is always derived from the signing key in use — the CLI refuses a resource
that names a different executor (BE-RES-04). Recommended CI convention:

```
bol:<fp>/git/<repo>/<commit-sha>/check/<name>
e.g. bol:c3efd641bfa0582f/git/bolina/90e46a5.../check/zig-build-test
```

The commit SHA inside the resource is the freshness anchor detached receipts otherwise
lack. Repo names are lowercased and sanitized to the grammar's charset. The path may carry
the placeholder `{sha}`, which `lastro run` substitutes with `git rev-parse HEAD` — derived
by the tool itself, never from a hand-written CI variable, so the anchor cannot be forged
by a typo (fase-3 acceptance criterion).

## 4. Verification (`lastro verify`)

Full verification takes the receipt, the executor's certificate, and the trusted CA keys:

1. Span parses (total, no trailing bytes) and its signature verifies over
   `(0x03 || TBS)` against `Span.executor`.
2. The certificate parses, every CA signature verifies over `(0x01 || TBS)`, every CA key
   is in the trusted set, role constraints hold, and the cert carries the **executor**
   role (BE-EVID-01: only executors produce evidence).
3. `cert.sig_pubkey == span.executor` — the cert is the signer's.
4. The resource fingerprint matches the cert's key (BE-RES-04/06).
5. The evidence class and ceiling derive from `method_id` through the fixed table —
   computed by the verifier, never read from the receipt (SPEC §7.4).

**Clock posture:** chain validation is clock-free (the audit stance, BE-HIST-01): an
expired certificate still proves what it signed while valid. The report *shows* the cert's
validity window and whether `observed_at` falls inside it; it does not enforce the wall
clock. `observed_at` is informative only, as everywhere in the protocol (BE-ENV-01).

**Unanchored mode:** `lastro verify` without `--cert` checks only step 1 and reports the
receipt as `UNANCHORED` — the signature is internally valid but bound to no identity.
Useful before a CA exists; never presentable as a verified receipt, and the output says so.

## 5. Trust model, stated before anyone states it for us

A receipt proves: **the holder of this signing key ran this command and observed this
output.** What that is worth depends on where the key lives:

- **CI runner (the intended L1 deployment):** the runner is a separate trust domain from
  any agent whose work is being verified. The receipt's strength is the CI platform's
  integrity. The signing key must live in a protected environment scoped to trusted
  workflows; fork PRs and untrusted triggers must never reach it.
- **Same machine, same user as the agent:** the agent can read the key or invoke the CLI
  itself. Receipts in this mode defend against *confabulation* (an agent claiming runs
  that never happened, misreporting results) — the overwhelmingly common failure — not
  against a malicious agent with shell access. Say which mode you run; this document just
  did.
- The digest hashes output that is not stored by default (`--save-output` keeps it);
  without the saved output, third parties verify the signature and metadata, not the
  output bytes themselves.

## 6. Keys and certificates

`lastro keygen` writes the Bolina node key layout (`sig.key`/`sig.pub`,
`static.key`/`static.pub`, 32-byte raw, 0600, dir 0700) so the standard Bolina CA tooling
issues the executor certificate directly: `bolina ca issue --role executor …` against the
same directory. Executor certs are capped at 30 days (BE-REV-01); the CI integration must
alarm before expiry (PREMORTEM item 1) — reissue is one command, forgetting it is the
product's most likely death.
