# lastro

**Signed, verifiable receipts for AI and CI work.**

Wrap any command. Get back a cryptographic receipt of exactly what ran, what it
produced, and who vouches for it — verifiable by anyone, forever, offline.

```
lastro keygen --dir keys
lastro run --key keys --namespace ci --path build/tests -- go test ./...
lastro verify lastro.receipt --cert keys/cert.bin --ca ca.pub
```

*Lastro* is Portuguese for **ballast** — the weight that keeps a ship stable.
An *"afirmação sem lastro"* is an unbacked claim. This tool exists so that
claims about work — especially work done by AI agents — carry their ballast.

## Why this exists

AI agents and CI pipelines make claims all day: *tests passed*, *task done*,
*deployed*, *fixed*. Today those claims are prose. You either trust the actor,
or you re-run the work yourself. Neither scales — and with autonomous agents
doing real work on real systems, "trust me" is not an audit trail.

A lastro receipt turns a claim into evidence:

- **what ran** — the exact command and its arguments
- **what happened** — a digest of the captured output stream, with the exit
  code sealed inside it (receipts are produced for failing runs too; a red
  run with a receipt beats a green run without one)
- **who vouches** — an Ed25519 signature under a certificate chain, so a
  third party can verify without trusting the machine that produced it

Verification is clock-free and offline: no service to call, no timestamps to
trust, just bytes and keys.

## What a receipt proves — and what it doesn't

Honesty about the boundary is part of the design:

- A receipt proves **what ran and what it output**. It does **not** prove that
  it was the *right* check to run. Choosing good checks remains a human
  judgment; lastro makes the execution of that judgment tamper-evident.
- On a single machine, key separation protects against **mistakes, not
  malice** — a root attacker who owns the box owns the keys. In CI, the
  runner is a separate trust domain from the code under test, and receipts
  get their natural threat model for free. Start there (that is also where
  we run it daily).
- The `run`/`verify` path is **fully offline** — there is no network daemon,
  no server, nothing to deploy. It is one static binary that wraps a command.
- If a command's output exceeds the capture cap (8 MiB by default), **no
  receipt is produced** and the wrapper exits 125. A receipt that silently
  covered truncated evidence would be worse than none.

## How it relates to Bolina

Receipts are [Bolina](https://github.com/adolfousier/bolina) **evidence
objects** — an intact Span (§7.1 of the protocol), detached profile. Bolina is
a protocol where *authority* (grants) and *evidence* (spans/claims) are
cryptographic objects on the wire; lastro implements the evidence half as a
standalone tool, and doubles as the protocol's second independent
implementation: its codec passes Bolina's frozen conformance vectors
byte-for-byte, and closed the protocol's cross-language interop gate with a
live Go↔Zig handshake against the real daemon.

## Why not in-toto / Sigstore?

Different layer, complementary goals. in-toto and Sigstore attest *software
supply chains* (artifacts, builds, provenance) against registries and
transparency logs. Lastro receipts attest *work executions* — including AI
agent actions — as protocol-native evidence objects designed to compose with
Bolina's grant chains (human authority) and to verify offline with no
infrastructure. An export bridge (DSSE / in-toto predicate) is on the roadmap
so receipts can flow into existing supply-chain tooling rather than compete
with it.

## Status — the honest version

- Codec conformant to the frozen Bolina v0.6.x vectors, byte-for-byte.
- Live cross-language handshake (Go initiator ↔ Zig daemon) proven against
  the real state machine — this gate caught a wire-format bug that 176 killed
  mutants, frozen vectors and a 24-hour soak had all missed. Cheap live gates
  earn their keep.
- 24-hour chaos + differential soak on real hardware: billions of fuzzed
  inputs, zero divergences, zero panics — and the soak's own validation was
  sealed with a lastro receipt, verified with exit 0. The protocol sealed its
  own proof.
- In daily production use since September 2026, emitting a signed receipt for
  every validated change in an autonomous CI pipeline.
- Post-quantum signatures are out of scope for v1 (versioned migration path).

## The adoption ladder

1. **L1 — receipts in CI**: wrap your test/build commands. Zero risk, immediate
   audit trail. *(You are here.)*
2. **L2 — receipts on agent actions**: every consequential action an AI agent
   takes emits a receipt ("12 claims, 11 backed").
3. **L3 — human grants**: irreversible actions require a byte-exact,
   single-use grant signed on a human's own device (Bolina §8).
4. **L4 — organizational ledger**: tamper-evident audit across the org.

Each rung stands alone; none requires the next.

## Repository layout

- `cmd/lastro` — the CLI (`keygen` / `run` / `verify`)
- `wire/` — the Bolina span/envelope codec (conformance-vector tested)
- `RECEIPT-PROFILE.md` — the normative receipt profile (what is in a receipt,
  exit-code trailer, caps, deviations from a full Span — there is exactly one)
- `PREMORTEM.md` — the risks we wrote down before building, and what each one
  demands of the design
- `evidence/` — real receipts from the protocol's own gate closures, kept in
  the repo so verification needs no attachments

## License

Apache-2.0 — the same license as the Bolina reference implementation.
