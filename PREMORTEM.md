# Premortem — written before the first line of code

**Date:** 2026-08-24 · **Product:** **Prova** — signed receipts for AI/CI work over the
Bolina protocol *(named 2026-08-24 after the risk-5 collision check; "attest" was the
working name and was rejected for colliding with GitHub's `gh attestation` vocabulary)* · **Exercise:** it is six months from now and this project is dead
or worse-than-dead (half-alive, teaching people that receipts rot). These are the ways it
happened, ranked by how likely I believe each one is, each with the earliest symptom and the
mitigation now baked into the plan. The discipline is Bolina's own: every failure records a
cause, and a risk named before it fires is a risk you can put a tripwire on.

---

## 1. The 30-day cert chore killed it *(most likely killer)*

**How it died.** BE-REV-01 caps executor certs at 30 days. Month one, the CI cert expired on
a Tuesday; Daniel was deep in Objais work; the seal pipeline went red (or worse, receipts
silently stopped appearing); three weeks later someone reissued it; month three nobody
reissued it. A red badge that stays red becomes furniture. The project taught its own repo
that receipts are optional — the exact opposite of its thesis.

**Earliest symptom.** The first expiry lands as a surprise instead of a calendar event.

**Mitigations baked in.**
- CI job fails **loudly N=7 days before** cert expiry with the one-line reissue command in
  the failure message, not just at expiry.
- The reissue is one documented command (`bolina ca issue --role executor …`), tested once
  end to end before phase 3 lands.
- Phase 3 does not merge into the Bolina repo until this alarm exists. A half-integration
  that can rot silently is worse than no integration.
- Honest note upstream: this chore is real product feedback about BE-REV-01's operational
  cost. Recorded for the crab's post-1.0 queue, not "solved" locally with a 10-year cert.

## 2. Receipts nobody reads *(most likely form of zombie survival)*

**How it died.** We produced receipts; they sat as CI artifacts; no human ever ran
`attest verify`; the seal paragraphs cited files nobody opened. Evidence without a consumer
is cost without value — the project didn't fail loudly, it just never mattered.

**Earliest symptom.** A release ships and nobody — including us — verified its receipts.

**Mitigations baked in.**
- The receipt is **rendered where eyes already are**: the seal paragraph / PR comment carries
  the human-readable summary (command, exit, digest, class, ceiling) plus the one-line verify
  command. Verification must be one copy-paste, zero setup beyond the binary.
- The first named consumer exists before the receipts do: the G1 external reviewer, whose
  brief will point at the sealed receipts as mechanically checkable claims.
- Tripwire: if by the second sealed release no one outside this session has verified a
  receipt, that is a product-thesis warning to confront, not ignore.

## 3. The detached profile drifted into a protocol fork

**How it died.** The MVP zeroed `origin` (no ledger in CI — one honest deviation). Then the
cert felt heavy, so we "simplified" it. Then the wire format grew a convenience field. Six
months in, attest receipts were no longer Bolina spans — the product stopped proving the
protocol and started proving an undocumented cousin, and the "the protocol seals itself with
itself" story became false without anyone deciding it.

**Earliest symptom.** A second deviation from SPEC bytes, made for convenience, without a
written decision.

**Mitigations baked in.**
- Hard rule, stated in RECEIPT-PROFILE.md: **wire bytes are SPEC bytes**, conformance is the
  frozen `test/vectors.json`, and the detached profile contains exactly **one** deviation
  (`origin = 0³²`, meaning "no causal anchor"). Any second deviation requires a written
  decision entry in this repo — the Bolina D-number discipline, imported.
- The conformance test against the frozen vectors runs in CI from day 1; a codec change that
  breaks a vector cannot merge.

## 4. Same-box theater in our own deployment *(the HN comment we predicted, come true)*

**How it died.** The signing key lived as a plain GitHub Actions secret. A fork PR with
workflow access — or any step in a compromised dependency chain — could read the key and sign
fake receipts. Someone noticed, wrote exactly the comment we ourselves predicted ("you moved
trust from the model to a file permission"), and the credibility of the self-sealing story
died in public.

**Earliest symptom.** The key is reachable from any workflow triggered by untrusted input.

**Mitigations baked in.**
- The key lives in a **protected environment** scoped to release/seal workflows on protected
  branches only; fork PRs and unprotected workflows never see it.
- RECEIPT-PROFILE.md states the trust model without inflation: a CI receipt proves *"this
  platform's runner executed this command in this workflow"* — at the CI platform's trust
  level, no more. Same-box limits declared before anyone else declares them for us.
- The premortem for the *product* stage (user machines) already exists in the strategy: L1 is
  CI-first precisely because the runner is a separate trust domain.

## 5. GitHub shipped this first *(the positioning death)*

**How it died.** GitHub's own **artifact attestations** (`gh attestation`, Sigstore-based)
already exist and cover build provenance natively, one flag away, zero setup. We launched a
tool that at first glance does the same thing but needs its own CA, its own binary, and a
30-day cert chore. Nobody read past the first paragraph to find the difference. The name
"attest" made the collision worse — we looked like a worse copy of a platform feature.

**Earliest symptom.** The first outside reader asks "how is this different from
`gh attestation`?" and the README has no answer above the fold.

**Mitigations baked in.**
- The differentiation is real and must be the *first thing said*: GitHub attests **artifact
  provenance** (this binary came from this build); we attest **runtime claims with reader-side
  confidence arithmetic** (this agent's statement is backed by this observation, worth at most
  X) — plus human-signed byte-exact authority at L3, vendor-neutral, no platform dependency.
  If that paragraph cannot be written crisply, that is a thesis problem to face, not defer.
- **Working name "attest" rejected; public name decided: Prova** (2026-08-24). Collision
  check across Prova/Aval/Lacre/Selo: Prova clean (nearest neighbour Prove.com, identity
  verification, different space); Aval taken by an active OSS project; Lacre is an existing
  security-adjacent GitHub org; Selo phonetically collides with Silo, an agent tool.
  Remaining due-diligence before repo-public: domain and trademark pass.
- Interop, not rivalry: emitting a Sigstore/in-toto-compatible export was already on the
  roadmap from the HN exercise; it turns the incumbent into a distribution channel.

## 6. The digest measured noise

**How it died.** `attest run` hashed stdout+stderr of test suites whose output embeds
timestamps, ordering jitter and progress bars. Every run's digest differed; the digest proved
nothing anyone could compare; readers learned the receipt's strongest field was decoration.
Separately: a mutation run's log was gigabytes and the capture was silently truncated — a
receipt claiming to attest output it never fully observed (a BE-EVID-14 violation in spirit).

**Earliest symptom.** Two identical green runs produce different digests and nobody can say
what the digest is *for*.

**Mitigations baked in.**
- The capture contract is defined in RECEIPT-PROFILE.md before code: what is captured
  (stdout+stderr, interleaved, byte-exact), the size cap, and the explicit rule that an
  output exceeding the cap produces **no receipt** rather than a receipt of a truncation
  (BE-EVID-14's rule, imported).
- The receipt's claim is scoped honestly: the digest proves *what was observed at this run*,
  it is not a reproducibility claim. The comparable, stable fields are exit code and
  resource_id (which embeds the commit SHA — the freshness anchor).

## 7. Selection bias — we only attested the runs that passed

**How it died.** A flaky suite failed; CI re-ran it; only the green run got a receipt. The
receipts were all true and the picture they painted was false. Nobody lied; the process
selected.

**Mitigation baked in.** Receipts are emitted for **every** run of an attested step, red and
green; the seal cites the receipt of the run it ships, and re-runs are visible as multiple
receipts for the same (sha, check). R2's lesson — never accept a single-sided metric —
applied to ourselves.

## 8. Scope crept back to L3 before L1 was solid

**How it died.** Grants and approval UX were more exciting than polishing capture semantics,
so we built half of each. L1 receipts stayed janky; L3 shipped without its key-custody story;
both halves discredited each other.

**Mitigation baked in.** L3 has an explicit entry condition, written here: **receipts stable
in two repos for one month** (green pipeline, zero rotted certs, zero profile deviations)
before any grant/approval code lands in this repo.

## 9. The feedback loop broke the crab's freeze

**How it died.** Dogfooding surfaced protocol warts (detached origin, cert lifetimes, cert
distribution). Each looked one-commit small. We forwarded them as "quick fixes"; the v1.0
freeze eroded commit by commit; the crab's gates slipped; both projects ended half-done.

**Mitigation baked in.** The triage contract, restated where the temptation will strike:
protocol *bug* → goes up now; protocol *wish* → post-1.0 queue, recorded here; product
friction → ours, protocol untouched. The premortem's job is to make the wish-vs-bug
distinction feel expensive to blur.

## 10. Owner starvation *(the boring one that compounds all others)*

**How it died.** Daniel's real job is Objais. The project needed four hours a week and got
zero for six weeks at the wrong moment (a cert expiry + a vectors update landed in the same
window). Nothing failed dramatically; everything decayed simultaneously.

**Mitigations baked in.**
- Phase gates sized so every phase ends in a *stable* state — the repo is never left
  mid-migration. Phase 1 (codec + vectors) is complete alone; phase 2 (CLI) is complete
  alone; phase 3 only lands with its alarm.
- Everything automatable is automated at land time (vector conformance in CI, cert alarm),
  so the idle-state maintenance cost is as close to zero as we can make it.
- This premortem is the standing scope-cut authority: when time is short, the answer is
  "cut scope to the last stable phase", never "ship the half-phase".

---

## What this premortem changed in the plan, summarized

1. Phase 3 gains a **cert-expiry alarm as a merge condition** (risk 1).
2. Phase 1 gains **negative-vector + differential discipline**, not just happy-path vectors
   (risks 3, 6 — the codec must reject what the Zig parser rejects).
3. Phase 2's first deliverable is **RECEIPT-PROFILE.md** — capture contract, the single
   origin deviation, the CI trust model, the honest scope of the digest (risks 3, 4, 6).
4. **"attest" demoted to internal working name**; public naming decision now blocks
   repo-public, with the `gh attestation` collision recorded (risk 5).
5. Receipts for **every run, red and green** (risk 7).
6. **L3 entry condition** written down (risk 8).
7. The **triage contract** is part of this repo's docs, not just conversation (risk 9).
8. Phases must each end stable; scope-cut rule standing (risk 10).
