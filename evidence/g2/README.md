# G2 interop evidence — committed so verification needs no attachment

The G2 gate (D-092): a Go Noise_IK initiator (this repo) completes a live
handshake with a real Zig `bolina` daemon, both bind under BE-TR-01, and a
Go-built Intent envelope is admitted by the daemon's state machine. This
directory holds the signed evidence so anyone can verify it from git —
no file transfer in the loop, which is the product's own thesis.

## Files

| File | What it is |
|---|---|
| `g2.receipt` | The Lastro receipt: a Bolina Span (SPEC §7.1) signed by the runner-g3 executor identity `a1c71dab7e4c24a3`, over the observed run |
| `g2-observed.log` | The exact byte stream the receipt's digest covers (the interop run + admission state) |
| `g2run.out` | The `lastro run` wrapper output (resource, digest, exit) |
| `stageC2.out` | The three-stage interop ladder, verbose |
| `daemon.log` | The Zig daemon's boot log for the run |

## What it proves

Against the **conformant** daemon (Bolina `9447ca8`, after the SPEC §4.1a
index-swap fix `e4fd0d4`), both sides at the conformant wire layout:

```
[A] handshake complete · transcript h identical both sides
[B] mutual binding verified · cert chain clock-free (BE-HIST-01)
[C] GET /v1/intents/<id> -> pending   (Go intent admitted by Zig)
```

The prior receipt (against the swapped daemon, via a workaround client)
is superseded — see Bolina D-095. This is the receipt against conformant
code on both ends.

## Verify it yourself

```sh
# 1. build the verifier
go build -o /tmp/lastro ./cmd/lastro

# 2. get the CI CA anchors and the runner-g3 cert from the bolina repo
#    (public material, committed there): ci/ca/ca/ca0.pub, ca1.pub, and
#    the runner-g3 cert.

# 3. verify
/tmp/lastro verify --cert <runner-g3 cert.bin> \
    --ca <ca0.pub> --ca <ca1.pub> evidence/g2/g2.receipt
```

Expected: `receipt: VERIFIED`, resource
`bol:a1c71dab7e4c24a3/git/bolina/9447ca8.../check/g2-interop-live`,
digest `de91a82a1a43c585fa02ff2744f7ab0e8422344eeacdbfdf803e75dfd88fe39f`,
chain validated clock-free.
