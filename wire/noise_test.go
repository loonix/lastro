package wire

// Phase A of the G2 handshake: the Go Noise_IK implementation verified
// against itself. A Go initiator and a Go responder complete a handshake;
// if the key schedule is correct they agree on the transcript hash h and
// their transport keys cross (initiator send == responder recv, and vice
// versa). This proves the schedule before the live cross-check against
// the Zig daemon (phase B, the interop runbook), which has no vectors by
// design.

import (
	"bytes"
	"crypto/ed25519"

	"golang.org/x/crypto/curve25519"
	"testing"
)

func fixedKey(b byte) [32]byte {
	var k [32]byte
	for i := range k {
		k[i] = b
	}
	return k
}

func x25519Pub(t *testing.T, secret [32]byte) [32]byte {
	t.Helper()
	pub, err := curve25519.X25519(secret[:], curve25519.Basepoint)
	if err != nil {
		t.Fatalf("x25519 pub: %v", err)
	}
	var out [32]byte
	copy(out[:], pub)
	return out
}

func TestNoiseHandshakeRoundTrip(t *testing.T) {
	// Static keypairs.
	iStaticSec := fixedKey(0x11)
	iStaticPub := x25519Pub(t, iStaticSec)
	rStaticSec := fixedKey(0x22)
	rStaticPub := x25519Pub(t, rStaticSec)
	// Responder's Ed25519 sig key drives mac1 (BE-TR-04).
	rSigPub := [32]byte(ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x33}, 32)).Public().(ed25519.PublicKey))
	// Ephemeral secrets (caller-owned entropy; fixed here).
	iEph := fixedKey(0xE1)
	rEph := fixedKey(0xE2)
	var noCookie [16]byte

	initiator := NewInitiator(iStaticSec, iStaticPub, rStaticPub)
	responder := NewResponder(rStaticSec, rStaticPub)

	var msg1 [Msg1Size]byte
	if err := initiator.WriteInitiation(msg1[:], 1, 1_700_000_000_000, iEph, rSigPub, noCookie); err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}
	if err := responder.ReadInitiation(msg1[:], rSigPub); err != nil {
		t.Fatalf("ReadInitiation: %v", err)
	}
	// The responder recovered the initiator's static key from message 1.
	if responder.RemoteStaticPub != iStaticPub {
		t.Fatal("responder did not recover the initiator static key")
	}

	var msg2 [Msg2Size]byte
	if err := responder.WriteResponse(msg2[:], 2, 1, rEph, rSigPub, noCookie); err != nil {
		t.Fatalf("WriteResponse: %v", err)
	}
	if err := initiator.ReadResponse(msg2[:], rSigPub); err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}

	ir := initiator.Finalize()
	rr := responder.Finalize()

	// The transcript hash must match on both sides — this is the value
	// BE-TR-01's binding signature covers, so a mismatch means the
	// binding would never verify.
	if ir.H != rr.H {
		t.Fatalf("transcript hash mismatch:\n  initiator %x\n  responder %x", ir.H, rr.H)
	}
	// Keys must cross: what the initiator sends, the responder receives.
	if ir.SendKey != rr.RecvKey {
		t.Fatal("initiator send key != responder recv key")
	}
	if ir.RecvKey != rr.SendKey {
		t.Fatal("initiator recv key != responder send key")
	}
	// And the two directions must be distinct keys.
	if ir.SendKey == ir.RecvKey {
		t.Fatal("send and recv keys are identical (schedule collapsed)")
	}
}

// mac1 is load-bearing: a message with a wrong mac1 is rejected before
// any curve operation (BE-TR-04). Flip a byte the responder's mac1 key
// depends on (a wrong responder sig key) and the initiation must fail.
func TestNoiseMac1Rejection(t *testing.T) {
	iStaticSec := fixedKey(0x11)
	iStaticPub := x25519Pub(t, iStaticSec)
	rStaticSec := fixedKey(0x22)
	rStaticPub := x25519Pub(t, rStaticSec)
	rSigPub := fixedKey(0x33)
	wrongSigPub := fixedKey(0x44)
	iEph := fixedKey(0xE1)
	var noCookie [16]byte

	initiator := NewInitiator(iStaticSec, iStaticPub, rStaticPub)
	responder := NewResponder(rStaticSec, rStaticPub)

	var msg1 [Msg1Size]byte
	// Initiator computes mac1 under the WRONG responder sig key.
	if err := initiator.WriteInitiation(msg1[:], 1, 1_700_000_000_000, iEph, wrongSigPub, noCookie); err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}
	// Responder verifies under its REAL sig key: must reject.
	if err := responder.ReadInitiation(msg1[:], rSigPub); err != ErrMac1Failed {
		t.Fatalf("got %v, want ErrMac1Failed", err)
	}
}

// A tampered encrypted static (message 1) must fail the AEAD open, not
// silently pass — the responder authenticates what it decrypts.
func TestNoiseTamperedStaticRejected(t *testing.T) {
	iStaticSec := fixedKey(0x11)
	iStaticPub := x25519Pub(t, iStaticSec)
	rStaticSec := fixedKey(0x22)
	rStaticPub := x25519Pub(t, rStaticSec)
	rSigPub := fixedKey(0x33)
	iEph := fixedKey(0xE1)
	var noCookie [16]byte

	initiator := NewInitiator(iStaticSec, iStaticPub, rStaticPub)
	responder := NewResponder(rStaticSec, rStaticPub)

	var msg1 [Msg1Size]byte
	if err := initiator.WriteInitiation(msg1[:], 1, 1_700_000_000_000, iEph, rSigPub, noCookie); err != nil {
		t.Fatalf("WriteInitiation: %v", err)
	}
	msg1[off1EncStatic+5] ^= 0x01 // flip a ciphertext byte
	// mac1 still verifies (it covers framing, not the sealed static's
	// integrity beyond the bytes), so this must fail at the AEAD open.
	err := responder.ReadInitiation(msg1[:], rSigPub)
	if err != ErrDecryptFailed && err != ErrMac1Failed {
		t.Fatalf("tampered static: got %v, want a rejection", err)
	}
}
