package wire

// Negative discipline (premortem item 2): passing the happy-path vectors
// is not enough — the codec must also reject what the reference parser
// rejects. Totality sweeps (every strict prefix fails), trailing bytes,
// canonical-order violations, bound violations, and wrong-domain-tag
// signature rejection.

import (
	"encoding/binary"
	"testing"
)

func certWire(t *testing.T) []byte {
	t.Helper()
	return mustHex(t, loadVectors(t).Structures.Cert.WireHex)
}

func spanWire(t *testing.T) []byte {
	t.Helper()
	return mustHex(t, loadVectors(t).Structures.Span.WireHex)
}

// BE-WIRE-02 totality: every strict prefix of a valid cert must fail,
// and never panic or read out of bounds.
func TestCertTruncationTotality(t *testing.T) {
	wire := certWire(t)
	for i := 0; i < len(wire); i++ {
		if _, err := ParseCert(wire[:i]); err == nil {
			t.Fatalf("ParseCert accepted a %d-byte prefix of a %d-byte cert", i, len(wire))
		}
	}
}

func TestCertTrailingByte(t *testing.T) {
	wire := append(append([]byte{}, certWire(t)...), 0x00)
	if _, err := ParseCert(wire); err == nil {
		t.Fatal("ParseCert accepted a trailing byte")
	}
}

// CA keys must be strictly ascending: swapping the two pairs of the
// vector cert (which carries 2 CA sigs in ascending order) must fail.
func TestCertCAOrderViolation(t *testing.T) {
	wire := certWire(t)
	cert, err := ParseCert(wire)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	if cert.CASigCount != 2 {
		t.Skipf("vector cert has %d CA sigs, test wants 2", cert.CASigCount)
	}
	const pairLen = LenCAKey + LenCASig
	swapped := append([]byte{}, wire[:len(cert.TBS)+1]...) // tbs + count byte
	swapped = append(swapped, cert.CASigs[pairLen:2*pairLen]...)
	swapped = append(swapped, cert.CASigs[:pairLen]...)
	if _, err := ParseCert(swapped); err == nil {
		t.Fatal("ParseCert accepted descending CA key order")
	}
}

// A duplicated CA key is not strictly ascending either.
func TestCertCADuplicateKey(t *testing.T) {
	wire := certWire(t)
	cert, err := ParseCert(wire)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	if cert.CASigCount != 2 {
		t.Skipf("vector cert has %d CA sigs, test wants 2", cert.CASigCount)
	}
	const pairLen = LenCAKey + LenCASig
	dup := append([]byte{}, wire[:len(cert.TBS)+1]...)
	dup = append(dup, cert.CASigs[:pairLen]...)
	dup = append(dup, cert.CASigs[:pairLen]...) // same pair twice
	if _, err := ParseCert(dup); err == nil {
		t.Fatal("ParseCert accepted a duplicate CA key")
	}
}

// ca_sig_count of zero is a parse failure (SPEC §3.1: 1..4).
func TestCertCACountZero(t *testing.T) {
	wire := certWire(t)
	cert, err := ParseCert(wire)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	zeroed := append([]byte{}, wire[:len(cert.TBS)]...)
	zeroed = append(zeroed, 0) // ca_sig_count = 0, nothing after
	if _, err := ParseCert(zeroed); err == nil {
		t.Fatal("ParseCert accepted ca_sig_count = 0")
	}
}

// scope_count above MaxScope is a parse failure before any scope bytes
// are read (a hand-built minimal prefix suffices).
func TestCertScopeOversize(t *testing.T) {
	var b []byte
	b = append(b, 3, 0x03)                  // version, role_bits
	b = append(b, make([]byte, 64)...)      // sig_pubkey + kex_pubkey
	b = append(b, make([]byte, 16)...)      // not_before + not_after
	b = binary.BigEndian.AppendUint16(b, 0) // name_len = 0
	b = append(b, MaxScope+1)               // scope_count = 9
	if _, err := ParseCert(b); err != ErrOversize {
		t.Fatalf("ParseCert(scope_count=9) = %v, want ErrOversize", err)
	}
}

func TestSpanTruncationTotality(t *testing.T) {
	wire := spanWire(t)
	for i := 0; i < len(wire); i++ {
		if _, err := ParseSpan(wire[:i]); err == nil {
			t.Fatalf("ParseSpan accepted a %d-byte prefix of a %d-byte span", i, len(wire))
		}
	}
}

func TestSpanTrailingByte(t *testing.T) {
	wire := append(append([]byte{}, spanWire(t)...), 0x00)
	if _, err := ParseSpan(wire); err == nil {
		t.Fatal("ParseSpan accepted a trailing byte")
	}
}

// BE-SIG-01: a valid signature under the wrong domain tag must refuse —
// the whole point of the tag table.
func TestSpanWrongDomainTag(t *testing.T) {
	span, err := ParseSpan(spanWire(t))
	if err != nil {
		t.Fatalf("ParseSpan: %v", err)
	}
	for _, tag := range []byte{DomainCert, DomainEnvelope, DomainGrant, DomainBinding, DomainRefusal} {
		if err := VerifySigned(tag, span.TBS, span.Sig, span.Executor); err == nil {
			t.Errorf("signature accepted under wrong domain tag 0x%02x", tag)
		}
	}
}

// A single flipped TBS bit must refuse (BE-WIRE-03: signatures cover the
// transmitted bytes exactly).
func TestSpanFlippedBit(t *testing.T) {
	wire := append([]byte{}, spanWire(t)...)
	wire[3] ^= 0x01 // inside span_id, inside TBS
	span, err := ParseSpan(wire)
	if err != nil {
		t.Fatalf("ParseSpan: %v", err)
	}
	if err := span.VerifySig(); err == nil {
		t.Fatal("signature accepted over a flipped TBS bit")
	}
}

// BE-EVID-13: unknown method ids fall to the Inference floor, never up.
func TestUnknownMethodFloorsToInference(t *testing.T) {
	for _, id := range []byte{0, 9, 42, 255} {
		class, ceiling := ClassOf(id)
		if class != Inference || ceiling != CeilingInference {
			t.Errorf("ClassOf(%d) = %v/%d, want Inference/%d", id, class, ceiling, CeilingInference)
		}
	}
}
