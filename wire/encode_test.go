package wire

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

// Re-encoding the parsed vector span must reproduce the wire bytes
// exactly — encoder and parser are inverses, pinned by the frozen
// vector, not by each other.
func TestSpanReencodeMatchesVector(t *testing.T) {
	wire := mustHex(t, loadVectors(t).Structures.Span.WireHex)
	span, err := ParseSpan(wire)
	if err != nil {
		t.Fatalf("ParseSpan: %v", err)
	}
	f := SpanFields{
		Version:    span.Version,
		MethodID:   span.MethodID,
		Volatility: span.Volatility,
		ObservedAt: span.ObservedAt,
		ResourceID: span.ResourceID,
	}
	copy(f.SpanID[:], span.SpanID)
	copy(f.TraceID[:], span.TraceID)
	copy(f.Origin[:], span.Origin)
	copy(f.Digest[:], span.Digest)
	copy(f.Executor[:], span.Executor)
	tbs, err := EncodeSpanTBS(&f)
	if err != nil {
		t.Fatalf("EncodeSpanTBS: %v", err)
	}
	if !bytes.Equal(tbs, span.TBS) {
		t.Fatal("re-encoded TBS differs from parsed TBS")
	}
	full := append(append([]byte{}, tbs...), span.Sig...)
	if !bytes.Equal(full, wire) {
		t.Fatal("re-encoded span differs from vector wire bytes")
	}
}

// Build -> parse -> verify round trip with a fresh key.
func TestBuildSpanRoundTrip(t *testing.T) {
	seed := bytes.Repeat([]byte{7}, ed25519.SeedSize)
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	f := SpanFields{
		Version:    2,
		ResourceID: []byte("bol:" + Fingerprint(pub) + "/git/demo/abc123/check/tests"),
		MethodID:   MethodSubprocess,
		Volatility: VolatilityVolatile,
		ObservedAt: 1700000000000,
	}
	copy(f.SpanID[:], bytes.Repeat([]byte{1}, LenSpanID))
	copy(f.TraceID[:], bytes.Repeat([]byte{2}, LenTraceID))
	// Origin stays zero: the detached profile's single deviation.
	d := Blake2s256([]byte("captured output"))
	f.Digest = d
	copy(f.Executor[:], pub)

	wire, err := BuildSpan(&f, priv)
	if err != nil {
		t.Fatalf("BuildSpan: %v", err)
	}
	span, err := ParseSpan(wire)
	if err != nil {
		t.Fatalf("ParseSpan: %v", err)
	}
	if err := span.VerifySig(); err != nil {
		t.Fatalf("VerifySig: %v", err)
	}
	if span.ObservedAt != f.ObservedAt || span.MethodID != MethodSubprocess {
		t.Fatal("round-trip field mismatch")
	}
	if !bytes.Equal(span.Origin, make([]byte, LenOrigin)) {
		t.Fatal("detached origin is not zeroed")
	}
}

// Cert re-encode: TBS from parsed vector fields must match, and
// reassembling with the vector's own pairs must reproduce the wire.
func TestCertReencodeMatchesVector(t *testing.T) {
	wire := mustHex(t, loadVectors(t).Structures.Cert.WireHex)
	cert, err := ParseCert(wire)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	f := CertFields{
		Version:   cert.Version,
		RoleBits:  cert.RoleBits,
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
		Name:      cert.Name,
	}
	copy(f.SigPubkey[:], cert.SigPubkey)
	copy(f.KexPubkey[:], cert.KexPubkey)
	for i := 0; i < int(cert.ScopeCount); i++ {
		var s [8]byte
		copy(s[:], cert.ScopeIDs[i*LenScopeID:(i+1)*LenScopeID])
		f.ScopeIDs = append(f.ScopeIDs, s)
	}
	tbs, err := EncodeCertTBS(&f)
	if err != nil {
		t.Fatalf("EncodeCertTBS: %v", err)
	}
	if !bytes.Equal(tbs, cert.TBS) {
		t.Fatal("re-encoded cert TBS differs")
	}
	full, err := AppendCertSignatures(tbs, cert.CAPairs())
	if err != nil {
		t.Fatalf("AppendCertSignatures: %v", err)
	}
	if !bytes.Equal(full, wire) {
		t.Fatal("re-encoded cert differs from vector wire bytes")
	}
}

// The encoder refuses out-of-order CA pairs instead of reordering.
func TestAppendCertSignaturesRefusesDisorder(t *testing.T) {
	cert, err := ParseCert(mustHex(t, loadVectors(t).Structures.Cert.WireHex))
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	pairs := cert.CAPairs()
	if len(pairs) != 2 {
		t.Skip("vector cert does not carry 2 pairs")
	}
	if _, err := AppendCertSignatures(cert.TBS, []CAPair{pairs[1], pairs[0]}); err == nil {
		t.Fatal("encoder accepted descending CA pairs")
	}
}

// Chain validation (no clock) accepts the vector cert under its own CAs
// and refuses forbidden role pairings and missing trust.
func TestValidateCertChainNoClock(t *testing.T) {
	cert, err := ParseCert(mustHex(t, loadVectors(t).Structures.Cert.WireHex))
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	var trusted [][]byte
	for _, p := range cert.CAPairs() {
		trusted = append(trusted, p.Key)
	}
	if err := ValidateCertChainNoClock(cert, trusted); err != nil {
		t.Fatalf("chain validation failed on the vector cert: %v", err)
	}
	if err := ValidateCertChainNoClock(cert, [][]byte{make([]byte, 32)}); err != ErrUntrustedCA {
		t.Fatalf("untrusted set: got %v, want ErrUntrustedCA", err)
	}
	for _, bits := range []byte{RoleAgent | RoleApprover, RoleAgent | RoleExecutor, RoleApprover | RoleExecutor} {
		if err := CheckRoleConstraints(bits); err != ErrRolePairForbidden {
			t.Errorf("role bits %08b: got %v, want ErrRolePairForbidden", bits, err)
		}
	}
}
