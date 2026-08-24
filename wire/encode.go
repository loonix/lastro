package wire

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"
)

// Encoders for the structures Prova mints. Encoding is the exact inverse
// of the parsers in this package: the round-trip and vector re-encode
// tests in encode_test.go pin that property.

var ErrFieldBounds = errors.New("wire: field exceeds declared bound")

// SpanFields is everything a span signs over (SPEC §7.1). The detached
// profile (RECEIPT-PROFILE.md §1) sets Origin to 32 zero bytes.
type SpanFields struct {
	Version    byte
	SpanID     [LenSpanID]byte
	TraceID    [LenTraceID]byte
	ResourceID []byte // <= MaxResource
	MethodID   byte
	Volatility byte
	Origin     [LenOrigin]byte
	ObservedAt uint64
	Digest     [LenDigest]byte
	Executor   [LenPubkey]byte
}

// EncodeSpanTBS serializes the to-be-signed region of a span.
func EncodeSpanTBS(f *SpanFields) ([]byte, error) {
	if len(f.ResourceID) > MaxResource {
		return nil, ErrFieldBounds
	}
	out := make([]byte, 0, 1+LenSpanID+LenTraceID+2+len(f.ResourceID)+1+1+LenOrigin+8+LenDigest+LenPubkey)
	out = append(out, f.Version)
	out = append(out, f.SpanID[:]...)
	out = append(out, f.TraceID[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(f.ResourceID)))
	out = append(out, f.ResourceID...)
	out = append(out, f.MethodID, f.Volatility)
	out = append(out, f.Origin[:]...)
	out = binary.BigEndian.AppendUint64(out, f.ObservedAt)
	out = append(out, f.Digest[:]...)
	out = append(out, f.Executor[:]...)
	return out, nil
}

// BuildSpan serializes and signs a complete span: TBS || Ed25519 over
// (DomainSpan || TBS). The private key must correspond to f.Executor.
func BuildSpan(f *SpanFields, priv ed25519.PrivateKey) ([]byte, error) {
	tbs, err := EncodeSpanTBS(f)
	if err != nil {
		return nil, err
	}
	sig := SignTagged(DomainSpan, tbs, priv)
	return append(tbs, sig...), nil
}

// CertFields is the to-be-signed content of a certificate (SPEC §3.1).
// Used by tests and future tooling; production certs come from the
// Bolina CA CLI.
type CertFields struct {
	Version   byte
	RoleBits  byte
	SigPubkey [LenPubkey]byte
	KexPubkey [LenKexPubkey]byte
	NotBefore uint64
	NotAfter  uint64
	Name      []byte   // <= MaxName
	ScopeIDs  [][8]byte // <= MaxScope entries
}

// EncodeCertTBS serializes the to-be-signed region of a certificate.
func EncodeCertTBS(f *CertFields) ([]byte, error) {
	if len(f.Name) > MaxName || len(f.ScopeIDs) > MaxScope {
		return nil, ErrFieldBounds
	}
	out := make([]byte, 0, 2+LenPubkey+LenKexPubkey+16+2+len(f.Name)+1+len(f.ScopeIDs)*LenScopeID)
	out = append(out, f.Version, f.RoleBits)
	out = append(out, f.SigPubkey[:]...)
	out = append(out, f.KexPubkey[:]...)
	out = binary.BigEndian.AppendUint64(out, f.NotBefore)
	out = binary.BigEndian.AppendUint64(out, f.NotAfter)
	out = binary.BigEndian.AppendUint16(out, uint16(len(f.Name)))
	out = append(out, f.Name...)
	out = append(out, byte(len(f.ScopeIDs)))
	for _, s := range f.ScopeIDs {
		out = append(out, s[:]...)
	}
	return out, nil
}

// AppendCertSignatures completes a certificate: tbs || count || pairs.
// Pairs must already be in strictly ascending ca_key order — the encoder
// refuses rather than reorders, so a caller cannot accidentally mint a
// cert the parser rejects.
func AppendCertSignatures(tbs []byte, pairs []CAPair) ([]byte, error) {
	if len(pairs) == 0 || len(pairs) > MaxCASigs {
		return nil, ErrFieldBounds
	}
	out := append(append([]byte{}, tbs...), byte(len(pairs)))
	for i, p := range pairs {
		if len(p.Key) != LenCAKey || len(p.Sig) != LenCASig {
			return nil, ErrFieldBounds
		}
		if i > 0 && string(p.Key) <= string(pairs[i-1].Key) {
			return nil, ErrMalformed
		}
		out = append(out, p.Key...)
		out = append(out, p.Sig...)
	}
	return out, nil
}
