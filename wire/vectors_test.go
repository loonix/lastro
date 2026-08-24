package wire

// Conformance against the frozen Bolina vectors (test/vectors.json,
// vendored in testdata/ — see testdata/VECTORS-SOURCE.md for provenance).
// These tests are the definition of correctness for this package: a
// change that breaks one is a bug here, never a "difference".

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"golang.org/x/crypto/curve25519"
)

type vectorsFile struct {
	Primitives struct {
		Blake2sKnown []struct {
			Input string `json:"input"`
			Hex   string `json:"hex"`
		} `json:"blake2s_known"`
	} `json:"primitives"`
	Keys map[string]struct {
		Seed        string `json:"seed"`
		SigPubkey   string `json:"sig_pubkey"`
		KexSeed     string `json:"kex_seed"`
		KexPubkey   string `json:"kex_pubkey"`
		OverlayAddr string `json:"overlay_addr"`
	} `json:"keys"`
	Addressing struct {
		Vectors []struct {
			SigPubkey   string `json:"sig_pubkey"`
			OverlayAddr string `json:"overlay_addr"`
		} `json:"vectors"`
	} `json:"addressing"`
	MethodIDTable struct {
		Rows []struct {
			MethodID  int    `json:"method_id"`
			Class     string `json:"class"`
			CeilingQ8 int    `json:"ceiling_q8"`
		} `json:"rows"`
	} `json:"method_id_table"`
	Digests []struct {
		Name      string `json:"name"`
		InputUTF8 string `json:"input_utf8"`
		Blake2s   string `json:"blake2s"`
	} `json:"digests"`
	ResourceID struct {
		Value string `json:"value"`
	} `json:"resource_id"`
	Structures struct {
		Cert certVec `json:"cert"`
		Span spanVec `json:"span"`
	} `json:"structures"`
}

type certVec struct {
	DomainTag   string `json:"domain_tag"`
	TbsHex      string `json:"tbs_hex"`
	SigInputHex string `json:"sig_input_hex"`
	CASigs      []struct {
		CAKey string `json:"ca_key"`
		Sig   string `json:"sig"`
	} `json:"ca_sigs"`
	WireHex string `json:"wire_hex"`
	Verify  string `json:"verify"`
	Fields  struct {
		Version    int    `json:"version"`
		SigPubkey  string `json:"sig_pubkey"`
		KexPubkey  string `json:"kex_pubkey"`
		NotBefore  uint64 `json:"not_before"`
		NotAfter   uint64 `json:"not_after"`
		Name       string `json:"name"`
		ScopeCount int    `json:"scope_count"`
		ScopeID    string `json:"scope_id"`
		CASigCount int    `json:"ca_sig_count"`
	} `json:"fields"`
}

type spanVec struct {
	DomainTag    string `json:"domain_tag"`
	TbsHex       string `json:"tbs_hex"`
	SigInputHex  string `json:"sig_input_hex"`
	SigHex       string `json:"sig_hex"`
	SignerPubkey string `json:"signer_pubkey"`
	WireHex      string `json:"wire_hex"`
	MethodClass  string `json:"method_id_class"`
	CeilingQ8    int    `json:"ceiling_q8"`
	Verify       string `json:"verify"`
}

func loadVectors(t *testing.T) *vectorsFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorsFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &v
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in vector: %v", err)
	}
	return b
}

func TestBlake2sKnownAnswers(t *testing.T) {
	v := loadVectors(t)
	if len(v.Primitives.Blake2sKnown) == 0 {
		t.Fatal("no blake2s known-answer vectors")
	}
	for _, ka := range v.Primitives.Blake2sKnown {
		got := Blake2s256([]byte(ka.Input))
		if hex.EncodeToString(got[:]) != ka.Hex {
			t.Errorf("blake2s(%q) = %x, vector says %s", ka.Input, got, ka.Hex)
		}
	}
}

func TestKeyDerivationAgreesWithVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.Keys) == 0 {
		t.Fatal("no key vectors")
	}
	for name, k := range v.Keys {
		seed := mustHex(t, k.Seed)
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		if hex.EncodeToString(pub) != k.SigPubkey {
			t.Errorf("%s: derived sig_pubkey %x != vector %s", name, pub, k.SigPubkey)
		}
		kexPub, err := curve25519.X25519(mustHex(t, k.KexSeed), curve25519.Basepoint)
		if err != nil {
			t.Fatalf("%s: x25519: %v", name, err)
		}
		if hex.EncodeToString(kexPub) != k.KexPubkey {
			t.Errorf("%s: derived kex_pubkey %x != vector %s", name, kexPub, k.KexPubkey)
		}
		addr := OverlayAddr(pub)
		if hex.EncodeToString(addr[:]) != k.OverlayAddr {
			t.Errorf("%s: overlay %x != vector %s", name, addr, k.OverlayAddr)
		}
	}
}

func TestAddressingVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.Addressing.Vectors) == 0 {
		t.Fatal("no addressing vectors")
	}
	for i, av := range v.Addressing.Vectors {
		addr := OverlayAddr(mustHex(t, av.SigPubkey))
		if hex.EncodeToString(addr[:]) != av.OverlayAddr {
			t.Errorf("addressing[%d]: %x != %s", i, addr, av.OverlayAddr)
		}
	}
}

func TestMethodTableMatchesVectors(t *testing.T) {
	v := loadVectors(t)
	if len(v.MethodIDTable.Rows) == 0 {
		t.Fatal("no method table rows")
	}
	for _, row := range v.MethodIDTable.Rows {
		class, ceiling := ClassOf(byte(row.MethodID))
		if class.String() != row.Class {
			t.Errorf("method %d: class %s, vector says %s", row.MethodID, class, row.Class)
		}
		if int(ceiling) != row.CeilingQ8 {
			t.Errorf("method %d: ceiling %d, vector says %d", row.MethodID, ceiling, row.CeilingQ8)
		}
	}
}

func TestDigestVectors(t *testing.T) {
	v := loadVectors(t)
	for _, d := range v.Digests {
		got := Blake2s256([]byte(d.InputUTF8))
		if hex.EncodeToString(got[:]) != d.Blake2s {
			t.Errorf("digest %s: %x != %s", d.Name, got, d.Blake2s)
		}
	}
}

func TestCertVector(t *testing.T) {
	v := loadVectors(t)
	cv := v.Structures.Cert
	if cv.Verify != "true" {
		t.Fatalf("cert vector expects verify=%q", cv.Verify)
	}
	wire := mustHex(t, cv.WireHex)
	cert, err := ParseCert(wire)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	// Decoded fields against the vector's field record.
	f := cv.Fields
	if int(cert.Version) != f.Version {
		t.Errorf("version %d != %d", cert.Version, f.Version)
	}
	if hex.EncodeToString(cert.SigPubkey) != f.SigPubkey {
		t.Errorf("sig_pubkey mismatch")
	}
	if hex.EncodeToString(cert.KexPubkey) != f.KexPubkey {
		t.Errorf("kex_pubkey mismatch")
	}
	if cert.NotBefore != f.NotBefore || cert.NotAfter != f.NotAfter {
		t.Errorf("validity window mismatch: %d..%d != %d..%d", cert.NotBefore, cert.NotAfter, f.NotBefore, f.NotAfter)
	}
	if string(cert.Name) != f.Name {
		t.Errorf("name %q != %q", cert.Name, f.Name)
	}
	if int(cert.ScopeCount) != f.ScopeCount {
		t.Errorf("scope_count %d != %d", cert.ScopeCount, f.ScopeCount)
	}
	if hex.EncodeToString(cert.ScopeIDs) != f.ScopeID {
		t.Errorf("scope_ids %x != %s", cert.ScopeIDs, f.ScopeID)
	}
	if int(cert.CASigCount) != f.CASigCount {
		t.Errorf("ca_sig_count %d != %d", cert.CASigCount, f.CASigCount)
	}
	// TBS boundary and signature input are byte-exact per the vector.
	if hex.EncodeToString(cert.TBS) != cv.TbsHex {
		t.Errorf("tbs mismatch")
	}
	sigInput := append([]byte{DomainCert}, cert.TBS...)
	if hex.EncodeToString(sigInput) != cv.SigInputHex {
		t.Errorf("sig_input mismatch")
	}
	// Every (ca_key, sig) pair matches the vector and verifies.
	pairs := cert.CAPairs()
	if len(pairs) != len(cv.CASigs) {
		t.Fatalf("%d pairs != %d in vector", len(pairs), len(cv.CASigs))
	}
	var trusted [][]byte
	for i, p := range pairs {
		if hex.EncodeToString(p.Key) != cv.CASigs[i].CAKey {
			t.Errorf("pair %d ca_key mismatch", i)
		}
		if hex.EncodeToString(p.Sig) != cv.CASigs[i].Sig {
			t.Errorf("pair %d sig mismatch", i)
		}
		trusted = append(trusted, p.Key)
	}
	if err := cert.VerifyCASignatures(nil); err != nil {
		t.Errorf("VerifyCASignatures(nil): %v", err)
	}
	if err := cert.VerifyCASignatures(trusted); err != nil {
		t.Errorf("VerifyCASignatures(trusted): %v", err)
	}
	// An untrusted set must refuse even with valid signatures (BE-ID-02).
	if err := cert.VerifyCASignatures([][]byte{make([]byte, 32)}); err == nil {
		t.Error("VerifyCASignatures accepted an untrusted CA")
	}
}

func TestSpanVector(t *testing.T) {
	v := loadVectors(t)
	sv := v.Structures.Span
	if sv.Verify != "true" {
		t.Fatalf("span vector expects verify=%q", sv.Verify)
	}
	wire := mustHex(t, sv.WireHex)
	span, err := ParseSpan(wire)
	if err != nil {
		t.Fatalf("ParseSpan: %v", err)
	}
	if hex.EncodeToString(span.TBS) != sv.TbsHex {
		t.Errorf("tbs mismatch")
	}
	sigInput := append([]byte{DomainSpan}, span.TBS...)
	if hex.EncodeToString(sigInput) != sv.SigInputHex {
		t.Errorf("sig_input mismatch")
	}
	if hex.EncodeToString(span.Sig) != sv.SigHex {
		t.Errorf("sig mismatch")
	}
	if hex.EncodeToString(span.Executor) != sv.SignerPubkey {
		t.Errorf("executor %x != signer_pubkey %s", span.Executor, sv.SignerPubkey)
	}
	if err := span.VerifySig(); err != nil {
		t.Errorf("VerifySig: %v", err)
	}
	class, ceiling := ClassOf(span.MethodID)
	if class.String() != sv.MethodClass {
		t.Errorf("class %s != %s", class, sv.MethodClass)
	}
	if int(ceiling) != sv.CeilingQ8 {
		t.Errorf("ceiling %d != %d", ceiling, sv.CeilingQ8)
	}
}

func TestExecutorFingerprintMatchesResourceID(t *testing.T) {
	v := loadVectors(t)
	execKey, ok := v.Keys["executor"]
	if !ok {
		t.Skip("no executor key in vectors")
	}
	fp := Fingerprint(mustHex(t, execKey.SigPubkey))
	want := "bol:" + fp + "/"
	if !bytes.HasPrefix([]byte(v.ResourceID.Value), []byte(want)) {
		t.Errorf("resource_id %q does not start with %q (BE-RES-06)", v.ResourceID.Value, want)
	}
}
