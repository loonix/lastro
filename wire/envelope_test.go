package wire

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type structVec struct {
	DomainTag    string `json:"domain_tag"`
	TbsHex       string `json:"tbs_hex"`
	SigInputHex  string `json:"sig_input_hex"`
	SigHex       string `json:"sig_hex"`
	SignerPubkey string `json:"signer_pubkey"`
	WireHex      string `json:"wire_hex"`
	Verify       string `json:"verify"`
}

type negativeVec struct {
	Name   string `json:"name"`
	Wire   string `json:"wire"`
	Expect string `json:"expect"`
	Reason string `json:"reason"`
}

func loadStructsAndNegatives(t *testing.T) (map[string]structVec, []negativeVec) {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var doc struct {
		Structures map[string]structVec `json:"structures"`
		Negatives  []negativeVec        `json:"negatives"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return doc.Structures, doc.Negatives
}

func TestEnvelopeVector(t *testing.T) {
	s, _ := loadStructsAndNegatives(t)
	ev := s["envelope_intent"]
	if ev.Verify != "true" {
		t.Fatalf("envelope vector expects verify=true, got %q", ev.Verify)
	}
	env, err := ParseEnvelope(mustHex(t, ev.WireHex))
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	if hex.EncodeToString(env.TBS) != ev.TbsHex {
		t.Error("envelope tbs mismatch")
	}
	sigInput := append([]byte{DomainEnvelope}, env.TBS...)
	if hex.EncodeToString(sigInput) != ev.SigInputHex {
		t.Error("envelope sig_input mismatch")
	}
	if hex.EncodeToString(env.Sender) != ev.SignerPubkey {
		t.Error("envelope sender != signer_pubkey")
	}
	if env.BodyType != BodyIntent {
		t.Errorf("body_type = %d, want %d (Intent)", env.BodyType, BodyIntent)
	}
	if err := env.VerifySig(); err != nil {
		t.Errorf("envelope VerifySig: %v", err)
	}
	// The body is an Intent — parse and check its fields resolve.
	it, err := ParseIntent(env.Body)
	if err != nil {
		t.Fatalf("ParseIntent(body): %v", err)
	}
	if string(it.Action) != "apt-get install -y sqlite3" {
		t.Errorf("intent action = %q", it.Action)
	}
	// The grant vector's action_digest is BLAKE2s of exactly these bytes.
	d := Blake2s256(it.Action)
	if hex.EncodeToString(d[:]) != "61a0be1fa7039021e3a6d10a38e41e21873abd4668419d6b45dfcd56686d60c3" {
		t.Errorf("BLAKE2s(action) = %x, not the digest vector", d)
	}
}

func TestGrantVector(t *testing.T) {
	s, _ := loadStructsAndNegatives(t)
	gv := s["grant"]
	if gv.Verify != "true" {
		t.Fatalf("grant vector expects verify=true")
	}
	g, err := ParseGrant(mustHex(t, gv.WireHex))
	if err != nil {
		t.Fatalf("ParseGrant: %v", err)
	}
	if hex.EncodeToString(g.TBS) != gv.TbsHex {
		t.Error("grant tbs mismatch")
	}
	sigInput := append([]byte{DomainGrant}, g.TBS...)
	if hex.EncodeToString(sigInput) != gv.SigInputHex {
		t.Error("grant sig_input mismatch")
	}
	if hex.EncodeToString(g.Sig) != gv.SigHex {
		t.Error("grant sig mismatch")
	}
	if g.Version != 2 {
		t.Errorf("grant version = %d, want 2", g.Version)
	}
	if VerifySigned(DomainGrant, g.TBS, g.Sig, g.Approver) != nil {
		t.Error("grant signature does not verify against approver")
	}
	// Re-encode the TBS from parsed fields and pin it against the wire.
	f := GrantFields{Version: g.Version, NotAfter: g.NotAfter, ResourceID: g.ResourceID}
	copy(f.GrantID[:], g.GrantID)
	copy(f.IntentID[:], g.IntentID)
	copy(f.Approver[:], g.Approver)
	copy(f.Subject[:], g.Subject)
	copy(f.Executor[:], g.Executor)
	copy(f.ActionDigest[:], g.ActionDigest)
	tbs, err := EncodeGrantTBS(&f)
	if err != nil || hex.EncodeToString(tbs) != gv.TbsHex {
		t.Errorf("grant re-encode mismatch: %v", err)
	}
}

func TestRefusalVector(t *testing.T) {
	s, _ := loadStructsAndNegatives(t)
	rv := s["refusal"]
	if rv.Verify != "true" {
		t.Fatalf("refusal vector expects verify=true")
	}
	r, err := ParseRefusal(mustHex(t, rv.WireHex))
	if err != nil {
		t.Fatalf("ParseRefusal: %v", err)
	}
	if hex.EncodeToString(r.TBS) != rv.TbsHex {
		t.Error("refusal tbs mismatch")
	}
	if err := r.VerifySigAgainst(mustHex(t, rv.SignerPubkey)); err != nil {
		t.Errorf("refusal VerifySig: %v", err)
	}
}

// The three negative vectors: an envelope with a truncated signature, one
// with a trailing byte, and one whose signature is valid but over the
// wrong domain tag. All three MUST reject — these are the vectors phase 1
// had to skip until Envelope existed.
func TestNegativeVectors(t *testing.T) {
	_, negs := loadStructsAndNegatives(t)
	if len(negs) != 3 {
		t.Fatalf("expected 3 negative vectors, got %d", len(negs))
	}
	for _, n := range negs {
		if n.Expect != "reject" {
			t.Fatalf("%s: expect=%q, want reject", n.Name, n.Expect)
		}
		wire := mustHex(t, n.Wire)
		switch n.Name {
		case "envelope_truncated_sig", "envelope_trailing_byte":
			// Structural: the parser itself must refuse.
			if _, err := ParseEnvelope(wire); err == nil {
				t.Errorf("%s: ParseEnvelope accepted it", n.Name)
			}
		case "envelope_wrong_domain_tag":
			// Parses, but the signature check must refuse (BE-SIG-01).
			env, err := ParseEnvelope(wire)
			if err != nil {
				// Acceptable too: rejecting earlier is still a reject.
				continue
			}
			if env.VerifySig() == nil {
				t.Errorf("%s: signature accepted under wrong domain tag", n.Name)
			}
		default:
			t.Errorf("unknown negative vector %q", n.Name)
		}
	}
}

func TestEnvelopeTruncationTotality(t *testing.T) {
	s, _ := loadStructsAndNegatives(t)
	wire := mustHex(t, s["envelope_intent"].WireHex)
	for i := 0; i < len(wire); i++ {
		if _, err := ParseEnvelope(wire[:i]); err == nil {
			t.Fatalf("ParseEnvelope accepted a %d-byte prefix", i)
		}
	}
}

func TestGrantTruncationTotality(t *testing.T) {
	s, _ := loadStructsAndNegatives(t)
	wire := mustHex(t, s["grant"].WireHex)
	for i := 0; i < len(wire); i++ {
		if _, err := ParseGrant(wire[:i]); err == nil {
			t.Fatalf("ParseGrant accepted a %d-byte prefix", i)
		}
	}
}
