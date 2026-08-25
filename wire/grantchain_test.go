package wire

// The grant chain end to end, minted in memory: CA -> approver cert +
// subject cert -> intent -> grant, verified by the 14-check routine, then
// each check driven to its own refusal. This is the G2 authority half:
// an independent implementation reproducing verifyGrantThen's decision,
// not just the wire bytes.

import (
	"bytes"
	"testing"
)

const (
	tMax  = 3600
	tRecv = 300
)

type chainFixture struct {
	ca1, ca2, approver, subject, executor identity
	trusted                               [][]byte
	resource                              string
	action                                []byte
	intentID                              [LenIntentID]byte
	grant                                 *Grant
	ctx                                   *GrantContext
}

func buildChain(t *testing.T) *chainFixture {
	t.Helper()
	f := &chainFixture{
		ca1:      newIdentity(0x11),
		ca2:      newIdentity(0x22),
		approver: newIdentity(0xA0),
		subject:  newIdentity(0x5B),
		executor: newIdentity(0xE0),
		action:   []byte("apt-get install -y sqlite3"),
	}
	f.trusted = [][]byte{f.ca1.pub, f.ca2.pub}
	f.resource = "bol:" + Fingerprint(f.executor.pub) + "/logs/deploy.log"
	copy(f.intentID[:], bytes.Repeat([]byte{0x0f}, LenIntentID))

	// Approver cert: v2 (no scope gate), approver role, quorum of 2 CAs.
	approverCert := mustParseCert(t, mintCertV2(t, f.approver, RoleApprover, []identity{f.ca1, f.ca2}))
	subjectCert := mustParseCert(t, mintCertV2(t, f.subject, RoleAgent, []identity{f.ca1}))

	digest := Blake2s256(f.action)
	gf := GrantFields{Version: 2, ResourceID: []byte(f.resource), NotAfter: 1_700_000_060_000}
	copy(gf.GrantID[:], bytes.Repeat([]byte{0x20}, LenGrantID))
	gf.IntentID = f.intentID
	copy(gf.Approver[:], f.approver.pub)
	copy(gf.Subject[:], f.subject.pub)
	copy(gf.Executor[:], f.executor.pub)
	gf.ActionDigest = digest
	tbs, err := EncodeGrantTBS(&gf)
	if err != nil {
		t.Fatalf("EncodeGrantTBS: %v", err)
	}
	sig := SignTagged(DomainGrant, tbs, f.approver.priv)
	g, err := ParseGrant(append(tbs, sig...))
	if err != nil {
		t.Fatalf("ParseGrant: %v", err)
	}
	f.grant = g

	f.ctx = &GrantContext{
		EnvelopeBodyType: BodyGrant,
		EnvelopeSender:   f.approver.pub,
		OwnPubkey:        f.executor.pub,
		TrustedCAs:       f.trusted,
		ApproverCert:     approverCert,
		SubjectCert:      subjectCert,
		Pending: &PendingIntent{
			IntentID:   f.intentID[:],
			Sender:     f.subject.pub,
			ResourceID: []byte(f.resource),
			Action:     f.action,
		},
		NowMS:        1_700_000_030_000,
		FirstReceipt: 1_700_000_030_000,
		TMaxSeconds:  tMax,
		TRecvSeconds: tRecv,
	}
	return f
}

// mintCertV2 signs a version-2 cert (no scope gate) for a subject.
func mintCertV2(t *testing.T, subj identity, roleBits byte, cas []identity) []byte {
	t.Helper()
	cf := CertFields{Version: 2, RoleBits: roleBits, NotBefore: 1_700_000_000_000, NotAfter: 1_700_000_000_000 + MaxPrivilegedLifetimeMS, Name: []byte("t")}
	copy(cf.SigPubkey[:], subj.pub)
	copy(cf.KexPubkey[:], bytes.Repeat([]byte{9}, LenKexPubkey))
	tbs, err := EncodeCertTBS(&cf)
	if err != nil {
		t.Fatalf("EncodeCertTBS: %v", err)
	}
	pairs := make([]CAPair, 0, len(cas))
	for _, ca := range cas {
		pairs = append(pairs, CAPair{Key: ca.pub, Sig: SignTagged(DomainCert, tbs, ca.priv)})
	}
	for i := range pairs {
		for j := i + 1; j < len(pairs); j++ {
			if bytes.Compare(pairs[j].Key, pairs[i].Key) < 0 {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}
	w, err := AppendCertSignatures(tbs, pairs)
	if err != nil {
		t.Fatalf("AppendCertSignatures: %v", err)
	}
	return w
}

func mustParseCert(t *testing.T, w []byte) *Cert {
	t.Helper()
	c, err := ParseCert(w)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	return c
}

func TestGrantChainAccepts(t *testing.T) {
	f := buildChain(t)
	if err := VerifyGrant(f.grant, f.ctx); err != nil {
		t.Fatalf("valid grant refused: %v", err)
	}
}

// Each check driven to its own refusal, asserting the FIRST failure is
// the expected one — this is what pins the ordering (RT-08 F3).
func TestGrantChainRefusals(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(g *Grant, c *GrantContext)
		wantErr error
	}{
		{"check0 version", func(g *Grant, c *GrantContext) { g.Version = 3 }, ErrBadVersion},
		{"check1 body_type", func(g *Grant, c *GrantContext) { c.EnvelopeBodyType = BodyIntent }, ErrBadEnvelopeBinding},
		{"check1 sender!=approver", func(g *Grant, c *GrantContext) { c.EnvelopeSender = c.SubjectCert.SigPubkey }, ErrBadEnvelopeBinding},
		{"check2 signature", func(g *Grant, c *GrantContext) { g.Sig[0] ^= 0x01 }, ErrGrantBadSignature},
		{"check5 executor", func(g *Grant, c *GrantContext) { c.OwnPubkey = c.SubjectCert.SigPubkey }, ErrWrongExecutor},
		{"check6 subject!=sender", func(g *Grant, c *GrantContext) { c.Pending.Sender = c.ApproverCert.SigPubkey }, ErrWrongSubject},
		{"check7 intent_id", func(g *Grant, c *GrantContext) { c.Pending.IntentID = bytes.Repeat([]byte{0xAA}, LenIntentID) }, ErrNoMatchingIntent},
		{"check8 resource", func(g *Grant, c *GrantContext) {
			c.Pending.ResourceID = []byte("bol:" + Fingerprint(c.OwnPubkey) + "/logs/other.log")
		}, ErrWrongResource},
		{"check9 action_digest", func(g *Grant, c *GrantContext) { c.Pending.Action = []byte("rm -rf /") }, ErrActionDigestMismatch},
		{"check10 already expired", func(g *Grant, c *GrantContext) { c.NowMS = g.NotAfter }, ErrExpired},
		{"check10 beyond T_max", func(g *Grant, c *GrantContext) {
			g.NotAfter = c.FirstReceipt + (tMax+1)*1000
			c.NowMS = c.FirstReceipt + 1000
		}, ErrExpired},
		{"check10 T_recv elapsed", func(g *Grant, c *GrantContext) { c.NowMS = c.FirstReceipt + (tRecv+1)*1000 }, ErrExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := buildChain(t)
			tc.mutate(f.grant, f.ctx)
			if err := VerifyGrant(f.grant, f.ctx); err != tc.wantErr {
				t.Errorf("got %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// A revoked approver or subject refuses at check 3 / 4 (BE-REV-02).
func TestGrantChainRevocation(t *testing.T) {
	f := buildChain(t)
	f.ctx.IsRevoked = func(k []byte) bool { return bytes.Equal(k, f.approver.pub) }
	if err := VerifyGrant(f.grant, f.ctx); err != ErrApproverRevoked {
		t.Errorf("revoked approver: got %v, want ErrApproverRevoked", err)
	}
	f2 := buildChain(t)
	f2.ctx.IsRevoked = func(k []byte) bool { return bytes.Equal(k, f2.subject.pub) }
	if err := VerifyGrant(f2.grant, f2.ctx); err != ErrSubjectRevoked {
		t.Errorf("revoked subject: got %v, want ErrSubjectRevoked", err)
	}
}

// A wrong-role cert refuses: an agent cert in the approver slot fails
// check 3 (BE-ROLE-01 makes agent+approver unmintable, so the role bit
// alone is the discriminator here).
func TestGrantChainApproverRoleRequired(t *testing.T) {
	f := buildChain(t)
	// Re-mint the approver identity's cert with only the agent role.
	agentCert := mustParseCert(t, mintCertV2(t, f.approver, RoleAgent, []identity{f.ca1, f.ca2}))
	f.ctx.ApproverCert = agentCert
	if err := VerifyGrant(f.grant, f.ctx); err != ErrBadApproverCert {
		t.Errorf("agent-role approver: got %v, want ErrBadApproverCert", err)
	}
}

// v3 scope binding: a covering scope accepts, a sibling scope refuses at
// check 3a. Mirrors the reference's D-085 tests, driven through the full
// chain rather than the scope function alone.
func TestGrantChainScopeBinding(t *testing.T) {
	f := buildChain(t)
	// Covering scope = hash of the resource's org prefix (up to first '/').
	org := f.resource[:bytesIndex(f.resource, '/')]
	covering := Blake2s256([]byte(org))
	sibling := Blake2s256([]byte("bol:other_org"))

	covCert := mustParseCertScoped(t, f.approver, RoleApprover, []identity{f.ca1, f.ca2}, covering[:8])
	f.ctx.ApproverCert = covCert
	if err := VerifyGrant(f.grant, f.ctx); err != nil {
		t.Fatalf("covering scope refused: %v", err)
	}

	f2 := buildChain(t)
	sibCert := mustParseCertScoped(t, f2.approver, RoleApprover, []identity{f2.ca1, f2.ca2}, sibling[:8])
	f2.ctx.ApproverCert = sibCert
	if err := VerifyGrant(f2.grant, f2.ctx); err != ErrApproverOutOfScope {
		t.Errorf("sibling scope: got %v, want ErrApproverOutOfScope", err)
	}

	// A v3 cert with EMPTY scope is deny-all (the F15 lesson).
	f3 := buildChain(t)
	emptyCert := mustParseCertScopedEmpty(t, f3.approver, RoleApprover, []identity{f3.ca1, f3.ca2})
	f3.ctx.ApproverCert = emptyCert
	if err := VerifyGrant(f3.grant, f3.ctx); err != ErrApproverOutOfScope {
		t.Errorf("empty scope (deny-all): got %v, want ErrApproverOutOfScope", err)
	}
}

func mustParseCertScoped(t *testing.T, subj identity, role byte, cas []identity, scope8 []byte) *Cert {
	t.Helper()
	var s [8]byte
	copy(s[:], scope8)
	return mustParseCert(t, mintCertV3(t, subj, role, cas, [][8]byte{s}))
}

func mustParseCertScopedEmpty(t *testing.T, subj identity, role byte, cas []identity) *Cert {
	t.Helper()
	return mustParseCert(t, mintCertV3(t, subj, role, cas, nil))
}

func mintCertV3(t *testing.T, subj identity, roleBits byte, cas []identity, scopes [][8]byte) []byte {
	t.Helper()
	cf := CertFields{Version: 3, RoleBits: roleBits, NotBefore: 1_700_000_000_000, NotAfter: 1_700_000_000_000 + MaxPrivilegedLifetimeMS, Name: []byte("t"), ScopeIDs: scopes}
	copy(cf.SigPubkey[:], subj.pub)
	copy(cf.KexPubkey[:], bytes.Repeat([]byte{9}, LenKexPubkey))
	tbs, err := EncodeCertTBS(&cf)
	if err != nil {
		t.Fatalf("EncodeCertTBS: %v", err)
	}
	pairs := make([]CAPair, 0, len(cas))
	for _, ca := range cas {
		pairs = append(pairs, CAPair{Key: ca.pub, Sig: SignTagged(DomainCert, tbs, ca.priv)})
	}
	for i := range pairs {
		for j := i + 1; j < len(pairs); j++ {
			if bytes.Compare(pairs[j].Key, pairs[i].Key) < 0 {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}
	w, err := AppendCertSignatures(tbs, pairs)
	if err != nil {
		t.Fatalf("AppendCertSignatures: %v", err)
	}
	return w
}

func bytesIndex(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return len(s)
}
