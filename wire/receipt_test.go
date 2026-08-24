package wire

// End-to-end of the RECEIPT-PROFILE.md §4 verification path, minting CA,
// cert and span in memory — the full chain the CLI drives, without
// needing the Bolina binary.

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

type identity struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newIdentity(seedByte byte) identity {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
	return identity{priv: priv, pub: priv.Public().(ed25519.PublicKey)}
}

// mintCert signs a cert for subject with the given CAs (sorted pairs).
func mintCert(t *testing.T, subject identity, roleBits byte, cas []identity, lifetimeMS uint64) []byte {
	t.Helper()
	f := CertFields{Version: 3, RoleBits: roleBits, NotBefore: 1_700_000_000_000, NotAfter: 1_700_000_000_000 + lifetimeMS, Name: []byte("test")}
	copy(f.SigPubkey[:], subject.pub)
	copy(f.KexPubkey[:], bytes.Repeat([]byte{9}, LenKexPubkey))
	tbs, err := EncodeCertTBS(&f)
	if err != nil {
		t.Fatalf("EncodeCertTBS: %v", err)
	}
	pairs := make([]CAPair, 0, len(cas))
	for _, ca := range cas {
		pairs = append(pairs, CAPair{Key: ca.pub, Sig: SignTagged(DomainCert, tbs, ca.priv)})
	}
	// Sort pairs by key ascending (the encoder refuses disorder).
	for i := 0; i < len(pairs); i++ {
		for j := i + 1; j < len(pairs); j++ {
			if bytes.Compare(pairs[j].Key, pairs[i].Key) < 0 {
				pairs[i], pairs[j] = pairs[j], pairs[i]
			}
		}
	}
	wire, err := AppendCertSignatures(tbs, pairs)
	if err != nil {
		t.Fatalf("AppendCertSignatures: %v", err)
	}
	return wire
}

func mintReceipt(t *testing.T, executor identity, resource string) []byte {
	t.Helper()
	f := SpanFields{Version: 2, ResourceID: []byte(resource), MethodID: MethodSubprocess, Volatility: VolatilityVolatile, ObservedAt: 1_700_000_100_000}
	copy(f.Executor[:], executor.pub)
	f.Digest = Blake2s256([]byte("observed output\n[lastro] exit-status=0\n"))
	w, err := BuildSpan(&f, executor.priv)
	if err != nil {
		t.Fatalf("BuildSpan: %v", err)
	}
	return w
}

func TestVerifyReceiptFullChain(t *testing.T) {
	ca1, ca2 := newIdentity(0x11), newIdentity(0x22)
	executor := newIdentity(0x33)
	trusted := [][]byte{ca1.pub, ca2.pub}

	certWire := mintCert(t, executor, RoleExecutor, []identity{ca1, ca2}, MaxPrivilegedLifetimeMS)
	cert, err := ParseCert(certWire)
	if err != nil {
		t.Fatalf("ParseCert: %v", err)
	}
	resource := "bol:" + Fingerprint(executor.pub) + "/git/demo/abc/check/tests"
	span, err := ParseSpan(mintReceipt(t, executor, resource))
	if err != nil {
		t.Fatalf("ParseSpan: %v", err)
	}
	if err := VerifyReceipt(span, cert, trusted); err != nil {
		t.Fatalf("VerifyReceipt: %v", err)
	}
}

func TestVerifyReceiptRefusals(t *testing.T) {
	ca := newIdentity(0x11)
	executor := newIdentity(0x33)
	other := newIdentity(0x44)
	trusted := [][]byte{ca.pub}
	resource := "bol:" + Fingerprint(executor.pub) + "/git/demo/abc/check/tests"
	span, err := ParseSpan(mintReceipt(t, executor, resource))
	if err != nil {
		t.Fatalf("ParseSpan: %v", err)
	}

	// Cert lacking the executor role refuses (BE-EVID-01).
	agentCert, _ := ParseCert(mintCert(t, executor, RoleAgent, []identity{ca}, MaxPrivilegedLifetimeMS))
	if err := VerifyReceipt(span, agentCert, trusted); err == nil {
		t.Error("accepted a cert without the executor role")
	}

	// Someone else's cert refuses (signer binding).
	otherCert, _ := ParseCert(mintCert(t, other, RoleExecutor, []identity{ca}, MaxPrivilegedLifetimeMS))
	if err := VerifyReceipt(span, otherCert, trusted); err == nil {
		t.Error("accepted a cert that is not the signer's")
	}

	// A resource naming a different executor's fingerprint refuses
	// (BE-RES-04): mint a span whose resource carries other's fp but is
	// signed by executor.
	wrongRes := "bol:" + Fingerprint(other.pub) + "/git/demo/abc/check/tests"
	wrongSpan, err := ParseSpan(mintReceipt(t, executor, wrongRes))
	if err != nil {
		t.Fatalf("ParseSpan: %v", err)
	}
	execCert, _ := ParseCert(mintCert(t, executor, RoleExecutor, []identity{ca}, MaxPrivilegedLifetimeMS))
	if err := VerifyReceipt(wrongSpan, execCert, trusted); err == nil {
		t.Error("accepted a resource naming a different executor")
	}

	// An executor cert above the 30-day cap refuses (BE-REV-01).
	longCert, _ := ParseCert(mintCert(t, executor, RoleExecutor, []identity{ca}, MaxPrivilegedLifetimeMS+1))
	if err := VerifyReceipt(span, longCert, trusted); err != ErrCertTooLongLived {
		t.Errorf("over-long cert: got %v, want ErrCertTooLongLived", err)
	}

	// An untrusted CA refuses even with a valid signature.
	if err := VerifyReceipt(span, execCert, [][]byte{other.pub}); err != ErrUntrustedCA {
		t.Errorf("untrusted CA: got %v, want ErrUntrustedCA", err)
	}
}
