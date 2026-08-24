package wire

import (
	"bytes"
	"errors"
)

// Certificate chain validation, clock-free — the audit stance
// (BE-HIST-01): every structural check with no time input, mirroring the
// reference implementation's validateCertNoClock split. The verifier of
// a detached receipt reports the validity window; it does not enforce
// the wall clock (RECEIPT-PROFILE.md §4).

const (
	// BE-ID-04: an approver cert needs >= 2 CA signatures.
	ApproverQuorum = 2
	// BE-REV-01: approver/executor certs capped at 30 days.
	MaxPrivilegedLifetimeMS = 2_592_000_000
)

var (
	ErrRolePairForbidden = errors.New("wire: forbidden role pairing (BE-ID-03)")
	ErrApproverNoQuorum  = errors.New("wire: approver cert below CA quorum (BE-ID-04)")
	ErrCertTooLongLived  = errors.New("wire: privileged cert exceeds 30-day cap (BE-REV-01)")
	ErrUntrustedCA       = errors.New("wire: CA key not in trusted set (BE-ID-02)")
)

// CheckRoleConstraints rejects the three forbidden pairings (BE-ID-03 /
// BE-ROLE-01/02/04): agent+approver, agent+executor, approver+executor.
func CheckRoleConstraints(roleBits byte) error {
	agent := roleBits&RoleAgent != 0
	approver := roleBits&RoleApprover != 0
	executor := roleBits&RoleExecutor != 0
	if (agent && approver) || (agent && executor) || (approver && executor) {
		return ErrRolePairForbidden
	}
	return nil
}

// ValidateCertChainNoClock runs every structural certificate check with
// zero clock input: role constraints, approver quorum, the BE-REV-01
// lifetime-span cap (a property of the cert's own window, not of any
// clock), and every CA signature against the trusted set. Rejection is
// unconditional; there is no warn-and-continue path (BE-ID-02).
func ValidateCertChainNoClock(cert *Cert, trusted [][]byte) error {
	if err := CheckRoleConstraints(cert.RoleBits); err != nil {
		return err
	}
	if cert.RoleBits&RoleApprover != 0 && int(cert.CASigCount) < ApproverQuorum {
		return ErrApproverNoQuorum
	}
	if cert.RoleBits&(RoleApprover|RoleExecutor) != 0 &&
		cert.NotAfter-cert.NotBefore > MaxPrivilegedLifetimeMS {
		return ErrCertTooLongLived
	}
	for _, p := range cert.CAPairs() {
		if err := VerifySigned(DomainCert, cert.TBS, p.Sig, p.Key); err != nil {
			return err
		}
		if !inSet(p.Key, trusted) {
			return ErrUntrustedCA
		}
	}
	return nil
}

// VerifyReceipt runs the full detached-receipt verification of
// RECEIPT-PROFILE.md §4 steps 1-4: span signature, cert chain (no
// clock), signer binding, and resource fingerprint. The caller derives
// class/ceiling (step 5) via ClassOf and renders the report.
func VerifyReceipt(span *Span, cert *Cert, trusted [][]byte) error {
	if err := span.VerifySig(); err != nil {
		return err
	}
	if err := ValidateCertChainNoClock(cert, trusted); err != nil {
		return err
	}
	if cert.RoleBits&RoleExecutor == 0 {
		return errors.New("wire: cert lacks executor role (BE-EVID-01)")
	}
	if !bytes.Equal(cert.SigPubkey, span.Executor) {
		return errors.New("wire: cert is not the span signer's")
	}
	fp := Fingerprint(cert.SigPubkey)
	want := "bol:" + fp + "/"
	if !bytes.HasPrefix(span.ResourceID, []byte(want)) {
		return errors.New("wire: resource fingerprint does not name this executor (BE-RES-04)")
	}
	return nil
}
