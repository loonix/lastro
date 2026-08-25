package wire

import (
	"bytes"
	"errors"
)

// The Grant verification chain (SPEC §8.2, BE-GRANT-03) — the single
// routine that gates every effect, running the enumerated checks in
// order and refusing on the first failure. This is the second half of
// G2: a Go implementation of the same 14-check sequence the reference's
// verifyGrantThen runs, so an independent implementation reproduces the
// authority decision, not just the wire bytes.
//
// This is the pure decision function: it takes the parsed grant, the
// pending intent it must match, the approver and subject certs, the
// executor's own key, the trust set, and the clock/receipt inputs, and
// returns the first failing check as a typed error, or nil. Durable
// concerns (the consumed-nonce ledger = check 11, the effect callback)
// live above this layer, exactly as they do in the reference: this
// function is everything a receiver can decide from bytes plus supplied
// state, with no I/O.

// GrantCheckError names the check that refused (parallel to the
// reference's VerifyError set), so a test asserts the reason a grant was
// refused, not a generic failure.
var (
	ErrBadVersion           = errors.New("grant: version != 2 (check 0)")
	ErrBadEnvelopeBinding   = errors.New("grant: not body_type=3, or sender != approver (check 1)")
	ErrGrantBadSignature    = errors.New("grant: signature does not verify (check 2)")
	ErrBadApproverCert      = errors.New("grant: approver cert invalid/wrong-role/not-grant-approver (check 3)")
	ErrApproverRevoked      = errors.New("grant: approver key revoked (check 3, BE-REV-02)")
	ErrApproverOutOfScope   = errors.New("grant: approver scope does not cover resource (check 3a)")
	ErrBadSubjectCert       = errors.New("grant: subject cert invalid/wrong-role/not-grant-subject (check 4)")
	ErrSubjectRevoked       = errors.New("grant: subject key revoked (check 4, BE-REV-02)")
	ErrSubjectOutOfScope    = errors.New("grant: subject scope does not cover resource (check 4a)")
	ErrWrongExecutor        = errors.New("grant: executor != this executor's key (check 5)")
	ErrWrongSubject         = errors.New("grant: subject != pending intent's sender (check 6)")
	ErrNoMatchingIntent     = errors.New("grant: intent_id matches no pending intent (check 7)")
	ErrWrongResource        = errors.New("grant: resource_id != pending intent's canonical (check 8)")
	ErrActionDigestMismatch = errors.New("grant: BLAKE2s(action) != action_digest (check 9, BE-GRANT-02)")
	ErrExpired              = errors.New("grant: expiry failed (check 10, BE-GRANT-05)")
)

// PendingIntent is the executor-side state a grant binds to: the one
// PENDING intent matched by id, carrying its sender, canonical resource,
// and action bytes (checks 6-9 bind to state the routine holds, the F13
// shape).
type PendingIntent struct {
	IntentID   []byte
	Sender     []byte // the intent envelope's sender = the agent
	ResourceID []byte // canonical, executor-resolved (§8.4)
	Action     []byte // the intent's action bytes, re-hashed for check 9
}

// GrantContext carries everything the chain needs beyond the grant and
// its envelope. Revocation and consumed-ledger are hooks (I/O lives above).
type GrantContext struct {
	EnvelopeBodyType byte
	EnvelopeSender   []byte // the grant envelope's sender, must equal Grant.Approver

	OwnPubkey    []byte   // check 5: this executor's own sig key
	TrustedCAs   [][]byte // checks 3/4 cert validation
	ApproverCert *Cert
	SubjectCert  *Cert
	Pending      *PendingIntent

	NowMS        uint64 // check 10 clock
	FirstReceipt uint64 // check 10: first-receipt time (per-grant, durable)
	TMaxSeconds  uint64 // default 3600
	TRecvSeconds uint64 // default 300

	// IsRevoked is consulted at use (BE-REV-02), not at cache fill. nil
	// means "nothing revoked" (tests without a revocation set).
	IsRevoked func(sigPubkey []byte) bool
}

// VerifyGrant runs BE-GRANT-03 checks 0..10 in the normative order and
// returns the first failing check, or nil if the grant is authorized up
// to the durable ledger commit (check 11) the caller performs. It never
// does I/O and never runs the effect: verification is a decision here,
// the reference folds the effect into the same call frame (BE-GRANT-03b).
func VerifyGrant(g *Grant, ctx *GrantContext) error {
	// 0. version must be 2 (the field is read, not ignored — RT-08 F6).
	if g.Version != 2 {
		return ErrBadVersion
	}
	// 1. arrived as a body_type=3 envelope whose sender is the approver.
	if ctx.EnvelopeBodyType != BodyGrant || !bytes.Equal(ctx.EnvelopeSender, g.Approver) {
		return ErrBadEnvelopeBinding
	}
	// 2. signature verifies against Grant.approver (domain tag 0x04).
	if VerifySigned(DomainGrant, g.TBS, g.Sig, g.Approver) != nil {
		return ErrGrantBadSignature
	}
	// 3. approver cert valid NOW, carries approver role, is the grant's approver.
	if ValidateCert(ctx.ApproverCert, ctx.TrustedCAs, ctx.NowMS) != nil {
		return ErrBadApproverCert
	}
	if ctx.ApproverCert.RoleBits&RoleApprover == 0 {
		return ErrBadApproverCert
	}
	if !bytes.Equal(ctx.ApproverCert.SigPubkey, g.Approver) {
		return ErrBadApproverCert
	}
	if ctx.IsRevoked != nil && ctx.IsRevoked(ctx.ApproverCert.SigPubkey) {
		return ErrApproverRevoked
	}
	// 3a. approver scope covers the grant's resource (v3 only; v2 skips).
	if ctx.ApproverCert.Version >= 3 && !scopeCoversResource(ctx.ApproverCert, g.ResourceID) {
		return ErrApproverOutOfScope
	}
	// 4. subject cert valid NOW, carries agent role, is the grant's subject.
	if ValidateCert(ctx.SubjectCert, ctx.TrustedCAs, ctx.NowMS) != nil {
		return ErrBadSubjectCert
	}
	if ctx.SubjectCert.RoleBits&RoleAgent == 0 {
		return ErrBadSubjectCert
	}
	if !bytes.Equal(ctx.SubjectCert.SigPubkey, g.Subject) {
		return ErrBadSubjectCert
	}
	if ctx.IsRevoked != nil && ctx.IsRevoked(ctx.SubjectCert.SigPubkey) {
		return ErrSubjectRevoked
	}
	// 4a. subject scope covers the resource (v3 only).
	if ctx.SubjectCert.Version >= 3 && !scopeCoversResource(ctx.SubjectCert, g.ResourceID) {
		return ErrSubjectOutOfScope
	}
	// 5. Grant.executor equals this executor's own key.
	if !bytes.Equal(g.Executor, ctx.OwnPubkey) {
		return ErrWrongExecutor
	}
	// 6. grant's subject is the pending intent's sender.
	if !bytes.Equal(g.Subject, ctx.Pending.Sender) {
		return ErrWrongSubject
	}
	// 7. intent_id matches the pending intent.
	if !bytes.Equal(g.IntentID, ctx.Pending.IntentID) {
		return ErrNoMatchingIntent
	}
	// 8. resource_id matches the pending intent's canonical resource.
	if !bytes.Equal(g.ResourceID, ctx.Pending.ResourceID) {
		return ErrWrongResource
	}
	// 9. action_digest equals BLAKE2s over the intent's action bytes.
	d := Blake2s256(ctx.Pending.Action)
	if !bytes.Equal(g.ActionDigest, d[:]) {
		return ErrActionDigestMismatch
	}
	// 10. expiry: all three conditions of BE-GRANT-05.
	if err := checkExpiry(g.NotAfter, ctx.NowMS, ctx.FirstReceipt, ctx.TMaxSeconds, ctx.TRecvSeconds); err != nil {
		return err
	}
	// 11 (consumed-nonce ledger) and the effect are the caller's, above
	// this pure decision function.
	return nil
}

// checkExpiry implements BE-GRANT-05: refuse if not_after is already
// past (non-strict), if it lies more than T_max beyond first receipt, or
// if more than T_recv has elapsed since first receipt. The second and
// third hold even against an adversarial approver clock.
func checkExpiry(notAfter, nowMS, firstReceiptMS, tMaxS, tRecvS uint64) error {
	tMaxMS := tMaxS * 1000
	tRecvMS := tRecvS * 1000
	if nowMS >= notAfter {
		return ErrExpired
	}
	if notAfter > firstReceiptMS+tMaxMS {
		return ErrExpired
	}
	if nowMS > firstReceiptMS+tRecvMS {
		return ErrExpired
	}
	return nil
}

// ValidateCert is the clocked cert validation (admission stance,
// BE-ID-02): the chain plus the validity window at nowMS. The audit
// stance (clock-free) is ValidateCertChainNoClock in validate.go.
func ValidateCert(cert *Cert, trusted [][]byte, nowMS uint64) error {
	if err := ValidateCertChainNoClock(cert, trusted); err != nil {
		return err
	}
	// Inclusive at not_before, exclusive at not_after (X.509 convention).
	if nowMS < cert.NotBefore || nowMS >= cert.NotAfter {
		return errors.New("cert: outside validity window (BE-ID-02)")
	}
	return nil
}

// scopeCoversResource walks the canonical resource_id from full path to
// root, hashing each ancestor prefix and checking its 8-byte truncation
// against the cert's scope_ids (D-085). A scope_id of BLAKE2s(prefix)[0..8]
// covers every resource under that prefix. Empty scope = deny-all. The
// walk strips at '/' boundaries, so a scope over ".../app" does NOT cover
// ".../app2/x" — the string-prefix confusion is structurally avoided.
func scopeCoversResource(cert *Cert, resourceID []byte) bool {
	end := len(resourceID)
	for end > 0 {
		h := Blake2s256(resourceID[:end])
		if certCarriesScope(cert, h[:8]) {
			return true
		}
		// Find the previous '/' to strip the last segment.
		newEnd := end
		for newEnd > 0 && resourceID[newEnd-1] != '/' {
			newEnd--
		}
		if newEnd == 0 {
			break // no '/' found, cannot strip further
		}
		end = newEnd - 1 // exclude the '/' itself from the next prefix
	}
	return false
}

// certCarriesScope reports whether the 8-byte scope appears among the
// cert's scope_ids (byte equality, the only rule §6 defines).
func certCarriesScope(cert *Cert, scope []byte) bool {
	for i := 0; i < int(cert.ScopeCount); i++ {
		off := i * LenScopeID
		if bytes.Equal(cert.ScopeIDs[off:off+LenScopeID], scope) {
			return true
		}
	}
	return false
}
