package wire

import "encoding/binary"

// Grant layout (SPEC §8.1) — an object capability: holding one is the
// authority, bound to one agent, one executor, one resource, one exact
// action, spent on use:
//
//	u8 version(=2) | [16] grant_id | [16] intent_id | [32] approver
//	[32] subject | [32] executor | u16 resource_len, resource_id
//	[32] action_digest | u64 not_after | [64] sig
//
// TBS is every byte before sig; sig is Ed25519 over (DomainGrant || TBS).
const LenActionDigest = 32

// Grant is a parsed grant. All slices alias the input buffer.
type Grant struct {
	Version      byte
	GrantID      []byte
	IntentID     []byte
	Approver     []byte
	Subject      []byte
	Executor     []byte
	ResourceID   []byte
	ActionDigest []byte
	NotAfter     uint64
	TBS          []byte
	Sig          []byte
}

// ParseGrant parses exactly one grant. Trailing bytes are an error.
func ParseGrant(buf []byte) (*Grant, error) {
	c := cursor{buf: buf}
	version, err := c.u8()
	if err != nil {
		return nil, err
	}
	grantID, err := c.take(LenGrantID)
	if err != nil {
		return nil, err
	}
	intentID, err := c.take(LenIntentID)
	if err != nil {
		return nil, err
	}
	approver, err := c.take(LenPubkey)
	if err != nil {
		return nil, err
	}
	subject, err := c.take(LenPubkey)
	if err != nil {
		return nil, err
	}
	executor, err := c.take(LenPubkey)
	if err != nil {
		return nil, err
	}
	resourceID, err := c.field16(MaxResource)
	if err != nil {
		return nil, err
	}
	actionDigest, err := c.take(LenActionDigest)
	if err != nil {
		return nil, err
	}
	notAfter, err := c.u64be()
	if err != nil {
		return nil, err
	}
	tbs := buf[:c.pos]
	sig, err := c.take(LenSig)
	if err != nil {
		return nil, err
	}
	if c.pos != len(buf) {
		return nil, ErrTrailingBytes
	}
	return &Grant{
		Version: version, GrantID: grantID, IntentID: intentID,
		Approver: approver, Subject: subject, Executor: executor,
		ResourceID: resourceID, ActionDigest: actionDigest,
		NotAfter: notAfter, TBS: tbs, Sig: sig,
	}, nil
}

// EncodeGrantTBS serializes a grant's to-be-signed region (tests + tooling).
type GrantFields struct {
	Version      byte
	GrantID      [LenGrantID]byte
	IntentID     [LenIntentID]byte
	Approver     [LenPubkey]byte
	Subject      [LenPubkey]byte
	Executor     [LenPubkey]byte
	ResourceID   []byte
	ActionDigest [LenActionDigest]byte
	NotAfter     uint64
}

func EncodeGrantTBS(f *GrantFields) ([]byte, error) {
	if len(f.ResourceID) > MaxResource {
		return nil, ErrFieldBounds
	}
	out := []byte{f.Version}
	out = append(out, f.GrantID[:]...)
	out = append(out, f.IntentID[:]...)
	out = append(out, f.Approver[:]...)
	out = append(out, f.Subject[:]...)
	out = append(out, f.Executor[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(f.ResourceID)))
	out = append(out, f.ResourceID...)
	out = append(out, f.ActionDigest[:]...)
	out = binary.BigEndian.AppendUint64(out, f.NotAfter)
	return out, nil
}
