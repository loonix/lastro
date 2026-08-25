package wire

import "encoding/binary"

// Envelope layout (SPEC §6.2) — the signed carrier every channel message
// travels in:
//
//	u8 version(=2) | [32] channel_id | [32] sender | u64 seq
//	u8 parent_count(0..4) | [32]* parents | u64 ts | u8 body_type
//	u32 body_len | body | [64] sig
//
// TBS is every byte before sig; sig is Ed25519 over (DomainEnvelope || TBS).
const (
	LenChannelID = 32
	LenParent    = 32
	LenIntentID  = 16
	LenGrantID   = 16
	LenDigest32  = 32
	MaxParents   = 4
	MaxResource_ = MaxResource // 256, shared with span
	MaxAction    = 256 * 1024
	MaxRationale = 4 * 1024
	MaxNote      = 1024

	// MaxBody = MAX_MESSAGE (1 MiB) − MAX_HEADER (512). The reference
	// derives it the same way; pinned as a constant here and covered by
	// the envelope vector's body_len.
	MaxMessage = 1 << 20
	MaxHeader  = 512
	MaxBody    = MaxMessage - MaxHeader

	// Body type discriminants (SPEC §6.3).
	BodyUtterance byte = 1
	BodyIntent    byte = 2
	BodyGrant     byte = 3
	BodyEffect    byte = 4
	BodyControl   byte = 5
	BodyRefusal   byte = 6
)

// Envelope is a parsed envelope. All slices alias the input buffer.
type Envelope struct {
	Version     byte
	ChannelID   []byte
	Sender      []byte
	Seq         uint64
	ParentCount byte
	Parents     []byte // ParentCount * LenParent bytes, flat
	Ts          uint64
	BodyType    byte
	Body        []byte
	TBS         []byte
	Sig         []byte
}

// ParseEnvelope parses exactly one envelope. Trailing bytes are an error.
func ParseEnvelope(buf []byte) (*Envelope, error) {
	c := cursor{buf: buf}
	version, err := c.u8()
	if err != nil {
		return nil, err
	}
	channelID, err := c.take(LenChannelID)
	if err != nil {
		return nil, err
	}
	sender, err := c.take(LenPubkey)
	if err != nil {
		return nil, err
	}
	seq, err := c.u64be()
	if err != nil {
		return nil, err
	}
	parentCount, err := c.u8()
	if err != nil {
		return nil, err
	}
	if parentCount > MaxParents {
		return nil, ErrOversize
	}
	parents, err := c.take(int(parentCount) * LenParent)
	if err != nil {
		return nil, err
	}
	ts, err := c.u64be()
	if err != nil {
		return nil, err
	}
	bodyType, err := c.u8()
	if err != nil {
		return nil, err
	}
	bodyLen, err := c.u32be()
	if err != nil {
		return nil, err
	}
	if int64(bodyLen) > MaxBody {
		return nil, ErrOversize
	}
	body, err := c.take(int(bodyLen))
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
	return &Envelope{
		Version: version, ChannelID: channelID, Sender: sender, Seq: seq,
		ParentCount: parentCount, Parents: parents, Ts: ts,
		BodyType: bodyType, Body: body, TBS: tbs, Sig: sig,
	}, nil
}

// VerifySig checks the envelope signature against its sender (BE-ENV-02).
func (e *Envelope) VerifySig() error {
	return VerifySigned(DomainEnvelope, e.TBS, e.Sig, e.Sender)
}

// Intent body (SPEC §6.3):
//
//	[16] intent_id | u16 resource_len, resource_id(<=256)
//	u32 action_len, action(<=256KiB, OPAQUE) | u16 rationale_len, rationale(<=4KiB)
//
// action is opaque bytes (BE-BODY-01); this slices it so a verifier can
// hash it for BE-GRANT-02, never parses it.
type Intent struct {
	IntentID   []byte
	ResourceID []byte
	Action     []byte
	Rationale  []byte
}

// ParseIntent parses an Intent body. Trailing bytes are an error.
func ParseIntent(buf []byte) (*Intent, error) {
	c := cursor{buf: buf}
	intentID, err := c.take(LenIntentID)
	if err != nil {
		return nil, err
	}
	resourceID, err := c.field16(MaxResource)
	if err != nil {
		return nil, err
	}
	action, err := c.field32(MaxAction)
	if err != nil {
		return nil, err
	}
	rationale, err := c.field16(MaxRationale)
	if err != nil {
		return nil, err
	}
	if c.pos != len(buf) {
		return nil, ErrTrailingBytes
	}
	return &Intent{IntentID: intentID, ResourceID: resourceID, Action: action, Rationale: rationale}, nil
}

// field32 reads a u32-length-prefixed field with a declared maximum.
func (c *cursor) field32(max int) ([]byte, error) {
	n, err := c.u32be()
	if err != nil {
		return nil, err
	}
	if int64(n) > int64(max) {
		return nil, ErrOversize
	}
	return c.take(int(n))
}

// Refusal (SPEC §8.5):
//
//	[16] intent_id | u16 note_len, note(<=1KiB) | [64] sig
//
// No version field: the binding content is the intent_id alone. sig is
// Ed25519 over (DomainRefusal || TBS). note is informative only.
type Refusal struct {
	IntentID []byte
	Note     []byte
	TBS      []byte
	Sig      []byte
}

// ParseRefusal parses exactly one Refusal. Trailing bytes are an error.
func ParseRefusal(buf []byte) (*Refusal, error) {
	c := cursor{buf: buf}
	intentID, err := c.take(LenIntentID)
	if err != nil {
		return nil, err
	}
	note, err := c.field16(MaxNote)
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
	return &Refusal{IntentID: intentID, Note: note, TBS: tbs, Sig: sig}, nil
}

// VerifySigAgainst checks the refusal signature against a sender key —
// the approver's, which the envelope carries (BE-GRANT-09).
func (r *Refusal) VerifySigAgainst(sender []byte) error {
	return VerifySigned(DomainRefusal, r.TBS, r.Sig, sender)
}

// EncodeIntentBody serializes an Intent body (used to build the envelope
// bodies the grant-chain tests exercise; the digest a Grant binds is
// BLAKE2s over Action alone, per BE-GRANT-02).
func EncodeIntentBody(it *Intent) ([]byte, error) {
	if len(it.IntentID) != LenIntentID || len(it.ResourceID) > MaxResource ||
		len(it.Action) > MaxAction || len(it.Rationale) > MaxRationale {
		return nil, ErrFieldBounds
	}
	out := append([]byte{}, it.IntentID...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(it.ResourceID)))
	out = append(out, it.ResourceID...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(it.Action)))
	out = append(out, it.Action...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(it.Rationale)))
	out = append(out, it.Rationale...)
	return out, nil
}
