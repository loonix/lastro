package wire

import "bytes"

// Certificate layout (SPEC §3.1):
//
//	u8 version(=3) | u8 role_bits | [32] sig_pubkey | [32] kex_pubkey
//	u64 not_before | u64 not_after | u16 name_len, name(<=64)
//	u8 scope_count(<=8) | [8]* scope_ids | u8 ca_sig_count(1..4)
//	([32] ca_key + [64] ca_sig) x ca_sig_count
//
// TBS is every byte preceding ca_sig_count; each CA signature covers
// (DomainCert || TBS). CA keys must be strictly ascending and pairwise
// distinct — a parse failure, not a policy check, so duplicate-key
// quorum forgery cannot encode (SPEC §3.1).
const (
	LenPubkey    = 32
	LenKexPubkey = 32
	LenScopeID   = 8
	MaxName      = 64
	MaxScope     = 8
	MaxCASigs    = 4
	LenCAKey     = 32
	LenCASig     = 64
)

// Role bits (SPEC §3.1).
const (
	RoleParticipant byte = 1 << 0
	RoleAgent       byte = 1 << 1
	RoleExecutor    byte = 1 << 2
	RoleApprover    byte = 1 << 3
	RoleLighthouse  byte = 1 << 4
	RoleRelay       byte = 1 << 5
)

// Cert is a parsed certificate. All slices alias the input buffer.
type Cert struct {
	Version    byte
	RoleBits   byte
	SigPubkey  []byte
	KexPubkey  []byte
	NotBefore  uint64
	NotAfter   uint64
	Name       []byte
	ScopeCount byte
	ScopeIDs   []byte // ScopeCount * LenScopeID bytes, flat
	CASigCount byte
	CASigs     []byte // CASigCount * (LenCAKey + LenCASig) bytes, flat pairs
	TBS        []byte // all bytes preceding ca_sig_count (signature input)
}

// CAPair is one (ca_key, ca_sig) entry from the certificate.
type CAPair struct {
	Key []byte
	Sig []byte
}

// ParseCert parses exactly one certificate. Trailing bytes are an error.
func ParseCert(buf []byte) (*Cert, error) {
	c := cursor{buf: buf}
	version, err := c.u8()
	if err != nil {
		return nil, err
	}
	roleBits, err := c.u8()
	if err != nil {
		return nil, err
	}
	sigPub, err := c.take(LenPubkey)
	if err != nil {
		return nil, err
	}
	kexPub, err := c.take(LenKexPubkey)
	if err != nil {
		return nil, err
	}
	notBefore, err := c.u64be()
	if err != nil {
		return nil, err
	}
	notAfter, err := c.u64be()
	if err != nil {
		return nil, err
	}
	name, err := c.field16(MaxName)
	if err != nil {
		return nil, err
	}
	scopeCount, err := c.u8()
	if err != nil {
		return nil, err
	}
	if scopeCount > MaxScope {
		return nil, ErrOversize
	}
	scopeIDs, err := c.take(int(scopeCount) * LenScopeID)
	if err != nil {
		return nil, err
	}
	// TBS freezes before ca_sig_count (SPEC §3.1).
	tbs := buf[:c.pos]
	caCount, err := c.u8()
	if err != nil {
		return nil, err
	}
	if caCount == 0 || caCount > MaxCASigs {
		return nil, ErrMalformed
	}
	caStart := c.pos
	var prev []byte
	for i := 0; i < int(caCount); i++ {
		key, err := c.take(LenCAKey)
		if err != nil {
			return nil, err
		}
		// Strictly ascending, pairwise distinct: canonical encoding.
		if i > 0 && bytes.Compare(key, prev) <= 0 {
			return nil, ErrMalformed
		}
		prev = key
		if _, err := c.take(LenCASig); err != nil {
			return nil, err
		}
	}
	caSigs := buf[caStart:c.pos]
	if c.pos != len(buf) {
		return nil, ErrTrailingBytes
	}
	return &Cert{
		Version:    version,
		RoleBits:   roleBits,
		SigPubkey:  sigPub,
		KexPubkey:  kexPub,
		NotBefore:  notBefore,
		NotAfter:   notAfter,
		Name:       name,
		ScopeCount: scopeCount,
		ScopeIDs:   scopeIDs,
		CASigCount: caCount,
		CASigs:     caSigs,
		TBS:        tbs,
	}, nil
}

// CAPairs returns the certificate's (ca_key, ca_sig) pairs.
func (ct *Cert) CAPairs() []CAPair {
	n := int(ct.CASigCount)
	pairs := make([]CAPair, 0, n)
	const pairLen = LenCAKey + LenCASig
	for i := 0; i < n; i++ {
		off := i * pairLen
		pairs = append(pairs, CAPair{
			Key: ct.CASigs[off : off+LenCAKey],
			Sig: ct.CASigs[off+LenCAKey : off+pairLen],
		})
	}
	return pairs
}

// VerifyCASignatures checks every (ca_key, ca_sig) pair over
// (DomainCert || TBS). If trusted is non-nil, every ca_key must also be
// in the trusted set (BE-ID-02: every pair verifies, every key trusted;
// rejection is unconditional).
func (ct *Cert) VerifyCASignatures(trusted [][]byte) error {
	for _, p := range ct.CAPairs() {
		if err := VerifySigned(DomainCert, ct.TBS, p.Sig, p.Key); err != nil {
			return err
		}
		if trusted != nil && !inSet(p.Key, trusted) {
			return ErrBadSignature
		}
	}
	return nil
}

func inSet(key []byte, set [][]byte) bool {
	for _, k := range set {
		if bytes.Equal(k, key) {
			return true
		}
	}
	return false
}
