package wire

// Noise_IK_25519_ChaChaPoly_BLAKE2s (SPEC §4.1, BE-TR-04) — the Go side
// of the G2 interop handshake. There are no frozen vectors for this by
// design: Noise derives fresh ephemeral keys each handshake, so the proof
// is a live handshake completing, not a byte comparison. This file
// mirrors the reference src/noise.zig exactly (same protocol name, empty
// prologue, big-endian nonce, split convention) so the Go initiator and
// the Zig responder — and vice versa — reach the same transport keys and
// the same transcript hash h (which BE-TR-01's binding signature covers).

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/blake2s"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const (
	dhLen   = 32
	hashLen = 32
	keyLen  = 32
	tagLen  = 16
	nonceLn = 12

	// SPEC §4.1: 33 bytes, longer than hashLen, so initial h = BLAKE2s(name).
	protocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s"

	// SPEC §4.1a message sizes and the mac1 offsets.
	Msg1Size      = 144
	Msg2Size      = 92
	msg1BeforeMac = 112
	msg2BeforeMac = 60

	off1SenderIndex = 4
	off1Ephemeral   = 8
	off1EncStatic   = 40 // 48 bytes (32 + 16 tag)
	off1EncTime     = 88 // 24 bytes (8 + 16 tag)
	off1Mac1        = 112
	off1Mac2        = 128

	off2SenderIndex   = 4
	off2ReceiverIndex = 8
	off2Ephemeral     = 12
	off2EncNothing    = 44 // 16 bytes (0 + 16 tag)
	off2Mac1          = 60
	off2Mac2          = 76

	mac1Label = "bolina-mac1-v2"
)

var (
	ErrMac1Failed    = errors.New("noise: mac1 verification failed")
	ErrDecryptFailed = errors.New("noise: AEAD decrypt failed")
	ErrIdentityPoint = errors.New("noise: peer public key is a low-order point")
)

// HandshakeResult: the two transport keys and the transcript hash a
// completed handshake yields. SendKey encrypts this side's outgoing
// transport, RecvKey decrypts the peer's, H is what BE-TR-01 binds.
type HandshakeResult struct {
	SendKey [keyLen]byte
	RecvKey [keyLen]byte
	H       [hashLen]byte
}

// transportNonce: four zero bytes then the big-endian u64 counter (SPEC
// §2.2). Shared by the handshake symmetric state and the transport AEAD.
func transportNonce(counter uint64) [nonceLn]byte {
	var nb [nonceLn]byte
	binary.BigEndian.PutUint64(nb[4:], counter)
	return nb
}

// hmacBlake2s computes HMAC-BLAKE2s-256 (unkeyed BLAKE2s under standard
// ipad/opad — the Noise HKDF core, not BLAKE2's built-in keyed mode).
func hmacBlake2s(key, data []byte) [hashLen]byte {
	const blockSize = 64 // BLAKE2s block size
	var k [blockSize]byte
	if len(key) > blockSize {
		h := blake2sSum(key)
		copy(k[:], h[:])
	} else {
		copy(k[:], key)
	}
	var ipad, opad [blockSize]byte
	for i := 0; i < blockSize; i++ {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5c
	}
	inner := blake2sSum(append(append([]byte{}, ipad[:]...), data...))
	outer := blake2sSum(append(append([]byte{}, opad[:]...), inner[:]...))
	return outer
}

func blake2sSum(data []byte) [hashLen]byte {
	return blake2s.Sum256(data)
}

// hkdf2: temp = HMAC(ck, ikm); o1 = HMAC(temp, 0x01); o2 = HMAC(temp, o1||0x02).
func hkdf2(ck [hashLen]byte, ikm []byte) (o1, o2 [hashLen]byte) {
	temp := hmacBlake2s(ck[:], ikm)
	o1 = hmacBlake2s(temp[:], []byte{1})
	o2 = hmacBlake2s(temp[:], append(append([]byte{}, o1[:]...), 2))
	return
}

// symmetricState is the Noise symmetric state.
type symmetricState struct {
	h      [hashLen]byte
	ck     [hashLen]byte
	k      [keyLen]byte
	n      uint64
	hasKey bool
}

func newSymmetricState() *symmetricState {
	s := &symmetricState{}
	s.h = blake2sSum([]byte(protocolName))
	s.ck = s.h
	return s
}

func (s *symmetricState) mixHash(data []byte) {
	s.h = blake2sSum(append(append([]byte{}, s.h[:]...), data...))
}

func (s *symmetricState) mixKey(ikm [dhLen]byte) {
	o1, o2 := hkdf2(s.ck, ikm[:])
	s.ck = o1
	s.k = o2
	s.n = 0
	s.hasKey = true
}

func (s *symmetricState) aead() (cipher.AEAD, error) {
	return chacha20poly1305.New(s.k[:])
}

// encryptAndHash: AEAD-encrypt plaintext under k with ad = h, append tag,
// advance the nonce, mixHash the ciphertext-with-tag. No key => passthrough.
func (s *symmetricState) encryptAndHash(plaintext []byte) ([]byte, error) {
	if !s.hasKey {
		s.mixHash(plaintext)
		return append([]byte{}, plaintext...), nil
	}
	aead, err := s.aead()
	if err != nil {
		return nil, err
	}
	nonce := transportNonce(s.n)
	ct := aead.Seal(nil, nonce[:], plaintext, s.h[:])
	s.n++
	s.mixHash(ct)
	return ct, nil
}

// decryptAndHash: the inverse. A tag mismatch is ErrDecryptFailed.
func (s *symmetricState) decryptAndHash(ct []byte) ([]byte, error) {
	if !s.hasKey {
		s.mixHash(ct)
		return append([]byte{}, ct...), nil
	}
	aead, err := s.aead()
	if err != nil {
		return nil, err
	}
	nonce := transportNonce(s.n)
	pt, err := aead.Open(nil, nonce[:], ct, s.h[:])
	if err != nil {
		return nil, ErrDecryptFailed
	}
	s.n++
	s.mixHash(ct)
	return pt, nil
}

// split: two transport keys from HKDF(ck, "", 2).
func (s *symmetricState) split() (c1, c2 [keyLen]byte) {
	return hkdf2(s.ck, nil)
}

func dh(localSecret, remotePub [dhLen]byte) ([dhLen]byte, error) {
	out, err := curve25519.X25519(localSecret[:], remotePub[:])
	if err != nil {
		return [dhLen]byte{}, ErrIdentityPoint
	}
	var r [dhLen]byte
	copy(r[:], out)
	return r, nil
}

// mac1Key = BLAKE2s-256("bolina-mac1-v2" || responder_sig_pubkey).
func mac1Key(responderSigPub [32]byte) [32]byte {
	return blake2sSum(append([]byte(mac1Label), responderSigPub[:]...))
}

// computeMac1 = BLAKE2s-128 keyed with mac1Key over the preceding bytes.
func computeMac1(responderSigPub [32]byte, preceding []byte) [16]byte {
	key := mac1Key(responderSigPub)
	h, _ := blake2s.New128(key[:])
	h.Write(preceding)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Initiator drives the Noise_IK initiation. The initiator knows the
// responder's static X25519 key (from its certificate, §5.1a).
type Initiator struct {
	sym             *symmetricState
	staticSecret    [dhLen]byte
	staticPublic    [dhLen]byte
	ephSecret       [dhLen]byte
	ephPublic       [dhLen]byte
	responderStatic [dhLen]byte
	re              [dhLen]byte
}

// NewInitiator seeds from the initiator's static keypair and the
// responder's static public. The empty prologue leaves h at the
// protocol-name hash; the responder static is the IK pre-message.
func NewInitiator(staticSecret, staticPublic, responderStatic [dhLen]byte) *Initiator {
	s := newSymmetricState()
	s.mixHash(responderStatic[:])
	return &Initiator{sym: s, staticSecret: staticSecret, staticPublic: staticPublic, responderStatic: responderStatic}
}

// WriteInitiation writes the 144-byte message 1 into out. Tokens: e, es,
// s, ss, then the encrypted timestamp. ephSecret is supplied so the
// caller owns entropy (RNG in production, fixed in a round-trip test).
func (in *Initiator) WriteInitiation(out []byte, senderIndex uint32, timestampMS uint64, ephSecret [dhLen]byte, responderSigPub [32]byte, mac2Cookie [16]byte) error {
	if len(out) < Msg1Size {
		return errors.New("noise: out too small")
	}
	in.ephSecret = ephSecret
	pub, err := curve25519.X25519(ephSecret[:], curve25519.Basepoint)
	if err != nil {
		return ErrIdentityPoint
	}
	copy(in.ephPublic[:], pub)
	copy(out[off1Ephemeral:], in.ephPublic[:])
	in.sym.mixHash(in.ephPublic[:])
	// es
	es, err := dh(in.ephSecret, in.responderStatic)
	if err != nil {
		return err
	}
	in.sym.mixKey(es)
	// s (initiator static, encrypted+hashed)
	encS, err := in.sym.encryptAndHash(in.staticPublic[:])
	if err != nil {
		return err
	}
	copy(out[off1EncStatic:], encS)
	// ss
	ss, err := dh(in.staticSecret, in.responderStatic)
	if err != nil {
		return err
	}
	in.sym.mixKey(ss)
	// encrypted timestamp (u64 ms, big-endian)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], timestampMS)
	encTs, err := in.sym.encryptAndHash(ts[:])
	if err != nil {
		return err
	}
	copy(out[off1EncTime:], encTs)
	// framing + DoS proofs
	out[0] = 1
	out[1], out[2], out[3] = 0, 0, 0
	binary.BigEndian.PutUint32(out[off1SenderIndex:], senderIndex)
	m1 := computeMac1(responderSigPub, out[:msg1BeforeMac])
	copy(out[off1Mac1:], m1[:])
	copy(out[off1Mac2:], mac2Cookie[:])
	return nil
}

// ReadResponse reads the 92-byte message 2, verifying mac1 first. Tokens:
// e, ee, se, then the empty encrypted payload.
func (in *Initiator) ReadResponse(msg2 []byte, responderSigPub [32]byte) error {
	if len(msg2) < Msg2Size {
		return errors.New("noise: msg2 too small")
	}
	var m1in [16]byte
	copy(m1in[:], msg2[off2Mac1:])
	if computeMac1(responderSigPub, msg2[:msg2BeforeMac]) != m1in {
		return ErrMac1Failed
	}
	copy(in.re[:], msg2[off2Ephemeral:off2Ephemeral+dhLen])
	in.sym.mixHash(in.re[:])
	// ee
	ee, err := dh(in.ephSecret, in.re)
	if err != nil {
		return err
	}
	in.sym.mixKey(ee)
	// se
	se, err := dh(in.staticSecret, in.re)
	if err != nil {
		return err
	}
	in.sym.mixKey(se)
	// empty encrypted payload
	if _, err := in.sym.decryptAndHash(msg2[off2EncNothing : off2EncNothing+tagLen]); err != nil {
		return err
	}
	return nil
}

// Finalize: the initiator sends under c1, receives under c2.
func (in *Initiator) Finalize() HandshakeResult {
	c1, c2 := in.sym.split()
	return HandshakeResult{SendKey: c1, RecvKey: c2, H: in.sym.h}
}

// Responder drives the Noise_IK response.
type Responder struct {
	sym             *symmetricState
	staticSecret    [dhLen]byte
	staticPublic    [dhLen]byte
	ephSecret       [dhLen]byte
	ephPublic       [dhLen]byte
	re              [dhLen]byte
	RemoteStaticPub [dhLen]byte
}

// NewResponder seeds from the responder's static keypair.
func NewResponder(staticSecret, staticPublic [dhLen]byte) *Responder {
	s := newSymmetricState()
	s.mixHash(staticPublic[:])
	return &Responder{sym: s, staticSecret: staticSecret, staticPublic: staticPublic}
}

// ReadInitiation reads message 1, verifying mac1 before any DH. Tokens:
// e, es, s, ss, then the encrypted timestamp. Captures the initiator
// static into RemoteStaticPub.
func (re *Responder) ReadInitiation(msg1 []byte, responderSigPub [32]byte) error {
	if len(msg1) < Msg1Size {
		return errors.New("noise: msg1 too small")
	}
	var m1in [16]byte
	copy(m1in[:], msg1[off1Mac1:])
	if computeMac1(responderSigPub, msg1[:msg1BeforeMac]) != m1in {
		return ErrMac1Failed
	}
	copy(re.re[:], msg1[off1Ephemeral:off1Ephemeral+dhLen])
	re.sym.mixHash(re.re[:])
	// es: DH(s_R, e_I)
	es, err := dh(re.staticSecret, re.re)
	if err != nil {
		return err
	}
	re.sym.mixKey(es)
	// s: initiator static, decrypted+hashed
	staticI, err := re.sym.decryptAndHash(msg1[off1EncStatic : off1EncStatic+dhLen+tagLen])
	if err != nil {
		return err
	}
	copy(re.RemoteStaticPub[:], staticI)
	// ss: DH(s_R, s_I)
	ss, err := dh(re.staticSecret, re.RemoteStaticPub)
	if err != nil {
		return err
	}
	re.sym.mixKey(ss)
	// encrypted timestamp
	if _, err := re.sym.decryptAndHash(msg1[off1EncTime : off1EncTime+8+tagLen]); err != nil {
		return err
	}
	return nil
}

// WriteResponse writes the 92-byte message 2. Tokens: e, ee, se, then the
// empty encrypted payload.
func (re *Responder) WriteResponse(out []byte, senderIndex, receiverIndex uint32, ephSecret [dhLen]byte, responderSigPub [32]byte, mac2Cookie [16]byte) error {
	if len(out) < Msg2Size {
		return errors.New("noise: out too small")
	}
	re.ephSecret = ephSecret
	pub, err := curve25519.X25519(ephSecret[:], curve25519.Basepoint)
	if err != nil {
		return ErrIdentityPoint
	}
	copy(re.ephPublic[:], pub)
	out[0] = 2
	out[1], out[2], out[3] = 0, 0, 0
	binary.BigEndian.PutUint32(out[off2SenderIndex:], senderIndex)
	binary.BigEndian.PutUint32(out[off2ReceiverIndex:], receiverIndex)
	copy(out[off2Ephemeral:], re.ephPublic[:])
	re.sym.mixHash(re.ephPublic[:])
	// ee: DH(e_R, e_I)
	ee, err := dh(re.ephSecret, re.re)
	if err != nil {
		return err
	}
	re.sym.mixKey(ee)
	// se: DH(e_R, s_I)
	se, err := dh(re.ephSecret, re.RemoteStaticPub)
	if err != nil {
		return err
	}
	re.sym.mixKey(se)
	// empty encrypted payload
	encNothing, err := re.sym.encryptAndHash(nil)
	if err != nil {
		return err
	}
	copy(out[off2EncNothing:], encNothing)
	// DoS proofs
	m1 := computeMac1(responderSigPub, out[:msg2BeforeMac])
	copy(out[off2Mac1:], m1[:])
	copy(out[off2Mac2:], mac2Cookie[:])
	return nil
}

// Finalize: the responder sends under c2, receives under c1.
func (re *Responder) Finalize() HandshakeResult {
	c1, c2 := re.sym.split()
	return HandshakeResult{SendKey: c2, RecvKey: c1, H: re.sym.h}
}
