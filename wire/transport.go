package wire

// Post-handshake transport (SPEC §4.1a type 4) and the BE-TR-01 binding
// frame — the two things the interop needs beyond the handshake itself:
// seal an envelope into a transport data packet, and build/verify the
// binding frame that authenticates the session's owner.

import (
	"crypto/ed25519"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	transportType   = 4
	transportHdrLen = 16 // type + reserved + receiver_index + counter
)

// SealTransport builds one type-4 data packet: a 16-byte header (type 4,
// zero reserved, peer's receiver_index, big-endian counter) followed by
// the ChaCha20-Poly1305 sealing of plaintext with the header as
// associated data (the "decrypt in place" shape, SPEC §4.1a).
func SealTransport(key [keyLen]byte, receiverIndex uint32, counter uint64, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, err
	}
	hdr := make([]byte, transportHdrLen)
	hdr[0] = transportType
	binary.BigEndian.PutUint32(hdr[4:], receiverIndex)
	binary.BigEndian.PutUint64(hdr[8:], counter)
	nonce := transportNonce(counter)
	ct := aead.Seal(nil, nonce[:], plaintext, hdr)
	return append(hdr, ct...), nil
}

// OpenTransport is the inverse: given the whole packet, decrypt the
// payload under key with the 16-byte header as associated data. Returns
// the plaintext and the counter the header carried.
func OpenTransport(key [keyLen]byte, packet []byte) ([]byte, uint64, error) {
	if len(packet) < transportHdrLen+tagLen {
		return nil, 0, errors.New("transport: packet too short")
	}
	if packet[0] != transportType {
		return nil, 0, errors.New("transport: not a type-4 packet")
	}
	counter := binary.BigEndian.Uint64(packet[8:16])
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, 0, err
	}
	nonce := transportNonce(counter)
	pt, err := aead.Open(nil, nonce[:], packet[transportHdrLen:], packet[:transportHdrLen])
	if err != nil {
		return nil, 0, ErrDecryptFailed
	}
	return pt, counter, nil
}

// BuildBindingFrame builds the BE-TR-01a binding message: u16be cert_len
// || cert || Ed25519 signature over (0x05 || h). This is the first
// plaintext each side sends inside the session; the peer verifies the
// cert clock-free and the signature over the transcript hash.
func BuildBindingFrame(cert []byte, sigSeed [32]byte, h [hashLen]byte) []byte {
	priv := ed25519.NewKeyFromSeed(sigSeed[:])
	msg := append([]byte{DomainBinding}, h[:]...)
	sig := ed25519.Sign(priv, msg)
	out := make([]byte, 2+len(cert)+len(sig))
	binary.BigEndian.PutUint16(out[:2], uint16(len(cert)))
	copy(out[2:], cert)
	copy(out[2+len(cert):], sig)
	return out
}

// ParseBindingFrame splits a binding frame into its cert bytes and the
// 64-byte signature.
func ParseBindingFrame(frame []byte) (cert, sig []byte, err error) {
	if len(frame) < 2 {
		return nil, nil, ErrTruncated
	}
	certLen := int(binary.BigEndian.Uint16(frame[:2]))
	if len(frame) != 2+certLen+LenSig {
		return nil, nil, errors.New("binding: length mismatch")
	}
	return frame[2 : 2+certLen], frame[2+certLen:], nil
}

// VerifyBindingFrame checks a received binding frame against a session's
// transcript hash and the trusted CA set: the cert parses and validates
// clock-free (audit stance, BE-HIST-01 — the session is live but the
// binding check is structural), and the signature verifies over
// (0x05 || h) against the cert's own sig key. Returns the verified cert.
func VerifyBindingFrame(frame []byte, h [hashLen]byte, trusted [][]byte) (*Cert, error) {
	certBytes, sig, err := ParseBindingFrame(frame)
	if err != nil {
		return nil, err
	}
	cert, err := ParseCert(certBytes)
	if err != nil {
		return nil, err
	}
	if err := ValidateCertChainNoClock(cert, trusted); err != nil {
		return nil, err
	}
	if VerifySigned(DomainBinding, h[:], sig, cert.SigPubkey) != nil {
		return nil, errors.New("binding: signature does not verify over h")
	}
	return cert, nil
}
