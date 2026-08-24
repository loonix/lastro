package wire

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"

	"golang.org/x/crypto/blake2s"
)

// BE-SIG-01 domain tags. Every Ed25519 signature in the protocol is
// computed over a one-byte tag prepended to the structure's encoded
// bytes; verification rejects a signature whose tag does not match the
// structure being verified.
const (
	DomainCert        byte = 0x01
	DomainEnvelope    byte = 0x02
	DomainSpan        byte = 0x03
	DomainGrant       byte = 0x04
	DomainBinding     byte = 0x05
	DomainRefusal     byte = 0x06
	DomainRelayReg    byte = 0x07
	DomainResourceSet byte = 0x08
)

var (
	ErrMalformedKey = errors.New("wire: malformed public key")
	ErrBadSignature = errors.New("wire: signature verification failed")
)

// VerifySigned verifies sig over (tag || tbs) against pubkey.
func VerifySigned(tag byte, tbs, sig, pubkey []byte) error {
	if len(pubkey) != ed25519.PublicKeySize {
		return ErrMalformedKey
	}
	if len(sig) != ed25519.SignatureSize {
		return ErrBadSignature
	}
	msg := make([]byte, 1+len(tbs))
	msg[0] = tag
	copy(msg[1:], tbs)
	if !ed25519.Verify(ed25519.PublicKey(pubkey), msg, sig) {
		return ErrBadSignature
	}
	return nil
}

// SignTagged signs (tag || tbs) with an Ed25519 private key. The signing
// half of VerifySigned; the attest CLI uses it to mint Span signatures.
func SignTagged(tag byte, tbs []byte, priv ed25519.PrivateKey) []byte {
	msg := make([]byte, 1+len(tbs))
	msg[0] = tag
	copy(msg[1:], tbs)
	return ed25519.Sign(priv, msg)
}

// Blake2s256 is the protocol hash (SPEC §2.1).
func Blake2s256(data []byte) [32]byte {
	return blake2s.Sum256(data)
}

// OverlayAddr derives a node's overlay address from its Ed25519 signing
// key: 0xfd || BLAKE2s-256(sig_pubkey)[0..15] (BE-ID-01, SPEC §3.2).
// The address is a commitment to the key; it is never asserted.
func OverlayAddr(sigPubkey []byte) [16]byte {
	h := blake2s.Sum256(sigPubkey)
	var addr [16]byte
	addr[0] = 0xfd
	copy(addr[1:], h[:15])
	return addr
}

// Fingerprint is the executor fingerprint used inside canonical resource
// ids: BLAKE2s-256(sig_pubkey)[0..8], 16 lowercase hex chars (BE-RES-06).
func Fingerprint(sigPubkey []byte) string {
	h := blake2s.Sum256(sigPubkey)
	return hex.EncodeToString(h[:8])
}
