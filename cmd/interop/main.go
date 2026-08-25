// Command interop drives the G2 live handshake: a Go Noise_IK initiator
// against a real bolina daemon (responder), then the binding frames both
// ways, then one Intent envelope through the session. It is the phase-B
// proof of gate G2 — two independent implementations agreeing live, not
// just on frozen bytes. See docs/G2-INTEROP-HANDSHAKE.md.
//
// Usage:
//
//	interop --daemon 127.0.0.1:7420 --node-go DIR --daemon-static FILE
//	        --daemon-sigpub FILE [--intent]
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/loonix/lastro/wire"
)

// SPEC §4.1a type-2 response index offsets: sender_index (responder's own
// slot) at byte 4, receiver_index (echo of our sender_index) at byte 8.
const (
	off2SenderConformant   = 4
	off2ReceiverConformant = 8
)

func readKey(path string) ([32]byte, error) {
	var k [32]byte
	b, err := os.ReadFile(path)
	if err != nil {
		return k, err
	}
	if len(b) != 32 {
		return k, fmt.Errorf("%s: expected 32 bytes, got %d", path, len(b))
	}
	copy(k[:], b)
	return k, nil
}

func fail(msg string, err error) {
	fmt.Fprintf(os.Stderr, "interop: %s: %v\n", msg, err)
	os.Exit(1)
}

func main() {
	daemonAddr := flag.String("daemon", "127.0.0.1:7420", "daemon UDP endpoint")
	nodeGo := flag.String("node-go", "node-go", "Go node dir (sig.key, static.key, cert.bin)")
	daemonStaticF := flag.String("daemon-static", "", "daemon static.pub (X25519, header encryption target)")
	daemonSigpubF := flag.String("daemon-sigpub", "", "daemon sig.pub (Ed25519, mac1 key)")
	trustDir := flag.String("ca", "node-go/ca", "dir of trusted CA pubkeys (ca0.pub..)")
	sendIntent := flag.Bool("intent", false, "stage C: send one Intent envelope after binding")
	resourceNS := flag.String("res-ns", "interop", "resource namespace for stage C")
	resourceID := flag.String("res-id", "demo", "resource path for stage C")
	flag.Parse()

	// Load the Go node's own material.
	goStaticSec, err := readKey(*nodeGo + "/static.key")
	if err != nil {
		fail("go static.key", err)
	}
	goStaticPub, err := readKey(*nodeGo + "/static.pub")
	if err != nil {
		fail("go static.pub", err)
	}
	goSigSeed, err := readKey(*nodeGo + "/sig.key")
	if err != nil {
		fail("go sig.key", err)
	}
	goCert, err := os.ReadFile(*nodeGo + "/cert.bin")
	if err != nil {
		fail("go cert.bin", err)
	}
	// The daemon's keys (the initiator must know both, §5.1a).
	daemonStatic, err := readKey(*daemonStaticF)
	if err != nil {
		fail("daemon static.pub", err)
	}
	daemonSigpub, err := readKey(*daemonSigpubF)
	if err != nil {
		fail("daemon sig.pub", err)
	}
	// Trust anchors.
	var trusted [][]byte
	for i := 0; i < 8; i++ {
		b, err := os.ReadFile(fmt.Sprintf("%s/ca%d.pub", *trustDir, i))
		if err != nil {
			break
		}
		trusted = append(trusted, b)
	}
	if len(trusted) == 0 {
		fail("trust set", fmt.Errorf("no CA pubkeys in %s", *trustDir))
	}

	conn, err := net.Dial("udp", *daemonAddr)
	if err != nil {
		fail("dial", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// --- Handshake: write initiation, read response. ---
	var eph [32]byte
	if _, err := rand.Read(eph[:]); err != nil {
		fail("entropy", err)
	}
	initiator := wire.NewInitiator(goStaticSec, goStaticPub, daemonStatic)
	var msg1 [wire.Msg1Size]byte
	senderIndex := uint32(0x51530001)
	if err := initiator.WriteInitiation(msg1[:], senderIndex, uint64(time.Now().UnixMilli()), eph, daemonSigpub, [16]byte{}); err != nil {
		fail("WriteInitiation", err)
	}
	if _, err := conn.Write(msg1[:]); err != nil {
		fail("send initiation", err)
	}
	fmt.Println("interop: [A] initiation sent (144 bytes)")

	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		fail("read response (stage A)", err)
	}
	if n < wire.Msg2Size || buf[0] != 2 {
		fail("stage A", fmt.Errorf("reply is %d bytes, first=0x%02x (want a 92-byte type-2)", n, buf[0]))
	}
	if err := initiator.ReadResponse(buf[:wire.Msg2Size], daemonSigpub); err != nil {
		fail("ReadResponse", err)
	}
	res := initiator.Finalize()
	// SPEC §4.1a conformant read: the type-2 response carries the
	// responder's own session index in sender_index (offset 4); offset 8
	// echoes our initiation sender_index. Transport packets to the daemon
	// use the daemon's sender_index as their receiver_index. (An earlier
	// interop read offset 8 to accommodate the handshake.zig index swap
	// this project fixed in e4fd0d4 — a strictly conformant initiator
	// like this one rejects a response whose announced index != slot,
	// which is exactly the defect the live handshake surfaced.)
	daemonIndex := binary.BigEndian.Uint32(buf[off2SenderConformant:])
	senderEcho := binary.BigEndian.Uint32(buf[off2ReceiverConformant:])
	fmt.Printf("interop: [A] handshake complete · transcript h=%x… · daemon index=0x%08x (echo=0x%08x)\n", res.H[:6], daemonIndex, senderEcho)

	// --- Binding: send ours, expect theirs. ---
	frame := wire.BuildBindingFrame(goCert, goSigSeed, res.H)
	pkt, err := wire.SealTransport(res.SendKey, daemonIndex, 0, frame)
	if err != nil {
		fail("seal binding", err)
	}
	if _, err := conn.Write(pkt); err != nil {
		fail("send binding", err)
	}
	fmt.Printf("interop: [B] binding frame sent (%d bytes cert)\n", len(goCert))

	// The daemon pushes its own binding frame right after the handshake
	// commit; read and verify it.
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	n, err = conn.Read(buf)
	if err != nil {
		fail("read daemon binding (stage B)", err)
	}
	theirFrame, _, err := wire.OpenTransport(res.RecvKey, buf[:n])
	if err != nil {
		fail("open daemon binding", err)
	}
	cert, err := wire.VerifyBindingFrame(theirFrame, res.H, trusted)
	if err != nil {
		fail("verify daemon binding", err)
	}
	fmt.Printf("interop: [B] daemon binding verified · daemon fp=%s · chain clock-free OK\n", wire.Fingerprint(cert.SigPubkey))

	if !*sendIntent {
		fmt.Println("interop: stages A+B green (handshake + mutual binding). Re-run with --intent for stage C.")
		return
	}

	// --- Stage C: one Intent envelope through the session. ---
	// The intent's resource must resolve at the daemon (BE-RES-02), so it
	// names the DAEMON's fingerprint (BE-RES-04). The daemon must have been
	// booted with BOLINA_RESOURCES=<this exact id>.
	daemonFP := wire.Fingerprint(cert.SigPubkey)
	resource := "bol:" + daemonFP + "/" + *resourceNS + "/" + *resourceID
	var intentID [16]byte
	rand.Read(intentID[:])
	fmt.Printf("interop: [C] intent_id=%x\n", intentID)
	intentBody, err := wire.EncodeIntentBody(&wire.Intent{
		IntentID:   intentID[:],
		ResourceID: []byte(resource),
		Action:     []byte("apt-get install -y sqlite3"),
		Rationale:  []byte("interop stage C"),
	})
	if err != nil {
		fail("encode intent", err)
	}
	// Envelope signed by the Go node (sender = its sig key). channel_id is
	// any 32 bytes for this phase-A dispatch path (no membership check).
	var channelID [32]byte
	goSigPub := ed25519Pub(goSigSeed)
	env, err := wire.BuildSignedEnvelope(2, channelID[:], goSigPub[:], 1, nil, 0, uint64(time.Now().UnixMilli()), wire.BodyIntent, intentBody, goSigSeed)
	if err != nil {
		fail("build envelope", err)
	}
	pkt, err = wire.SealTransport(res.SendKey, daemonIndex, 1, env)
	if err != nil {
		fail("seal envelope", err)
	}
	if _, err := conn.Write(pkt); err != nil {
		fail("send envelope", err)
	}
	fmt.Printf("interop: [C] Intent envelope sent (%d bytes) · resource %s\n", len(env), resource)
	time.Sleep(300 * time.Millisecond)
	fmt.Println("interop: [C] check the daemon metrics for bolina_intents_admitted_total")
}

func ed25519Pub(seed [32]byte) [32]byte {
	pub := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	var out [32]byte
	copy(out[:], pub)
	return out
}
