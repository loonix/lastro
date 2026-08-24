// Command lastro mints and verifies detached Bolina receipts
// (RECEIPT-PROFILE.md). Three subcommands:
//
//	lastro keygen --dir DIR
//	lastro run --key DIR --namespace ns --path p [flags] -- command args...
//	lastro verify FILE.receipt [--cert cert.bin] [--ca ca.pub]...
//
// Exit codes: run exits with the child's code when the receipt was
// written, 125 when the child ran but no receipt could be produced, 127
// when the child could not start. verify exits 0 fully verified, 1
// invalid, 2 usage, 3 unanchored (signature valid, no identity given).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/curve25519"

	"github.com/loonix/lastro/wire"
)

const (
	defaultMaxOutput = 8 << 20 // 8 MiB (RECEIPT-PROFILE.md §2)

	exitNoReceipt = 125
	exitNoStart   = 127

	verifyOK         = 0
	verifyInvalid    = 1
	verifyUsage      = 2
	verifyUnanchored = 3
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(verifyUsage)
	}
	switch os.Args[1] {
	case "keygen":
		os.Exit(cmdKeygen(os.Args[2:]))
	case "run":
		os.Exit(cmdRun(os.Args[2:]))
	case "verify":
		os.Exit(cmdVerify(os.Args[2:]))
	default:
		usage()
		os.Exit(verifyUsage)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `lastro — signed receipts for AI/CI work (Bolina spans, detached profile)

  lastro keygen --dir DIR
  lastro run --key DIR --namespace NS --path P [--trace HEX32] [--out FILE]
            [--max-output N] [--save-output FILE] -- command args...
  lastro verify FILE.receipt [--cert cert.bin] [--ca ca.pub]...
`)
}

// ---------------------------------------------------------------------------
// keygen: the Bolina node key layout (sig.key/sig.pub, static.key/
// static.pub, 32-byte raw, 0600, dir 0700), so `bolina ca issue` works
// against the same directory. Never regenerates over existing secrets.
// ---------------------------------------------------------------------------

func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	dir := fs.String("dir", "", "key directory to create")
	fs.Parse(args)
	if *dir == "" {
		fmt.Fprintln(os.Stderr, "lastro keygen: --dir is required")
		return verifyUsage
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "lastro keygen: %v\n", err)
		return 1
	}
	sigKeyPath := filepath.Join(*dir, "sig.key")
	if _, err := os.Stat(sigKeyPath); err == nil {
		fmt.Fprintf(os.Stderr, "lastro keygen: %s exists; refusing to overwrite key material\n", sigKeyPath)
		return 1
	}
	var sigSeed, kexSecret [32]byte
	if _, err := rand.Read(sigSeed[:]); err != nil {
		fmt.Fprintf(os.Stderr, "lastro keygen: entropy: %v\n", err)
		return 1
	}
	if _, err := rand.Read(kexSecret[:]); err != nil {
		fmt.Fprintf(os.Stderr, "lastro keygen: entropy: %v\n", err)
		return 1
	}
	sigPub := ed25519.NewKeyFromSeed(sigSeed[:]).Public().(ed25519.PublicKey)
	kexPub, err := curve25519.X25519(kexSecret[:], curve25519.Basepoint)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lastro keygen: x25519: %v\n", err)
		return 1
	}
	files := []struct {
		name string
		data []byte
	}{
		{"sig.key", sigSeed[:]},
		{"sig.pub", sigPub},
		{"static.key", kexSecret[:]},
		{"static.pub", kexPub},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(*dir, f.name), f.data, 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "lastro keygen: write %s: %v\n", f.name, err)
			return 1
		}
	}
	fmt.Printf("lastro: keys written to %s\n", *dir)
	fmt.Printf("lastro: executor fingerprint %s\n", wire.Fingerprint(sigPub))
	fmt.Println("lastro: request an executor certificate with: bolina ca issue --role executor ...")
	return 0
}

// ---------------------------------------------------------------------------
// run: execute, observe, mint the receipt.
// ---------------------------------------------------------------------------

// captureWriter tees child output into a bounded buffer. Stdout and
// stderr pipes are copied on separate goroutines by os/exec, so the
// merge is mutex-guarded; the merged order is "as observed by this
// process" (RECEIPT-PROFILE.md §2).
type captureWriter struct {
	mu       sync.Mutex
	buf      []byte
	max      int
	exceeded bool
}

func (w *captureWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.exceeded {
		if len(w.buf)+len(p) > w.max {
			w.exceeded = true
		} else {
			w.buf = append(w.buf, p...)
		}
	}
	return len(p), nil
}

func cmdRun(args []string) int {
	// Split our flags from the child command at "--".
	sep := -1
	for i, a := range args {
		if a == "--" {
			sep = i
			break
		}
	}
	if sep < 0 || sep == len(args)-1 {
		fmt.Fprintln(os.Stderr, "lastro run: missing '-- command args...'")
		return verifyUsage
	}
	child := args[sep+1:]

	fs := flag.NewFlagSet("run", flag.ExitOnError)
	keyDir := fs.String("key", "", "key directory (from lastro keygen)")
	namespace := fs.String("namespace", "", "resource namespace ([a-z0-9-], <=32)")
	resPath := fs.String("path", "", "resource path ([a-z0-9-._/], <=180)")
	traceHex := fs.String("trace", "", "optional 16-byte trace id, hex (groups runs)")
	outPath := fs.String("out", "lastro.receipt", "receipt output file")
	maxOutput := fs.Int("max-output", defaultMaxOutput, "capture cap in bytes; exceeding it produces no receipt")
	saveOutput := fs.String("save-output", "", "also write the captured stream (with trailer) to this file")
	fs.Parse(args[:sep])

	if *keyDir == "" || *namespace == "" || *resPath == "" {
		fmt.Fprintln(os.Stderr, "lastro run: --key, --namespace and --path are required")
		return verifyUsage
	}
	resolvedPath, err := resolveShaTemplate(*resPath, gitHead)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lastro run: %v\n", err)
		return verifyUsage
	}
	if err := validateResource(*namespace, resolvedPath); err != nil {
		fmt.Fprintf(os.Stderr, "lastro run: %v\n", err)
		return verifyUsage
	}
	seed, err := os.ReadFile(filepath.Join(*keyDir, "sig.key"))
	if err != nil || len(seed) != ed25519.SeedSize {
		fmt.Fprintf(os.Stderr, "lastro run: cannot read signing key: %v\n", err)
		return exitNoReceipt
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	resource := "bol:" + wire.Fingerprint(pub) + "/" + *namespace + "/" + resolvedPath
	if len(resource) > wire.MaxResource {
		fmt.Fprintln(os.Stderr, "lastro run: resource id exceeds 256 bytes")
		return verifyUsage
	}

	var traceID [wire.LenTraceID]byte
	if *traceHex != "" {
		b, err := hex.DecodeString(*traceHex)
		if err != nil || len(b) != wire.LenTraceID {
			fmt.Fprintln(os.Stderr, "lastro run: --trace must be 32 hex chars")
			return verifyUsage
		}
		copy(traceID[:], b)
	} else if _, err := rand.Read(traceID[:]); err != nil {
		fmt.Fprintf(os.Stderr, "lastro run: entropy: %v\n", err)
		return exitNoReceipt
	}

	// Execute and observe. Output streams through unchanged.
	cap := &captureWriter{max: *maxOutput}
	cmd := exec.Command(child[0], child[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = io.MultiWriter(os.Stdout, cap)
	cmd.Stderr = io.MultiWriter(os.Stderr, cap)
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "lastro run: cannot start %q: %v\n", child[0], err)
		return exitNoStart
	}
	exitCode := 0
	if err := cmd.Wait(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exitCode = ee.ExitCode()
		} else {
			fmt.Fprintf(os.Stderr, "lastro run: wait: %v\n", err)
			return exitNoReceipt
		}
	}

	// BE-EVID-14: an observation that was not fully captured is not an
	// observation. No receipt, loud exit.
	if cap.exceeded {
		fmt.Fprintf(os.Stderr, "lastro run: output exceeded %d bytes; NO receipt written (child exited %d)\n", *maxOutput, exitCode)
		return exitNoReceipt
	}

	// Canonical trailer folds the exit code into the observed stream
	// (RECEIPT-PROFILE.md §2): covered by the digest, readable whenever
	// the output is saved.
	captured := append(cap.buf, []byte(fmt.Sprintf("\n[lastro] exit-status=%d\n", exitCode))...)
	if *saveOutput != "" {
		if err := os.WriteFile(*saveOutput, captured, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "lastro run: save-output: %v; NO receipt written\n", err)
			return exitNoReceipt
		}
	}

	f := wire.SpanFields{
		Version:    2,
		ResourceID: []byte(resource),
		MethodID:   wire.MethodSubprocess, // compile-time constant (BE-EVID-11)
		Volatility: wire.VolatilityVolatile,
		ObservedAt: uint64(time.Now().UnixMilli()),
		TraceID:    traceID,
		Digest:     wire.Blake2s256(captured),
	}
	if _, err := rand.Read(f.SpanID[:]); err != nil {
		fmt.Fprintf(os.Stderr, "lastro run: entropy: %v\n", err)
		return exitNoReceipt
	}
	copy(f.Executor[:], pub)
	// Origin stays zeroed: the detached profile's single deviation.

	receipt, err := wire.BuildSpan(&f, priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lastro run: build span: %v\n", err)
		return exitNoReceipt
	}
	if err := os.WriteFile(*outPath, receipt, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "lastro run: write receipt: %v; child exited %d\n", err, exitCode)
		return exitNoReceipt
	}
	fmt.Fprintf(os.Stderr, "lastro: receipt %s · %s · exit %d · %d bytes observed · digest %s…\n",
		*outPath, resource, exitCode, len(captured), hex.EncodeToString(f.Digest[:8]))
	return exitCode
}

// resolveShaTemplate replaces every "{sha}" in the path with the current
// git HEAD commit, derived from git itself — never from a hand-written
// variable (fase-3 acceptance criterion: a receipt's freshness anchor
// must not be forgeable by a typo'd CI variable). The substituted value
// is validated as lowercase hex before use; the final path still passes
// the full §8.4 grammar check.
func resolveShaTemplate(p string, headFn func() (string, error)) (string, error) {
	if !strings.Contains(p, "{sha}") {
		return p, nil
	}
	raw, err := headFn()
	if err != nil {
		return "", fmt.Errorf("--path contains {sha} but git HEAD is unavailable: %v", err)
	}
	sha := strings.ToLower(strings.TrimSpace(raw))
	if len(sha) < 7 || len(sha) > 64 {
		return "", fmt.Errorf("git HEAD %q is not a commit sha", sha)
	}
	for _, c := range sha {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return "", fmt.Errorf("git HEAD %q is not hex", sha)
		}
	}
	return strings.ReplaceAll(p, "{sha}", sha), nil
}

func gitHead() (string, error) {
	out, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// validateResource enforces the SPEC §8.4 grammar.
func validateResource(ns, p string) error {
	if len(ns) == 0 || len(ns) > 32 {
		return errors.New("namespace must be 1..32 chars")
	}
	for _, c := range ns {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("namespace char %q outside [a-z0-9-]", c)
		}
	}
	if len(p) == 0 || len(p) > 180 {
		return errors.New("path must be 1..180 chars")
	}
	for _, c := range p {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' || c == '/') {
			return fmt.Errorf("path char %q outside [a-z0-9-._/]", c)
		}
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return fmt.Errorf("path segment %q not allowed", seg)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// verify: the RECEIPT-PROFILE.md §4 report.
// ---------------------------------------------------------------------------

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func cmdVerify(args []string) int {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	certPath := fs.String("cert", "", "executor certificate (wire format)")
	var caPaths stringList
	fs.Var(&caPaths, "ca", "trusted CA public key file (repeatable)")
	fs.Parse(args)
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "lastro verify: exactly one receipt file")
		return verifyUsage
	}
	raw, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "lastro verify: %v\n", err)
		return verifyInvalid
	}
	span, err := wire.ParseSpan(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lastro verify: INVALID: receipt does not parse: %v\n", err)
		return verifyInvalid
	}
	if err := span.VerifySig(); err != nil {
		fmt.Fprintf(os.Stderr, "lastro verify: INVALID: signature: %v\n", err)
		return verifyInvalid
	}
	class, ceiling := wire.ClassOf(span.MethodID)

	if *certPath == "" {
		printReport(span, class, ceiling, "UNANCHORED — signature valid, bound to no identity (no --cert given)", nil)
		return verifyUnanchored
	}
	certRaw, err := os.ReadFile(*certPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lastro verify: %v\n", err)
		return verifyInvalid
	}
	cert, err := wire.ParseCert(certRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lastro verify: INVALID: cert does not parse: %v\n", err)
		return verifyInvalid
	}
	if len(caPaths) == 0 {
		fmt.Fprintln(os.Stderr, "lastro verify: --cert requires at least one --ca")
		return verifyUsage
	}
	var trusted [][]byte
	for _, p := range caPaths {
		k, err := os.ReadFile(p)
		if err != nil || len(k) != wire.LenCAKey {
			fmt.Fprintf(os.Stderr, "lastro verify: bad CA key %s\n", p)
			return verifyUsage
		}
		trusted = append(trusted, k)
	}
	if err := wire.VerifyReceipt(span, cert, trusted); err != nil {
		fmt.Fprintf(os.Stderr, "lastro verify: INVALID: %v\n", err)
		return verifyInvalid
	}
	printReport(span, class, ceiling, "VERIFIED", cert)
	return verifyOK
}

func printReport(span *wire.Span, class wire.Class, ceiling uint8, verdict string, cert *wire.Cert) {
	fmt.Printf("receipt:    %s\n", verdict)
	fmt.Printf("resource:   %s\n", span.ResourceID)
	fmt.Printf("method:     %d → %s, ceiling %.2f (q8 %d)\n", span.MethodID, class, float64(ceiling)/255, ceiling)
	fmt.Printf("observed:   %s (informative only, BE-ENV-01)\n", time.UnixMilli(int64(span.ObservedAt)).UTC().Format(time.RFC3339))
	fmt.Printf("digest:     %s\n", hex.EncodeToString(span.Digest))
	fmt.Printf("executor:   %s\n", wire.Fingerprint(span.Executor))
	if cert != nil {
		nb := time.UnixMilli(int64(cert.NotBefore)).UTC().Format(time.RFC3339)
		na := time.UnixMilli(int64(cert.NotAfter)).UTC().Format(time.RFC3339)
		inWindow := span.ObservedAt >= cert.NotBefore && span.ObservedAt < cert.NotAfter
		fmt.Printf("cert:       %s .. %s (observed_at in window: %v; chain validated clock-free, BE-HIST-01)\n", nb, na, inWindow)
	}
}
