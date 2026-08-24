package wire

// Span layout (SPEC §7.1) — a signed record that a specific observation
// was actually made by a specific executor:
//
//	u8 version(=2) | [16] span_id | [16] trace_id
//	u16 resource_len, resource_id(<=256) | u8 method_id | u8 volatility
//	[32] origin | u64 observed_at | [32] digest | [32] executor | [64] sig
//
// TBS is every byte from the span's start up to (not including) sig; the
// signature is Ed25519 over (DomainSpan || TBS).
//
// Detached-profile note (Prova, RECEIPT-PROFILE.md): a receipt produced
// outside a mesh carries origin = 32 zero bytes, meaning "no causal
// anchor". The wire bytes are unchanged SPEC bytes; the zeroed origin is
// a profile convention, not a format deviation.
const (
	LenSpanID   = 16
	LenTraceID  = 16
	MaxResource = 256
	LenOrigin   = 32
	LenDigest   = 32
	LenSig      = 64

	// Volatility values (SPEC §7.1). Receivers treat anything
	// unrecognized as volatile (BE-EVID-06, fail-closed).
	VolatilityVolatile byte = 1
	VolatilityStable   byte = 2
)

// Span is a parsed span. All slices alias the input buffer.
type Span struct {
	Version    byte
	SpanID     []byte
	TraceID    []byte
	ResourceID []byte
	MethodID   byte
	Volatility byte
	Origin     []byte
	ObservedAt uint64
	Digest     []byte
	Executor   []byte
	TBS        []byte
	Sig        []byte
}

// ParseSpan parses exactly one span. Trailing bytes are an error.
func ParseSpan(buf []byte) (*Span, error) {
	c := cursor{buf: buf}
	s, err := readSpan(&c)
	if err != nil {
		return nil, err
	}
	if c.pos != len(buf) {
		return nil, ErrTrailingBytes
	}
	return s, nil
}

// readSpan reads one span at the cursor. TBS is sliced relative to the
// span's own start, so spans parsed inline inside a larger structure
// sign over the right bytes (the reference parser's rule).
func readSpan(c *cursor) (*Span, error) {
	start := c.pos
	version, err := c.u8()
	if err != nil {
		return nil, err
	}
	spanID, err := c.take(LenSpanID)
	if err != nil {
		return nil, err
	}
	traceID, err := c.take(LenTraceID)
	if err != nil {
		return nil, err
	}
	resourceID, err := c.field16(MaxResource)
	if err != nil {
		return nil, err
	}
	methodID, err := c.u8()
	if err != nil {
		return nil, err
	}
	volatility, err := c.u8()
	if err != nil {
		return nil, err
	}
	origin, err := c.take(LenOrigin)
	if err != nil {
		return nil, err
	}
	observedAt, err := c.u64be()
	if err != nil {
		return nil, err
	}
	digest, err := c.take(LenDigest)
	if err != nil {
		return nil, err
	}
	executor, err := c.take(LenPubkey)
	if err != nil {
		return nil, err
	}
	tbs := c.buf[start:c.pos]
	sig, err := c.take(LenSig)
	if err != nil {
		return nil, err
	}
	return &Span{
		Version:    version,
		SpanID:     spanID,
		TraceID:    traceID,
		ResourceID: resourceID,
		MethodID:   methodID,
		Volatility: volatility,
		Origin:     origin,
		ObservedAt: observedAt,
		Digest:     digest,
		Executor:   executor,
		TBS:        tbs,
		Sig:        sig,
	}, nil
}

// VerifySig checks the span's signature against its own executor key
// (BE-EVID-01 first half; the executor-role check needs the cert and
// lives with the caller).
func (s *Span) VerifySig() error {
	return VerifySigned(DomainSpan, s.TBS, s.Sig, s.Executor)
}
