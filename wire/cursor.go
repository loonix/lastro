// Package wire implements the Bolina wire format for the structures Lastro
// consumes: Cert (SPEC §3.1) and Span (SPEC §7.1), plus the BE-SIG-01
// domain-separated signature verification they require.
//
// Discipline inherited from the reference implementation (parser.zig):
// every parse is total (any input either yields a structure or an error,
// never a read past the buffer), every length is bounded before it drives
// a slice, unknown trailing bytes are a parse failure, and returned slices
// alias the caller's buffer (no copies, no allocation beyond headers).
//
// Conformance is defined by the frozen vectors in testdata/vectors.json,
// not by this package's own opinion: a change that breaks a vector is a
// bug here, never a "difference".
package wire

import "errors"

var (
	// ErrTruncated: input ended before a declared field completed.
	ErrTruncated = errors.New("wire: truncated")
	// ErrOversize: a count or length exceeded its declared bound.
	ErrOversize = errors.New("wire: length exceeds declared bound")
	// ErrTrailingBytes: input carried bytes after the single structure.
	ErrTrailingBytes = errors.New("wire: trailing bytes")
	// ErrMalformed: structural violation (bad count, CA key order, ...).
	ErrMalformed = errors.New("wire: malformed")
)

// cursor is a position-tracking, bounds-checked reader over a caller
// slice — the same shape as parser.zig's Cursor, so the two
// implementations reject at the same offsets.
type cursor struct {
	buf []byte
	pos int
}

func (c *cursor) need(n int) error {
	if len(c.buf)-c.pos < n {
		return ErrTruncated
	}
	return nil
}

func (c *cursor) u8() (byte, error) {
	if err := c.need(1); err != nil {
		return 0, err
	}
	v := c.buf[c.pos]
	c.pos++
	return v, nil
}

func (c *cursor) u16be() (uint16, error) {
	if err := c.need(2); err != nil {
		return 0, err
	}
	v := uint16(c.buf[c.pos])<<8 | uint16(c.buf[c.pos+1])
	c.pos += 2
	return v, nil
}

func (c *cursor) u32be() (uint32, error) {
	if err := c.need(4); err != nil {
		return 0, err
	}
	v := uint32(c.buf[c.pos])<<24 | uint32(c.buf[c.pos+1])<<16 |
		uint32(c.buf[c.pos+2])<<8 | uint32(c.buf[c.pos+3])
	c.pos += 4
	return v, nil
}

func (c *cursor) u64be() (uint64, error) {
	if err := c.need(8); err != nil {
		return 0, err
	}
	var v uint64
	for i := 0; i < 8; i++ {
		v = v<<8 | uint64(c.buf[c.pos+i])
	}
	c.pos += 8
	return v, nil
}

// take returns n bytes aliased into the caller buffer.
func (c *cursor) take(n int) ([]byte, error) {
	if err := c.need(n); err != nil {
		return nil, err
	}
	out := c.buf[c.pos : c.pos+n]
	c.pos += n
	return out, nil
}

// field16 reads a u16-length-prefixed field with a declared maximum.
// A length above the maximum is a parse failure, never a truncation.
func (c *cursor) field16(max int) ([]byte, error) {
	n, err := c.u16be()
	if err != nil {
		return nil, err
	}
	if int(n) > max {
		return nil, ErrOversize
	}
	return c.take(int(n))
}
