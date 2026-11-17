// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"bytes"
	"fmt"
	"unicode/utf8"
)

// A small CBOR (RFC 8949) decoder for exactly what WebAuthn carries:
// attestation objects, COSE keys and authenticator extension outputs.
//
// It reads the deterministic encoding of RFC 8949 §4.2 and refuses
// everything else, because a signature or a credential comparison made over
// two encodings of one value is a malleability the verifier did not ask for:
//
//   - integers and lengths in their shortest form (§4.2.1), so one value has
//     one encoding;
//   - no indefinite lengths (§4.2.1), no tags, no floats, no "undefined";
//   - text strings valid UTF-8 (§3.1);
//   - map keys only integers or text, in strictly increasing order of their
//     encoding (§4.2.1), which also rules out duplicates (§5.6);
//   - bounded: nesting depth, total number of items and input size are
//     capped, and a declared length is checked against the bytes that are
//     there BEFORE anything is allocated, so a header claiming 4 GiB costs
//     nothing.
//
// Values decode to int64, []byte, string, []any, cborMap, bool and nil.
const (
	// MaxCBORInput is the largest input the decoder reads, in bytes.
	MaxCBORInput = 64 << 10
	// maxCBORDepth is the deepest nesting of arrays and maps.
	maxCBORDepth = 8
	// maxCBORItems is the most data items one decode may produce.
	maxCBORItems = 1024
)

// cborMap is a decoded map, in wire order (which is key order, enforced).
type cborMap []cborPair

type cborPair struct {
	Key any // int64 or string
	Val any
}

// get returns the value for an int64 or string key.
func (m cborMap) get(key any) (any, bool) {
	for _, p := range m {
		if p.Key == key {
			return p.Val, true
		}
	}
	return nil, false
}

type cborDecoder struct {
	b     []byte
	pos   int
	items int
}

func cborErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrCBOR}, a...)...)
}

// decodeCBOR decodes the single data item at the start of b and returns it
// with the number of bytes it occupied.
func decodeCBOR(b []byte) (any, int, error) {
	if len(b) > MaxCBORInput {
		return nil, 0, cborErr("input of %d bytes exceeds %d", len(b), MaxCBORInput)
	}
	d := &cborDecoder{b: b}
	v, err := d.item(0)
	if err != nil {
		return nil, 0, err
	}
	return v, d.pos, nil
}

// decodeCBORExact is decodeCBOR for a buffer that must hold one item and
// nothing else.
func decodeCBORExact(b []byte) (any, error) {
	v, n, err := decodeCBOR(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, fmt.Errorf("%w: %d byte(s) after the CBOR item", ErrTrailingBytes, len(b)-n)
	}
	return v, nil
}

// head reads an initial byte and its argument, refusing a non-shortest form.
func (d *cborDecoder) head() (major byte, arg uint64, info byte, err error) {
	if d.pos >= len(d.b) {
		return 0, 0, 0, cborErr("truncated item")
	}
	ib := d.b[d.pos]
	d.pos++
	major, info = ib>>5, ib&0x1f
	if major == 7 && info >= 24 && info <= 27 {
		return 0, 0, 0, cborErr("simple value or float (additional information %d) not accepted", info)
	}
	var n int
	switch {
	case info < 24:
		return major, uint64(info), info, nil
	case info == 24:
		n = 1
	case info == 25:
		n = 2
	case info == 26:
		n = 4
	case info == 27:
		n = 8
	case info == 31:
		return 0, 0, 0, cborErr("indefinite length (RFC 8949 §4.2.1)")
	default:
		return 0, 0, 0, cborErr("reserved additional information %d", info)
	}
	if len(d.b)-d.pos < n {
		return 0, 0, 0, cborErr("truncated argument")
	}
	for i := 0; i < n; i++ {
		arg = arg<<8 | uint64(d.b[d.pos+i])
	}
	d.pos += n
	// §4.2.1: the argument takes the shortest form that holds it.
	shortest := [...]uint64{24, 1 << 8, 1 << 16, 1 << 32}[info-24]
	if arg < shortest {
		return 0, 0, 0, cborErr("argument %d not in its shortest form (RFC 8949 §4.2.1)", arg)
	}
	return major, arg, info, nil
}

func (d *cborDecoder) item(depth int) (any, error) {
	d.items++
	if d.items > maxCBORItems {
		return nil, cborErr("more than %d items", maxCBORItems)
	}
	major, arg, info, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if arg > 1<<63-1 {
			return nil, cborErr("integer %d out of int64 range", arg)
		}
		return int64(arg), nil
	case 1:
		if arg > 1<<63-1 {
			return nil, cborErr("negative integer -1-%d out of int64 range", arg)
		}
		return -1 - int64(arg), nil
	case 2, 3:
		if arg > uint64(len(d.b)-d.pos) {
			return nil, cborErr("string of %d bytes with %d left", arg, len(d.b)-d.pos)
		}
		s := d.b[d.pos : d.pos+int(arg)]
		d.pos += int(arg)
		if major == 2 {
			return append([]byte(nil), s...), nil
		}
		if !utf8.Valid(s) {
			return nil, cborErr("text string is not UTF-8")
		}
		return string(s), nil
	case 4:
		if depth >= maxCBORDepth {
			return nil, cborErr("nesting deeper than %d", maxCBORDepth)
		}
		// Every element takes at least one byte: a count above what is left is
		// a lie, and is refused before a slice is sized from it.
		if arg > uint64(len(d.b)-d.pos) {
			return nil, cborErr("array of %d items with %d bytes left", arg, len(d.b)-d.pos)
		}
		out := make([]any, 0, int(arg))
		for i := uint64(0); i < arg; i++ {
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if depth >= maxCBORDepth {
			return nil, cborErr("nesting deeper than %d", maxCBORDepth)
		}
		if arg > uint64(len(d.b)-d.pos)/2 {
			return nil, cborErr("map of %d pairs with %d bytes left", arg, len(d.b)-d.pos)
		}
		out := make(cborMap, 0, int(arg))
		var prev []byte
		for i := uint64(0); i < arg; i++ {
			start := d.pos
			k, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, cborErr("map key of type %T (only integers and text)", k)
			}
			enc := d.b[start:d.pos]
			if prev != nil {
				c := bytes.Compare(prev, enc)
				if c == 0 {
					return nil, cborErr("duplicate map key %v (RFC 8949 §5.6)", k)
				}
				if c > 0 {
					return nil, cborErr("map keys not in bytewise order at %v (RFC 8949 §4.2.1)", k)
				}
			}
			prev = enc
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, cborPair{Key: k, Val: v})
		}
		return out, nil
	case 6:
		return nil, cborErr("tag %d not accepted", arg)
	default: // 7
		switch info {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, cborErr("simple value or float (additional information %d) not accepted", info)
	}
}
