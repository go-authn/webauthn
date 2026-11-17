// SPDX-License-Identifier: BSD-3-Clause

package webauthn

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestCBORAccepts(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want any
	}{
		{"zero", []byte{0x00}, int64(0)},
		{"23", []byte{0x17}, int64(23)},
		{"24 in one byte", []byte{0x18, 24}, int64(24)},
		{"256 in two", []byte{0x19, 1, 0}, int64(256)},
		{"65536 in four", []byte{0x1a, 0, 1, 0, 0}, int64(65536)},
		{"2^32 in eight", []byte{0x1b, 0, 0, 0, 1, 0, 0, 0, 0}, int64(1 << 32)},
		{"max int64", []byte{0x1b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, int64(1<<63 - 1)},
		{"-1", []byte{0x20}, int64(-1)},
		{"min int64", []byte{0x3b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, int64(-1 << 63)},
		{"bytes", []byte{0x42, 1, 2}, []byte{1, 2}},
		{"text", []byte{0x63, 'a', 'b', 'c'}, "abc"},
		{"array", []byte{0x82, 1, 2}, []any{int64(1), int64(2)}},
		{"false true null", []byte{0x83, 0xf4, 0xf5, 0xf6}, []any{false, true, nil}},
		{"empty map", []byte{0xa0}, cborMap{}},
		{"sorted map", []byte{0xa2, 0x01, 0x02, 0x03, 0x04}, cborMap{{int64(1), int64(2)}, {int64(3), int64(4)}}},
		{"int keys before text keys", []byte{0xa2, 0x01, 0x00, 0x61, 'a', 0x00}, cborMap{{int64(1), int64(0)}, {"a", int64(0)}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeCBORExact(tc.in)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v want %#v", got, tc.want)
			}
			if !bytes.Equal(enc(got), tc.in) {
				t.Fatalf("does not re-encode to its input")
			}
		})
	}
}

func nested(depth int) []byte {
	return append(bytes.Repeat([]byte{0x81}, depth), 0x00)
}

func TestCBORRefuses(t *testing.T) {
	bigArray := append([]byte{0x99, 0x04, 0x4c}, make([]byte, 1100)...)
	for _, tc := range []struct {
		name string
		in   []byte
		want error
		msg  string
	}{
		{"empty", nil, ErrCBOR, "truncated"},
		{"overlong 1-byte int", []byte{0x18, 0x17}, ErrCBOR, "shortest"},
		{"overlong 2-byte int", []byte{0x19, 0x00, 0xff}, ErrCBOR, "shortest"},
		{"overlong 4-byte int", []byte{0x1a, 0, 0, 0xff, 0xff}, ErrCBOR, "shortest"},
		{"overlong 8-byte int", []byte{0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff}, ErrCBOR, "shortest"},
		{"overlong length", []byte{0x58, 0x01, 'a'}, ErrCBOR, "shortest"},
		{"indefinite bytes", []byte{0x5f, 0x41, 0x00, 0xff}, ErrCBOR, "indefinite"},
		{"indefinite array", []byte{0x9f, 0xff}, ErrCBOR, "indefinite"},
		{"indefinite map", []byte{0xbf, 0xff}, ErrCBOR, "indefinite"},
		{"reserved info", []byte{0x1c}, ErrCBOR, "reserved"},
		{"truncated argument", []byte{0x19, 0x01}, ErrCBOR, "truncated"},
		{"tag", []byte{0xc1, 0x00}, ErrCBOR, "tag"},
		{"float16", []byte{0xf9, 0, 0}, ErrCBOR, "float"},
		{"float32", []byte{0xfa, 0, 0, 0, 0}, ErrCBOR, "float"},
		{"undefined", []byte{0xf7}, ErrCBOR, "simple"},
		{"simple 16", []byte{0xf0}, ErrCBOR, "simple"},
		{"break", []byte{0xff}, ErrCBOR, "indefinite"},
		{"uint over int64", []byte{0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0}, ErrCBOR, "range"},
		{"nint over int64", []byte{0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0}, ErrCBOR, "range"},
		{"bytes longer than input", []byte{0x45, 1}, ErrCBOR, "left"},
		{"4 GiB header", []byte{0x5a, 0xff, 0xff, 0xff, 0xff}, ErrCBOR, "left"},
		{"2^64 header", []byte{0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ErrCBOR, "left"},
		{"array longer than input", []byte{0x83, 0x00}, ErrCBOR, "left"},
		{"array count lie", []byte{0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ErrCBOR, "left"},
		{"map count lie", []byte{0xbb, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, ErrCBOR, "left"},
		{"bad map key", []byte{0xa1, 0x18, 0x00, 0x00}, ErrCBOR, "shortest"},
		{"element missing", []byte{0x82, 0x00}, ErrCBOR, "left"},
		{"map value missing", []byte{0xa1, 0x00}, ErrCBOR, "left"},
		{"nested element missing", []byte{0x81, 0x81}, ErrCBOR, "left"},
		{"invalid UTF-8", []byte{0x62, 0xc3, 0x28}, ErrCBOR, "UTF-8"},
		{"duplicate key", []byte{0xa2, 0x01, 0x00, 0x01, 0x00}, ErrCBOR, "duplicate"},
		{"duplicate text key", []byte{0xa2, 0x61, 'a', 0x00, 0x61, 'a', 0x00}, ErrCBOR, "duplicate"},
		{"unsorted keys", []byte{0xa2, 0x03, 0x00, 0x01, 0x00}, ErrCBOR, "order"},
		{"text key before int key", []byte{0xa2, 0x61, 'a', 0x00, 0x01, 0x00}, ErrCBOR, "order"},
		{"byte-string key", []byte{0xa1, 0x41, 0x00, 0x00}, ErrCBOR, "key of type"},
		{"array key", []byte{0xa1, 0x80, 0x00}, ErrCBOR, "key of type"},
		{"depth 9", nested(9), ErrCBOR, "nesting"},
		{"deep map", append(bytes.Repeat([]byte{0xa1, 0x00}, 9), 0x00), ErrCBOR, "nesting"},
		{"1100 items", bigArray, ErrCBOR, "items"},
		{"trailing byte", []byte{0x00, 0x00}, ErrTrailingBytes, "after"},
		{"trailing after map", []byte{0xa0, 0xf6}, ErrTrailingBytes, "after"},
		{"over the size cap", bytes.Repeat([]byte{0x00}, MaxCBORInput+1), ErrCBOR, "exceeds"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeCBORExact(tc.in)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
			if !strings.Contains(err.Error(), tc.msg) {
				t.Fatalf("error %q does not mention %q", err, tc.msg)
			}
		})
	}
}

func TestCBORDepthLimitIsExact(t *testing.T) {
	if _, err := decodeCBORExact(nested(maxCBORDepth)); err != nil {
		t.Fatalf("depth %d must be accepted: %v", maxCBORDepth, err)
	}
	if _, err := decodeCBORExact(nested(maxCBORDepth + 1)); err == nil {
		t.Fatal("one deeper must be refused")
	}
}

func TestCBORItemLimitIsExact(t *testing.T) {
	ok := append([]byte{0x99, 0x03, 0xff}, make([]byte, 1023)...) // 1 + 1023 = 1024 items
	if _, err := decodeCBORExact(ok); err != nil {
		t.Fatalf("1024 items must be accepted: %v", err)
	}
}

func TestCBORPrefix(t *testing.T) {
	v, n, err := decodeCBOR([]byte{0x01, 0xff, 0xff})
	if err != nil || v != int64(1) || n != 1 {
		t.Fatalf("%v %d %v", v, n, err)
	}
}

func TestCBORMapGet(t *testing.T) {
	mm := m("a", int64(1), int64(2), "b")
	if v, ok := mm.get("a"); !ok || v != int64(1) {
		t.Fatal("string key")
	}
	if v, ok := mm.get(int64(2)); !ok || v != "b" {
		t.Fatal("int key")
	}
	if _, ok := mm.get("z"); ok {
		t.Fatal("absent key found")
	}
}
