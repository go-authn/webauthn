// corpus writes testdata/fuzz entries from the W3C vectors plus hand-picked
// malformed inputs. Usage: corpus <repo-dir>
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func q(b []byte) string { return fmt.Sprintf("[]byte(%q)", b) }

func write(dir, target, name string, args ...string) {
	d := filepath.Join(dir, "testdata", "fuzz", target)
	if err := os.MkdirAll(d, 0o755); err != nil {
		panic(err)
	}
	s := "go test fuzz v1\n"
	for _, a := range args {
		s += a + "\n"
	}
	if err := os.WriteFile(filepath.Join(d, name), []byte(s), 0o644); err != nil {
		panic(err)
	}
}

func z(n int) string { return hex.EncodeToString(make([]byte, n)) }

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func main() {
	dir := os.Args[1]
	raw, err := os.ReadFile(filepath.Join(dir, "testdata", "w3c-vectors.json"))
	if err != nil {
		panic(err)
	}
	var v struct {
		Registration   []map[string]string
		Authentication []map[string]string
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		panic(err)
	}
	for i, r := range v.Registration {
		n := fmt.Sprintf("w3c-reg-%02d", i)
		ao, cd := unhex(r["attestationObject"]), unhex(r["clientDataJSON"])
		write(dir, "FuzzCBOR", n, q(ao))
		write(dir, "FuzzAttestationObject", n, q(ao), q(cd))
		write(dir, "FuzzClientData", n, q(cd))
	}
	for i, r := range v.Authentication {
		n := fmt.Sprintf("w3c-auth-%02d", i)
		ad, cd, sig, key := unhex(r["authenticatorData"]), unhex(r["clientDataJSON"]), unhex(r["signature"]), unhex(r["credentialPubKey"])
		write(dir, "FuzzAuthenticatorData", n, q(ad), "bool(false)")
		write(dir, "FuzzAssertion", n, q(cd), q(ad), q(sig))
		write(dir, "FuzzCOSEKey", n, q(key))
		write(dir, "FuzzCBOR", n+"-key", q(key))
	}
	bad := map[string][]byte{
		"overlong-int":      {0x18, 0x01},
		"indefinite-map":    {0xbf, 0x01, 0x02, 0xff},
		"dup-key":           {0xa2, 0x01, 0x00, 0x01, 0x00},
		"unsorted":          {0xa2, 0x03, 0x00, 0x01, 0x00},
		"huge-length":       {0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"deep":              unhex("8181818181818181818181818181818181818100"),
		"tag":               {0xc1, 0x00},
		"float":             {0xf9, 0x3c, 0x00},
		"es384-key":         unhex("a501020338222002" + "2158" + "30" + z(48) + "2258" + "30" + z(48)),
		"trailing-after-ok": {0xa0, 0x00},
	}
	for n, b := range bad {
		write(dir, "FuzzCBOR", "bad-"+n, q(b))
		write(dir, "FuzzCOSEKey", "bad-"+n, q(b))
		write(dir, "FuzzAttestationObject", "bad-"+n, q(b), q(nil))
		write(dir, "FuzzAuthenticatorData", "bad-"+n, q(b), "bool(true)")
	}
}
