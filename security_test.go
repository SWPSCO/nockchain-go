package nockchain

import (
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestValidationBoundaries(t *testing.T) {
	k, err := Master(make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	prv, _ := k.Zprv()
	if _, err = ParsePublicKey(prv); err == nil {
		t.Fatal("private key accepted as watch-only")
	}
	pub, _ := k.Zpub()
	payload := decodeBase58(pub)
	payload = payload[:len(payload)-4]
	for _, mutate := range []func([]byte){
		func(b []byte) { b[4] = 0 },
		func(b []byte) { b[0] ^= 1 },
		func(b []byte) { b[46] = 0 },
		func(b []byte) { binary.BigEndian.PutUint64(b[47:], Prime) },
		func(b []byte) { b[60] ^= 1 },
		func(b []byte) { b[10] = 1 },
	} {
		b := append([]byte{}, payload...)
		mutate(b)
		encoded := encodeBase58(append(b, checksum(b)...))
		if _, err = ParseExtendedKey(encoded); err == nil {
			t.Fatal("accepted malformed key with valid checksum")
		}
	}
	var zero ExtendedKey
	if _, err = zero.Address(); err == nil {
		t.Fatal("zero key issues address")
	}
	if _, err = zero.LockAddress(); err == nil {
		t.Fatal("zero key issues lock")
	}
	if _, err = zero.PublicBytes(); err == nil {
		t.Fatal("zero key issues public bytes")
	}
	if _, err = zero.Zpub(); err == nil {
		t.Fatal("zero key serializes")
	}
	if _, err = LockRoot(Digest{Prime}); err == nil {
		t.Fatal("noncanonical digest accepted")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		if got := fmt.Sprintf(format, k); got != "Nockchain key (private)" {
			t.Fatalf("unexpected diagnostic %s", got)
		}
	}
}

func TestAmounts(t *testing.T) {
	for _, v := range []uint64{0, 1, 2, 65535, 65536, 65537, math.MaxUint64} {
		text := FormatNocks(v)
		got, err := ParseNocks(text)
		if err != nil || got != v {
			t.Fatalf("round trip %d (%s): %d %v", v, text, got, err)
		}
	}
	if FormatNocks(1) != "0.0000152587890625" {
		t.Fatal("nick value")
	}
	for _, v := range []string{"-1", "+1", "1e3", "1/2", " 1", "1.", ".1", "0.0000000000000001", strings.Repeat("9", 41), "281474976710656"} {
		if _, err := ParseNocks(v); err == nil {
			t.Errorf("accepted %q", v)
		}
	}
}

func FuzzParseExtendedKey(f *testing.F) {
	k, _ := Master(make([]byte, 64))
	pub, _ := k.Zpub()
	prv, _ := k.Zprv()
	f.Add(pub)
	f.Add(prv)
	f.Add("")
	f.Add("zpub")
	f.Fuzz(func(t *testing.T, s string) {
		k, err := ParseExtendedKey(s)
		if err != nil {
			return
		}
		var encoded string
		if k.IsPrivate() {
			encoded, err = k.Zprv()
		} else {
			encoded, err = k.Zpub()
		}
		if err != nil || encoded != s {
			t.Fatal("accepted noncanonical extended key")
		}
	})
}
func FuzzParseDigest(f *testing.F) {
	k, _ := Master(make([]byte, 64))
	s, _ := k.Address()
	f.Add(s)
	f.Add("")
	f.Add("1111")
	f.Fuzz(func(t *testing.T, s string) {
		d, err := ParseDigest(s)
		if err == nil && (!d.Valid() || d.String() != s) {
			t.Fatal("accepted noncanonical digest")
		}
	})
}

func BenchmarkPublicDerivation(b *testing.B) {
	k, _ := Master(make([]byte, 64))
	k = k.Public()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := k.Child(uint32(i) & 0x7fffffff); err != nil {
			b.Fatal(err)
		}
	}
}
