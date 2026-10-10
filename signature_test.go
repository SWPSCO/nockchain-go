package nockchain

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestRustSignatures(t *testing.T) {
	var f struct {
		Signatures []struct {
			Seed                string
			Path                []uint32
			Message             Digest
			Challenge, Response [8]uint32
		}
	}
	b, e := os.ReadFile("testdata/reference.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	if len(f.Signatures) != 105 {
		t.Fatal("signature corpus incomplete")
	}
	for i, v := range f.Signatures {
		seed, _ := hex.DecodeString(v.Seed)
		k, e := Master(seed)
		if e != nil {
			t.Fatal(e)
		}
		for _, index := range v.Path {
			k, e = k.Child(index)
			if e != nil {
				t.Fatal(e)
			}
		}
		got, e := k.SignDigest(v.Message)
		if e != nil || got != (Signature{v.Challenge, v.Response}) {
			t.Fatalf("Rust signature %d differs", i)
		}
		pub, _ := k.PublicBytes()
		if !VerifyDigest(pub, v.Message, got) {
			t.Fatalf("signature %d rejected", i)
		}
		wrong := v.Message
		wrong[0] = (wrong[0] + 1) % Prime
		if VerifyDigest(pub, wrong, got) {
			t.Fatal("changed message accepted")
		}
	}
}
func TestSignatureRejections(t *testing.T) {
	k, _ := Master(make([]byte, 64))
	pub, _ := k.PublicBytes()
	message := Digest{1, 2, 3, 4, 5}
	s, _ := k.SignDigest(message)
	if _, e := k.Public().SignDigest(message); e == nil {
		t.Fatal("public key signs")
	}
	if _, e := k.SignDigest(Digest{Prime}); e == nil {
		t.Fatal("noncanonical digest signed")
	}
	if _, e := (ExtendedKey{}).SignDigest(message); e == nil {
		t.Fatal("invalid key signs")
	}
	for _, v := range []Signature{{}, {Challenge: s.Challenge}, {Response: s.Response}, {Challenge: scalarLimbs(order), Response: s.Response}} {
		if VerifyDigest(pub, message, v) {
			t.Fatal("invalid scalar accepted")
		}
	}
	if VerifyDigest(nil, message, s) || VerifyDigest(pub, Digest{Prime}, s) {
		t.Fatal("invalid input accepted")
	}
	other, _ := k.Child(1)
	otherPub, _ := other.PublicBytes()
	if VerifyDigest(otherPub, message, s) {
		t.Fatal("wrong public key accepted")
	}
}
