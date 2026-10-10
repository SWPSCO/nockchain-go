package nockchain

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// Fixtures come from tx-types' no_std Cheetah implementation and nockster-core's
// V1 address/lock code, using only deterministic, public test seeds.
func TestRustReference(t *testing.T) {
	var fixtures struct {
		Keys []struct {
			Seed, Secret, Chain, Public, Address, Lock, Zpub, Zprv string
			Path                                                   []uint32
		}
		Nouns []struct {
			Noun   json.RawMessage
			Digest Digest
		}
		Hashes []struct {
			Words  []uint64
			Digest Digest
		}
	}
	b, err := os.ReadFile("testdata/reference.json")
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(b, &fixtures); err != nil {
		t.Fatal(err)
	}
	for i, v := range fixtures.Hashes {
		got, err := HashWords(v.Words)
		if err != nil || got != v.Digest {
			t.Fatalf("hash %d got %v want %v: %v", i, got, v.Digest, err)
		}
	}
	for i, v := range fixtures.Nouns {
		got, err := HashNoun(fixtureNoun(t, v.Noun))
		if err != nil || got != v.Digest {
			t.Fatalf("noun %d got %v want %v: %v", i, got, v.Digest, err)
		}
	}
	for i, v := range fixtures.Keys {
		seed, _ := hex.DecodeString(v.Seed)
		k, err := Master(seed)
		if err != nil {
			t.Fatal(err)
		}
		for _, index := range v.Path {
			parent := k
			k, err = k.Child(index)
			if err != nil {
				t.Fatal(err)
			}
			if index < 1<<31 {
				pub, err := parent.Public().Child(index)
				if err != nil || testAddress(t, pub) != testAddress(t, k) {
					t.Fatalf("public derivation %d differs: %v", i, err)
				}
			}
		}
		checks := map[string][2]string{"secret": {hex.EncodeToString(k.secret[:]), v.Secret}, "chain": {hex.EncodeToString(k.chain[:]), v.Chain}, "public": {hex.EncodeToString(testPublic(t, k)), v.Public}, "address": {testAddress(t, k), v.Address}, "lock": {testLock(t, k), v.Lock}}
		pub, _ := k.Zpub()
		prv, _ := k.Zprv()
		checks["zpub"] = [2]string{pub, v.Zpub}
		checks["zprv"] = [2]string{prv, v.Zprv}
		for name, pair := range checks {
			if pair[0] != pair[1] {
				t.Fatalf("vector %d %s got %s want %s", i, name, pair[0], pair[1])
			}
		}
		for _, encoded := range []string{pub, prv} {
			parsed, err := ParseExtendedKey(encoded)
			if err != nil || testAddress(t, parsed) != v.Address {
				t.Fatalf("parse vector %d: %v", i, err)
			}
		}
		d, err := ParseDigest(v.Address)
		if err != nil || d.String() != v.Address {
			t.Fatalf("digest vector %d: %v", i, err)
		}
	}
}

func TestRejectInvalidKeys(t *testing.T) {
	k, err := Master(make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = k.Public().Child(1 << 31); err == nil {
		t.Fatal("public hardened child accepted")
	}
	if _, err = k.Public().Zprv(); err == nil {
		t.Fatal("public key exports secret")
	}
	for _, path := range []string{"", "m/", "m//1", "m/2147483648", "m/01", "m/-1", "1/2"} {
		if _, err = k.Derive(path); err == nil {
			t.Errorf("accepted %q", path)
		}
	}
	if _, err = Master(make([]byte, 32)); err == nil {
		t.Fatal("accepted short seed")
	}
	if _, err = HashWords([]uint64{Prime}); err == nil {
		t.Fatal("accepted noncanonical belt")
	}
	pub, _ := k.Zpub()
	if _, err = ParseExtendedKey(pub[:len(pub)-1] + "0"); err == nil {
		t.Fatal("accepted damaged checksum")
	}
	for _, s := range []string{"", "0", "1111", "not an address"} {
		if _, err = ParseDigest(s); err == nil {
			t.Errorf("accepted digest %q", s)
		}
	}
	k.depth = 255
	if _, err = k.Child(0); err == nil {
		t.Fatal("accepted depth overflow")
	}
}

func testAddress(t *testing.T, k ExtendedKey) string {
	t.Helper()
	s, e := k.Address()
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func testLock(t *testing.T, k ExtendedKey) string {
	t.Helper()
	s, e := k.LockAddress()
	if e != nil {
		t.Fatal(e)
	}
	return s
}
func testPublic(t *testing.T, k ExtendedKey) []byte {
	t.Helper()
	s, e := k.PublicBytes()
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func fixtureNoun(t *testing.T, raw json.RawMessage) Noun {
	t.Helper()
	if len(raw) > 0 && raw[0] == '[' {
		var pair []json.RawMessage
		if err := json.Unmarshal(raw, &pair); err != nil || len(pair) != 2 {
			t.Fatalf("invalid fixture cell: %s", raw)
		}
		return Cell(fixtureNoun(t, pair[0]), fixtureNoun(t, pair[1]))
	}
	var value uint64
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	noun, err := Atom(value)
	if err != nil {
		t.Fatal(err)
	}
	return noun
}
