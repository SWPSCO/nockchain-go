package nockchain

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestRustJam(t *testing.T) {
	var f struct {
		Nouns []struct {
			Noun json.RawMessage
			Jam  string
		}
	}
	b, e := os.ReadFile("testdata/reference.json")
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(b, &f); e != nil {
		t.Fatal(e)
	}
	for _, v := range f.Nouns {
		n := fixtureNoun(t, v.Noun)
		want, e := hex.DecodeString(v.Jam)
		if e != nil || len(want) == 0 {
			t.Fatal("missing jam vector")
		}
		got, e := Jam(n)
		if e != nil || !bytes.Equal(got, want) {
			t.Fatal("Rust jam mismatch")
		}
		decoded, e := Cue(want)
		if e != nil || !nounEqual(n, decoded) {
			t.Fatal("Rust cue mismatch")
		}
	}
}
func TestCueBackreferencesAndLimits(t *testing.T) {
	// [42 42], with its tail referring to the atom starting at bit 2.
	w := bitWriter{}
	w.write(1, 2)
	w.write(0, 1)
	w.mat(42)
	w.write(3, 2)
	w.mat(2)
	n, e := Cue(w.bytes)
	if e != nil || !nounEqual(n, Cell(Noun{atom: 42}, Noun{atom: 42})) {
		t.Fatal("valid backreference rejected", e)
	}
	bad := [][]byte{nil, {0}, {3}, {2, 0}, {0xff}}
	// A cell pointing to itself, and an atom outside the field.
	cycle := bitWriter{}
	cycle.write(1, 2)
	cycle.write(3, 2)
	cycle.mat(0)
	bad = append(bad, cycle.bytes)
	field := bitWriter{}
	field.write(0, 1)
	field.mat(Prime)
	bad = append(bad, field.bytes)
	for _, b := range bad {
		if _, e := Cue(b); e == nil {
			t.Fatalf("malformed jam accepted: %x", b)
		}
	}
	shared := Noun{atom: 1}
	for i := 0; i < 60; i++ {
		shared = Cell(shared, shared)
	}
	if _, e := Jam(shared); e == nil {
		t.Fatal("unbounded DAG encoded")
	}
	deep := Noun{}
	for i := 0; i < 80000; i++ {
		deep = Cell(Noun{atom: 1}, deep)
	}
	b, e := Jam(deep)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := Cue(b)
	if e != nil {
		t.Fatal(e)
	}
	a, _ := HashNoun(deep)
	c, _ := HashNoun(decoded)
	if a != c {
		t.Fatal("deep tree changed")
	}
}
func FuzzCue(f *testing.F) {
	for _, b := range [][]byte{{2}, {12}, {0}, {3}} {
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 4096 {
			return
		}
		n, e := Cue(b)
		if e != nil {
			return
		}
		encoded, e := Jam(n)
		if e != nil {
			t.Fatal(e)
		}
		again, e := Cue(encoded)
		if e != nil {
			t.Fatal(e)
		}
		x, _ := HashNoun(n)
		y, _ := HashNoun(again)
		if x != y {
			t.Fatal("roundtrip changed noun")
		}
	})
}
