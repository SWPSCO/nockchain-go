package nockchain

import "testing"

func TestBasedNouns(t *testing.T) {
	if _, err := Atom(Prime); err == nil {
		t.Fatal("non-field atom accepted")
	}
	a, _ := Atom(Prime - 1)
	if v, ok := a.AsAtom(); !ok || v != Prime-1 {
		t.Fatal("atom")
	}
	b, _ := Atom(1)
	c, _ := Atom(2)
	right := Tuple(a, b, c)
	left := Cell(Cell(a, b), c)
	rh, err := HashNoun(right)
	if err != nil {
		t.Fatal(err)
	}
	lh, err := HashNoun(left)
	if err != nil {
		t.Fatal(err)
	}
	if rh == lh {
		t.Fatal("noun shape is not represented")
	}
	if _, ok := right.AsAtom(); ok {
		t.Fatal("cell reported as atom")
	}
	if _, _, ok := a.AsCell(); ok {
		t.Fatal("atom reported as cell")
	}
	if _, _, ok := right.AsCell(); !ok {
		t.Fatal("cell")
	}
	zeroHash, _ := HashNoun(Tuple())
	listHash, _ := HashNoun(List())
	if zeroHash != listHash || zeroHash != hashAtom(0) {
		t.Fatal("empty tuple/list")
	}
	if _, err := HashNounWithLimit(right, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := HashNounWithLimit(right, 4); err == nil {
		t.Fatal("logical node budget ignored")
	}
	shared := a
	for i := 0; i < 60; i++ {
		shared = Cell(shared, shared)
	}
	if _, err := HashNounWithLimit(shared, 100); err == nil {
		t.Fatal("exponential DAG accepted")
	}
	deep := a
	for i := 0; i < 80000; i++ {
		deep = Cell(b, deep)
	}
	if _, err := HashNoun(deep); err != nil {
		t.Fatal("deep noun: ", err)
	}
}
