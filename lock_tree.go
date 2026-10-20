package nockchain

import (
	"errors"
	"math/bits"
)

// LockFormV1 is a complete condition or tagged tree of alternative conditions.
type LockFormV1 interface {
	Root() (Digest, error)
	Noun() Noun
	Metadata() Noun
	lockLeaves() []LockV1
}

// LockTreeV1 is an immutable balanced OR tree, padded with burn leaves.
type LockTreeV1 struct {
	conditions []LockV1
	root       Digest
}

func NewLockTreeV1(conditions []LockV1) (LockTreeV1, error) {
	if len(conditions) < 2 || len(conditions) > 16 {
		return LockTreeV1{}, errors.New("a lock tree requires 2 through 16 conditions")
	}
	values := append([]LockV1(nil), conditions...)
	for _, c := range values {
		if _, e := c.Root(); e != nil {
			return LockTreeV1{}, e
		}
	}
	arity := 1 << bits.Len(uint(len(values)-1))
	for len(values) < arity {
		values = append(values, BurnLockV1())
	}
	hashes := make([]Digest, len(values))
	for i, c := range values {
		hashes[i] = c.root
	}
	for len(hashes) > 1 {
		parents := []Digest{}
		for i := 0; i < len(hashes); i += 2 {
			parents = append(parents, hashCell(hashes[i], hashes[i+1]))
		}
		hashes = parents
	}
	return LockTreeV1{values, hashCell(hashAtom(uint64(arity)), hashes[0])}, nil
}
func (t LockTreeV1) Root() (Digest, error) {
	if len(t.conditions) < 2 {
		return Digest{}, errors.New("uninitialized lock tree")
	}
	return t.root, nil
}
func (t LockTreeV1) Conditions() []LockV1 { return append([]LockV1(nil), t.conditions...) }
func (t LockTreeV1) lockLeaves() []LockV1 { return t.Conditions() }
func (t LockTreeV1) Noun() Noun {
	values := make([]Noun, len(t.conditions))
	for i, c := range t.conditions {
		values[i] = c.Noun()
	}
	if len(values) == 0 {
		return Noun{}
	}
	for len(values) > 1 {
		parents := []Noun{}
		for i := 0; i < len(values); i += 2 {
			parents = append(parents, Cell(values[i], values[i+1]))
		}
		values = parents
	}
	return Cell(Noun{atom: uint64(len(t.conditions))}, values[0])
}
func (t LockTreeV1) Metadata() Noun {
	return Tuple(Cell(Noun{atom: 0x6b636f6c}, Cell(Noun{}, t.Noun())), Noun{}, Noun{})
}
func ParseLock(noun Noun) (LockFormV1, error) {
	if e := boundedNoun(noun); e != nil {
		return nil, e
	}
	if noun.cell == nil {
		return nil, errMalformed
	}
	if noun.cell.head.cell != nil {
		return ParseSpendCondition(noun)
	}
	arity := noun.cell.head.atom
	if arity != 2 && arity != 4 && arity != 8 && arity != 16 {
		return nil, errors.New("invalid lock arity")
	}
	var walk func(Noun, int) ([]LockV1, error)
	walk = func(body Noun, count int) ([]LockV1, error) {
		if count == 1 {
			c, e := ParseSpendCondition(body)
			return []LockV1{c}, e
		}
		p, e := parts(body, 2)
		if e != nil {
			return nil, e
		}
		left, e := walk(p[0], count/2)
		if e != nil {
			return nil, e
		}
		right, e := walk(p[1], count/2)
		return append(left, right...), e
	}
	leaves, e := walk(noun.cell.tail, int(arity))
	if e != nil {
		return nil, e
	}
	return NewLockTreeV1(leaves)
}

var stubAxisHash = Digest{1988594973584463658, 8158631336633700141, 2161567007650232260, 460329990575991155, 8368574252173164961}

// LockMerkleProof is a detached proof value. Transactions snapshot its path.
type LockMerkleProof struct {
	Condition LockV1
	Axis      uint64
	Root      Digest
	Path      []Digest
	Full      bool
}

func (p LockMerkleProof) clone() LockMerkleProof { p.Path = append([]Digest(nil), p.Path...); return p }
func (p LockMerkleProof) validate() error {
	if _, e := p.Condition.Root(); e != nil {
		return e
	}
	if p.Axis >= Prime || !p.Root.Valid() || len(p.Path) > 63 {
		return errors.New("invalid lock proof")
	}
	for _, d := range p.Path {
		if !d.Valid() {
			return errors.New("invalid lock proof sibling")
		}
	}
	return nil
}
func (p LockMerkleProof) Noun() (Noun, error) {
	if e := p.validate(); e != nil {
		return Noun{}, e
	}
	siblings := make([]Noun, len(p.Path))
	for i, d := range p.Path {
		siblings[i] = digestNoun(d)
	}
	fields := []Noun{p.Condition.Noun(), {atom: p.Axis}, Cell(digestNoun(p.Root), List(siblings...))}
	if p.Full {
		fields = append([]Noun{{atom: 0x6c6c7566}}, fields...)
	}
	return Tuple(fields...), nil
}
func (p LockMerkleProof) noun() Noun { n, _ := p.Noun(); return n }
func (p LockMerkleProof) Hash() (Digest, error) {
	if e := p.validate(); e != nil {
		return Digest{}, e
	}
	path := hashAtom(0)
	for i := len(p.Path) - 1; i >= 0; i-- {
		path = hashCell(p.Path[i], path)
	}
	proof := hashCell(p.Root, path)
	if p.Full {
		return foldHashes(hashAtom(0x6c6c7566), p.Condition.root, hashAtom(p.Axis), proof), nil
	}
	return foldHashes(p.Condition.root, stubAxisHash, proof), nil
}
func (p LockMerkleProof) VerifyInclusion() bool {
	if p.validate() != nil || p.Axis == 0 {
		return false
	}
	axis, leaf := p.Axis, p.Condition.root
	for _, sibling := range p.Path {
		if axis == 1 {
			return false
		}
		if axis&1 == 1 {
			leaf = hashCell(sibling, leaf)
		} else {
			leaf = hashCell(leaf, sibling)
		}
		axis >>= 1
	}
	return axis == 1 && leaf == p.Root
}
func (p LockMerkleProof) Check(firstName Digest) bool {
	bound, e := NoteFirstV1(p.Root)
	if e != nil || firstName != bound {
		return false
	}
	leaf := p.Axis == 1
	for _, arity := range []uint64{2, 4, 8, 16} {
		if p.Axis >= 3*arity && p.Axis < 4*arity && len(p.Path) > 0 && p.Path[len(p.Path)-1] == hashAtom(arity) {
			leaf = true
		}
	}
	return ((p.Full && leaf) || (!p.Full && p.Axis == 1)) && p.VerifyInclusion()
}
func (p LockMerkleProof) ValidStubAxis(isProtocolFund bool) bool {
	return isProtocolFund || p.Full || p.Axis == 1
}
func ParseLockMerkleProof(noun Noun) (LockMerkleProof, error) {
	if e := boundedNoun(noun); e != nil {
		return LockMerkleProof{}, e
	}
	if noun.cell == nil {
		return LockMerkleProof{}, errMalformed
	}
	full := noun.cell.head == (Noun{atom: 0x6c6c7566})
	count := 3
	if full {
		count = 4
	}
	fields, e := parts(noun, count)
	if e != nil {
		return LockMerkleProof{}, e
	}
	if full {
		fields = fields[1:]
	}
	condition, e := ParseSpendCondition(fields[0])
	if e != nil {
		return LockMerkleProof{}, e
	}
	axis, e := atomValue(fields[1])
	if e != nil {
		return LockMerkleProof{}, e
	}
	proof, e := parts(fields[2], 2)
	if e != nil {
		return LockMerkleProof{}, e
	}
	root, e := nounDigest(proof[0])
	if e != nil {
		return LockMerkleProof{}, e
	}
	path := []Digest{}
	tail := proof[1]
	for tail.cell != nil {
		d, e := nounDigest(tail.cell.head)
		if e != nil {
			return LockMerkleProof{}, e
		}
		path = append(path, d)
		tail = tail.cell.tail
	}
	if !zero(tail) {
		return LockMerkleProof{}, errMalformed
	}
	p := LockMerkleProof{condition, axis, root, path, full}
	return p, p.validate()
}
func BuildLockMerkleProof(lock LockFormV1, leafNumber int, full bool) (LockMerkleProof, error) {
	if lock == nil {
		return LockMerkleProof{}, errors.New("missing lock")
	}
	root, e := lock.Root()
	if e != nil {
		return LockMerkleProof{}, e
	}
	conditions := lock.lockLeaves()
	if leafNumber < 1 || leafNumber > len(conditions) {
		return LockMerkleProof{}, errors.New("lock leaf number out of range")
	}
	offset := leafNumber - 1
	index := offset
	hashes := make([]Digest, len(conditions))
	for i, c := range conditions {
		hashes[i] = c.root
	}
	path := []Digest{}
	for len(hashes) > 1 {
		path = append(path, hashes[index^1])
		parents := []Digest{}
		for i := 0; i < len(hashes); i += 2 {
			parents = append(parents, hashCell(hashes[i], hashes[i+1]))
		}
		hashes = parents
		index /= 2
	}
	axis := uint64(1)
	if len(conditions) > 1 {
		path = append(path, hashAtom(uint64(len(conditions))))
		axis = uint64(3*len(conditions) + offset)
	}
	return LockMerkleProof{conditions[offset], axis, root, path, full}, nil
}
func preimageTree(values []Noun) (*nounTree, error) {
	var tree *nounTree
	seen := map[Digest]Noun{}
	for _, value := range values {
		if e := boundedNoun(value); e != nil {
			return nil, e
		}
		key := hashEach(value)
		if old, ok := seen[key]; ok && !nounEqual(old, value) {
			return nil, errors.New("conflicting hashlock preimages")
		}
		seen[key] = value
		if len(seen) > 32 {
			return nil, errors.New("excessive hashlock preimages")
		}
		h := hashCell(key, key)
		tree = treePut(tree, newTree(digestNoun(key), value, h, h, true))
	}
	return tree, nil
}
func parsePreimages(noun Noun) ([]Noun, error) {
	values := []Noun{}
	_, e := readTree(noun, true, 32, func(k, v Noun) (Digest, Digest, error) {
		key, e := nounDigest(k)
		if e != nil {
			return Digest{}, Digest{}, e
		}
		if key != hashEach(v) {
			return Digest{}, Digest{}, errors.New("hashlock preimage does not match its key")
		}
		values = append(values, v)
		h := hashCell(key, key)
		return h, h, nil
	})
	return values, e
}
