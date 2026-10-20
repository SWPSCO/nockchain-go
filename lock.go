package nockchain

import "errors"

// HeightRange is an inclusive interval. Nil endpoints are unbounded.
type HeightRange struct{ Min, Max *uint64 }

// TimelockV1 requires both the absolute height and age since the input's origin
// to fall within their ranges. Heights come from verified chain state.
type TimelockV1 struct{ Relative, Absolute HeightRange }

func cloneRange(r HeightRange) HeightRange {
	if r.Min != nil {
		v := *r.Min
		r.Min = &v
	}
	if r.Max != nil {
		v := *r.Max
		r.Max = &v
	}
	return r
}
func (t TimelockV1) clone() TimelockV1 {
	return TimelockV1{cloneRange(t.Relative), cloneRange(t.Absolute)}
}
func (r HeightRange) valid() bool {
	return (r.Min == nil || *r.Min < Prime) && (r.Max == nil || *r.Max < Prime) && (r.Min == nil || r.Max == nil || *r.Min <= *r.Max)
}
func (r HeightRange) contains(v uint64) bool {
	return (r.Min == nil || v >= *r.Min) && (r.Max == nil || v <= *r.Max)
}

// Allows checks inclusive absolute and relative bounds without arithmetic wraparound.
func (t TimelockV1) Allows(height, origin uint64) bool {
	return t.Relative.valid() && t.Absolute.valid() && height < Prime && origin <= height && t.Absolute.contains(height) && t.Relative.contains(height-origin)
}
func optionalHeight(v *uint64) Noun {
	if v == nil {
		return Noun{}
	}
	return Cell(Noun{}, Noun{atom: *v})
}
func rangeNoun(r HeightRange) Noun { return Cell(optionalHeight(r.Min), optionalHeight(r.Max)) }
func optionalHash(v *uint64) Digest {
	if v == nil {
		return hashAtom(0)
	}
	return hashCell(hashAtom(0), hashAtom(*v))
}
func rangeHash(r HeightRange) Digest { return hashCell(optionalHash(r.Min), optionalHash(r.Max)) }

// LockV1 is one immutable conjunctive spend condition.
type LockV1 struct {
	threshold int
	keys      []Digest
	time      *TimelockV1
	condition Noun
	root      Digest
	times     []TimelockV1
	policies  []RequiredPKHPolicy
	hashes    []Digest
	burn      bool
}
type RequiredPKHPolicy struct {
	Threshold int
	Keys      []Digest
}

func digestSet(keys []Digest) (Noun, error) {
	if len(keys) > 32 {
		return Noun{}, errors.New("hash set entry limit exceeded")
	}
	var tree *nounTree
	seen := map[Digest]bool{}
	for _, key := range keys {
		if !key.Valid() || seen[key] {
			return Noun{}, errors.New("invalid or duplicate hash set entry")
		}
		seen[key] = true
		tree = treePut(tree, newTree(digestNoun(key), Noun{}, key, key, false))
	}
	return tree.noun(), nil
}
func readDigestSet(noun Noun) ([]Digest, *nounTree, error) {
	keys := []Digest{}
	tree, e := readTree(noun, false, 32, func(k, v Noun) (Digest, Digest, error) { d, e := nounDigest(k); keys = append(keys, d); return d, d, e })
	return keys, tree, e
}
func NewPKHLockV1(threshold int, keys []Digest, timelock *TimelockV1) (LockV1, error) {
	if threshold < 1 || threshold > len(keys) {
		return LockV1{}, errors.New("invalid signature threshold")
	}
	set, e := digestSet(keys)
	if e != nil {
		return LockV1{}, e
	}
	primitives := []Noun{Tuple(Noun{atom: 0x686b70}, Noun{atom: uint64(threshold)}, set)}
	if timelock != nil {
		if !timelock.Relative.valid() || !timelock.Absolute.valid() {
			return LockV1{}, errors.New("invalid timelock")
		}
		primitives = append(primitives, Tuple(Noun{atom: 0x6d6974}, rangeNoun(timelock.Relative), rangeNoun(timelock.Absolute)))
	}
	return ParseSpendCondition(List(primitives...))
}
func NewHashlockV1(hashes []Digest) (LockV1, error) {
	set, e := digestSet(hashes)
	if e != nil {
		return LockV1{}, e
	}
	return ParseSpendCondition(List(Cell(Noun{atom: 0x786168}, set)))
}
func BurnLockV1() LockV1 {
	lock, _ := ParseSpendCondition(List(Cell(Noun{atom: 0x6e7262}, Noun{})))
	return lock
}

// WithHashlocks adds required preimages to this condition.
func (l LockV1) WithHashlocks(hashes []Digest) (LockV1, error) {
	if _, e := l.Root(); e != nil {
		return LockV1{}, e
	}
	set, e := digestSet(hashes)
	if e != nil {
		return LockV1{}, e
	}
	primitives := []Noun{}
	for n := l.condition; n.cell != nil; n = n.cell.tail {
		primitives = append(primitives, n.cell.head)
	}
	primitives = append(primitives, Cell(Noun{atom: 0x786168}, set))
	return ParseSpendCondition(List(primitives...))
}

// ParseSpendCondition validates and retains primitive order in the commitment.
func ParseSpendCondition(noun Noun) (LockV1, error) {
	if e := boundedNoun(noun); e != nil {
		return LockV1{}, e
	}
	l := LockV1{condition: noun}
	values := []Digest{}
	tail := noun
	for tail.cell != nil {
		p, e := parts(tail.cell.head, 2)
		if e != nil {
			return LockV1{}, e
		}
		tag, e := atomValue(p[0])
		if e != nil {
			return LockV1{}, e
		}
		switch tag {
		case 0x686b70:
			body, e := parts(p[1], 2)
			if e != nil {
				return LockV1{}, e
			}
			threshold, e := atomValue(body[0])
			if e != nil {
				return LockV1{}, e
			}
			keys, tree, e := readDigestSet(body[1])
			if e != nil {
				return LockV1{}, e
			}
			if threshold < 1 || threshold > uint64(len(keys)) {
				return LockV1{}, errors.New("invalid signature threshold")
			}
			l.policies = append(l.policies, RequiredPKHPolicy{int(threshold), keys})
			values = append(values, foldHashes(hashAtom(tag), hashAtom(threshold), tree.digest(false)))
		case 0x6d6974:
			body, e := parts(p[1], 2)
			if e != nil {
				return LockV1{}, e
			}
			rel, e := parseRange(body[0])
			if e != nil {
				return LockV1{}, e
			}
			abs, e := parseRange(body[1])
			if e != nil {
				return LockV1{}, e
			}
			l.times = append(l.times, TimelockV1{rel, abs})
			values = append(values, foldHashes(hashAtom(tag), rangeHash(rel), rangeHash(abs)))
		case 0x786168:
			hashes, tree, e := readDigestSet(p[1])
			if e != nil {
				return LockV1{}, e
			}
			l.hashes = append(l.hashes, hashes...)
			values = append(values, hashCell(hashAtom(tag), tree.digest(false)))
		case 0x6e7262:
			if !zero(p[1]) {
				return LockV1{}, errMalformed
			}
			l.burn = true
			values = append(values, hashCell(hashAtom(tag), hashAtom(0)))
		default:
			return LockV1{}, errors.New("invalid lock primitive")
		}
		tail = tail.cell.tail
	}
	if !zero(tail) || len(values) == 0 {
		return LockV1{}, errors.New("empty or malformed spend condition")
	}
	l.root = hashAtom(0)
	for i := len(values) - 1; i >= 0; i-- {
		l.root = hashCell(values[i], l.root)
	}
	if len(l.policies) > 0 {
		l.threshold = l.policies[0].Threshold
		l.keys = append([]Digest(nil), l.policies[0].Keys...)
	}
	for _, p := range l.policies[min(1, len(l.policies)):] {
		intersection := []Digest{}
		for _, key := range l.keys {
			for _, other := range p.Keys {
				if key == other {
					intersection = append(intersection, key)
					break
				}
			}
		}
		l.keys = intersection
	}
	if len(l.times) > 0 {
		time := l.times[0].clone()
		l.time = &time
	}
	return l, nil
}
func (l LockV1) Root() (Digest, error) {
	if zero(l.condition) {
		return Digest{}, errors.New("uninitialized lock")
	}
	return l.root, nil
}
func (l LockV1) Noun() Noun           { return l.condition }
func (l LockV1) Metadata() Noun       { return l.metadata() }
func (l LockV1) lockLeaves() []LockV1 { return []LockV1{l} }
func (l LockV1) RequiredPKHPolicy() (*RequiredPKHPolicy, error) {
	if _, e := l.Root(); e != nil {
		return nil, e
	}
	if len(l.policies) == 0 {
		return nil, nil
	}
	for _, p := range l.policies {
		if p.Threshold != l.threshold {
			return nil, errors.New("PKH conditions cannot share a satisfying signature map")
		}
	}
	if len(l.keys) < l.threshold {
		return nil, errors.New("PKH conditions cannot share a satisfying signature map")
	}
	return &RequiredPKHPolicy{l.threshold, l.Keys()}, nil
}
func (l LockV1) Allows(height *uint64, origin uint64, preimages []Noun) (bool, error) {
	if _, e := l.RequiredPKHPolicy(); e != nil {
		return false, e
	}
	if l.burn {
		return false, nil
	}
	for _, t := range l.times {
		if height == nil || !t.Allows(*height, origin) {
			return false, nil
		}
	}
	supplied := map[Digest]bool{}
	for _, value := range preimages {
		if e := boundedNoun(value); e != nil {
			return false, e
		}
		supplied[hashEach(value)] = true
	}
	for _, h := range l.hashes {
		if !supplied[h] {
			return false, nil
		}
	}
	return true, nil
}

// Keys returns a detached copy of the authorized public-key hashes.
func (l LockV1) Keys() []Digest { return append([]Digest(nil), l.keys...) }

// Threshold returns the exact number of signatures required per input.
func (l LockV1) Threshold() int { return l.threshold }

// Timelocks returns every conjunctive height constraint as detached copies.
func (l LockV1) Timelocks() []TimelockV1 {
	out := make([]TimelockV1, len(l.times))
	for i, value := range l.times {
		out[i] = value.clone()
	}
	return out
}

// Hashes returns every required preimage hash as a detached copy.
func (l LockV1) Hashes() []Digest { return append([]Digest(nil), l.hashes...) }

// IsBurn reports whether this condition contains a burn primitive.
func (l LockV1) IsBurn() bool { return l.burn }

// Timelock returns the first height constraint, or nil.
func (l LockV1) Timelock() *TimelockV1 {
	if l.time == nil {
		return nil
	}
	t := l.time.clone()
	return &t
}
func (l LockV1) authorizes(k Digest) bool {
	for _, v := range l.keys {
		if v == k {
			return true
		}
	}
	return false
}
func (l LockV1) metadata() Noun {
	return Tuple(Cell(Noun{atom: 0x6b636f6c}, Cell(Noun{}, l.condition)), Noun{}, Noun{})
}
func (l LockV1) proof() Noun {
	return Tuple(Noun{atom: 0x6c6c7566}, l.condition, Noun{atom: 1}, Cell(digestNoun(l.root), Noun{}))
}
func (l LockV1) proofHash() Digest {
	return foldHashes(hashAtom(0x6c6c7566), l.root, hashAtom(1), hashCell(l.root, hashAtom(0)))
}

// NoteFirstV1 computes the lock-bound first component of a V1 note name.
func NoteFirstV1(lockRoot Digest) (Digest, error) {
	if !lockRoot.Valid() {
		return Digest{}, errors.New("invalid lock root")
	}
	return hashCell(hashAtom(0), lockRoot), nil
}

// NoteV1 contains the complete input record required for parent commitments.
// NoteData is a canonical based-noun metadata map, including every stored entry.
// The application verifies the record's existence, unspent status and finality.
type NoteV1 struct {
	OriginPage uint64
	Name       NoteName
	NoteData   Noun
	Nicks      uint64
}

// Noun encodes the complete persisted note record.
func (n NoteV1) Noun() (Noun, error) {
	if _, e := n.Hash(); e != nil {
		return Noun{}, e
	}
	return Tuple(Noun{atom: 1}, Noun{atom: n.OriginPage}, n.Name.noun(), n.NoteData, Noun{atom: n.Nicks}), nil
}

// ParseNoteV1 validates a complete V1 note record.
func ParseNoteV1(noun Noun) (NoteV1, error) {
	out := NoteV1{}
	if e := boundedNoun(noun); e != nil {
		return out, e
	}
	p, e := parts(noun, 5)
	if e != nil || p[0] != (Noun{atom: 1}) {
		return out, errors.New("expected V1 note")
	}
	out.OriginPage, e = atomValue(p[1])
	if e != nil {
		return out, e
	}
	name, e := parts(p[2], 3)
	if e != nil || !zero(name[2]) {
		return out, errMalformed
	}
	out.Name.First, e = nounDigest(name[0])
	if e != nil {
		return out, e
	}
	out.Name.Last, e = nounDigest(name[1])
	if e != nil {
		return out, e
	}
	out.NoteData = p[3]
	out.Nicks, e = atomValue(p[4])
	if e != nil {
		return out, e
	}
	_, e = out.Hash()
	return out, e
}

// Hash commits the complete version, origin, name, metadata and asset value.
func (n NoteV1) Hash() (Digest, error) {
	name, e := n.Name.Hash()
	if e != nil {
		return Digest{}, e
	}
	if n.OriginPage >= Prime || n.Nicks == 0 || n.Nicks >= Prime {
		return Digest{}, errors.New("invalid note height or value")
	}
	data, e := metadataHash(n.NoteData)
	if e != nil {
		return Digest{}, e
	}
	return foldHashes(hashAtom(1), hashAtom(n.OriginPage), name, data, hashAtom(n.Nicks)), nil
}
