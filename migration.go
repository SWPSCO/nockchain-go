package nockchain

import "errors"

// InputNote is a complete record authenticated by the caller against chain state.
type InputNote interface {
	Hash() (Digest, error)
	Noun() (Noun, error)
	Identity() NoteName
	Amount() uint64
	OriginHeight() uint64
	Version() int
	snapshot() InputNote
}

func (n NoteV1) Identity() NoteName   { return n.Name }
func (n NoteV1) Amount() uint64       { return n.Nicks }
func (n NoteV1) OriginHeight() uint64 { return n.OriginPage }
func (n NoteV1) Version() int         { return 1 }
func (n NoteV1) snapshot() InputNote  { return n }

// InputLock is the committed authorization policy of an input.
type InputLock interface {
	Root() (Digest, error)
	Noun() Noun
}
type signingLock interface {
	InputLock
	Keys() []Digest
	Threshold() int
	authorizes(Digest) bool
}

// LockV0 commits the public keys of a V0 input.
type LockV0 struct {
	threshold int
	public    [][]byte
	keys      []Digest
	root      Digest
	noun      Noun
}

func NewLockV0(threshold int, publicKeys [][]byte) (LockV0, error) {
	if threshold < 1 || threshold > len(publicKeys) || len(publicKeys) > 32 {
		return LockV0{}, errors.New("invalid migration signature threshold")
	}
	out := LockV0{threshold: threshold}
	seen := map[Digest]bool{}
	var tree *nounTree
	for _, bytes := range publicKeys {
		point, e := parsePoint(bytes)
		if e != nil {
			return LockV0{}, e
		}
		noun := publicNoun(point)
		hash := mustHashNoun(noun)
		if seen[hash] {
			return LockV0{}, errors.New("duplicate migration public key")
		}
		seen[hash] = true
		out.public = append(out.public, append([]byte(nil), bytes...))
		out.keys = append(out.keys, hash)
		tree = treePut(tree, newTree(noun, Noun{}, hash, hash, false))
	}
	out.root = hashCell(hashAtom(uint64(threshold)), tree.digest(false))
	out.noun = Cell(Noun{atom: uint64(threshold)}, tree.noun())
	return out, nil
}
func (l LockV0) Root() (Digest, error) {
	if l.threshold < 1 {
		return Digest{}, errors.New("uninitialized migration lock")
	}
	return l.root, nil
}
func (l LockV0) Noun() Noun     { return l.noun }
func (l LockV0) Threshold() int { return l.threshold }
func (l LockV0) Keys() []Digest { return append([]Digest(nil), l.keys...) }
func (l LockV0) PublicKeys() [][]byte {
	keys := make([][]byte, len(l.public))
	for i, key := range l.public {
		keys[i] = append([]byte(nil), key...)
	}
	return keys
}
func (l LockV0) authorizes(key Digest) bool {
	for _, k := range l.keys {
		if k == key {
			return true
		}
	}
	return false
}
func ParseLockV0(noun Noun) (LockV0, error) {
	p, e := parts(noun, 2)
	if e != nil {
		return LockV0{}, e
	}
	threshold, e := atomValue(p[0])
	if e != nil || threshold > 32 {
		return LockV0{}, errors.New("invalid migration threshold")
	}
	keys := [][]byte{}
	_, e = readTree(p[1], false, 32, func(k, v Noun) (Digest, Digest, error) {
		key, e := parsePublic(k)
		if e != nil {
			return Digest{}, Digest{}, e
		}
		keys = append(keys, key)
		hash := mustHashNoun(k)
		return hash, hash, nil
	})
	if e != nil {
		return LockV0{}, e
	}
	return NewLockV0(int(threshold), keys)
}
func NoteFirstV0(lock LockV0, hasTimelock bool) (Digest, error) {
	root, e := lock.Root()
	if e != nil {
		return Digest{}, e
	}
	tim := uint64(1)
	if hasTimelock {
		tim = 0
	}
	return foldHashes(hashAtom(0), hashAtom(tim), root, hashAtom(0)), nil
}

// NoteV0 retains source, coinbase and timelock data in its parent commitment.
type NoteV0 struct {
	OriginPage uint64
	Name       NoteName
	Lock       LockV0
	Source     Digest
	Nicks      uint64
	Timelock   *TimelockV1
	Coinbase   bool
}

func (n NoteV0) Identity() NoteName   { return n.Name }
func (n NoteV0) Amount() uint64       { return n.Nicks }
func (n NoteV0) OriginHeight() uint64 { return n.OriginPage }
func (n NoteV0) Version() int         { return 0 }
func (n NoteV0) snapshot() InputNote {
	if n.Timelock != nil {
		value := n.Timelock.clone()
		n.Timelock = &value
	}
	return n
}
func (n NoteV0) validate() error {
	if n.OriginPage >= Prime || n.Nicks == 0 || n.Nicks >= Prime || !n.Source.Valid() {
		return errors.New("invalid migration note")
	}
	if _, e := n.Name.Hash(); e != nil {
		return e
	}
	if _, e := n.Lock.Root(); e != nil {
		return e
	}
	if n.Timelock != nil {
		t := n.Timelock
		if !t.Relative.valid() || !t.Absolute.valid() || (t.Relative.Min == nil && t.Relative.Max == nil && t.Absolute.Min == nil && t.Absolute.Max == nil) {
			return errors.New("invalid or empty migration timelock")
		}
	}
	return nil
}
func (n NoteV0) Noun() (Noun, error) {
	if e := n.validate(); e != nil {
		return Noun{}, e
	}
	time := Noun{}
	if n.Timelock != nil {
		time = Tuple(Noun{}, rangeNoun(n.Timelock.Absolute), rangeNoun(n.Timelock.Relative))
	}
	coinbase := uint64(1)
	if n.Coinbase {
		coinbase = 0
	}
	return Tuple(Tuple(Noun{}, Noun{atom: n.OriginPage}, time), n.Name.noun(), n.Lock.Noun(), Cell(digestNoun(n.Source), Noun{atom: coinbase}), Noun{atom: n.Nicks}), nil
}
func (n NoteV0) Hash() (Digest, error) {
	if e := n.validate(); e != nil {
		return Digest{}, e
	}
	time := hashAtom(0)
	if n.Timelock != nil {
		time = foldHashes(hashAtom(0), rangeHash(n.Timelock.Absolute), rangeHash(n.Timelock.Relative))
	}
	coinbase := uint64(1)
	if n.Coinbase {
		coinbase = 0
	}
	name, _ := n.Name.Hash()
	return hashCell(foldHashes(hashAtom(0), hashAtom(n.OriginPage), time), foldHashes(name, n.Lock.root, hashCell(n.Source, hashAtom(coinbase)), hashAtom(n.Nicks))), nil
}
func (n NoteV0) Admits(height *uint64) bool {
	first, e := NoteFirstV0(n.Lock, n.Timelock != nil)
	return e == nil && n.Name.First == first && (n.Timelock == nil || (height != nil && n.Timelock.Allows(*height, n.OriginPage)))
}
func ParseNoteV0(noun Noun) (NoteV0, error) {
	out := NoteV0{}
	if e := boundedNoun(noun); e != nil {
		return out, e
	}
	p, e := parts(noun, 5)
	if e != nil {
		return out, e
	}
	meta, e := parts(p[0], 3)
	if e != nil || !zero(meta[0]) {
		return out, errors.New("unsupported migration note version")
	}
	out.OriginPage, e = atomValue(meta[1])
	if e != nil {
		return out, e
	}
	name, e := parts(p[1], 3)
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
	out.Lock, e = ParseLockV0(p[2])
	if e != nil {
		return out, e
	}
	source, e := parts(p[3], 2)
	if e != nil {
		return out, e
	}
	out.Source, e = nounDigest(source[0])
	if e != nil {
		return out, e
	}
	coinbase, e := atomValue(source[1])
	if e != nil || coinbase > 1 {
		return out, errMalformed
	}
	out.Coinbase = coinbase == 0
	out.Nicks, e = atomValue(p[4])
	if e != nil {
		return out, e
	}
	if !zero(meta[2]) {
		time, e := parts(meta[2], 3)
		if e != nil || !zero(time[0]) {
			return out, errMalformed
		}
		abs, e := parseRange(time[1])
		if e != nil {
			return out, e
		}
		rel, e := parseRange(time[2])
		if e != nil {
			return out, e
		}
		out.Timelock = &TimelockV1{rel, abs}
	}
	return out, out.validate()
}

func snapshotInput(note InputNote) (InputNote, error) {
	switch value := note.(type) {
	case NoteV1:
		return value, nil
	case NoteV0:
		return value.snapshot(), nil
	case *NoteV1:
		if value != nil {
			return *value, nil
		}
	case *NoteV0:
		if value != nil {
			return value.snapshot(), nil
		}
	}
	return nil, errors.New("invalid input note")
}
