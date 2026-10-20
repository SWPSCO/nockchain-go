package nockchain

import (
	"encoding/binary"
	"errors"
	"math/big"
	"sort"
	"strings"
	"unicode/utf8"
)

type NoteDataEntry struct {
	Key   string
	Value Noun
}

// NoteData is an immutable canonical metadata map.
type NoteData struct{ entries []NoteDataEntry }

func noteDataKey(key string) (string, uint64, error) {
	key = strings.TrimSpace(key)
	if key == "" || len(key) > 8 || !utf8.ValidString(key) {
		return "", 0, errors.New("invalid note-data key")
	}
	var bytes [8]byte
	copy(bytes[:], key)
	value := binary.LittleEndian.Uint64(bytes[:])
	if value >= Prime {
		return "", 0, errors.New("note-data key exceeds field")
	}
	return key, value, nil
}
func NewNoteData(entries []NoteDataEntry) (NoteData, error) {
	values := map[string]Noun{}
	for _, entry := range entries {
		key, _, e := noteDataKey(entry.Key)
		if e != nil {
			return NoteData{}, e
		}
		if e := boundedNoun(entry.Value); e != nil {
			return NoteData{}, e
		}
		if prior, ok := values[key]; ok && !nounEqual(prior, entry.Value) {
			return NoteData{}, errors.New("conflicting note-data values")
		}
		values[key] = entry.Value
	}
	if len(values) > 64 {
		return NoteData{}, errors.New("too many note-data entries")
	}
	out := NoteData{}
	for key, value := range values {
		out.entries = append(out.entries, NoteDataEntry{key, value})
	}
	sort.Slice(out.entries, func(i, j int) bool { return out.entries[i].Key < out.entries[j].Key })
	return out, nil
}
func (d NoteData) Entries() []NoteDataEntry { return append([]NoteDataEntry(nil), d.entries...) }
func (d NoteData) tree() *nounTree {
	var tree *nounTree
	for _, entry := range d.entries {
		_, key, _ := noteDataKey(entry.Key)
		h := hashCell(hashAtom(key), hashEach(entry.Value))
		tree = treePut(tree, newTree(Noun{atom: key}, entry.Value, h, h, true))
	}
	return tree
}
func (d NoteData) Noun() Noun   { return d.tree().noun() }
func (d NoteData) Hash() Digest { return d.tree().digest(false) }
func (d NoteData) Words() uint64 {
	words := uint64(1)
	for _, entry := range d.entries {
		words += 1 + leaves(entry.Value)
	}
	return words
}
func metadataEntries(noun Noun) (map[uint64]Noun, error) {
	entries := map[uint64]Noun{}
	_, e := readTree(noun, true, 64, func(k, v Noun) (Digest, Digest, error) {
		key, e := atomValue(k)
		if e != nil {
			return Digest{}, Digest{}, e
		}
		entries[key] = v
		h := hashCell(hashAtom(key), hashEach(v))
		return h, h, nil
	})
	return entries, e
}
func ParseNoteData(noun Noun) (NoteData, error) {
	fields, e := metadataEntries(noun)
	if e != nil {
		return NoteData{}, e
	}
	entries := []NoteDataEntry{}
	for key, value := range fields {
		var bytes [8]byte
		binary.LittleEndian.PutUint64(bytes[:], key)
		size := 8
		for size > 0 && bytes[size-1] == 0 {
			size--
		}
		if !utf8.Valid(bytes[:size]) {
			return NoteData{}, errors.New("invalid note-data key encoding")
		}
		entries = append(entries, NoteDataEntry{string(bytes[:size]), value})
	}
	return NewNoteData(entries)
}
func NoteDataFromLock(lock LockFormV1) (NoteData, error) {
	if lock == nil {
		return NoteData{}, errors.New("missing lock")
	}
	if _, e := lock.Root(); e != nil {
		return NoteData{}, e
	}
	return NewNoteData([]NoteDataEntry{{"lock", Cell(Noun{}, lock.Noun())}})
}
func (d NoteData) WithEntry(key string, value Noun) (NoteData, error) {
	name, _, e := noteDataKey(key)
	if e != nil {
		return NoteData{}, e
	}
	entries := []NoteDataEntry{}
	for _, entry := range d.entries {
		if entry.Key != name {
			entries = append(entries, entry)
		}
	}
	return NewNoteData(append(entries, NoteDataEntry{name, value}))
}

type LockData struct{ Lock LockFormV1 }

func (d LockData) Noun() (Noun, error) {
	if d.Lock == nil {
		return Noun{}, errors.New("missing lock")
	}
	if _, e := d.Lock.Root(); e != nil {
		return Noun{}, e
	}
	return Cell(Noun{}, d.Lock.Noun()), nil
}
func ParseLockData(noun Noun) (LockData, error) {
	p, e := parts(noun, 2)
	if e != nil || !zero(p[0]) {
		return LockData{}, errors.New("unsupported lock-data version")
	}
	lock, e := ParseLock(p[1])
	return LockData{lock}, e
}

// BridgeDepositDataPayload contains a 20-byte big-endian EVM address.
type BridgeDepositDataPayload struct{ EVMAddress [20]byte }

func (d BridgeDepositDataPayload) Noun() Noun {
	value := new(big.Int).SetBytes(d.EVMAddress[:])
	prime := new(big.Int).SetUint64(Prime)
	digits := make([]Noun, 3)
	for i := range digits {
		q, r := new(big.Int), new(big.Int)
		q.QuoRem(value, prime, r)
		digits[i] = Noun{atom: r.Uint64()}
		value = q
	}
	return Tuple(append([]Noun{{}, {atom: 0x65736162}}, digits...)...)
}
func ParseBridgeDepositData(noun Noun) (BridgeDepositDataPayload, error) {
	p, e := parts(noun, 5)
	if e != nil || !zero(p[0]) || p[1] != (Noun{atom: 0x65736162}) {
		return BridgeDepositDataPayload{}, errors.New("unsupported bridge version or network")
	}
	value := new(big.Int)
	prime := new(big.Int).SetUint64(Prime)
	for i := 4; i >= 2; i-- {
		digit, e := atomValue(p[i])
		if e != nil {
			return BridgeDepositDataPayload{}, e
		}
		value.Mul(value, prime).Add(value, new(big.Int).SetUint64(digit))
	}
	if value.BitLen() > 160 {
		return BridgeDepositDataPayload{}, errors.New("EVM address exceeds 160 bits")
	}
	out := BridgeDepositDataPayload{}
	value.FillBytes(out.EVMAddress[:])
	return out, nil
}

type BridgeWithdrawalDataPayload struct {
	BEID               []uint64
	BaseHash, LockRoot Digest
	BaseBatchEnd       uint64
}

func (d BridgeWithdrawalDataPayload) Noun() (Noun, error) {
	if !d.BaseHash.Valid() || !d.LockRoot.Valid() || d.BaseBatchEnd >= Prime {
		return Noun{}, errors.New("invalid withdrawal payload")
	}
	beid := make([]Noun, len(d.BEID))
	for i, v := range d.BEID {
		if v >= Prime {
			return Noun{}, errors.New("invalid withdrawal BEID")
		}
		beid[i] = Noun{atom: v}
	}
	n := Tuple(Noun{}, List(beid...), digestNoun(d.BaseHash), digestNoun(d.LockRoot), Noun{atom: d.BaseBatchEnd})
	return n, boundedNoun(n)
}
func ParseBridgeWithdrawalData(noun Noun) (BridgeWithdrawalDataPayload, error) {
	if e := boundedNoun(noun); e != nil {
		return BridgeWithdrawalDataPayload{}, e
	}
	p, e := parts(noun, 5)
	if e != nil || !zero(p[0]) {
		return BridgeWithdrawalDataPayload{}, errors.New("unsupported withdrawal version")
	}
	out := BridgeWithdrawalDataPayload{}
	tail := p[1]
	for tail.cell != nil {
		v, e := atomValue(tail.cell.head)
		if e != nil {
			return out, e
		}
		out.BEID = append(out.BEID, v)
		tail = tail.cell.tail
	}
	if !zero(tail) {
		return out, errMalformed
	}
	out.BaseHash, e = nounDigest(p[2])
	if e != nil {
		return out, e
	}
	out.LockRoot, e = nounDigest(p[3])
	if e != nil {
		return out, e
	}
	out.BaseBatchEnd, e = atomValue(p[4])
	return out, e
}

// DecodedNoteDataEntry retains unknown versions and networks as raw Noun values.
type DecodedNoteDataEntry struct {
	Key     string
	Payload any
}

func (d NoteData) Decoded() []DecodedNoteDataEntry {
	result := []DecodedNoteDataEntry{}
	for _, entry := range d.entries {
		var payload any = entry.Value
		switch entry.Key {
		case "lock":
			if v, e := ParseLockData(entry.Value); e == nil {
				payload = v
			}
		case "bridge":
			if v, e := ParseBridgeDepositData(entry.Value); e == nil {
				payload = v
			}
		case "bridge-w":
			if v, e := ParseBridgeWithdrawalData(entry.Value); e == nil {
				payload = v
			}
		}
		result = append(result, DecodedNoteDataEntry{entry.Key, payload})
	}
	return result
}
