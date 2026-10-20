package nockchain

import "errors"

// FundMaturity distinguishes an inactive rule from an active zero-age rule.
type FundMaturity struct {
	CandidateHeight uint64
	Minimum         *uint64
}

func (m FundMaturity) Admits(origin uint64) bool {
	return origin < Prime && m.CandidateHeight < Prime && (m.Minimum == nil || (origin <= m.CandidateHeight && m.CandidateHeight-origin >= *m.Minimum))
}

type FundMaturityPolicy struct{ ActivationHeight, Minimum uint64 }

func (p FundMaturityPolicy) FundMinimumAt(height uint64) *uint64 {
	if height < p.ActivationHeight {
		return nil
	}
	minimum := p.Minimum
	return &minimum
}
func (p FundMaturityPolicy) At(height uint64) FundMaturity {
	return FundMaturity{height, p.FundMinimumAt(height)}
}

// FundLockPolicy authenticates a configured recovery script and fund-note identity.
type FundLockPolicy struct {
	LockRoot, FirstName Digest
	Maturity            FundMaturityPolicy
}

func (p FundLockPolicy) valid() bool {
	return p.LockRoot.Valid() && p.FirstName.Valid() && p.Maturity.ActivationHeight < Prime && p.Maturity.Minimum < Prime
}
func (p FundLockPolicy) Authenticates(proof LockMerkleProof, firstName Digest) bool {
	bound, _ := NoteFirstV1(p.LockRoot)
	return p.valid() && firstName == p.FirstName && proof.Axis == 1 && proof.Condition.root == p.LockRoot && proof.Check(bound)
}

type LockResolution struct {
	Lock       InputLock
	LeafNumber int
	Preimages  []Noun
	FundPolicy *FundLockPolicy
}

func (r LockResolution) leaf() int {
	if r.LeafNumber == 0 {
		return 1
	}
	return r.LeafNumber
}
func (r LockResolution) Admits(input InputNote, height *uint64) (bool, error) {
	normalized, err := snapshotInput(input)
	if err != nil {
		return false, err
	}
	input = normalized
	if note, ok := input.snapshot().(NoteV0); ok {
		lock, ok := r.Lock.(LockV0)
		return ok && lock.root == note.Lock.root && note.Admits(height) && r.leaf() == 1 && len(r.Preimages) == 0 && r.FundPolicy == nil, nil
	}
	note, ok := input.snapshot().(NoteV1)
	if !ok {
		return false, errors.New("invalid input version")
	}
	form, ok := r.Lock.(LockFormV1)
	if !ok {
		return false, nil
	}
	proof, e := BuildLockMerkleProof(form, r.leaf(), true)
	if e != nil {
		return false, e
	}
	if r.FundPolicy != nil {
		if height == nil || !r.FundPolicy.Authenticates(proof, note.Name.First) || !r.FundPolicy.Maturity.At(*height).Admits(note.OriginPage) {
			return false, nil
		}
	} else if !proof.Check(note.Name.First) {
		return false, nil
	}
	return proof.Condition.Allows(height, note.OriginPage, r.Preimages)
}

type LockMatcher interface {
	Resolve(InputNote) (*LockResolution, error)
}

func disclosedLock(note NoteV1) (LockFormV1, error) {
	data, e := ParseNoteData(note.NoteData)
	if e != nil {
		return nil, e
	}
	for _, entry := range data.Decoded() {
		if entry.Key == "lock" {
			if value, ok := entry.Payload.(LockData); ok {
				return value.Lock, nil
			}
		}
	}
	return nil, nil
}

type SigningKeyLockMatcher struct {
	SignerPKH           Digest
	CoinbaseRelativeMin *uint64
}

func NewSigningKeyLockMatcher(pkh Digest) SigningKeyLockMatcher {
	minimum := uint64(100)
	return SigningKeyLockMatcher{pkh, &minimum}
}
func (m SigningKeyLockMatcher) Resolve(input InputNote) (*LockResolution, error) {
	normalized, err := snapshotInput(input)
	if err != nil {
		return nil, err
	}
	input = normalized
	if !m.SignerPKH.Valid() {
		return nil, errors.New("invalid signer PKH")
	}
	if note, ok := input.snapshot().(NoteV0); ok {
		if note.Lock.threshold == 1 && note.Lock.authorizes(m.SignerPKH) {
			return &LockResolution{Lock: note.Lock}, nil
		}
		return nil, nil
	}
	note, ok := input.snapshot().(NoteV1)
	if !ok {
		return nil, errors.New("invalid input version")
	}
	disclosed, e := disclosedLock(note)
	if e != nil {
		return nil, e
	}
	simple, e := NewPKHLockV1(1, []Digest{m.SignerPKH}, nil)
	if e != nil {
		return nil, e
	}
	locks := []LockFormV1{disclosed, simple}
	if m.CoinbaseRelativeMin != nil {
		time := TimelockV1{Relative: HeightRange{Min: m.CoinbaseRelativeMin}}
		coinbase, e := NewPKHLockV1(1, []Digest{m.SignerPKH}, &time)
		if e != nil {
			return nil, e
		}
		locks = append(locks, coinbase)
	}
	for _, lock := range locks {
		if lock == nil {
			continue
		}
		root, e := lock.Root()
		if e != nil {
			return nil, e
		}
		bound, _ := NoteFirstV1(root)
		if note.Name.First != bound {
			continue
		}
		for index, c := range lock.lockLeaves() {
			if len(c.policies) == 1 && len(c.times) <= 1 && len(c.hashes) == 0 && !c.burn && c.threshold == 1 && c.authorizes(m.SignerPKH) {
				return &LockResolution{Lock: lock, LeafNumber: index + 1}, nil
			}
		}
	}
	return nil, nil
}

type LockRootLockMatcher struct {
	LockRoot   Digest
	Lock       LockFormV1
	LeafNumber int
	Preimages  []Noun
	FundPolicy *FundLockPolicy
}

func (m LockRootLockMatcher) Resolve(input InputNote) (*LockResolution, error) {
	normalized, err := snapshotInput(input)
	if err != nil {
		return nil, err
	}
	input = normalized
	note, ok := input.snapshot().(NoteV1)
	if !ok {
		return nil, nil
	}
	bound, e := NoteFirstV1(m.LockRoot)
	if e != nil {
		return nil, e
	}
	if m.Lock != nil {
		root, e := m.Lock.Root()
		if e != nil {
			return nil, e
		}
		if root != m.LockRoot {
			return nil, errors.New("planning lock does not match its root")
		}
	}
	direct := note.Name.First == bound
	fund := m.FundPolicy
	if !direct && (fund == nil || fund.LockRoot != m.LockRoot || note.Name.First != fund.FirstName) {
		return nil, nil
	}
	var lock LockFormV1
	if direct {
		lock, e = disclosedLock(note)
		if e != nil {
			return nil, e
		}
	}
	if lock != nil {
		root, _ := lock.Root()
		if root != m.LockRoot {
			lock = nil
		}
	}
	if lock == nil {
		lock = m.Lock
	}
	if lock == nil {
		return nil, nil
	}
	if !direct && len(lock.lockLeaves()) > 1 {
		return nil, nil
	}
	if direct {
		fund = nil
	}
	return &LockResolution{lock, m.LeafNumber, append([]Noun(nil), m.Preimages...), fund}, nil
}
