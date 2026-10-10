package nockchain

import (
	"errors"
	"fmt"
	"math/bits"
)

// NoteName identifies a V1 input note by its two digests.
type NoteName struct{ First, Last Digest }

func (n NoteName) noun() Noun { return List(digestNoun(n.First), digestNoun(n.Last)) }

// Hash returns the name commitment used as an output seed's parent.
func (n NoteName) Hash() (Digest, error) {
	if !n.First.Valid() || !n.Last.Valid() {
		return Digest{}, errors.New("invalid note name")
	}
	return hashCell(n.First, hashCell(n.Last, hashAtom(0))), nil
}

// PaymentV1 pays nicks to a single-signature public-key hash. Change is explicit.
type PaymentV1 struct {
	Recipient Digest
	Nicks     uint64
}

// SpendPlanV1 consumes one plain single-signature note. Value and LockRoot must
// come from verified chain state. Every nick must be assigned to outputs or Fee.
type SpendPlanV1 struct {
	Name     NoteName
	Value    uint64
	LockRoot Digest
	Outputs  []PaymentV1
	Fee      uint64
}

// TransferV1 is an immutable signed V1 transaction with full PKH lock proofs.
// Construction checks declared balances and fees, not input existence or finality.
type TransferV1 struct {
	raw   Noun
	id    Digest
	valid bool
}

// ID returns the V1 transaction identifier, or an error for an uninitialized value.
func (t TransferV1) ID() (Digest, error) {
	if !t.valid {
		return Digest{}, errors.New("uninitialized transfer")
	}
	return t.id, nil
}

// Noun returns the immutable [1 id spends] transaction noun.
func (t TransferV1) Noun() (Noun, error) {
	if !t.valid {
		return Noun{}, errors.New("uninitialized transfer")
	}
	return t.raw, nil
}

// Jam encodes the signed transaction for wallet/RPC transport.
func (t TransferV1) Jam() ([]byte, error) {
	if !t.valid {
		return nil, errors.New("uninitialized transfer")
	}
	return Jam(t.raw)
}

const MaxTransferInputs = 64
const MaxTransferOutputs = 256

// MinimumTransferFeeV1 computes the V1 fee for plain PKH inputs and outputs.
// Output lock metadata is merged per recipient. The caller supplies every
// recipient, including change, across all input spends.
func MinimumTransferFeeV1(inputs int, recipients []Digest) (uint64, error) {
	if inputs < 1 || inputs > MaxTransferInputs || len(recipients) < 1 || len(recipients) > MaxTransferOutputs {
		return 0, errors.New("transfer size out of range")
	}
	unique := map[Digest]bool{}
	for _, p := range recipients {
		if !p.Valid() {
			return 0, errors.New("invalid recipient")
		}
		unique[p] = true
	}
	// Each merged lock metadata map has 14 leaves; a signed full PKH witness has 56.
	return uint64(len(unique))*14*(1<<14) + uint64(inputs)*56*(1<<12), nil
}

// SignTransferV1 builds and signs up to 64 input spends with this one key. It
// supports plain 1-of-1 PKH locks, explicit outputs/change, and full lock proofs.
// It rejects duplicate notes/recipients, mismatched locks, imbalanced values,
// insufficient fees, and non-field amounts. Run offline; arithmetic is variable-time.
func (k ExtendedKey) SignTransferV1(plans []SpendPlanV1) (TransferV1, error) {
	if k.secret == nil || k.pub.z == (field{}) {
		return TransferV1{}, errors.New("private signing key required")
	}
	if len(plans) < 1 || len(plans) > MaxTransferInputs {
		return TransferV1{}, errors.New("input count out of range")
	}
	pkh := publicKeyHash(k.pub)
	lock, _ := LockRoot(pkh)
	recipients := []Digest{}
	names := map[NoteName]bool{}
	var fees uint64
	// Validate every spend before producing any signature.
	for _, p := range plans {
		if _, e := p.Name.Hash(); e != nil {
			return TransferV1{}, e
		}
		if names[p.Name] {
			return TransferV1{}, errors.New("duplicate input note")
		}
		names[p.Name] = true
		if p.LockRoot != lock {
			return TransferV1{}, errors.New("input lock does not authorize this key")
		}
		if p.Value == 0 || p.Value >= Prime || p.Fee >= Prime || len(p.Outputs) == 0 {
			return TransferV1{}, errors.New("invalid input amount or outputs")
		}
		total := p.Fee
		seen := map[Digest]bool{}
		for _, o := range p.Outputs {
			if !o.Recipient.Valid() || o.Nicks == 0 || o.Nicks >= Prime || seen[o.Recipient] {
				return TransferV1{}, errors.New("invalid or duplicate output")
			}
			seen[o.Recipient] = true
			next, carry := bits.Add64(total, o.Nicks, 0)
			if carry != 0 {
				return TransferV1{}, errors.New("amount overflow")
			}
			total = next
			recipients = append(recipients, o.Recipient)
			if len(recipients) > MaxTransferOutputs {
				return TransferV1{}, errors.New("output count out of range")
			}
		}
		if total != p.Value {
			return TransferV1{}, errors.New("input value differs from outputs plus fee")
		}
		next, carry := bits.Add64(fees, p.Fee, 0)
		if carry != 0 {
			return TransferV1{}, errors.New("fee overflow")
		}
		fees = next
	}
	minimum, e := MinimumTransferFeeV1(len(plans), recipients)
	if e != nil {
		return TransferV1{}, e
	}
	if fees < minimum {
		return TransferV1{}, fmt.Errorf("fee below minimum %d nicks", minimum)
	}
	var spends *nounTree
	nilHash := hashAtom(0)
	for _, p := range plans {
		parent, _ := p.Name.Hash()
		var seeds *nounTree
		for _, o := range p.Outputs {
			root, _ := LockRoot(o.Recipient)
			metadata := lockMetadata(o.Recipient)
			seed := Tuple(Noun{}, digestNoun(root), metadata, Noun{atom: o.Nicks}, digestNoun(parent))
			metadataHash := hashCell(hashCell(hashAtom(0x6b636f6c), hashEach(Cell(Noun{}, pkhCondition(o.Recipient)))), hashCell(nilHash, nilHash))
			regular := foldHashes(root, metadataHash, hashAtom(o.Nicks), parent)
			seeds = treePut(seeds, newTree(seed, Noun{}, regular, hashCell(nilHash, regular), false))
		}
		sighash := hashCell(seeds.digest(true), hashAtom(p.Fee))
		signature, err := k.SignDigest(sighash)
		if err != nil {
			return TransferV1{}, err
		}
		public := publicNoun(k.pub)
		sigNoun := signature.noun()
		signatureMap := Tuple(Cell(digestNoun(pkh), Cell(public, sigNoun)), Noun{}, Noun{})
		proof := Tuple(Noun{atom: 0x6c6c7566}, pkhCondition(pkh), Noun{atom: 1}, Cell(digestNoun(lock), Noun{}))
		witness := Tuple(proof, signatureMap, Noun{}, Noun{})
		proofHash := foldHashes(hashAtom(0x6c6c7566), lock, hashAtom(1), hashCell(lock, nilHash))
		signatureMapHash := hashCell(hashCell(pkh, hashCell(mustHashNoun(public), mustHashNoun(sigNoun))), hashCell(nilHash, nilHash))
		witnessHash := foldHashes(proofHash, signatureMapHash, nilHash, nilHash)
		spend := Tuple(Noun{atom: 1}, witness, seeds.noun(), Noun{atom: p.Fee})
		spendHash := foldHashes(hashAtom(1), witnessHash, seeds.digest(false), hashAtom(p.Fee))
		pairHash := hashCell(parent, spendHash)
		spends = treePut(spends, newTree(p.Name.noun(), spend, pairHash, pairHash, true))
	}
	id := hashCell(hashAtom(1), spends.digest(false))
	return TransferV1{Tuple(Noun{atom: 1}, digestNoun(id), spends.noun()), id, true}, nil
}
func digestNoun(d Digest) Noun {
	var a [5]Noun
	for i, v := range d {
		a[i] = Noun{atom: v}
	}
	return Tuple(a[:]...)
}
func publicNoun(p point) Noun {
	p = p.affine()
	var x, y [6]Noun
	for i := range x {
		x[i] = Noun{atom: p.x[i]}
		y[i] = Noun{atom: p.y[i]}
	}
	return Tuple(Tuple(x[:]...), Tuple(y[:]...), Noun{atom: 1})
}
func pkhCondition(p Digest) Noun {
	return List(Tuple(Noun{atom: 0x686b70}, Noun{atom: 1}, Tuple(digestNoun(p), Noun{}, Noun{})))
}
func lockMetadata(p Digest) Noun {
	return Tuple(Cell(Noun{atom: 0x6b636f6c}, Cell(Noun{}, pkhCondition(p))), Noun{}, Noun{})
}
func mustHashNoun(n Noun) Digest {
	d, e := HashNoun(n)
	if e != nil {
		panic(e)
	}
	return d
}
func hashEach(n Noun) Digest {
	if n.cell == nil {
		return hashAtom(n.atom)
	}
	return hashCell(hashEach(n.cell.head), hashEach(n.cell.tail))
}
func foldHashes(d ...Digest) Digest {
	r := d[len(d)-1]
	for i := len(d) - 2; i >= 0; i-- {
		r = hashCell(d[i], r)
	}
	return r
}

// Internal treaps operate only on bounded, constructed transaction nouns.
type nounTree struct {
	key, value                         Noun
	regular, signature, sort, priority Digest
	left, right                        *nounTree
	isMap                              bool
}

func newTree(k, v Noun, regular, signature Digest, isMap bool) *nounTree {
	h := mustHashNoun(k)
	return &nounTree{key: k, value: v, regular: regular, signature: signature, sort: h, priority: hashCell(h, h), isMap: isMap}
}
func (t *nounTree) noun() Noun {
	if t == nil {
		return Noun{}
	}
	v := t.key
	if t.isMap {
		v = Cell(v, t.value)
	}
	return Tuple(v, t.left.noun(), t.right.noun())
}
func (t *nounTree) digest(sig bool) Digest {
	if t == nil {
		return hashAtom(0)
	}
	d := t.regular
	if sig {
		d = t.signature
	}
	return hashCell(d, hashCell(t.left.digest(sig), t.right.digest(sig)))
}
func digestLess(a, b Digest) bool {
	for i := 4; i >= 0; i-- {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
func nounEqual(a, b Noun) bool {
	if a.cell == nil || b.cell == nil {
		return a.cell == nil && b.cell == nil && a.atom == b.atom
	}
	return nounEqual(a.cell.head, b.cell.head) && nounEqual(a.cell.tail, b.cell.tail)
}
func nounLess(a, b Noun) bool {
	if nounEqual(a, b) {
		return true
	}
	if a.cell == nil || b.cell == nil {
		return a.cell == nil && b.cell == nil && a.atom < b.atom
	}
	if nounEqual(a.cell.head, b.cell.head) {
		return nounLess(a.cell.tail, b.cell.tail)
	}
	return nounLess(a.cell.head, b.cell.head)
}
func treeLess(a, b *nounTree, priority bool) bool {
	x, y := a.sort, b.sort
	if priority {
		x, y = a.priority, b.priority
	}
	if x == y {
		return nounLess(a.key, b.key)
	}
	return digestLess(x, y)
}
func treePut(t, n *nounTree) *nounTree {
	if t == nil {
		return n
	}
	if nounEqual(t.key, n.key) {
		n.left, n.right = t.left, t.right
		return n
	}
	if treeLess(n, t, false) {
		t.left = treePut(t.left, n)
		if !treeLess(t, t.left, true) {
			r := t.left
			t.left = r.right
			r.right = t
			return r
		}
	} else {
		t.right = treePut(t.right, n)
		if !treeLess(t, t.right, true) {
			r := t.right
			t.right = r.left
			r.left = t
			return r
		}
	}
	return t
}
