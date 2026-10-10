package nockchain

import "errors"

// MaxNounNodes bounds the logical tree visited by HashNoun. Shared subtrees
// count once per occurrence, so a small DAG cannot trigger unbounded expansion.
const MaxNounNodes = 1 << 20

// Noun is an immutable based noun: an atom in [0, Prime), or a cell of nouns.
// The zero value is the atom 0. This is the field-constrained noun used by
// Nockchain's hashing paths, not an arbitrary-precision Nock atom container.
type Noun struct {
	atom uint64
	cell *nounCell
}
type nounCell struct{ head, tail Noun }

// Atom constructs a field-valued atom without reducing out-of-range input.
func Atom(value uint64) (Noun, error) {
	if value >= Prime {
		return Noun{}, errors.New("noun atom is outside the Goldilocks field")
	}
	return Noun{atom: value}, nil
}

// Cell constructs an immutable head/tail pair.
func Cell(head, tail Noun) Noun { return Noun{cell: &nounCell{head, tail}} }

// AsAtom returns the atom and true, or zero and false for a cell.
func (n Noun) AsAtom() (uint64, bool) { return n.atom, n.cell == nil }

// AsCell returns the head, tail, and true, or zero values and false for an atom.
func (n Noun) AsCell() (Noun, Noun, bool) {
	if n.cell == nil {
		return Noun{}, Noun{}, false
	}
	return n.cell.head, n.cell.tail, true
}

// Tuple constructs a right-associated tuple; an empty tuple is atom 0.
func Tuple(values ...Noun) Noun {
	if len(values) == 0 {
		return Noun{}
	}
	n := values[len(values)-1]
	for i := len(values) - 2; i >= 0; i-- {
		n = Cell(values[i], n)
	}
	return n
}

// List constructs a Hoon list with an atom-0 terminator.
func List(values ...Noun) Noun {
	n := Noun{}
	for i := len(values) - 1; i >= 0; i-- {
		n = Cell(values[i], n)
	}
	return n
}

// HashNoun computes TIP5 hash-noun-varlen, retaining both leaf values and shape.
// Traversal is iterative and bounded by MaxNounNodes.
func HashNoun(noun Noun) (Digest, error) { return HashNounWithLimit(noun, MaxNounNodes) }

// HashNounWithLimit uses a caller-selected logical-node limit from 1 through
// MaxNounNodes. It rejects oversized trees before invoking the permutation.
func HashNounWithLimit(noun Noun, maxNodes int) (Digest, error) {
	if maxNodes < 1 || maxNodes > MaxNounNodes {
		return Digest{}, errors.New("invalid noun node limit")
	}
	type frame struct {
		n         Noun
		afterHead bool
	}
	stack := []frame{{n: noun}}
	leaves := []uint64{}
	shape := []uint64{}
	nodes := 0
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if f.afterHead {
			shape = append(shape, 1)
			stack = append(stack, frame{n: f.n})
			continue
		}
		nodes++
		if nodes > maxNodes {
			return Digest{}, errors.New("noun exceeds logical node limit")
		}
		if f.n.cell == nil {
			leaves = append(leaves, f.n.atom)
			continue
		}
		shape = append(shape, 0)
		stack = append(stack, frame{n: f.n.cell.tail, afterHead: true}, frame{n: f.n.cell.head})
	}
	words := make([]uint64, 1, 1+len(leaves)+len(shape))
	words[0] = uint64(len(leaves))
	words = append(words, leaves...)
	words = append(words, shape...)
	return HashWords(words)
}
