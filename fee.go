package nockchain

import (
	"errors"
	"math"
	"math/bits"
)

const BythosPhase uint64 = 54000

// FeeParameters uses the candidate height to select the consensus fee schedule.
type FeeParameters struct{ Height, BythosPhase, BaseFee, InputFeeDivisor, MinFee uint64 }

func DefaultFeeParameters() FeeParameters {
	return FeeParameters{BythosPhase, BythosPhase, 16384, 4, 256}
}
func (p FeeParameters) WitnessDivisor() uint64 {
	if p.Height < p.BythosPhase || p.InputFeeDivisor == 0 {
		return 1
	}
	return p.InputFeeDivisor
}

type FeeBreakdown struct{ SeedFee, WitnessFee, WordFee, MinimumFee, WitnessDivisor uint64 }
type WordCountBreakdown struct{ SeedWords, WitnessWords uint64 }
type ChainContext struct {
	CandidateHeight *uint64
	Fees            FeeParameters
}

func DefaultChainContext() ChainContext { return ChainContext{Fees: DefaultFeeParameters()} }
func ChainContextAtHeight(height uint64) ChainContext {
	fees := DefaultFeeParameters()
	fees.Height = height
	return ChainContext{&height, fees}
}
func satMul(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	if hi != 0 {
		return math.MaxUint64
	}
	return lo
}
func satAdd(a, b uint64) uint64 {
	lo, carry := bits.Add64(a, b, 0)
	if carry != 0 {
		return math.MaxUint64
	}
	return lo
}
func ComputeMinimumFee(words WordCountBreakdown, p FeeParameters) FeeBreakdown {
	base := p.BaseFee
	if p.Height < p.BythosPhase {
		base = satMul(base, 2)
	}
	seed := satMul(words.SeedWords, base)
	witness := satMul(words.WitnessWords, base) / p.WitnessDivisor()
	total := satAdd(seed, witness)
	return FeeBreakdown{seed, witness, total, max(total, p.MinFee), p.WitnessDivisor()}
}
func ComputeBridgeFee(amount, nicksFeePerNock uint64) uint64 {
	nocks := amount / 65536
	if amount%65536 != 0 {
		nocks++
	}
	return satMul(nocks, nicksFeePerNock)
}
func nounEntries(noun Noun, isMap bool, maximum int) ([][2]Noun, error) {
	tree, e := readTree(noun, isMap, maximum, func(k, v Noun) (Digest, Digest, error) { return Digest{}, Digest{}, nil })
	if e != nil {
		return nil, e
	}
	values := [][2]Noun{}
	var tap func(*nounTree)
	tap = func(t *nounTree) {
		if t != nil {
			tap(t.right)
			values = append(values, [2]Noun{t.key, t.value})
			tap(t.left)
		}
	}
	tap(tree)
	return values, nil
}
func NoteDataWords(noun Noun) (uint64, error) {
	entries, e := metadataEntries(noun)
	if e != nil {
		return 0, e
	}
	words := uint64(1)
	for _, v := range entries {
		words += 1 + leaves(v)
	}
	return words, nil
}

// TransactionWords counts encoded V1 and V0-migration witnesses and seed metadata.
// Signature estimation adds the exact missing PKH entries for unsigned V1 spends.
func TransactionWords(spends Noun, mergeByLockRoot, estimateSignatures bool) (WordCountBreakdown, error) {
	result := WordCountBreakdown{}
	merged := map[Digest]map[uint64]Noun{}
	rows, e := nounEntries(spends, true, 64)
	if e != nil {
		return result, e
	}
	for _, row := range rows {
		p, e := parts(row[1], 4)
		if e != nil {
			return result, e
		}
		version, e := atomValue(p[0])
		if e != nil || version > 1 {
			return result, errors.New("unsupported spend version")
		}
		if _, e := atomValue(p[3]); e != nil {
			return result, e
		}
		result.WitnessWords += leaves(p[1])
		if estimateSignatures && version == 1 {
			w, e := parts(p[1], 4)
			if e != nil {
				return result, e
			}
			proof, e := ParseLockMerkleProof(w[0])
			if e != nil {
				return result, e
			}
			if _, e := proof.Condition.RequiredPKHPolicy(); e != nil {
				return result, e
			}
			signatures, e := nounEntries(w[1], true, 32)
			if e != nil {
				return result, e
			}
			if proof.Condition.threshold > len(signatures) {
				result.WitnessWords += uint64(proof.Condition.threshold-len(signatures)) * 35
			}
		}
		seeds, e := nounEntries(p[2], false, 256)
		if e != nil {
			return result, e
		}
		for _, seed := range seeds {
			p, e := parts(seed[0], 5)
			if e != nil {
				return result, e
			}
			root, e := nounDigest(p[1])
			if e != nil {
				return result, e
			}
			if _, e := atomValue(p[3]); e != nil {
				return result, e
			}
			entries, e := metadataEntries(p[2])
			if e != nil {
				return result, e
			}
			if mergeByLockRoot {
				if merged[root] == nil {
					merged[root] = map[uint64]Noun{}
				}
				for key, value := range entries {
					merged[root][key] = value
				}
			} else {
				result.SeedWords++
				for _, value := range entries {
					result.SeedWords += 1 + leaves(value)
				}
			}
		}
	}
	for _, entries := range merged {
		result.SeedWords++
		for _, value := range entries {
			result.SeedWords += 1 + leaves(value)
		}
	}
	return result, nil
}
