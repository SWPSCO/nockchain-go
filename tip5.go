package nockchain

import (
	"errors"
	"math/big"
)

// Digest contains five canonical Goldilocks field elements, least significant first.
type Digest [5]uint64

// Valid reports whether each digest limb is a canonical field element.
func (d Digest) Valid() bool {
	for _, v := range d {
		if v >= Prime {
			return false
		}
	}
	return true
}

var mds = [16]uint64{61402, 17845, 26798, 59689, 12021, 40901, 41351, 27521, 56951, 12034, 53865, 43244, 7454, 33823, 28750, 1108}

const montgomeryR uint64 = 0xffffffff

var montgomeryInverse = new(big.Int).ModInverse(new(big.Int).SetUint64(montgomeryR), new(big.Int).SetUint64(Prime)).Uint64()

func permute(s *[16]uint64) {
	for round := 0; round < 7; round++ {
		var a, b [16]uint64
		for i, v := range s {
			if i < 4 {
				for j := 0; j < 8; j++ {
					a[i] |= uint64(lookupTable[byte(v>>uint(8*j))]) << uint(8*j)
				}
				if a[i] >= Prime {
					a[i] -= Prime
				}
			} else {
				v2 := mul(v, v)
				v4 := mul(v2, v2)
				a[i] = mul(mul(v4, v2), v)
			}
		}
		for i := range b {
			for j := range a {
				b[i] = add(b[i], mul(mds[(j-i+16)%16], a[j]))
			}
			b[i] = add(b[i], mul(roundConstants[round*16+i], montgomeryR))
		}
		*s = b
	}
}
func digest(s [16]uint64) (d Digest) {
	for i := range d {
		d[i] = mul(s[i], montgomeryInverse)
	}
	return
}

// HashWords computes the variable-length TIP5 hash with replace absorption.
func HashWords(words []uint64) (Digest, error) {
	for _, v := range words {
		if v >= Prime {
			return Digest{}, errors.New("TIP5 input is not a canonical field element")
		}
	}
	var s [16]uint64
	for len(words) >= 10 {
		for i, v := range words[:10] {
			s[i] = mul(v, montgomeryR)
		}
		permute(&s)
		words = words[10:]
	}
	for i := 0; i < 10; i++ {
		s[i] = 0
	}
	for i, v := range words {
		s[i] = mul(v, montgomeryR)
	}
	s[len(words)] = montgomeryR
	permute(&s)
	return digest(s), nil
}
func hashWords(words []uint64) Digest {
	d, err := HashWords(words)
	if err != nil {
		panic(err)
	}
	return d
}
func hashCell(a, b Digest) Digest {
	var s [16]uint64
	for i := 0; i < 5; i++ {
		s[i] = mul(a[i], montgomeryR)
		s[i+5] = mul(b[i], montgomeryR)
	}
	for i := 10; i < 16; i++ {
		s[i] = montgomeryR
	}
	permute(&s)
	return digest(s)
}
func hashAtom(a uint64) Digest { return hashWords([]uint64{1, a}) }

// String encodes a digest as the chain's base-Prime integer in Base58.
func (d Digest) String() string {
	if !d.Valid() {
		return ""
	}
	n := new(big.Int)
	p := new(big.Int).SetUint64(Prime)
	for i := 4; i >= 0; i-- {
		n.Mul(n, p)
		n.Add(n, new(big.Int).SetUint64(d[i]))
	}
	return encodeBase58(n.Bytes())
}

// ParseDigest rejects noncanonical Base58 and integers outside the digest range.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	if len(s) == 0 || len(s) > 55 {
		return d, errors.New("invalid Nockchain digest")
	}
	b := decodeBase58(s)
	if len(b) == 0 || encodeBase58(b) != s {
		return d, errors.New("invalid Nockchain digest encoding")
	}
	n := new(big.Int).SetBytes(b)
	p := new(big.Int).SetUint64(Prime)
	rem := new(big.Int)
	for i := range d {
		n.QuoRem(n, p, rem)
		d[i] = rem.Uint64()
	}
	if n.Sign() != 0 || d.String() != s {
		return Digest{}, errors.New("Nockchain digest overflow")
	}
	return d, nil
}

func publicKeyHash(p point) Digest {
	p = p.affine()
	// Noun [[x0 x1 x2 x3 x4 x5] [y0 y1 y2 y3 y4 y5] 1].
	var x, y [6]Noun
	for i := 0; i < 6; i++ {
		x[i] = Noun{atom: p.x[i]}
		y[i] = Noun{atom: p.y[i]}
	}
	d, err := HashNoun(Tuple(Tuple(x[:]...), Tuple(y[:]...), Noun{atom: 1}))
	if err != nil {
		panic(err)
	} // Coordinates are canonical and this tree has 25 nodes.
	return d
}

// LockRoot returns the V1 single-signature PKH lock for an address digest.
func LockRoot(pkh Digest) (Digest, error) {
	if !pkh.Valid() {
		return Digest{}, errors.New("invalid public-key hash")
	}
	nilHash := hashAtom(0)
	set := hashCell(pkh, hashCell(nilHash, nilHash))
	primitive := hashCell(hashAtom(0x686b70), hashCell(hashAtom(1), set))
	return hashCell(primitive, nilHash), nil
}
