// Package nockchain implements Nockchain receiving-address primitives.
// Key derivation uses variable-time arithmetic. Servers use public extended
// keys; private key operations are intended for offline wallet tooling.
package nockchain

import (
	"math/big"
	"math/bits"
)

const Prime uint64 = 0xffffffff00000001

type field [6]uint64

var one = field{1}
var inverseExponent = new(big.Int).Sub(new(big.Int).Exp(new(big.Int).SetUint64(Prime), big.NewInt(6), nil), big.NewInt(2))

func add(a, b uint64) uint64 {
	s, c := bits.Add64(a, b, 0)
	if c != 0 {
		return s - Prime
	}
	if s >= Prime {
		return s - Prime
	}
	return s
}
func sub(a, b uint64) uint64 {
	if a >= b {
		return a - b
	}
	return Prime - (b - a)
}
func mul(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	_, r := bits.Div64(hi, lo, Prime)
	return r
}
func (a field) add(b field) (r field) {
	for i := range r {
		r[i] = add(a[i], b[i])
	}
	return
}
func (a field) sub(b field) (r field) {
	for i := range r {
		r[i] = sub(a[i], b[i])
	}
	return
}
func (a field) scale(b uint64) (r field) {
	for i := range r {
		r[i] = mul(a[i], b)
	}
	return
}
func (a field) mul(b field) (r field) {
	for i, x := range a {
		for j, y := range b {
			v := mul(x, y)
			k := i + j
			if k >= 6 {
				k -= 6
				v = mul(v, 7)
			}
			r[k] = add(r[k], v)
		}
	}
	return
}
func (a field) square() field { return a.mul(a) }
func (a field) inverse() field {
	r := one
	for i := inverseExponent.BitLen() - 1; i >= 0; i-- {
		r = r.square()
		if inverseExponent.Bit(i) != 0 {
			r = r.mul(a)
		}
	}
	return r
}
