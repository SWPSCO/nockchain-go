package nockchain

import (
	"encoding/binary"
	"errors"
	"math/big"
)

var order, _ = new(big.Int).SetString("7af2599b3b3f22d0563fbf0f990a37b5327aa72330157722d443623eaed4accf", 16)
var generator = point{
	x: field{2754611494552410273, 8599518745794843693, 10526511002404673680, 4830863958577994148, 375185138577093320, 12938930721685970739},
	y: field{15384029202802550068, 2774812795997841935, 14375303400746062753, 10708493419890101954, 13187678623570541764, 9990732138772505951},
	z: one,
}
var curveB = field{395, 1}

// point uses Jacobian coordinates; z=0 represents infinity.
type point struct{ x, y, z field }

func (p point) double() point {
	if p.z == (field{}) || p.y == (field{}) {
		return point{}
	}
	a := p.x.square()
	b := p.y.square()
	c := b.square()
	d := p.x.add(b).square().sub(a).sub(c).scale(2)
	e := a.scale(3).add(p.z.square().square())
	x := e.square().sub(d.scale(2))
	return point{x, e.mul(d.sub(x)).sub(c.scale(8)), p.y.mul(p.z).scale(2)}
}
func (p point) plus(q point) point {
	if p.z == (field{}) {
		return q
	}
	if q.z == (field{}) {
		return p
	}
	z1 := p.z.square()
	z2 := q.z.square()
	u1 := p.x.mul(z2)
	u2 := q.x.mul(z1)
	s1 := p.y.mul(q.z).mul(z2)
	s2 := q.y.mul(p.z).mul(z1)
	if u1 == u2 {
		if s1 == s2 {
			return p.double()
		}
		return point{}
	}
	h := u2.sub(u1)
	i := h.scale(2).square()
	j := h.mul(i)
	r := s2.sub(s1).scale(2)
	v := u1.mul(i)
	x := r.square().sub(j).sub(v.scale(2))
	y := r.mul(v.sub(x)).sub(s1.mul(j).scale(2))
	z := p.z.add(q.z).square().sub(z1).sub(z2).mul(h)
	return point{x, y, z}
}
func (p point) times(n *big.Int) point {
	r := point{}
	for i := n.BitLen() - 1; i >= 0; i-- {
		r = r.double()
		if n.Bit(i) != 0 {
			r = r.plus(p)
		}
	}
	return r
}
func (p point) affine() point {
	if p.z == (field{}) || p.z == one {
		return p
	}
	z := p.z.inverse()
	z2 := z.square()
	return point{p.x.mul(z2), p.y.mul(z2).mul(z), one}
}
func (p point) bytes() []byte {
	p = p.affine()
	out := make([]byte, 97)
	out[0] = 1
	offset := 1
	for _, f := range []field{p.y, p.x} {
		for i := 5; i >= 0; i-- {
			binary.BigEndian.PutUint64(out[offset:], f[i])
			offset += 8
		}
	}
	return out
}
func parsePoint(data []byte) (point, error) {
	if len(data) != 97 || data[0] != 1 {
		return point{}, errors.New("invalid Cheetah public key")
	}
	p := point{z: one}
	offset := 1
	for _, f := range []*field{&p.y, &p.x} {
		for i := 5; i >= 0; i-- {
			f[i] = binary.BigEndian.Uint64(data[offset:])
			offset += 8
			if f[i] >= Prime {
				return point{}, errors.New("noncanonical Cheetah coordinate")
			}
		}
	}
	if p.y.square() != p.x.square().mul(p.x).add(p.x).add(curveB) || p.times(order).z != (field{}) {
		return point{}, errors.New("Cheetah point outside prime-order subgroup")
	}
	return p, nil
}
