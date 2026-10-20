package nockchain

import (
	"errors"
	"math/bits"
)

// MaxJamBytes bounds based-noun wire input and output.
const MaxJamBytes = 16 << 20

// Jam emits canonical structural backreferences with bounded logical expansion.
func Jam(noun Noun) ([]byte, error) {
	type frame struct {
		n     Noun
		ready bool
	}
	type key struct {
		atom       uint64
		head, tail int
		cell       bool
	}
	ids := map[Noun]int{}
	intern := map[key]int{}
	sizes := []int{}
	visit := []frame{{noun, false}}
	active := map[Noun]bool{}
	count := 0
	for len(visit) > 0 {
		f := visit[len(visit)-1]
		visit = visit[:len(visit)-1]
		if _, ok := ids[f.n]; ok {
			continue
		}
		if !f.ready {
			count++
			if active[f.n] || count > MaxNounNodes {
				return nil, errors.New("cyclic noun or logical node limit exceeded")
			}
		}
		if f.n.cell != nil && !f.ready {
			active[f.n] = true
			visit = append(visit, frame{f.n, true}, frame{f.n.cell.tail, false}, frame{f.n.cell.head, false})
			continue
		}
		delete(active, f.n)
		k := key{atom: f.n.atom}
		size := 1
		if f.n.cell != nil {
			k = key{head: ids[f.n.cell.head], tail: ids[f.n.cell.tail], cell: true}
			size += sizes[k.head] + sizes[k.tail]
		}
		if size > MaxNounNodes {
			return nil, errors.New("noun exceeds logical node limit")
		}
		id, ok := intern[k]
		if !ok {
			id = len(sizes)
			intern[k] = id
			sizes = append(sizes, size)
		}
		ids[f.n] = id
	}
	w := bitWriter{}
	refs := map[int]int{}
	stack := []Noun{noun}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		id := ids[n]
		prior, seen := refs[id]
		if seen && (n.cell != nil || bits.Len64(n.atom) > bits.Len(uint(prior))) {
			w.write(3, 2)
			w.mat(uint64(prior))
		} else {
			if !seen {
				refs[id] = w.bit
			}
			if n.cell == nil {
				w.write(0, 1)
				w.mat(n.atom)
			} else {
				w.write(1, 2)
				stack = append(stack, n.cell.tail, n.cell.head)
			}
		}
		if len(w.bytes) > MaxJamBytes {
			return nil, errors.New("jam exceeds byte limit")
		}
	}
	return w.bytes, nil
}

type bitWriter struct {
	bytes []byte
	bit   int
}

func (w *bitWriter) write(v uint64, n int) {
	for i := 0; i < n; i++ {
		if w.bit/8 == len(w.bytes) {
			w.bytes = append(w.bytes, 0)
		}
		w.bytes[w.bit/8] |= byte((v>>i)&1) << uint(w.bit%8)
		w.bit++
	}
}
func (w *bitWriter) mat(v uint64) {
	n := bits.Len64(v)
	if n == 0 {
		w.write(1, 1)
		return
	}
	size := bits.Len(uint(n))
	w.write(0, size)
	w.write(1, 1)
	w.write(uint64(n), size-1)
	w.write(v, n)
}

type bitReader struct {
	bytes []byte
	bit   int
}

func (r *bitReader) read(n int) (uint64, error) {
	if n < 0 || n > 64 || n > len(r.bytes)*8-r.bit {
		return 0, errors.New("truncated or oversized jam atom")
	}
	var v uint64
	for i := 0; i < n; i++ {
		v |= uint64((r.bytes[r.bit/8]>>uint(r.bit%8))&1) << uint(i)
		r.bit++
	}
	return v, nil
}
func (r *bitReader) rub() (uint64, error) {
	size := 0
	for {
		b, e := r.read(1)
		if e != nil {
			return 0, e
		}
		if b == 1 {
			break
		}
		size++
		if size > 7 {
			return 0, errors.New("jam atom exceeds field width")
		}
	}
	if size == 0 {
		return 0, nil
	}
	low, e := r.read(size - 1)
	if e != nil {
		return 0, e
	}
	n := int(low) + (1 << (size - 1))
	return r.read(n)
}

// Cue decodes a based noun, including references to completed earlier nouns.
// Cycles, forward references, out-of-field atoms, excess data, and excessive
// logical expansion are rejected. At most seven trailing zero pad bits are allowed.
func Cue(data []byte) (Noun, error) {
	if len(data) == 0 || len(data) > MaxJamBytes {
		return Noun{}, errors.New("invalid jam size")
	}
	r := bitReader{bytes: data}
	type saved struct {
		noun  Noun
		nodes int
	}
	refs := map[int]saved{}
	type frame struct {
		start int
		head  *saved
	}
	stack := []frame{}
	var result saved
	for {
		start := r.bit
		first, e := r.read(1)
		if e != nil {
			return Noun{}, e
		}
		var current saved
		if first == 0 {
			v, e := r.rub()
			if e != nil {
				return Noun{}, e
			}
			a, e := Atom(v)
			if e != nil {
				return Noun{}, e
			}
			current = saved{a, 1}
			refs[start] = current
		} else {
			second, e := r.read(1)
			if e != nil {
				return Noun{}, e
			}
			if second == 0 {
				if len(stack) >= MaxNounNodes {
					return Noun{}, errors.New("jam exceeds node limit")
				}
				stack = append(stack, frame{start: start})
				continue
			}
			pos, e := r.rub()
			if e != nil {
				return Noun{}, e
			}
			if pos >= uint64(start) {
				return Noun{}, errors.New("invalid jam backreference")
			}
			var ok bool
			current, ok = refs[int(pos)]
			if !ok {
				return Noun{}, errors.New("invalid or cyclic jam backreference")
			}
		}
		for {
			if len(stack) == 0 {
				result = current
				break
			}
			f := &stack[len(stack)-1]
			if f.head == nil {
				copy := current
				f.head = &copy
				break
			}
			count := 1 + f.head.nodes + current.nodes
			if count > MaxNounNodes {
				return Noun{}, errors.New("jam exceeds logical node limit")
			}
			current = saved{Cell(f.head.noun, current.noun), count}
			refs[f.start] = current
			stack = stack[:len(stack)-1]
		}
		if len(stack) == 0 {
			break
		}
	}
	if len(data)*8-r.bit > 7 {
		return Noun{}, errors.New("trailing jam data")
	}
	for r.bit < len(data)*8 {
		b, _ := r.read(1)
		if b != 0 {
			return Noun{}, errors.New("trailing jam data")
		}
	}
	return result.noun, nil
}
