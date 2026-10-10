package nockchain

import (
	"encoding/binary"
	"errors"
	"math/big"
)

// Signature is a Cheetah Schnorr challenge and response, each expressed as eight
// little-endian 32-bit limbs. Both scalars must be nonzero and below the group order.
type Signature struct {
	Challenge [8]uint32
	Response  [8]uint32
}

func scalarLimbs(n *big.Int) (out [8]uint32) {
	var b [32]byte
	n.FillBytes(b[:])
	for i := range out {
		out[i] = binary.BigEndian.Uint32(b[28-4*i : 32-4*i])
	}
	return
}
func limbsScalar(limbs [8]uint32) *big.Int {
	var b [32]byte
	for i, v := range limbs {
		binary.BigEndian.PutUint32(b[28-4*i:32-4*i], v)
	}
	return new(big.Int).SetBytes(b[:])
}
func digestScalar(d Digest) *big.Int {
	n, p := new(big.Int), new(big.Int).SetUint64(Prime)
	for i := 3; i >= 0; i-- {
		n.Mul(n, p)
		n.Add(n, new(big.Int).SetUint64(d[i]))
	}
	return n.Mod(n, order)
}
func pointWords(p point) []uint64 {
	p = p.affine()
	return append(append(make([]uint64, 0, 12), p.x[:]...), p.y[:]...)
}

// SignDigest creates the deterministic, secret-bound V1 Schnorr signature.
// Arithmetic is variable-time: use only in offline, trusted wallet tooling.
// Signing a digest does not review transaction destinations, fees, or chain state.
func (k ExtendedKey) SignDigest(message Digest) (Signature, error) {
	if k.secret == nil || k.pub.z == (field{}) || !message.Valid() {
		return Signature{}, errors.New("signing requires a valid private key and digest")
	}
	secret := new(big.Int).SetBytes(k.secret[:])
	limbs := scalarLimbs(secret)
	transcript := append(pointWords(k.pub), message[:]...)
	for _, v := range limbs {
		transcript = append(transcript, uint64(v))
	}
	defer clear(transcript)
	defer clear(limbs[:])
	nonce := digestScalar(hashWords(transcript))
	if !validScalar(nonce) {
		return Signature{}, errors.New("zero signing nonce")
	}
	challengeWords := append(pointWords(generator.times(nonce)), pointWords(k.pub)...)
	challengeWords = append(challengeWords, message[:]...)
	challenge := digestScalar(hashWords(challengeWords))
	response := new(big.Int).Mul(challenge, secret)
	response.Add(response, nonce).Mod(response, order)
	if !validScalar(challenge) || !validScalar(response) {
		return Signature{}, errors.New("zero signature scalar")
	}
	return Signature{scalarLimbs(challenge), scalarLimbs(response)}, nil
}

// VerifyDigest verifies a signature against a strictly validated 97-byte Cheetah
// public key and a canonical digest. It rejects infinity and noncanonical scalars.
func VerifyDigest(public []byte, message Digest, signature Signature) bool {
	if !message.Valid() {
		return false
	}
	p, err := parsePoint(public)
	if err != nil {
		return false
	}
	c, s := limbsScalar(signature.Challenge), limbsScalar(signature.Response)
	if !validScalar(c) || !validScalar(s) {
		return false
	}
	r := generator.times(s).plus(p.times(new(big.Int).Sub(order, c))).affine()
	if r.z == (field{}) {
		return false
	}
	transcript := append(pointWords(r), pointWords(p)...)
	transcript = append(transcript, message[:]...)
	return digestScalar(hashWords(transcript)).Cmp(c) == 0
}

func (s Signature) noun() Noun {
	var c, r [8]Noun
	for i := range c {
		c[i] = Noun{atom: uint64(s.Challenge[i])}
		r[i] = Noun{atom: uint64(s.Response[i])}
	}
	return Cell(Tuple(c[:]...), Tuple(r[:]...))
}
