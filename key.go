package nockchain

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"math/big"
	"strconv"
	"strings"
)

// ExtendedKey is a V1 Cheetah SLIP-10 key. Public removes its private scalar.
type ExtendedKey struct {
	secret *[32]byte
	pub    point
	chain  [32]byte
	depth  byte
	index  uint32
	parent [4]byte
}

// Generate creates a private wallet using crypto/rand. Export its Zprv for
// recovery before using any receiving address. Use this operation offline.
func Generate() (ExtendedKey, error) {
	var seed [64]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return ExtendedKey{}, err
	}
	defer clear(seed[:])
	return Master(seed[:])
}

// IsPrivate reports whether this extended key contains a private scalar.
func (k ExtendedKey) IsPrivate() bool { return k.secret != nil }

// String identifies the key without exposing its scalar or chain code.
func (k ExtendedKey) String() string {
	if k.pub.z == (field{}) {
		return "Nockchain key (invalid)"
	}
	if k.IsPrivate() {
		return "Nockchain key (private)"
	}
	return "Nockchain key (public)"
}

// GoString keeps formatted diagnostic output free of key material.
func (k ExtendedKey) GoString() string { return k.String() }

func hmac512(key, data []byte) []byte {
	h := hmac.New(sha512.New, key)
	h.Write(data)
	return h.Sum(nil)
}
func validScalar(n *big.Int) bool { return n.Sign() > 0 && n.Cmp(order) < 0 }

// Master derives a V1 wallet from a 64-byte seed. It is intended for offline use.
func Master(seed []byte) (ExtendedKey, error) {
	if len(seed) != 64 {
		return ExtendedKey{}, errors.New("Nockchain seed must contain 64 bytes")
	}
	i := hmac512([]byte("Nockchain seed"), seed)
	for retry := 0; retry < 1024; retry++ {
		n := new(big.Int).SetBytes(i[:32])
		if validScalar(n) {
			k := ExtendedKey{secret: new([32]byte), pub: generator.times(n).affine()}
			copy(k.secret[:], i[:32])
			copy(k.chain[:], i[32:])
			return k, nil
		}
		i = hmac512([]byte("Nockchain seed"), i)
	}
	return ExtendedKey{}, errors.New("Nockchain master derivation failed")
}

// Public returns the watch-only extended key.
func (k ExtendedKey) Public() ExtendedKey { k.secret = nil; return k }

// Child derives an index; indices >= 2^31 require a private parent.
func (k ExtendedKey) Child(index uint32) (ExtendedKey, error) {
	if k.depth == 255 || k.pub.z == (field{}) {
		return ExtendedKey{}, errors.New("invalid derivation parent")
	}
	var ib [4]byte
	binary.BigEndian.PutUint32(ib[:], index)
	var data []byte
	if index >= 1<<31 {
		if k.secret == nil {
			return ExtendedKey{}, errors.New("hardened child requires private key")
		}
		data = append([]byte{0}, k.secret[:]...)
	} else {
		data = k.pub.bytes()
	}
	data = append(data, ib[:]...)
	for retry := 0; retry < 1024; retry++ {
		i := hmac512(k.chain[:], data)
		n := new(big.Int).SetBytes(i[:32])
		if validScalar(n) {
			child := ExtendedKey{depth: k.depth + 1, index: index}
			copy(child.chain[:], i[32:])
			if k.secret != nil {
				n.Add(n, new(big.Int).SetBytes(k.secret[:]))
				n.Mod(n, order)
				if n.Sign() != 0 {
					child.secret = new([32]byte)
					n.FillBytes(child.secret[:])
					child.pub = generator.times(n).affine()
				}
			} else {
				child.pub = k.pub.plus(generator.times(n)).affine()
			}
			if child.pub.z != (field{}) {
				p := k.pub.affine()
				words := append(append([]uint64{}, p.x[:]...), p.y[:]...)
				fp := hashWords(words)
				var b [8]byte
				binary.BigEndian.PutUint64(b[:], fp[0])
				copy(child.parent[:], b[:4])
				return child, nil
			}
		}
		data = append(append([]byte{1}, i[32:]...), ib[:]...)
	}
	return ExtendedKey{}, errors.New("Nockchain child derivation failed")
}

// Derive follows an absolute m/... path from this key, rejecting empty components.
func (k ExtendedKey) Derive(path string) (ExtendedKey, error) {
	parts := strings.Split(path, "/")
	if parts[0] != "m" {
		return ExtendedKey{}, errors.New("derivation path must begin with m")
	}
	for _, part := range parts[1:] {
		hard := strings.HasSuffix(part, "'")
		if hard {
			part = strings.TrimSuffix(part, "'")
		}
		i, err := strconv.ParseUint(part, 10, 31)
		if err != nil || strconv.FormatUint(i, 10) != part {
			return ExtendedKey{}, errors.New("invalid derivation index")
		}
		if hard {
			i |= 1 << 31
		}
		k, err = k.Child(uint32(i))
		if err != nil {
			return ExtendedKey{}, err
		}
	}
	return k, nil
}

// Address is the V1 public-key hash used by sending wallets.
func (k ExtendedKey) Address() (string, error) {
	if k.pub.z == (field{}) {
		return "", errors.New("invalid extended key")
	}
	return publicKeyHash(k.pub).String(), nil
}

// LockAddress is the standard single-signature lock root used by Nockblocks.
func (k ExtendedKey) LockAddress() (string, error) {
	if k.pub.z == (field{}) {
		return "", errors.New("invalid extended key")
	}
	d, err := LockRoot(publicKeyHash(k.pub))
	return d.String(), err
}

// PublicBytes returns the 97-byte Hoon ser-p encoding.
func (k ExtendedKey) PublicBytes() ([]byte, error) {
	if k.pub.z == (field{}) {
		return nil, errors.New("invalid extended key")
	}
	return k.pub.bytes(), nil
}

func checksum(data []byte) []byte { h := sha256.Sum256(data); h = sha256.Sum256(h[:]); return h[:4] }
func (k ExtendedKey) serialize(private bool) (string, error) {
	if k.pub.z == (field{}) {
		return "", errors.New("invalid extended key")
	}
	prefix := uint32(0x0c0ebb09)
	data := k.pub.bytes()
	if private {
		if k.secret == nil {
			return "", errors.New("private key is unavailable")
		}
		prefix = 0x01106331
		data = append([]byte{0}, k.secret[:]...)
	}
	payload := make([]byte, 46)
	binary.BigEndian.PutUint32(payload, prefix)
	payload[4] = 1
	payload[5] = k.depth
	copy(payload[6:10], k.parent[:])
	binary.BigEndian.PutUint32(payload[10:14], k.index)
	copy(payload[14:46], k.chain[:])
	payload = append(payload, data...)
	return encodeBase58(append(payload, checksum(payload)...)), nil
}

// Zpub exports the public extended key for watch-only address generation.
func (k ExtendedKey) Zpub() (string, error) { return k.serialize(false) }

// Zprv exports the private extended key for offline wallet recovery.
func (k ExtendedKey) Zprv() (string, error) { return k.serialize(true) }

// ParseExtendedKey validates a V1 zpub or zprv, including its point and checksum.
func ParseExtendedKey(text string) (ExtendedKey, error) {
	var k ExtendedKey
	if len(text) > 210 {
		return k, errors.New("invalid extended key length")
	}
	b := decodeBase58(text)
	if len(b) != 83 && len(b) != 147 {
		return k, errors.New("invalid extended key length")
	}
	payload := b[:len(b)-4]
	if encodeBase58(b) != text || !bytes.Equal(b[len(b)-4:], checksum(payload)) || payload[4] != 1 {
		return k, errors.New("invalid V1 extended key")
	}
	prefix := binary.BigEndian.Uint32(payload)
	k.depth = payload[5]
	copy(k.parent[:], payload[6:10])
	k.index = binary.BigEndian.Uint32(payload[10:14])
	copy(k.chain[:], payload[14:46])
	if k.depth == 0 && (k.index != 0 || k.parent != [4]byte{}) {
		return ExtendedKey{}, errors.New("invalid master metadata")
	}
	if prefix == 0x01106331 && len(payload) == 79 && payload[46] == 0 {
		n := new(big.Int).SetBytes(payload[47:])
		if !validScalar(n) {
			return ExtendedKey{}, errors.New("invalid private scalar")
		}
		k.secret = new([32]byte)
		copy(k.secret[:], payload[47:])
		k.pub = generator.times(n).affine()
	} else if prefix == 0x0c0ebb09 && len(payload) == 143 {
		var err error
		k.pub, err = parsePoint(payload[46:])
		if err != nil {
			return ExtendedKey{}, err
		}
	} else {
		return ExtendedKey{}, errors.New("invalid extended key type")
	}
	return k, nil
}

// ParsePublicKey accepts only a valid V1 zpub, rejecting private key material.
func ParsePublicKey(text string) (ExtendedKey, error) {
	k, err := ParseExtendedKey(text)
	if err != nil {
		return ExtendedKey{}, err
	}
	if k.IsPrivate() {
		return ExtendedKey{}, errors.New("watch-only configuration requires a zpub")
	}
	return k, nil
}
