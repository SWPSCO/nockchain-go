package nockchain

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"strings"

	"github.com/tyler-smith/go-bip39/wordlists"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/text/unicode/norm"
)

// RecoveryPhrase stores an English BIP39 mnemonic. Formatting is redacted;
// Words explicitly exports the recovery secret. Store it offline.
type RecoveryPhrase struct{ words string }

func (p RecoveryPhrase) String() string             { return "Nockchain recovery phrase (redacted)" }
func (p RecoveryPhrase) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte(p.String())) }

// Words exports the seed phrase for an offline backup. Never log its return value.
func (p RecoveryPhrase) Words() string { return p.words }

// Seed is a 64-byte wallet seed with redacted diagnostic formatting.
type Seed struct {
	data  [64]byte
	valid bool
}

func (s Seed) String() string             { return "Nockchain seed (redacted)" }
func (s Seed) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(s.String())) }

// Bytes explicitly exports a copy of the seed. A zero Seed is invalid.
func (s Seed) Bytes() ([64]byte, error) {
	if !s.valid {
		return [64]byte{}, errors.New("uninitialized seed")
	}
	return s.data, nil
}

// Key derives the master extended private key from this seed. Use offline.
func (s Seed) Key() (ExtendedKey, error) {
	if !s.valid {
		return ExtendedKey{}, errors.New("uninitialized seed")
	}
	return Master(s.data[:])
}

var englishWords = append([]string(nil), wordlists.English...)
var englishIndex = func() map[string]int {
	m := make(map[string]int, len(englishWords))
	for i, w := range englishWords {
		m[w] = i
	}
	return m
}()

// GenerateSeed creates a random 64-byte seed. Its backup is the raw seed or the
// resulting zprv; a raw seed cannot be converted back into a BIP39 phrase.
func GenerateSeed() (Seed, error) {
	s := Seed{valid: true}
	if _, e := rand.Read(s.data[:]); e != nil {
		return Seed{}, e
	}
	return s, nil
}

// GenerateMnemonic creates a 24-word English BIP39 phrase from crypto/rand.
func GenerateMnemonic() (RecoveryPhrase, error) {
	var entropy [32]byte
	if _, e := rand.Read(entropy[:]); e != nil {
		return RecoveryPhrase{}, e
	}
	defer clear(entropy[:])
	return mnemonicFromEntropy(entropy[:])
}
func mnemonicFromEntropy(entropy []byte) (RecoveryPhrase, error) {
	if len(entropy) < 16 || len(entropy) > 32 || len(entropy)%4 != 0 {
		return RecoveryPhrase{}, errors.New("entropy must be 128 to 256 bits in 32-bit increments")
	}
	hash := sha256.Sum256(entropy)
	data := append(append([]byte(nil), entropy...), hash[0])
	defer clear(data)
	count := (len(entropy)*8 + len(entropy)/4) / 11
	words := make([]string, count)
	for i := range words {
		value := 0
		for j := 0; j < 11; j++ {
			bit := i*11 + j
			value = value<<1 | int((data[bit/8]>>uint(7-bit%8))&1)
		}
		words[i] = englishWords[value]
	}
	return RecoveryPhrase{strings.Join(words, " ")}, nil
}

// SeedFromMnemonic validates an English BIP39 checksum and derives a seed using
// NFKD-normalized mnemonic and passphrase. Whitespace between words is normalized.
func SeedFromMnemonic(phrase, passphrase string) (Seed, error) {
	if len(phrase) > 1024 || len(passphrase) > 4096 {
		return Seed{}, errors.New("mnemonic or passphrase exceeds size limit")
	}
	words := strings.Fields(norm.NFKD.String(phrase))
	count := len(words)
	if count < 12 || count > 24 || count%3 != 0 {
		return Seed{}, errors.New("invalid BIP39 word count")
	}
	data := make([]byte, (count*11+7)/8)
	defer clear(data)
	for i, w := range words {
		v, ok := englishIndex[w]
		if !ok {
			return Seed{}, errors.New("invalid English BIP39 word")
		}
		for j := 0; j < 11; j++ {
			bit := i*11 + j
			data[bit/8] |= byte((v>>uint(10-j))&1) << uint(7-bit%8)
		}
	}
	entropyLen := count * 11 * 32 / 33 / 8
	checksumBits := entropyLen / 4
	hash := sha256.Sum256(data[:entropyLen])
	mask := byte(0xff << uint(8-checksumBits))
	if data[entropyLen]&mask != hash[0]&mask {
		return Seed{}, errors.New("invalid BIP39 checksum")
	}
	normalized := strings.Join(words, " ")
	derived := pbkdf2.Key([]byte(normalized), []byte("mnemonic"+norm.NFKD.String(passphrase)), 2048, 64, sha512.New)
	defer clear(derived)
	s := Seed{valid: true}
	copy(s.data[:], derived)
	return s, nil
}

// GenerateWallet creates a master key and its 24-word recovery phrase. Back up
// the phrase and optional passphrase before using the wallet. The key exposes
// Zpub, Zprv, Address, and Derive for explicit export and derivation.
func GenerateWallet(passphrase string) (ExtendedKey, RecoveryPhrase, error) {
	phrase, e := GenerateMnemonic()
	if e != nil {
		return ExtendedKey{}, RecoveryPhrase{}, e
	}
	key, e := RestoreWallet(phrase.Words(), passphrase)
	if e != nil {
		return ExtendedKey{}, RecoveryPhrase{}, e
	}
	return key, phrase, nil
}

// RestoreWallet recovers a V1 master key from a BIP39 phrase and passphrase.
// An incorrect passphrase produces a different valid wallet, not an error.
func RestoreWallet(phrase, passphrase string) (ExtendedKey, error) {
	seed, e := SeedFromMnemonic(phrase, passphrase)
	if e != nil {
		return ExtendedKey{}, e
	}
	defer clear(seed.data[:])
	return seed.Key()
}
