package nockchain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestBIP39Reference(t *testing.T) {
	b, e := os.ReadFile("testdata/bip39.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors [][]string
	if e = json.Unmarshal(b, &vectors); e != nil {
		t.Fatal(e)
	}
	if len(vectors) != 24 {
		t.Fatal("missing English BIP39 vectors")
	}
	for i, v := range vectors {
		entropy, _ := hex.DecodeString(v[0])
		phrase, e := mnemonicFromEntropy(entropy)
		if e != nil || phrase.Words() != v[1] {
			t.Fatalf("vector %d phrase mismatch", i)
		}
		seed, e := SeedFromMnemonic(v[1], "TREZOR")
		if e != nil {
			t.Fatalf("vector %d rejected", i)
		}
		raw, _ := seed.Bytes()
		if hex.EncodeToString(raw[:]) != v[2] {
			t.Fatalf("vector %d seed mismatch", i)
		}
	}
}
func TestWalletRecovery(t *testing.T) {
	key, phrase, e := GenerateWallet("café")
	if e != nil {
		t.Fatal(e)
	}
	restored, e := RestoreWallet(phrase.Words(), "cafe\u0301")
	if e != nil {
		t.Fatal(e)
	}
	a, _ := key.Zprv()
	b, _ := restored.Zprv()
	if a != b {
		t.Fatal("wallet recovery differs")
	}
	other, e := RestoreWallet(phrase.Words(), "")
	if e != nil {
		t.Fatal(e)
	}
	c, _ := other.Zpub()
	d, _ := key.Zpub()
	if c == d {
		t.Fatal("passphrase not applied")
	}
	for _, format := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x"} {
		if strings.Contains(fmt.Sprintf(format, phrase), phrase.Words()) {
			t.Fatal("phrase leaks in formatting")
		}
	}
	seed, e := SeedFromMnemonic(phrase.Words(), "")
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := seed.Bytes()
	copyRaw := raw
	copyRaw[0] ^= 1
	again, _ := seed.Bytes()
	if again != raw {
		t.Fatal("mutable seed export")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "%x"} {
		if !strings.Contains(fmt.Sprintf(format, seed), "redacted") {
			t.Fatal("seed is not redacted")
		}
	}
	for _, n := range []int{16, 20, 24, 28, 32} {
		p, e := mnemonicFromEntropy(make([]byte, n))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = SeedFromMnemonic("  "+strings.ReplaceAll(p.Words(), " ", "\n\t")+" ", ""); e != nil {
			t.Fatal(e)
		}
	}
	s, e := GenerateSeed()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.Key(); e != nil {
		t.Fatal(e)
	}
	if _, e = (Seed{}).Key(); e == nil {
		t.Fatal("zero seed accepted")
	}
	if _, e = (Seed{}).Bytes(); e == nil {
		t.Fatal("zero seed exported")
	}
	for _, bad := range []string{"", strings.Repeat("abandon ", 12), strings.Repeat("nope ", 24), strings.Repeat("x", 1025)} {
		if _, e = SeedFromMnemonic(bad, ""); e == nil {
			t.Fatal("invalid phrase accepted")
		}
	}
	if _, e = SeedFromMnemonic(phrase.Words(), strings.Repeat("x", 4097)); e == nil {
		t.Fatal("oversized passphrase accepted")
	}
}

// This opt-in test reads secrets only in memory. Failures never print key material.
func TestLocalWalletExport(t *testing.T) {
	path := os.Getenv("NOCKCHAIN_TEST_KEY")
	if path == "" {
		t.Skip("set NOCKCHAIN_TEST_KEY to verify a local wallet export")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal("cannot read local wallet export")
	}
	defer clear(data)
	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var zprv, zpub, phrase string
	for _, line := range lines {
		s := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(s, "zprv"):
			zprv = s
		case strings.HasPrefix(s, "zpub"):
			zpub = s
		case len(strings.Fields(s)) == 24:
			phrase = strings.Trim(s, "\"'")
		}
	}
	if zprv == "" || zpub == "" || phrase == "" {
		t.Fatal("wallet export lacks required fields")
	}
	key, e := ParseExtendedKey(zprv)
	if e != nil {
		t.Fatal("wallet private key rejected")
	}
	pub, e := key.Zpub()
	if e != nil || pub != zpub {
		t.Fatal("wallet public key mismatch")
	}
	restored, e := RestoreWallet(phrase, "")
	if e != nil {
		t.Fatal("wallet phrase rejected")
	}
	actual, e := restored.Zprv()
	if e != nil || actual != zprv {
		t.Fatal("restored wallet private key mismatch")
	}
	address, e := key.Address()
	if e != nil {
		t.Fatal("wallet address derivation failed")
	}
	found := false
	for _, s := range lines {
		if strings.TrimSpace(s) == address {
			found = true
		}
	}
	if !found {
		t.Fatal("wallet address does not match export")
	}
	message := Digest{1, 2, 3, 4, 5}
	sig, e := key.SignDigest(message)
	if e != nil {
		t.Fatal("wallet signature failed")
	}
	public, e := key.PublicBytes()
	if e != nil || !VerifyDigest(public, message, sig) {
		t.Fatal("wallet signature verification failed")
	}
}
