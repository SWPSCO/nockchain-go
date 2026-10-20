package nockchain

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"testing"
)

type walletProofVector struct {
	Index                int
	Stub, Full           string
	StubHash, FullHash   []string
	StubValid, FullValid bool
}
type walletLockVector struct {
	Form   string
	Root   []string
	Proofs []walletProofVector
}
type walletDataVector struct {
	Case, Data, Words string
	Hash              []string
}
type walletFeeVector struct{ Case, Spends, Height, Base, Divisor, Minimum, SeedWords, WitnessWords, Fee string }
type walletVectors struct {
	Migrations        []walletMigrationVector
	Plans             []walletPlanVector
	Locks             []walletLockVector
	NoteData          []walletDataVector
	Fees, Withdrawals []walletFeeVector
	Raw               []struct{ Name, Jam string }
}

func loadWalletVectors(t *testing.T) walletVectors {
	t.Helper()
	data, e := os.ReadFile("testdata/wallet/reference.json")
	if e != nil {
		t.Fatal(e)
	}
	var v walletVectors
	if e := json.Unmarshal(data, &v); e != nil {
		t.Fatal(e)
	}
	return v
}
func walletNumber(t *testing.T, s string) uint64 {
	t.Helper()
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func walletDigest(t *testing.T, values []string) Digest {
	t.Helper()
	if len(values) != 5 {
		t.Fatal("invalid digest fixture")
	}
	var d Digest
	for i, v := range values {
		d[i] = walletNumber(t, v)
	}
	return d
}
func walletNoun(t *testing.T, s string) Noun {
	t.Helper()
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	n, e := Cue(b)
	if e != nil {
		t.Fatal(e)
	}
	return n
}
func walletJam(t *testing.T, n Noun) string {
	t.Helper()
	b, e := Jam(n)
	if e != nil {
		t.Fatal(e)
	}
	return hex.EncodeToString(b)
}
func TestCanonicalWalletPayloads(t *testing.T) {
	v := loadWalletVectors(t)
	payloads := []string{}
	for _, row := range v.Raw {
		payloads = append(payloads, row.Jam)
	}
	for _, row := range v.NoteData {
		payloads = append(payloads, row.Data)
	}
	for _, row := range append(v.Fees, v.Withdrawals...) {
		payloads = append(payloads, row.Spends)
	}
	for _, row := range v.Locks {
		payloads = append(payloads, row.Form)
		for _, p := range row.Proofs {
			payloads = append(payloads, p.Stub, p.Full)
		}
	}
	for _, payload := range payloads {
		if walletJam(t, walletNoun(t, payload)) != payload {
			t.Fatal("canonical JAM differs from official payload")
		}
	}
}
func TestHoonLockProofOracle(t *testing.T) {
	count := 0
	for _, row := range loadWalletVectors(t).Locks {
		lock, e := ParseLock(walletNoun(t, row.Form))
		if e != nil {
			t.Fatal(e)
		}
		root, e := lock.Root()
		if e != nil || root != walletDigest(t, row.Root) {
			t.Fatal("lock root", e)
		}
		if walletJam(t, lock.Noun()) != row.Form {
			t.Fatal("lock noun")
		}
		first, _ := NoteFirstV1(root)
		for _, v := range row.Proofs {
			for _, full := range []bool{false, true} {
				expected, hash, valid := v.Stub, v.StubHash, v.StubValid
				if full {
					expected, hash, valid = v.Full, v.FullHash, v.FullValid
				}
				proof, e := BuildLockMerkleProof(lock, v.Index, full)
				if e != nil {
					t.Fatal(e)
				}
				noun, e := proof.Noun()
				if e != nil || walletJam(t, noun) != expected {
					t.Fatal("proof bytes", e)
				}
				actual, e := proof.Hash()
				if e != nil || actual != walletDigest(t, hash) {
					t.Fatal("proof hash", e)
				}
				if proof.Check(first) != valid {
					t.Fatal("proof verdict")
				}
				decoded, e := ParseLockMerkleProof(walletNoun(t, expected))
				if e != nil || walletJam(t, decoded.noun()) != expected {
					t.Fatal("proof decode", e)
				}
				if proof.ValidStubAxis(false) != (full || proof.Axis == 1) || !proof.ValidStubAxis(true) {
					t.Fatal("stub axis")
				}
				bad := proof.clone()
				bad.Axis = 0
				if bad.Check(first) {
					t.Fatal("zero axis accepted")
				}
				bad = proof.clone()
				bad.Path = append(bad.Path, root)
				if bad.Check(first) {
					t.Fatal("long path accepted")
				}
			}
			count++
		}
	}
	if count != 31 {
		t.Fatal(count)
	}
}
func TestHoonNoteDataOracle(t *testing.T) {
	for _, v := range loadWalletVectors(t).NoteData {
		data, e := ParseNoteData(walletNoun(t, v.Data))
		if e != nil {
			t.Fatal(v.Case, e)
		}
		if data.Hash() != walletDigest(t, v.Hash) || data.Words() != walletNumber(t, v.Words) || walletJam(t, data.Noun()) != v.Data {
			t.Fatal(v.Case, "metadata mismatch")
		}
		entries := map[string]Noun{}
		for _, entry := range data.Entries() {
			entries[entry.Key] = entry.Value
		}
		for _, entry := range data.Decoded() {
			var noun Noun
			switch payload := entry.Payload.(type) {
			case Noun:
				noun = payload
			case LockData:
				noun, e = payload.Noun()
			case BridgeDepositDataPayload:
				noun = payload.Noun()
			case BridgeWithdrawalDataPayload:
				noun, e = payload.Noun()
			default:
				t.Fatal("unknown payload type")
			}
			if e != nil || !nounEqual(noun, entries[entry.Key]) {
				t.Fatal(v.Case, "payload round trip", e)
			}
		}
	}
}
func TestHoonFeeOracle(t *testing.T) {
	v := loadWalletVectors(t)
	for _, row := range v.Fees {
		height := walletNumber(t, row.Height)
		words, e := TransactionWords(walletNoun(t, row.Spends), height >= 10, false)
		if e != nil {
			t.Fatal(e)
		}
		if words != (WordCountBreakdown{walletNumber(t, row.SeedWords), walletNumber(t, row.WitnessWords)}) {
			t.Fatal(row.Case, "word counts", words)
		}
		fees := FeeParameters{height, 10, walletNumber(t, row.Base), walletNumber(t, row.Divisor), walletNumber(t, row.Minimum)}
		if ComputeMinimumFee(words, fees).MinimumFee != walletNumber(t, row.Fee) {
			t.Fatal(row.Case, "fee")
		}
	}
	for _, row := range v.Withdrawals {
		height := walletNumber(t, row.Height)
		words, e := TransactionWords(walletNoun(t, row.Spends), height >= 10, true)
		if e != nil {
			t.Fatal(e)
		}
		if words != (WordCountBreakdown{walletNumber(t, row.SeedWords), walletNumber(t, row.WitnessWords)}) {
			t.Fatal(row.Case, "withdrawal words", words)
		}
		if ComputeMinimumFee(words, FeeParameters{height, 10, 256, 4, 0}).MinimumFee != walletNumber(t, row.Fee) {
			t.Fatal(row.Case, "withdrawal fee")
		}
	}
}
func TestCanonicalJamStructuralSharingAndExpansion(t *testing.T) {
	value := Tuple(Noun{atom: 1000}, Noun{atom: 1001})
	shared := Cell(value, value)
	separate := Cell(Tuple(Noun{atom: 1000}, Noun{atom: 1001}), Tuple(Noun{atom: 1000}, Noun{atom: 1001}))
	a, e := Jam(shared)
	if e != nil {
		t.Fatal(e)
	}
	b, e := Jam(separate)
	if e != nil || !bytes.Equal(a, b) {
		t.Fatal("structural sharing changes wire bytes", e)
	}
	for i := 0; i < 21; i++ {
		value = Cell(value, value)
	}
	if _, e := Jam(value); e == nil {
		t.Fatal("logical expansion bomb accepted")
	}
}

type walletOutputVector struct {
	Root         []string
	Data, Amount string
}
type walletPlanVector struct {
	Case, Height, Order                                          string
	Signer                                                       []string
	Candidates, Selection, Selected                              []string
	Outputs, Emitted                                             []walletOutputVector
	Refund                                                       walletOutputVector
	Sweep                                                        *walletOutputVector
	ExactFee                                                     *string
	Refunds                                                      []struct{ Name, Amount string }
	SelectedTotal, Fee, MinimumFee, SeedWords, WitnessWords, Jam string
}

func TestRustPlannerOracle(t *testing.T) {
	decodeName := func(wire string) NoteName {
		p, e := parts(walletNoun(t, wire), 3)
		if e != nil {
			t.Fatal(e)
		}
		first, e := nounDigest(p[0])
		if e != nil {
			t.Fatal(e)
		}
		last, e := nounDigest(p[1])
		if e != nil {
			t.Fatal(e)
		}
		return NoteName{first, last}
	}
	output := func(v walletOutputVector) PlannedOutput {
		return PlannedOutput{walletDigest(t, v.Root), walletNoun(t, v.Data), walletNumber(t, v.Amount)}
	}
	for _, row := range loadWalletVectors(t).Plans {
		t.Run(row.Case, func(t *testing.T) {
			chain := ChainContextAtHeight(walletNumber(t, row.Height))
			request := PlanRequest{Refund: output(row.Refund), Chain: &chain, Order: SelectionOrder(row.Order)}
			for _, wire := range row.Candidates {
				note, e := ParseNoteV1(walletNoun(t, wire))
				if e != nil {
					t.Fatal(e)
				}
				noun, e := note.Noun()
				if e != nil || walletJam(t, noun) != wire {
					t.Fatal("complete note round trip", e)
				}
				request.Candidates = append(request.Candidates, note)
			}
			for _, o := range row.Outputs {
				request.Outputs = append(request.Outputs, output(o))
			}
			if row.Selection != nil {
				request.Selection = []NoteName{}
				for _, name := range row.Selection {
					request.Selection = append(request.Selection, decodeName(name))
				}
			}
			if row.ExactFee != nil {
				fee := walletNumber(t, *row.ExactFee)
				request.FeeNicks = &fee
			}
			if row.Sweep != nil {
				value := output(*row.Sweep)
				request.Sweep = &value
			}
			result, e := Plan(request, NewSigningKeyLockMatcher(walletDigest(t, row.Signer)))
			if e != nil {
				t.Fatal(e)
			}
			wire, e := result.Transaction.Jam()
			if e != nil || hex.EncodeToString(wire) != row.Jam {
				t.Fatal("planner transaction differs from Rust core", e)
			}
			if result.SelectedTotal != walletNumber(t, row.SelectedTotal) || result.FinalFee != walletNumber(t, row.Fee) || result.MinimumFee != walletNumber(t, row.MinimumFee) || result.WordCounts != (WordCountBreakdown{walletNumber(t, row.SeedWords), walletNumber(t, row.WitnessWords)}) {
				t.Fatal("planner result differs")
			}
			if len(result.Selected) != len(row.Selected) || len(result.Refunds) != len(row.Refunds) {
				t.Fatal("selected or refund count")
			}
			for i, note := range result.Selected {
				if note.Identity() != decodeName(row.Selected[i]) {
					t.Fatal("selection order")
				}
			}
			for i, refund := range result.Refunds {
				if refund.Name != decodeName(row.Refunds[i].Name) || refund.Amount != walletNumber(t, row.Refunds[i].Amount) {
					t.Fatal("refund")
				}
			}
		})
	}
}

type walletMigrationVector struct {
	Case, Seed, Height                                       string
	Signer                                                   []string
	Candidates                                               []string
	Parents                                                  [][]string
	Outputs                                                  []walletOutputVector
	Refund                                                   walletOutputVector
	Sweep                                                    *walletOutputVector
	Fee, MinimumFee, SeedWords, WitnessWords, Jam, SignedJam string
}

func TestRustMigrationOracle(t *testing.T) {
	output := func(v walletOutputVector) PlannedOutput {
		return PlannedOutput{walletDigest(t, v.Root), walletNoun(t, v.Data), walletNumber(t, v.Amount)}
	}
	for _, row := range loadWalletVectors(t).Migrations {
		t.Run(row.Case, func(t *testing.T) {
			chain := ChainContextAtHeight(walletNumber(t, row.Height))
			request := PlanRequest{Refund: output(row.Refund), Chain: &chain, Version: V0Only}
			notes := []NoteV0{}
			for i, wire := range row.Candidates {
				note, e := ParseNoteV0(walletNoun(t, wire))
				if e != nil {
					t.Fatal(e)
				}
				noun, e := note.Noun()
				if e != nil || walletJam(t, noun) != wire {
					t.Fatal("migration noun", e)
				}
				parent, e := note.Hash()
				if e != nil || parent != walletDigest(t, row.Parents[i]) {
					t.Fatal("migration parent", e)
				}
				notes = append(notes, note)
				request.Candidates = append(request.Candidates, note)
			}
			for _, o := range row.Outputs {
				request.Outputs = append(request.Outputs, output(o))
			}
			if row.Sweep != nil {
				value := output(*row.Sweep)
				request.Sweep = &value
			}
			result, e := Plan(request, NewSigningKeyLockMatcher(walletDigest(t, row.Signer)))
			if e != nil {
				t.Fatal(e)
			}
			wire, e := result.Transaction.Jam()
			if e != nil || hex.EncodeToString(wire) != row.Jam {
				t.Fatal("migration planner bytes", e)
			}
			if result.FinalFee != walletNumber(t, row.Fee) || result.MinimumFee != walletNumber(t, row.MinimumFee) || result.WordCounts != (WordCountBreakdown{walletNumber(t, row.SeedWords), walletNumber(t, row.WitnessWords)}) {
				t.Fatal("migration fee or words")
			}
			signed, e := result.Transaction.Sign(testKey(t, row.Seed))
			if e != nil {
				t.Fatal(e)
			}
			wire, e = signed.Jam()
			if e != nil || hex.EncodeToString(wire) != row.SignedJam {
				t.Fatal("migration signed bytes", e)
			}
			if e = signed.VerifySignatures(); e != nil {
				t.Fatal(e)
			}
			if e = signed.ValidateInputs(result.Selected, chain.Fees.Height); e != nil {
				t.Fatal(e)
			}
			if _, e := ParseTransactionV1(wire); e == nil {
				t.Fatal("migration inspection requires complete input")
			}
			parsed, e := ParseTransactionV1(wire, TransactionOptions{Fees: &chain.Fees, MigrationNotes: notes})
			if e != nil {
				t.Fatal(e)
			}
			if e = parsed.VerifySignatures(); e != nil {
				t.Fatal(e)
			}
			if e = parsed.ValidateInputs(result.Selected, chain.Fees.Height); e != nil {
				t.Fatal(e)
			}
			merged, e := parsed.MergeSignatures(signed)
			if e != nil {
				t.Fatal(e)
			}
			back, _ := merged.Jam()
			if !bytes.Equal(back, wire) {
				t.Fatal("migration merge bytes")
			}
			changed := make([]InputNote, len(result.Selected))
			for i, value := range result.Selected {
				note := value.(NoteV0)
				note.Source = Digest{1, 2, 3, 4, 5}
				changed[i] = note
			}
			if e = signed.ValidateInputs(changed, chain.Fees.Height); e == nil {
				t.Fatal("source mutation accepted")
			}
		})
	}
}

func TestWalletFeeAndBridgeBounds(t *testing.T) {
	maximum := ^uint64(0)
	p := DefaultFeeParameters()
	p.BaseFee = maximum
	p.MinFee = 0
	if got := ComputeMinimumFee(WordCountBreakdown{WitnessWords: 2}, p); got.MinimumFee != maximum/4 {
		t.Fatal("witness saturation before discount", got)
	}
	p.Height = 0
	if got := ComputeMinimumFee(WordCountBreakdown{SeedWords: 2}, p); got.MinimumFee != maximum {
		t.Fatal("pre-phase saturation", got)
	}
	if ComputeBridgeFee(65537, 7) != 14 || ComputeBridgeFee(0, maximum) != 0 || ComputeBridgeFee(maximum, maximum) != maximum {
		t.Fatal("bridge ceiling or saturation")
	}
	value := BridgeDepositDataPayload{}
	for i := range value.EVMAddress {
		value.EVMAddress[i] = 255
	}
	parsed, e := ParseBridgeDepositData(value.Noun())
	if e != nil || parsed != value {
		t.Fatal("160-bit EVM address", e)
	}
	oversized := Tuple(Noun{}, Noun{atom: 0x65736162}, Noun{}, Noun{}, Noun{atom: Prime - 1})
	if _, e := ParseBridgeDepositData(oversized); e == nil {
		t.Fatal("oversized EVM address")
	}
}
