package nockchain

import (
	"bytes"
	"testing"
)

func plannerSetup(t *testing.T) (ExtendedKey, Digest, LockV1, PlannedOutput, PlannedOutput) {
	t.Helper()
	key := testKey(t, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f")
	pkh := publicKeyHash(key.pub)
	lock, e := NewPKHLockV1(1, []Digest{pkh}, nil)
	if e != nil {
		t.Fatal(e)
	}
	refund := PlannedOutput{lock.root, lock.Metadata(), 0}
	payment, e := PlannedPayment(Digest{7, 8, 9, 10, 11}, 1000000, false)
	if e != nil {
		t.Fatal(e)
	}
	return key, pkh, lock, refund, payment
}
func plannerNote(t *testing.T, amount, last, origin uint64, lock LockFormV1) NoteV1 {
	t.Helper()
	root, e := lock.Root()
	if e != nil {
		t.Fatal(e)
	}
	first, _ := NoteFirstV1(root)
	return NoteV1{origin, NoteName{first, Digest{last, 2, 3, 4, 5}}, lock.Metadata(), amount}
}
func TestPlannerSelectionAndPhase(t *testing.T) {
	key, pkh, lock, refund, payment := plannerSetup(t)
	notes := []InputNote{plannerNote(t, 2000000, 1, 100, lock), plannerNote(t, 4000000, 2, 100, lock)}
	chain := ChainContextAtHeight(54000)
	request := PlanRequest{Candidates: notes, Outputs: []PlannedOutput{payment}, Refund: refund, Chain: &chain}
	result, e := Plan(request, NewSigningKeyLockMatcher(pkh))
	if e != nil {
		t.Fatal(e)
	}
	if len(result.Selected) != 1 || result.Selected[0].Identity() != notes[1].Identity() {
		t.Fatal("selection")
	}
	total := result.FinalFee
	for _, output := range result.Outputs {
		total += output.Amount
	}
	if result.SelectedTotal != total {
		t.Fatal("conservation")
	}
	signed, e := result.Transaction.Sign(key)
	if e != nil {
		t.Fatal(e)
	}
	if e = signed.VerifySignatures(); e != nil {
		t.Fatal(e)
	}
	if e = signed.ValidateInputs(result.Selected, 54000); e != nil {
		t.Fatal(e)
	}
	wire, _ := signed.Jam()
	parsed, e := ParseTransactionV1(wire)
	if e != nil {
		t.Fatal(e)
	}
	back, _ := parsed.Jam()
	if !bytes.Equal(wire, back) {
		t.Fatal("wire")
	}
	fees := DefaultFeeParameters()
	fees.MinFee++
	alternate, e := ParseTransactionV1(wire, TransactionOptions{Fees: &fees})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := signed.MergeSignatures(alternate); e == nil {
		t.Fatal("different fee context merged")
	}
	before := ChainContextAtHeight(53999)
	request.Chain = &before
	prior, e := Plan(request, NewSigningKeyLockMatcher(pkh))
	if e != nil {
		t.Fatal(e)
	}
	summary, _ := prior.Transaction.Summary()
	if prior.MinimumFee <= result.MinimumFee || summary.Spends[0].Proof.Full {
		t.Fatal("fee phase")
	}
	request.Selection = []NoteName{notes[0].Identity(), notes[0].Identity()}
	if _, e := Plan(request, NewSigningKeyLockMatcher(pkh)); e == nil {
		t.Fatal("duplicate manual input")
	}
}
func TestPlannerHashlockTreeAndRefund(t *testing.T) {
	key, _, lock, _, payment := plannerSetup(t)
	claim, e := lock.WithHashlocks([]Digest{hashEach(Noun{atom: 42})})
	if e != nil {
		t.Fatal(e)
	}
	tree, e := NewLockTreeV1([]LockV1{claim, lock})
	if e != nil {
		t.Fatal(e)
	}
	root, _ := tree.Root()
	note := plannerNote(t, 8000000, 1, 100, tree)
	chain := ChainContextAtHeight(170000)
	request := PlanRequest{Candidates: []InputNote{note}, Outputs: []PlannedOutput{payment}, Refund: PlannedOutput{root, tree.Metadata(), 0}, Chain: &chain}
	matcher := LockRootLockMatcher{LockRoot: root, Lock: tree}
	if _, e := Plan(request, matcher); e == nil {
		t.Fatal("missing preimage")
	}
	matcher.Preimages = []Noun{{atom: 42}}
	result, e := Plan(request, matcher)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := result.Transaction.Sign(key)
	if e != nil {
		t.Fatal(e)
	}
	if e = signed.VerifySignatures(); e != nil {
		t.Fatal(e)
	}
	if e = signed.ValidateInputs(result.Selected, 170000); e != nil {
		t.Fatal(e)
	}
	wire, _ := signed.Jam()
	parsed, e := ParseTransactionV1(wire)
	if e != nil {
		t.Fatal(e)
	}
	back, _ := parsed.Jam()
	if !bytes.Equal(wire, back) {
		t.Fatal("wire")
	}
	summary, _ := parsed.Summary()
	if summary.Spends[0].Proof.Axis != 6 {
		t.Fatal("axis")
	}
	found := false
	for _, output := range summary.Spends[0].Outputs {
		if output.LockRoot == root {
			lock, e := output.Lock()
			if e != nil {
				t.Fatal(e)
			}
			if _, ok := lock.(LockTreeV1); !ok {
				t.Fatal("refund loses tree")
			}
			found = true
		}
	}
	if !found {
		t.Fatal("missing refund")
	}
	fees := DefaultFeeParameters()
	fees.MinFee++
	alternate, e := ParseTransactionV1(wire, TransactionOptions{Fees: &fees})
	if e != nil {
		t.Fatal(e)
	}
	if _, e := signed.MergeSignatures(alternate); e == nil {
		t.Fatal("different fee context merged")
	}
	before := ChainContextAtHeight(53999)
	request.Chain = &before
	if _, e := Plan(request, matcher); e == nil {
		t.Fatal("tree before activation")
	}
}
func TestPlannerFundMaturity(t *testing.T) {
	key, _, lock, refund, payment := plannerSetup(t)
	policy := FundLockPolicy{lock.root, Digest{99, 2, 3, 4, 5}, FundMaturityPolicy{170000, 100}}
	note := plannerNote(t, 5000000, 1, 169950, lock)
	note.Name.First = policy.FirstName
	chain := ChainContextAtHeight(169999)
	request := PlanRequest{Candidates: []InputNote{note}, Outputs: []PlannedOutput{payment}, Refund: refund, Chain: &chain}
	matcher := LockRootLockMatcher{LockRoot: lock.root, Lock: lock, FundPolicy: &policy}
	if _, e := Plan(request, matcher); e != nil {
		t.Fatal(e)
	}
	chain.Fees.Height = 170000
	if _, e := Plan(request, matcher); e != nil {
		t.Fatal("fee height changes fund maturity", e)
	}
	chain = ChainContextAtHeight(170000)
	chain.Fees.Height = 169999
	if _, e := Plan(request, matcher); e == nil {
		t.Fatal("immature fund")
	}
	chain = ChainContextAtHeight(170050)
	result, e := Plan(request, matcher)
	if e != nil {
		t.Fatal(e)
	}
	signed, e := result.Transaction.Sign(key)
	if e != nil {
		t.Fatal(e)
	}
	if e = signed.ValidateInputs([]InputNote{note}, 170050); e != nil {
		t.Fatal(e)
	}
	wire, _ := signed.Jam()
	if _, e := ParseTransactionV1(wire); e == nil {
		t.Fatal("unauthenticated fund identity")
	}
	parsed, e := ParseTransactionV1(wire, TransactionOptions{FundPolicy: &policy})
	if e != nil {
		t.Fatal(e)
	}
	if e = parsed.ValidateInputs([]InputNote{note}, 170050); e != nil {
		t.Fatal(e)
	}
	if !(FundMaturity{10, nil}).Admits(11) || (FundMaturity{10, bound(0)}).Admits(11) {
		t.Fatal("inactive versus active zero maturity")
	}
}
func TestPlannerSweep(t *testing.T) {
	_, pkh, lock, refund, payment := plannerSetup(t)
	notes := []InputNote{plannerNote(t, 3000000, 1, 100, lock), plannerNote(t, 4000000, 2, 100, lock)}
	chain := ChainContextAtHeight(54000)
	payment.Amount = 0
	result, e := Plan(PlanRequest{Candidates: notes, Refund: refund, Chain: &chain, Order: SelectionAscending, Sweep: &payment}, NewSigningKeyLockMatcher(pkh))
	if e != nil {
		t.Fatal(e)
	}
	if len(result.Selected) != 2 || result.Selected[0].Identity() != notes[0].Identity() || len(result.Refunds) != 0 {
		t.Fatal("sweep selection")
	}
	total := result.FinalFee
	for _, o := range result.Outputs {
		total += o.Amount
	}
	if total != 7000000 {
		t.Fatal("sweep conservation")
	}
	summary, _ := result.Transaction.Summary()
	for _, spend := range summary.Spends {
		if len(spend.Outputs) == 0 {
			t.Fatal("empty seed")
		}
	}
}
