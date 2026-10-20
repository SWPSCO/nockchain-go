package nockchain

import (
	"bytes"
	"errors"
)

// ReceiveAddress identifies a non-hardened child of a public receiving branch.
// Address is the wallet destination; LockRoot is its indexed output lock.
type ReceiveAddress struct {
	Index             uint32
	Address, LockRoot string
}

// DeriveReceiveAddress validates a zpub and derives the requested receiving
// child. Reserve the index durably before handing its address to a payer.
func DeriveReceiveAddress(zpub string, index uint32) (ReceiveAddress, error) {
	k, e := ParsePublicKey(zpub)
	if e != nil {
		return ReceiveAddress{}, e
	}
	child, e := k.Child(index)
	if e != nil {
		return ReceiveAddress{}, e
	}
	a, e := child.Address()
	if e != nil {
		return ReceiveAddress{}, e
	}
	lock, e := child.LockAddress()
	if e != nil {
		return ReceiveAddress{}, e
	}
	return ReceiveAddress{index, a, lock}, nil
}

// UnspentNote describes an input from a trusted chain-state source. The library
// does not establish that it exists, is unspent, or has reached finality.
type UnspentNote struct {
	Note     NoteV1
	LockRoot Digest
}

// Payment is a wallet address and exact decimal NOCK amount, such as "1.25".
type Payment struct{ Address, Amount string }

// TransferOptions controls explicit change and fees. Empty ChangeAddress sends
// change to the sender. FeeNicks=0 selects the minimum fee for the resulting plan.
type TransferOptions struct {
	Chain         *ChainContext
	ChangeAddress string
	FeeNicks      uint64
}

// TransferSummary is a detached review of a prepared payment. Amounts are nicks.
type TransferSummary struct {
	InputCount                                      int
	InputNicks, PaymentNicks, FeeNicks, ChangeNicks uint64
	ChangeAddress                                   string
	Payments                                        []Payment
}

// PreparedTransfer is an immutable, unsigned payment plan ready for review.
type PreparedTransfer struct {
	transaction TransactionV1
	notes       []NoteV1
	summary     TransferSummary
	public      []byte
}

// Summary returns a detached copy. Altering it cannot change the plan being signed.
func (p PreparedTransfer) Summary() TransferSummary {
	s := p.summary
	s.Payments = append([]Payment(nil), s.Payments...)
	return s
}

// Sign checks the signing key against the reviewed sender and signs the plan.
// Private-key arithmetic is variable-time; signing belongs in offline tooling.
func (p PreparedTransfer) Sign(key ExtendedKey) (TransferV1, error) {
	pub, e := key.PublicBytes()
	if e != nil || len(p.notes) == 0 || !bytes.Equal(pub, p.public) {
		return TransferV1{}, errors.New("signing key does not match prepared transfer")
	}
	tx, e := p.transaction.Sign(key)
	if e != nil {
		return TransferV1{}, e
	}
	return TransferV1{tx.raw, tx.id, true}, nil
}

// PrepareTransfer consumes all supplied notes, pays the requested recipients,
// computes fees, and adds explicit change. It accepts a public-only sender so
// review can happen separately from signing. Supply notes controlled by that
// exact key and verify chain state before calling this function. SelectTransfer
// selects a sufficient subset when consuming every note is unnecessary.
func PrepareTransfer(sender ExtendedKey, notes []UnspentNote, payments []Payment, options TransferOptions) (PreparedTransfer, error) {
	return prepareTransfer(sender, notes, payments, options, true)
}
func prepareTransfer(sender ExtendedKey, notes []UnspentNote, payments []Payment, options TransferOptions, manual bool) (PreparedTransfer, error) {
	if len(notes) == 0 || len(payments) == 0 || len(payments) > MaxTransferOutputs {
		return PreparedTransfer{}, errors.New("transfer size out of range")
	}
	public, e := sender.PublicBytes()
	if e != nil {
		return PreparedTransfer{}, e
	}
	address, e := sender.Address()
	if e != nil {
		return PreparedTransfer{}, e
	}
	pkh, _ := ParseDigest(address)
	change := options.ChangeAddress
	if change == "" {
		change = address
	}
	changePKH, e := ParseDigest(change)
	if e != nil {
		return PreparedTransfer{}, e
	}
	refund, e := PlannedPayment(changePKH, 0, false)
	if e != nil {
		return PreparedTransfer{}, e
	}
	request := PlanRequest{Refund: refund, Chain: options.Chain}
	if manual {
		request.Selection = make([]NoteName, 0, len(notes))
	}
	if options.FeeNicks != 0 {
		fee := options.FeeNicks
		request.FeeNicks = &fee
	}
	for _, unspent := range notes {
		bound, e := NoteFirstV1(unspent.LockRoot)
		if e != nil || bound != unspent.Note.Name.First {
			return PreparedTransfer{}, errors.New("input name does not bind supplied lock root")
		}
		request.Candidates = append(request.Candidates, unspent.Note)
		if manual {
			request.Selection = append(request.Selection, unspent.Note.Name)
		}
	}
	summary := TransferSummary{ChangeAddress: change}
	for _, payment := range payments {
		recipient, e := ParseDigest(payment.Address)
		if e != nil {
			return PreparedTransfer{}, e
		}
		amount, e := ParseNocks(payment.Amount)
		if e != nil || amount == 0 || amount >= Prime {
			return PreparedTransfer{}, errors.New("invalid payment amount")
		}
		output, e := PlannedPayment(recipient, amount, false)
		if e != nil {
			return PreparedTransfer{}, e
		}
		request.Outputs = append(request.Outputs, output)
		summary.PaymentNicks, e = addAmount(summary.PaymentNicks, amount)
		if e != nil {
			return PreparedTransfer{}, e
		}
		summary.Payments = append(summary.Payments, Payment{payment.Address, FormatNocks(amount)})
	}
	result, e := Plan(request, NewSigningKeyLockMatcher(pkh))
	if e != nil {
		return PreparedTransfer{}, e
	}
	if result.FinalFee < result.MinimumFee {
		return PreparedTransfer{}, errors.New("fee below minimum")
	}
	summary.InputCount = len(result.Selected)
	summary.InputNicks = result.SelectedTotal
	summary.FeeNicks = result.FinalFee
	for _, refund := range result.Refunds {
		summary.ChangeNicks += refund.Amount
	}
	selectedV1 := make([]NoteV1, len(result.Selected))
	for i, note := range result.Selected {
		selectedV1[i] = note.(NoteV1)
	}
	return PreparedTransfer{transaction: result.Transaction, notes: selectedV1, summary: summary, public: public}, nil
}
