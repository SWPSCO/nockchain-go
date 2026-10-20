package nockchain

import (
	"errors"
	"sort"
)

type PlannedOutput struct {
	LockRoot Digest
	NoteData Noun
	Amount   uint64
}

func PlannedPayment(pkh Digest, amount uint64, private bool) (PlannedOutput, error) {
	lock, e := NewPKHLockV1(1, []Digest{pkh}, nil)
	if e != nil {
		return PlannedOutput{}, e
	}
	data := Noun{}
	if !private {
		data = lock.Metadata()
	}
	output := PlannedOutput{lock.root, data, amount}
	return normalizeOutput(output)
}
func normalizeOutput(output PlannedOutput) (PlannedOutput, error) {
	if !output.LockRoot.Valid() || output.Amount >= Prime {
		return output, errors.New("invalid planned output")
	}
	data, e := ParseNoteData(output.NoteData)
	if e != nil {
		return output, e
	}
	output.NoteData = data.Noun()
	return output, nil
}

type SelectionOrder string

const (
	SelectionDescending SelectionOrder = "descending"
	SelectionAscending  SelectionOrder = "ascending"
)

// PlanRequest contains complete verified candidates and pure planning policies.
// Nil Selection selects sufficient inputs; a non-nil slice selects exactly those names.
// Nil FeeNicks solves the minimum fee; a value records that exact fee for review.
type CandidateVersionPolicy int

const (
	V1Only CandidateVersionPolicy = iota
	V0Only
)

type PlanRequest struct {
	Version    CandidateVersionPolicy
	Candidates []InputNote
	Outputs    []PlannedOutput
	Refund     PlannedOutput
	Chain      *ChainContext
	Selection  []NoteName
	Order      SelectionOrder
	FeeNicks   *uint64
	Sweep      *PlannedOutput
}
type Refund struct {
	Name   NoteName
	Amount uint64
}
type PlanResult struct {
	Transaction          TransactionV1
	Selected             []InputNote
	SelectedTotal        uint64
	Outputs              []PlannedOutput
	Refunds              []Refund
	FinalFee, MinimumFee uint64
	WordCounts           WordCountBreakdown
}
type resolvedCandidate struct {
	note       InputNote
	resolution LockResolution
}

func mergePlanned(outputs *[]PlannedOutput, output PlannedOutput) error {
	if output.Amount == 0 {
		return nil
	}
	for i, old := range *outputs {
		if old.LockRoot == output.LockRoot {
			if !nounEqual(old.NoteData, output.NoteData) {
				return errors.New("conflicting note data for the same output lock")
			}
			amount, e := addAmount(old.Amount, output.Amount)
			if e != nil || amount >= Prime {
				return errors.New("output amount overflow")
			}
			(*outputs)[i].Amount = amount
			return nil
		}
	}
	*outputs = append(*outputs, output)
	return nil
}
func planningCandidates(request PlanRequest, matcher LockMatcher, chain ChainContext) ([]resolvedCandidate, error) {
	if matcher == nil {
		return nil, errors.New("missing lock matcher")
	}
	request.Candidates = append([]InputNote(nil), request.Candidates...)
	seen := map[NoteName]bool{}
	for i, note := range request.Candidates {
		value, e := snapshotInput(note)
		if e != nil {
			return nil, e
		}
		note = value
		request.Candidates[i] = value
		if _, e := note.Hash(); e != nil {
			return nil, e
		}
		if seen[note.Identity()] {
			return nil, errors.New("duplicate input note")
		}
		seen[note.Identity()] = true
	}
	manual := map[NoteName]bool{}
	for _, name := range request.Selection {
		if manual[name] || !seen[name] {
			return nil, errors.New("duplicate or missing manual input")
		}
		manual[name] = true
	}
	result := []resolvedCandidate{}
	for _, note := range request.Candidates {
		if request.Selection != nil && !manual[note.Identity()] {
			continue
		}
		var resolved *LockResolution
		var e error
		if (request.Version == V0Only) == (note.Version() == 0) {
			resolved, e = matcher.Resolve(note)
		}
		if e != nil {
			return nil, e
		}
		admitted := false
		if resolved != nil {
			admitted, e = resolved.Admits(note, chain.CandidateHeight)
			if e != nil {
				return nil, e
			}
			if form, ok := resolved.Lock.(LockFormV1); ok && chain.Fees.Height < chain.Fees.BythosPhase && len(form.lockLeaves()) > 1 {
				admitted = false
			}
		}
		if admitted {
			result = append(result, resolvedCandidate{note.snapshot(), *resolved})
		} else if request.Selection != nil {
			return nil, errors.New("manual input is not spendable")
		}
	}
	sort.Slice(result, func(i, j int) bool {
		a, b := result[i].note, result[j].note
		if a.Amount() != b.Amount() {
			if request.Order == SelectionAscending {
				return a.Amount() < b.Amount()
			}
			return a.Amount() > b.Amount()
		}
		if a.Identity().First != b.Identity().First {
			return a.Identity().First.String() < b.Identity().First.String()
		}
		return a.Identity().Last.String() < b.Identity().Last.String()
	})
	return result, nil
}
func assemblePlan(selected []resolvedCandidate, outputs []PlannedOutput, refund PlannedOutput, fee uint64, chain ChainContext) (PlanResult, error) {
	out := PlanResult{FinalFee: fee}
	if len(selected) < 1 || len(selected) > MaxTransferInputs {
		return out, errors.New("input count out of range")
	}
	total, payments := uint64(0), uint64(0)
	var e error
	for _, c := range selected {
		total, e = addAmount(total, c.note.Amount())
		if e != nil {
			return out, e
		}
	}
	for _, o := range outputs {
		payments, e = addAmount(payments, o.Amount)
		if e != nil {
			return out, e
		}
	}
	needed, e := addAmount(payments, fee)
	if e != nil {
		return out, e
	}
	if needed > total {
		return out, errors.New("insufficient funds")
	}
	if fee > total-uint64(len(selected)) {
		return out, errors.New("fee leaves an input without a positive seed")
	}
	remaining := make([]uint64, len(outputs))
	for i, o := range outputs {
		remaining[i] = o.Amount
	}
	remainingFee := fee
	plans := []LockedSpendPlanV1{}
	var fundPolicy *FundLockPolicy
	for _, c := range selected {
		note, resolved := c.note, c.resolution
		inputFee := min(remainingFee, note.Amount()-1)
		remainingFee -= inputFee
		capacity := note.Amount() - inputFee
		allocated := []PlannedOutput{}
		for i, o := range outputs {
			amount := min(capacity, remaining[i])
			if amount > 0 {
				o.Amount = amount
				if e := mergePlanned(&allocated, o); e != nil {
					return out, e
				}
				capacity -= amount
				remaining[i] -= amount
			}
		}
		if capacity > 0 {
			out.Refunds = append(out.Refunds, Refund{note.Identity(), capacity})
			r := refund
			r.Amount = capacity
			if e := mergePlanned(&allocated, r); e != nil {
				return out, e
			}
		}
		p := LockedSpendPlanV1{Note: note, Lock: resolved.Lock, LeafNumber: resolved.leaf(), Preimages: resolved.Preimages, Fee: inputFee}
		for _, o := range allocated {
			root, data := o.LockRoot, o.NoteData
			p.Outputs = append(p.Outputs, LockedPaymentV1{LockRoot: &root, NoteData: &data, Nicks: o.Amount})
			if e := mergePlanned(&out.Outputs, o); e != nil {
				return out, e
			}
		}
		plans = append(plans, p)
		if resolved.FundPolicy != nil {
			if fundPolicy != nil && *fundPolicy != *resolved.FundPolicy {
				return out, errors.New("conflicting fund policies")
			}
			value := *resolved.FundPolicy
			fundPolicy = &value
		}
		out.Selected = append(out.Selected, note)
	}
	if remainingFee != 0 {
		return out, errors.New("input allocation does not cover fee")
	}
	for _, value := range remaining {
		if value != 0 {
			return out, errors.New("input allocation does not cover payments")
		}
	}
	out.Transaction, e = prepareTransaction(plans, chain.Fees, fundPolicy, false)
	if e != nil {
		return out, e
	}
	noun, _ := out.Transaction.Noun()
	fields, _ := parts(noun, 3)
	out.WordCounts, e = TransactionWords(fields[2], chain.Fees.Height >= chain.Fees.BythosPhase, true)
	if e != nil {
		return out, e
	}
	summary, e := out.Transaction.Summary()
	if e != nil {
		return out, e
	}
	for _, c := range selected {
		if note, ok := c.note.(NoteV0); ok {
			out.WordCounts.WitnessWords += uint64(note.Lock.threshold) * 30
		}
	}
	out.MinimumFee = summary.MinimumFeeNicks
	out.SelectedTotal = total
	return out, nil
}

// Plan selects inputs, assigns every input's value, and solves the encoded minimum fee.
func Plan(request PlanRequest, matcher LockMatcher) (PlanResult, error) {
	if request.Version != V1Only && request.Version != V0Only {
		return PlanResult{}, errors.New("invalid candidate version")
	}
	chain := DefaultChainContext()
	if request.Chain != nil {
		chain = *request.Chain
	}
	if chain.CandidateHeight != nil && *chain.CandidateHeight >= Prime {
		return PlanResult{}, errors.New("invalid candidate height")
	}
	if request.Order != "" && request.Order != SelectionAscending && request.Order != SelectionDescending {
		return PlanResult{}, errors.New("invalid selection order")
	}
	if request.FeeNicks != nil && *request.FeeNicks >= Prime {
		return PlanResult{}, errors.New("fee exceeds field")
	}
	refund, e := normalizeOutput(request.Refund)
	if e != nil {
		return PlanResult{}, e
	}
	candidates, e := planningCandidates(request, matcher, chain)
	if e != nil {
		return PlanResult{}, e
	}
	if len(candidates) == 0 {
		return PlanResult{}, errors.New("no spendable inputs")
	}
	outputs := []PlannedOutput{}
	paymentTotal := uint64(0)
	for _, output := range request.Outputs {
		output, e = normalizeOutput(output)
		if e != nil {
			return PlanResult{}, e
		}
		if output.Amount == 0 {
			return PlanResult{}, errors.New("payment amount must be positive")
		}
		if e := mergePlanned(&outputs, output); e != nil {
			return PlanResult{}, e
		}
		paymentTotal, e = addAmount(paymentTotal, output.Amount)
		if e != nil {
			return PlanResult{}, e
		}
	}
	var sweep *PlannedOutput
	if request.Sweep != nil {
		value, e := normalizeOutput(*request.Sweep)
		if e != nil {
			return PlanResult{}, e
		}
		sweep = &value
		if len(outputs) > 0 {
			return PlanResult{}, errors.New("sweep has one planner-assigned destination")
		}
	} else if len(outputs) == 0 {
		return PlanResult{}, errors.New("at least one payment is required")
	}
	allInputs := sweep != nil || request.Selection != nil
	fee := chain.Fees.MinFee
	if request.FeeNicks != nil {
		fee = *request.FeeNicks
	}
	for round := 0; round < len(candidates)*2+8; round++ {
		needed, e := addAmount(paymentTotal, fee)
		if e != nil {
			return PlanResult{}, e
		}
		total := uint64(0)
		selected := []resolvedCandidate{}
		for _, c := range candidates {
			total, e = addAmount(total, c.note.Amount())
			if e != nil {
				return PlanResult{}, e
			}
			selected = append(selected, c)
			if !allInputs && total >= needed {
				break
			}
		}
		roundOutputs := append([]PlannedOutput(nil), outputs...)
		if sweep != nil {
			if total <= fee {
				return PlanResult{}, errors.New("balance does not cover the network fee")
			}
			value := *sweep
			value.Amount = total - fee
			roundOutputs = append(roundOutputs, value)
		}
		result, e := assemblePlan(selected, roundOutputs, refund, fee, chain)
		if e != nil {
			return PlanResult{}, e
		}
		if request.FeeNicks != nil || result.MinimumFee <= fee {
			return result, nil
		}
		if sweep == nil {
			remainder := total - paymentTotal
			if chain.Fees.MinFee <= remainder && remainder <= result.MinimumFee {
				exact, e := assemblePlan(selected, roundOutputs, refund, remainder, chain)
				if e == nil && exact.MinimumFee <= remainder {
					return exact, nil
				}
			}
		}
		fee = result.MinimumFee
	}
	return PlanResult{}, errors.New("network fee does not converge")
}
