package wasmapi

import (
	"encoding/hex"
	"errors"
	nockchain "github.com/SWPSCO/nockchain-go"
)

type feeParameters struct{ Height, BythosPhase, BaseFee, InputFeeDivisor, MinFee *string }

func (p feeParameters) decode() (nockchain.FeeParameters, error) {
	out := nockchain.DefaultFeeParameters()
	for _, entry := range []struct {
		source *string
		target *uint64
	}{{p.Height, &out.Height}, {p.BythosPhase, &out.BythosPhase}, {p.BaseFee, &out.BaseFee}, {p.InputFeeDivisor, &out.InputFeeDivisor}, {p.MinFee, &out.MinFee}} {
		if entry.source != nil {
			value, e := number(*entry.source)
			if e != nil {
				return out, e
			}
			*entry.target = value
		}
	}
	return out, nil
}

type fundPolicy struct{ LockRoot, FirstName, ActivationHeight, Minimum string }

func (p fundPolicy) decode() (nockchain.FundLockPolicy, error) {
	out := nockchain.FundLockPolicy{}
	var e error
	out.LockRoot, e = nockchain.ParseDigest(p.LockRoot)
	if e != nil {
		return out, e
	}
	out.FirstName, e = nockchain.ParseDigest(p.FirstName)
	if e != nil {
		return out, e
	}
	out.Maturity.ActivationHeight, e = number(p.ActivationHeight)
	if e != nil {
		return out, e
	}
	out.Maturity.Minimum, e = number(p.Minimum)
	return out, e
}
func decodeJam(s string) (nockchain.Noun, error) {
	if len(s) > 2<<20 {
		return nockchain.Noun{}, errors.New("noun hex exceeds adapter limit")
	}
	bytes, e := hex.DecodeString(s)
	if e != nil {
		return nockchain.Noun{}, e
	}
	return nockchain.Cue(bytes)
}
func decodePreimages(values []string) ([]nockchain.Noun, error) {
	out := []nockchain.Noun{}
	for _, wire := range values {
		noun, e := decodeJam(wire)
		if e != nil {
			return nil, e
		}
		out = append(out, noun)
	}
	return out, nil
}
func (r request) transactionOptions() (nockchain.TransactionOptions, error) {
	out := nockchain.TransactionOptions{}
	if r.Fees != nil {
		fees, e := r.Fees.decode()
		if e != nil {
			return out, e
		}
		out.Fees = &fees
	}
	if r.FundPolicy != nil {
		fund, e := r.FundPolicy.decode()
		if e != nil {
			return out, e
		}
		out.FundPolicy = &fund
	}
	for _, record := range r.Notes {
		if record.Jam != "" {
			value, e := record.decode()
			if e != nil {
				return out, e
			}
			if migration, ok := value.(nockchain.NoteV0); ok {
				out.MigrationNotes = append(out.MigrationNotes, migration)
			}
		}
	}
	return out, nil
}
func (o output) payment() (nockchain.LockedPaymentV1, error) {
	value := nockchain.LockedPaymentV1{}
	var e error
	value.Nicks, e = number(o.Nicks)
	if e != nil {
		return value, e
	}
	if o.LockRoot != "" {
		if o.Lock.specified() {
			return value, errors.New("choose an output lock or lock root")
		}
		root, e := nockchain.ParseDigest(o.LockRoot)
		if e != nil {
			return value, e
		}
		value.LockRoot = &root
	} else {
		value.Lock, e = o.Lock.decode()
		if e != nil {
			return value, e
		}
	}
	if o.NoteDataJam != nil {
		data, e := decodeJam(*o.NoteDataJam)
		if e != nil {
			return value, e
		}
		value.NoteData = &data
	}
	return value, nil
}
func (o output) planned() (nockchain.PlannedOutput, error) {
	payment, e := o.payment()
	if e != nil {
		return nockchain.PlannedOutput{}, e
	}
	value := nockchain.PlannedOutput{Amount: payment.Nicks}
	if payment.Lock != nil {
		value.LockRoot, e = payment.Lock.Root()
		if e != nil {
			return value, e
		}
		value.NoteData = payment.Lock.Metadata()
	} else {
		value.LockRoot = *payment.LockRoot
	}
	if payment.NoteData != nil {
		value.NoteData = *payment.NoteData
	}
	return value, nil
}

type noteName struct{ First, Last string }

func (n noteName) decode() (nockchain.NoteName, error) {
	first, e := nockchain.ParseDigest(n.First)
	if e != nil {
		return nockchain.NoteName{}, e
	}
	last, e := nockchain.ParseDigest(n.Last)
	return nockchain.NoteName{First: first, Last: last}, e
}

type planning struct {
	Outputs    []output
	Refund     output
	Sweep      *output
	Selection  []noteName
	Order      string
	FeeNicks   *string
	Version    *int
	SignerPKH  string
	LockRoot   string
	Lock       *lock
	LeafNumber int
	Preimages  []string
}

func (r request) plan(options nockchain.TransactionOptions) (any, error) {
	if r.Planning == nil {
		return nil, errors.New("planning request required")
	}
	p := r.Planning
	request := nockchain.PlanRequest{Order: nockchain.SelectionOrder(p.Order)}
	var e error
	chain := nockchain.DefaultChainContext()
	if r.Height != "" {
		height, e := number(r.Height)
		if e != nil {
			return nil, e
		}
		chain = nockchain.ChainContextAtHeight(height)
	}
	if options.Fees != nil {
		chain.Fees = *options.Fees
	}
	request.Chain = &chain
	if p.Version != nil {
		switch *p.Version {
		case 0:
			request.Version = nockchain.V0Only
		case 1:
			request.Version = nockchain.V1Only
		default:
			return nil, errors.New("invalid candidate version")
		}
	}
	for _, record := range r.Notes {
		note, e := record.decode()
		if e != nil {
			return nil, e
		}
		request.Candidates = append(request.Candidates, note)
	}
	for _, record := range p.Outputs {
		output, e := record.planned()
		if e != nil {
			return nil, e
		}
		request.Outputs = append(request.Outputs, output)
	}
	request.Refund, e = p.Refund.planned()
	if e != nil {
		return nil, e
	}
	if p.Sweep != nil {
		value, e := p.Sweep.planned()
		if e != nil {
			return nil, e
		}
		request.Sweep = &value
	}
	if p.Selection != nil {
		request.Selection = []nockchain.NoteName{}
		for _, value := range p.Selection {
			name, e := value.decode()
			if e != nil {
				return nil, e
			}
			request.Selection = append(request.Selection, name)
		}
	}
	if p.FeeNicks != nil {
		value, e := number(*p.FeeNicks)
		if e != nil {
			return nil, e
		}
		request.FeeNicks = &value
	}
	var matcher nockchain.LockMatcher
	if p.SignerPKH != "" {
		if p.LockRoot != "" || p.Lock != nil || len(p.Preimages) > 0 {
			return nil, errors.New("choose one lock matcher")
		}
		key, e := nockchain.ParseDigest(p.SignerPKH)
		if e != nil {
			return nil, e
		}
		matcher = nockchain.NewSigningKeyLockMatcher(key)
	} else {
		root, e := nockchain.ParseDigest(p.LockRoot)
		if e != nil {
			return nil, e
		}
		m := nockchain.LockRootLockMatcher{LockRoot: root, LeafNumber: p.LeafNumber, FundPolicy: options.FundPolicy}
		if p.Lock != nil {
			m.Lock, e = p.Lock.decode()
			if e != nil {
				return nil, e
			}
		}
		m.Preimages, e = decodePreimages(p.Preimages)
		if e != nil {
			return nil, e
		}
		matcher = m
	}
	result, e := nockchain.Plan(request, matcher)
	if e != nil {
		return nil, e
	}
	tx, e := wire(result.Transaction)
	if e != nil {
		return nil, e
	}
	selected := []any{}
	for _, note := range result.Selected {
		noun, e := note.Noun()
		if e != nil {
			return nil, e
		}
		encoded, e := nockchain.Jam(noun)
		if e != nil {
			return nil, e
		}
		selected = append(selected, map[string]any{"first": note.Identity().First.String(), "last": note.Identity().Last.String(), "jam": hex.EncodeToString(encoded)})
	}
	refunds := []any{}
	for _, refund := range result.Refunds {
		refunds = append(refunds, map[string]any{"first": refund.Name.First.String(), "last": refund.Name.Last.String(), "amount": decimal(refund.Amount)})
	}
	outputs := []any{}
	for _, output := range result.Outputs {
		jam, _ := nockchain.Jam(output.NoteData)
		outputs = append(outputs, map[string]any{"lockRoot": output.LockRoot.String(), "noteDataJam": hex.EncodeToString(jam), "nicks": decimal(output.Amount)})
	}
	return map[string]any{"transaction": tx, "selected": selected, "selectedTotal": decimal(result.SelectedTotal), "outputs": outputs, "refunds": refunds, "finalFee": decimal(result.FinalFee), "minimumFee": decimal(result.MinimumFee), "seedWords": decimal(result.WordCounts.SeedWords), "witnessWords": decimal(result.WordCounts.WitnessWords)}, nil
}
