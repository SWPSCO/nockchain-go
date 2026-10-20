// Package wasmapi implements the JSON boundary for the JavaScript WebAssembly adapter.
package wasmapi

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	nockchain "github.com/SWPSCO/nockchain-go"
)

type heightRange struct{ Min, Max *string }
type timelock struct{ Relative, Absolute heightRange }
type lock struct {
	Jam        string
	Conditions []lock
	Hashes     []string
	Burn       bool
	Threshold  int
	Keys       []string
	Timelock   *timelock
}
type note struct{ OriginPage, First, Last, NoteDataJam, Nicks, Jam string }
type output struct {
	LockRoot    string
	NoteDataJam *string
	Lock        lock
	Nicks       string
}
type spend struct {
	LeafNumber int
	Preimages  []string
	Note       note
	Lock       lock
	Outputs    []output
	Fee        string
}
type request struct {
	Fees        *feeParameters `json:"fees"`
	FundPolicy  *fundPolicy    `json:"fundPolicy"`
	Planning    *planning      `json:"planning"`
	Method      string         `json:"method"`
	Zpub        string         `json:"zpub"`
	Key         string         `json:"key"`
	Path        string         `json:"path"`
	Index       uint32         `json:"index"`
	Amount      string         `json:"amount"`
	Nicks       string         `json:"nicks"`
	Jam         string         `json:"jam"`
	OtherJam    string         `json:"otherJam"`
	Plans       []spend        `json:"plans"`
	Notes       []note         `json:"notes"`
	Height      string         `json:"height"`
	InputLocks  []lock         `json:"inputLocks"`
	OutputLocks []lock         `json:"outputLocks"`
}

func number(s string) (uint64, error) {
	n, e := strconv.ParseUint(s, 10, 64)
	if e != nil || strconv.FormatUint(n, 10) != s {
		return 0, errors.New("expected canonical decimal uint64 string")
	}
	return n, nil
}
func decimal(n uint64) string { return strconv.FormatUint(n, 10) }
func (r heightRange) decode() (nockchain.HeightRange, error) {
	out := nockchain.HeightRange{}
	for i, p := range []*string{r.Min, r.Max} {
		if p == nil {
			continue
		}
		v, e := number(*p)
		if e != nil {
			return out, e
		}
		if i == 0 {
			out.Min = &v
		} else {
			out.Max = &v
		}
	}
	return out, nil
}
func (l lock) specified() bool {
	return l.Jam != "" || len(l.Conditions) > 0 || l.Burn || l.Threshold != 0 || len(l.Keys) > 0 || len(l.Hashes) > 0 || l.Timelock != nil
}
func (l lock) decode() (nockchain.LockFormV1, error) {
	variants := 0
	for _, present := range []bool{l.Jam != "", len(l.Conditions) > 0, l.Burn, l.Threshold != 0 || len(l.Keys) > 0 || len(l.Hashes) > 0 || l.Timelock != nil} {
		if present {
			variants++
		}
	}
	if variants != 1 {
		return nil, errors.New("choose one lock representation")
	}
	if l.Jam != "" {
		noun, e := decodeJam(l.Jam)
		if e != nil {
			return nil, e
		}
		return nockchain.ParseLock(noun)
	}
	if len(l.Conditions) > 0 {
		conditions := []nockchain.LockV1{}
		for _, entry := range l.Conditions {
			form, e := entry.decode()
			if e != nil {
				return nil, e
			}
			condition, ok := form.(nockchain.LockV1)
			if !ok {
				return nil, errors.New("lock-tree children must be conditions")
			}
			conditions = append(conditions, condition)
		}
		return nockchain.NewLockTreeV1(conditions)
	}
	if l.Burn {
		return nockchain.BurnLockV1(), nil
	}
	hashes := []nockchain.Digest{}
	for _, text := range l.Hashes {
		hash, e := nockchain.ParseDigest(text)
		if e != nil {
			return nil, e
		}
		hashes = append(hashes, hash)
	}
	if len(l.Keys) == 0 && len(hashes) > 0 {
		if l.Timelock != nil || l.Threshold != 0 {
			return nil, errors.New("encode a general conjunctive condition as lock jam")
		}
		return nockchain.NewHashlockV1(hashes)
	}
	keys := make([]nockchain.Digest, len(l.Keys))
	for i, s := range l.Keys {
		d, e := nockchain.ParseDigest(s)
		if e != nil {
			return nockchain.LockV1{}, e
		}
		keys[i] = d
	}
	var tm *nockchain.TimelockV1
	if l.Timelock != nil {
		r, e := l.Timelock.Relative.decode()
		if e != nil {
			return nockchain.LockV1{}, e
		}
		a, e := l.Timelock.Absolute.decode()
		if e != nil {
			return nockchain.LockV1{}, e
		}
		tm = &nockchain.TimelockV1{Relative: r, Absolute: a}
	}
	value, e := nockchain.NewPKHLockV1(l.Threshold, keys, tm)
	if e != nil {
		return nil, e
	}
	if len(hashes) > 0 {
		return value.WithHashlocks(hashes)
	}
	return value, nil
}
func (n note) decode() (nockchain.InputNote, error) {
	if n.Jam != "" {
		if n.OriginPage != "" || n.First != "" || n.Last != "" || n.NoteDataJam != "" || n.Nicks != "" {
			return nil, errors.New("choose one complete note representation")
		}
		noun, e := decodeJam(n.Jam)
		if e != nil {
			return nil, e
		}
		head, _, ok := noun.AsCell()
		if !ok {
			return nil, errors.New("expected complete note record")
		}
		if version, ok := head.AsAtom(); ok && version == 1 {
			return nockchain.ParseNoteV1(noun)
		}
		return nockchain.ParseNoteV0(noun)
	}
	out := nockchain.NoteV1{}
	var e error
	out.OriginPage, e = number(n.OriginPage)
	if e != nil {
		return out, e
	}
	out.Nicks, e = number(n.Nicks)
	if e != nil {
		return out, e
	}
	out.Name.First, e = nockchain.ParseDigest(n.First)
	if e != nil {
		return out, e
	}
	out.Name.Last, e = nockchain.ParseDigest(n.Last)
	if e != nil {
		return out, e
	}
	b, e := hex.DecodeString(n.NoteDataJam)
	if e != nil {
		return out, e
	}
	out.NoteData, e = nockchain.Cue(b)
	if e != nil {
		return out, e
	}
	_, e = out.Hash()
	return out, e
}
func parseTx(s string, options nockchain.TransactionOptions) (nockchain.TransactionV1, error) {
	if len(s) > 2<<20 {
		return nockchain.TransactionV1{}, errors.New("transaction hex exceeds adapter limit")
	}
	b, e := hex.DecodeString(s)
	if e != nil {
		return nockchain.TransactionV1{}, e
	}
	return nockchain.ParseTransactionV1(b, options)
}
func encodeRange(r nockchain.HeightRange) map[string]any {
	out := map[string]any{"min": nil, "max": nil}
	if r.Min != nil {
		out["min"] = decimal(*r.Min)
	}
	if r.Max != nil {
		out["max"] = decimal(*r.Max)
	}
	return out
}
func encodeLock(form nockchain.InputLock) map[string]any {
	if lock, ok := form.(nockchain.LockV0); ok {
		root, _ := lock.Root()
		keys := []string{}
		for _, key := range lock.PublicKeys() {
			keys = append(keys, hex.EncodeToString(key))
		}
		return map[string]any{"version": 0, "root": root.String(), "threshold": lock.Threshold(), "publicKeys": keys}
	}
	if tree, ok := form.(nockchain.LockTreeV1); ok {
		root, _ := tree.Root()
		conditions := []any{}
		for _, condition := range tree.Conditions() {
			conditions = append(conditions, encodeLock(condition))
		}
		wire, _ := nockchain.Jam(tree.Noun())
		return map[string]any{"root": root.String(), "conditions": conditions, "lockJam": hex.EncodeToString(wire)}
	}
	l := form.(nockchain.LockV1)
	root, _ := l.Root()
	keys := []string{}
	for _, k := range l.Keys() {
		keys = append(keys, k.String())
	}
	wire, _ := nockchain.Jam(l.Noun())
	out := map[string]any{"root": root.String(), "threshold": l.Threshold(), "keys": keys, "timelock": nil, "lockJam": hex.EncodeToString(wire)}
	hashes := []string{}
	for _, hash := range l.Hashes() {
		hashes = append(hashes, hash.String())
	}
	times := []any{}
	for _, tm := range l.Timelocks() {
		times = append(times, map[string]any{"relative": encodeRange(tm.Relative), "absolute": encodeRange(tm.Absolute)})
	}
	out["hashes"], out["timelocks"], out["burn"] = hashes, times, l.IsBurn()
	if tm := l.Timelock(); tm != nil {
		out["timelock"] = map[string]any{"relative": encodeRange(tm.Relative), "absolute": encodeRange(tm.Absolute)}
	}
	return out
}
func review(tx nockchain.TransactionV1) (any, error) {
	s, e := tx.Summary()
	if e != nil {
		return nil, e
	}
	spends := []any{}
	for _, sp := range s.Spends {
		outputs := []any{}
		for _, o := range sp.Outputs {
			metadata, _ := nockchain.Jam(o.NoteData)
			item := map[string]any{"lockRoot": o.LockRoot.String(), "nicks": decimal(o.Nicks), "parentHash": o.ParentHash.String(), "noteDataJam": hex.EncodeToString(metadata), "lock": nil}
			if l, e := o.Lock(); e == nil {
				item["lock"] = encodeLock(l)
			}
			outputs = append(outputs, item)
		}
		signed := []string{}
		for _, k := range sp.SignedKeys {
			signed = append(signed, k.String())
		}
		var proofJam any
		if _, migration := sp.Lock.(nockchain.LockV0); !migration {
			proof, e := sp.Proof.Noun()
			if e != nil {
				return nil, e
			}
			proofWire, e := nockchain.Jam(proof)
			if e != nil {
				return nil, e
			}
			proofJam = hex.EncodeToString(proofWire)
		}
		spends = append(spends, map[string]any{"proofJam": proofJam, "first": sp.Name.First.String(), "last": sp.Name.Last.String(), "lock": encodeLock(sp.Lock), "fee": decimal(sp.Fee), "signatureHash": sp.SignatureHash.String(), "signedKeys": signed, "outputs": outputs})
	}
	return map[string]any{"id": s.ID.String(), "feeNicks": decimal(s.FeeNicks), "outputNicks": decimal(s.OutputNicks), "minimumFeeNicks": decimal(s.MinimumFeeNicks), "spends": spends}, nil
}
func wire(tx nockchain.TransactionV1) (any, error) {
	b, e := tx.Jam()
	if e != nil {
		return nil, e
	}
	s, e := review(tx)
	if e != nil {
		return nil, e
	}
	return map[string]any{"jam": hex.EncodeToString(b), "summary": s}, nil
}
func run(r request) (any, error) {
	options, e := r.transactionOptions()
	if e != nil {
		return nil, e
	}
	switch r.Method {
	case "plan":
		return r.plan(options)
	case "receive":
		a, e := nockchain.DeriveReceiveAddress(r.Zpub, r.Index)
		if e != nil {
			return nil, e
		}
		return map[string]any{"index": a.Index, "address": a.Address, "lockRoot": a.LockRoot}, nil
	case "derivePublic":
		k, e := nockchain.ParsePublicKey(r.Zpub)
		if e != nil {
			return nil, e
		}
		k, e = k.Derive(r.Path)
		if e != nil {
			return nil, e
		}
		z, _ := k.Zpub()
		a, _ := k.Address()
		l, _ := k.LockAddress()
		return map[string]any{"zpub": z, "address": a, "lockRoot": l}, nil
	case "parseNocks":
		n, e := nockchain.ParseNocks(r.Amount)
		if e != nil {
			return nil, e
		}
		return decimal(n), nil
	case "formatNocks":
		n, e := number(r.Nicks)
		if e != nil {
			return nil, e
		}
		return nockchain.FormatNocks(n), nil
	case "lock":
		if len(r.InputLocks) != 1 {
			return nil, errors.New("lock requires one inputLocks entry")
		}
		l, e := r.InputLocks[0].decode()
		if e != nil {
			return nil, e
		}
		out := encodeLock(l)
		root, _ := l.Root()
		first, _ := nockchain.NoteFirstV1(root)
		out["first"] = first.String()
		return out, nil
	case "minimumFee":
		var ins, outs []nockchain.LockFormV1
		for _, l := range r.InputLocks {
			v, e := l.decode()
			if e != nil {
				return nil, e
			}
			ins = append(ins, v)
		}
		for _, l := range r.OutputLocks {
			v, e := l.decode()
			if e != nil {
				return nil, e
			}
			outs = append(outs, v)
		}
		n, e := nockchain.MinimumTransactionFeeV1(ins, outs, options)
		if e != nil {
			return nil, e
		}
		return decimal(n), nil
	case "prepareTransaction":
		plans := make([]nockchain.LockedSpendPlanV1, len(r.Plans))
		for i, p := range r.Plans {
			n, e := p.Note.decode()
			if e != nil {
				return nil, e
			}
			var l nockchain.InputLock
			if migration, ok := n.(nockchain.NoteV0); ok {
				l = migration.Lock
			} else {
				l, e = p.Lock.decode()
				if e != nil {
					return nil, e
				}
			}
			fee, e := number(p.Fee)
			if e != nil {
				return nil, e
			}
			preimages, e := decodePreimages(p.Preimages)
			if e != nil {
				return nil, e
			}
			plans[i] = nockchain.LockedSpendPlanV1{Note: n, Lock: l, Fee: fee, LeafNumber: p.LeafNumber, Preimages: preimages}
			for _, o := range p.Outputs {
				payment, e := o.payment()
				if e != nil {
					return nil, e
				}
				plans[i].Outputs = append(plans[i].Outputs, payment)
			}
		}
		tx, e := nockchain.PrepareTransactionV1(plans, options)
		if e != nil {
			return nil, e
		}
		return wire(tx)
	case "inspect", "verifySignatures", "signTransaction", "mergeSignatures", "validateInputs":
		tx, e := parseTx(r.Jam, options)
		if e != nil {
			return nil, e
		}
		switch r.Method {
		case "inspect":
			return review(tx)
		case "verifySignatures":
			if e = tx.VerifySignatures(); e != nil {
				return nil, e
			}
			return true, nil
		case "signTransaction":
			key, e := nockchain.ParseExtendedKey(r.Key)
			if e != nil {
				return nil, e
			}
			tx, e = tx.Sign(key)
			if e != nil {
				return nil, e
			}
			return wire(tx)
		case "mergeSignatures":
			other, e := parseTx(r.OtherJam, options)
			if e != nil {
				return nil, e
			}
			tx, e = tx.MergeSignatures(other)
			if e != nil {
				return nil, e
			}
			return wire(tx)
		case "validateInputs":
			notes := make([]nockchain.InputNote, len(r.Notes))
			for i, n := range r.Notes {
				notes[i], e = n.decode()
				if e != nil {
					return nil, e
				}
			}
			height, e := number(r.Height)
			if e != nil {
				return nil, e
			}
			if e = tx.ValidateInputs(notes, height); e != nil {
				return nil, e
			}
			return true, nil
		}
	}
	return nil, errors.New("unknown method")
}

// Call handles one bounded request and returns an envelope. Amounts, heights,
// and digest limbs never pass through JavaScript floating-point numbers.
func Call(input string) string {
	if len(input) > 4<<20 {
		return `{"error":"request exceeds adapter limit"}`
	}
	d := json.NewDecoder(bytes.NewBufferString(input))
	d.DisallowUnknownFields()
	var r request
	if e := d.Decode(&r); e != nil {
		return `{"error":"invalid request JSON or fields"}`
	}
	if e := d.Decode(new(any)); e != io.EOF {
		return `{"error":"expected one JSON request"}`
	}
	result, e := run(r)
	var b []byte
	if e != nil {
		b, _ = json.Marshal(map[string]any{"error": e.Error()})
	} else {
		b, _ = json.Marshal(map[string]any{"result": result})
	}
	return string(b)
}
