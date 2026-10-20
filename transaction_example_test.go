package nockchain_test

import (
	"fmt"
	nockchain "github.com/SWPSCO/nockchain-go"
)

func ExamplePrepareTransactionV1() {
	// Public fixture keys and illustrative notes. Never fund these addresses.
	alice, _ := nockchain.Master(make([]byte, 64))
	seed := make([]byte, 64)
	seed[0] = 1
	bob, _ := nockchain.Master(seed)
	a, _ := alice.Address()
	b, _ := bob.Address()
	ah, _ := nockchain.ParseDigest(a)
	bh, _ := nockchain.ParseDigest(b)
	lock, _ := nockchain.NewPKHLockV1(2, []nockchain.Digest{ah, bh}, nil)
	root, _ := lock.Root()
	first, _ := nockchain.NoteFirstV1(root)
	note := nockchain.NoteV1{
		OriginPage: 100,
		Name:       nockchain.NoteName{First: first, Last: nockchain.Digest{1, 2, 3, 4, 5}},
		Nicks:      10_000_000,
	}
	fee, _ := nockchain.MinimumTransactionFeeV1([]nockchain.LockFormV1{lock}, []nockchain.LockFormV1{lock})
	plan, err := nockchain.PrepareTransactionV1([]nockchain.LockedSpendPlanV1{{
		Note: note, Lock: lock, Fee: fee,
		Outputs: []nockchain.LockedPaymentV1{{Lock: lock, Nicks: note.Nicks - fee}},
	}})
	if err != nil {
		panic(err)
	}
	// Each signer independently reviews the same immutable plan before signing.
	signedByAlice, _ := plan.Sign(alice)
	signedByBob, _ := plan.Sign(bob)
	complete, err := signedByAlice.MergeSignatures(signedByBob)
	if err != nil {
		panic(err)
	}
	fmt.Println(complete.VerifySignatures() == nil)
	fmt.Println(complete.ValidateInputs([]nockchain.InputNote{note}, 105) == nil)
	// Output:
	// true
	// true
}
