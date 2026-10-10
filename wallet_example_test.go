package nockchain_test

import (
	"fmt"
	nockchain "github.com/yapishu/nockchain-go"
)

func ExampleGenerateWallet() {
	key, recovery, err := nockchain.GenerateWallet("")
	if err != nil {
		panic(err)
	}
	// Back up recovery.Words() privately; do not log it.
	restored, err := nockchain.RestoreWallet(recovery.Words(), "")
	if err != nil {
		panic(err)
	}
	public, _ := key.Zpub()
	recoveredPublic, _ := restored.Zpub()
	fmt.Println(public == recoveredPublic)
	// Output: true
}

func ExampleDeriveReceiveAddress() {
	// Public fixture seed. Never send funds to this wallet.
	key, _ := nockchain.Master(make([]byte, 64))
	zpub, _ := key.Zpub()
	receive, err := nockchain.DeriveReceiveAddress(zpub, 42)
	if err != nil {
		panic(err)
	}
	fmt.Println(receive.Index, receive.Address != "", receive.LockRoot != "")
	// Output: 42 true true
}

func ExamplePrepareTransfer() {
	// Illustrative note data; the application obtains verified notes from chain state.
	key, _ := nockchain.Master(make([]byte, 64))
	address, _ := key.Address()
	pkh, _ := nockchain.ParseDigest(address)
	lock, _ := nockchain.LockRoot(pkh)
	notes := []nockchain.UnspentNote{{
		Name:     nockchain.NoteName{First: nockchain.Digest{1, 2, 3, 4, 5}, Last: nockchain.Digest{6, 7, 8, 9, 10}},
		LockRoot: lock, Nicks: 10_000_000,
	}}
	plan, err := nockchain.PrepareTransfer(key.Public(), notes,
		[]nockchain.Payment{{Address: address, Amount: "1.25"}}, nockchain.TransferOptions{})
	if err != nil {
		panic(err)
	}
	summary := plan.Summary()
	// Obtain authorization for this review before calling Sign in a real wallet.
	tx, err := plan.Sign(key)
	if err != nil {
		panic(err)
	}
	wire, err := tx.Jam()
	if err != nil {
		panic(err)
	}
	fmt.Println(summary.PaymentNicks, summary.FeeNicks, len(wire) > 0)
	// Output: 81920 458752 true
}
