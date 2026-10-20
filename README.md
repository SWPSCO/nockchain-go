# nockchain-go

Nockchain wallet planning and transaction tools in Go. Derive receiving addresses,
review transactions, prepare payments, and sign single-key or multisig spends.
Use the same package natively or through its WebAssembly adapter.

[![Go checks](https://github.com/SWPSCO/nockchain-go/actions/workflows/ci.yml/badge.svg)](https://github.com/SWPSCO/nockchain-go/actions/workflows/ci.yml)

The official upstream is [SWPSCO/nockchain-go](https://github.com/SWPSCO/nockchain-go).
Published versions and WebAssembly bundles are available in
[Releases](https://github.com/SWPSCO/nockchain-go/releases).

```sh
go get github.com/SWPSCO/nockchain-go@v0.2.0
```

Requires **Go 1.23+**. Import as `nockchain "github.com/SWPSCO/nockchain-go"`.
Private repository access requires authenticated Git and
`GOPRIVATE=github.com/SWPSCO/nockchain-go`.

## Capabilities

| Area | API |
| --- | --- |
| Wallets and recovery | `GenerateWallet`, `RestoreWallet`, `Master`, `ParseExtendedKey` |
| Public receiving branches | `ParsePublicKey`, `DeriveReceiveAddress` |
| Exact native NOCK amounts | `ParseNocks`, `FormatNocks` |
| Coin selection and change | `Plan`, `SelectTransfer`, `PrepareTransfer` |
| Lock policies and proofs | `NewPKHLockV1`, `NewLockTreeV1`, `BuildLockMerkleProof` |
| Metadata and bridge payloads | `NewNoteData`, `ParseNoteData`, `ComputeBridgeFee` |
| V0 migration | `ParseNoteV0`, `Plan` with `V0Only` |
| Transaction inspection | `ParseTransactionV1`, `Summary`, `ID` |
| Independent signing | `Sign`, `MergeSignatures`, `VerifySignatures` |
| Input records and height checks | `NoteV1.Hash`, `ValidateInputs` |
| Protocol primitives | Cheetah Schnorr, TIP5, immutable based nouns, `Jam`, `Cue` |
| JavaScript | [WebAssembly build, typed wrapper, and browser example](web/README.md) |

## Receive without a spending key

```go
// Reserve the index durably before giving its address to a payer.
receive, err := nockchain.DeriveReceiveAddress(zpub, 42)
if err != nil { return err }
// receive.Address is the wallet destination.
// receive.LockRoot is the indexed output lock.
```

Use a dedicated non-hardened public receiving branch. `ParsePublicKey` rejects
private extended keys; `key.Public()` removes private material. Derivation paths
are relative to the supplied key: `key.Derive("m/44'/0'/0'/9000")`. Store the branch
path and scan its allocated indices during recovery. A public extended key is
privacy-sensitive.

## Generate or recover a wallet

```go
key, recovery, err := nockchain.GenerateWallet("") // optional BIP39 passphrase
if err != nil { return err }
// Back up recovery.Words() privately before receiving funds. Never log it.
restored, err := nockchain.RestoreWallet(recovery.Words(), "")
if err != nil { return err }
_ = key
_ = restored
```

`GenerateWallet` creates a 24-word English mnemonic. Recovery accepts valid 12,
15, 18, 21, or 24-word phrases with BIP39 Unicode normalization. A wrong passphrase
produces a different valid wallet. `Zprv` explicitly exports spending authority;
`Zpub` exports a public branch. Diagnostic formatting redacts secrets.

For seed-based integrations, `GenerateSeed` creates 64 random bytes and `Master`
accepts an existing 64-byte seed. These seeds have no mnemonic unless derived
through `SeedFromMnemonic`; back them up as seed bytes or a zprv.

## Select coins, review, and sign

```go
// Each verifiedNote contains OriginPage, Name, complete NoteData, and Nicks.
notes := []nockchain.UnspentNote{{Note: verifiedNote, LockRoot: inputLock}}
plan, err := nockchain.SelectTransfer(key.Public(), notes,
    []nockchain.Payment{{Address: destination, Amount: "1.25"}},
    nockchain.TransferOptions{})
if err != nil { return err }
review := plan.Summary()
// Present review and obtain the wallet user's authorization before signing.
tx, err := plan.Sign(key)
if err != nil { return err }
wire, err := tx.Jam()
_ = review
_ = wire
```

`SelectTransfer` chooses a sufficient subset using largest amounts first with
stable note-name ordering. It ignores foreign locks and rejects malformed or
duplicate records. `PrepareTransfer` consumes all supplied notes. Both support
single-signature PKH inputs, merge repeated recipients, estimate fees, and return
change to the sender unless `ChangeAddress` is set. `FeeNicks` selects an explicit
fee. With automatic fees, a remainder too small to cover change metadata becomes
part of the fee; the review shows the exact amount.

`1 NOCK = 65,536 nicks`. Decimal payment strings are exact; inexact values are
rejected. Reviews and selected `Notes()` are detached copies. Low-level
`SignTransferV1` accepts explicit per-input `SpendPlanV1` allocations.

**Supply the complete input record.** Output parent commitments include the
note's version, origin, name, all metadata, and value. `NoteFirstV1(lockRoot)`
computes its lock-bound first name component; it does not establish that the note
exists. Decode metadata with `Cue` from the chain's based-noun encoding. Empty
metadata is the zero `Noun` only when the stored record is actually empty.

## Pure planning and lock policies

```go
payment, err := nockchain.PlannedPayment(recipientPKH, 1_000_000, false)
if err != nil { return err }
root, err := senderLock.Root()
if err != nil { return err }
chain := nockchain.ChainContextAtHeight(chainHeight)
result, err := nockchain.Plan(nockchain.PlanRequest{
    Candidates: verifiedNotes, // []nockchain.InputNote
    Outputs: []nockchain.PlannedOutput{payment},
    Refund: nockchain.PlannedOutput{LockRoot: root, NoteData: senderLock.Metadata()},
    Chain: &chain,
}, nockchain.NewSigningKeyLockMatcher(senderPKH))
if err != nil { return err }
// Review Transaction.Summary(), Selected, FinalFee, MinimumFee, Refunds, and WordCounts.
signed, err := result.Transaction.Sign(sender)
```

`Selection`, `Order`, `FeeNicks`, and `Sweep` in `PlanRequest` control selection
and allocation. `LockRootLockMatcher` supplies `Lock`, `LeafNumber`, `Preimages`,
and an optional `FundPolicy`. `NewLockTreeV1`, `LockMerkleProof`, and
`BuildLockMerkleProof` expose policies at the transaction boundary.

The pure planner selects eligible notes, reserves a positive seed for every
input, assigns payments and refunds, and solves the fee from the encoded
transaction. Selection sorts by amount and then Base58 note name. An explicit
selection requires every chosen note to be eligible. A sweep consumes all
eligible candidates into one destination. An exact fee remains visible in the
review even when it is below the required minimum; signing rejects an underfunded
transaction.

The signing-key matcher handles single-signature PKH policies and the coinbase
relative-age policy. The root matcher selects a specific leaf of a disclosed
lock, checks hashlock preimages, and can use an explicitly configured fund root,
authoritative first name, and maturity policy. Fund maturity uses the candidate
height. Fee parameters independently select the fee schedule; the height helper
sets both together. With no candidate height, timed and fund inputs are ineligible.

Lock trees contain up to 16 leaves and pad to a power of two with burn conditions.
Leaf numbers start at 1. Conditions support PKH, timelock, hashlock, and burn
primitives; a burn condition cannot be spent. Proofs preserve the outer tree tag,
axis, and sibling path. Before Bythos, ordinary inputs use single-leaf stub proofs;
at Bythos they use full proofs. Refund metadata preserves the entire chosen
output policy, including trees and custom entries.

## Metadata, bridge payloads, and V0 migration

`NoteData` provides canonical metadata maps, hashing, word counts, and typed
`LockData`, `BridgeDepositDataPayload`, and `BridgeWithdrawalDataPayload` values.
Deposit addresses are exactly 20 big-endian bytes. Unknown versions and networks
remain raw nouns. `ComputeBridgeFee` rounds up to whole NOCK before applying the
rate and saturates at uint64 limits. Construct an opaque `LockedPaymentV1` with
`LockRoot` and explicit `NoteData`; full lock forms disclose their metadata by
default. Ethereum transaction construction and submission belong to the caller.

`ParseNoteV0` reads complete V0 records, including public-key policy, source,
coinbase flag, and optional timelock. Set `Version: V0Only` in `PlanRequest` to
migrate those notes into V1 outputs. When parsing a migration transaction,
supply `TransactionOptions{MigrationNotes: verifiedV0Notes, Fees: &fees}` to
`ParseTransactionV1`; the wire witness does not contain the V0 input policy.
Parent validation commits to the complete supplied record. `V1Only` is the
default candidate policy; V0 and V1 candidates are selected separately.
`ParseNoteV1` and `NoteV1.Noun` round-trip complete V1 records.

## Multisig and timelocks

```go
minAge, maxHeight := uint64(10), uint64(500_000)
lock, err := nockchain.NewPKHLockV1(2, []nockchain.Digest{alicePKH, bobPKH, carolPKH},
    &nockchain.TimelockV1{
        Relative: nockchain.HeightRange{Min: &minAge},
        Absolute: nockchain.HeightRange{Max: &maxHeight},
    })
if err != nil { return err }
fee, err := nockchain.MinimumTransactionFeeV1(
    []nockchain.LockFormV1{lock}, []nockchain.LockFormV1{recipientLock})
if err != nil { return err }
plan, err := nockchain.PrepareTransactionV1([]nockchain.LockedSpendPlanV1{{
    Note: verifiedNote, Lock: lock, Fee: fee,
    Outputs: []nockchain.LockedPaymentV1{{Lock: recipientLock, Nicks: verifiedNote.Nicks-fee}},
}})
if err != nil { return err }
// Alice and Bob independently review the same plan.
a, err := plan.Sign(aliceKey)
if err != nil { return err }
b, err := plan.Sign(bobKey)
if err != nil { return err }
signed, err := a.MergeSignatures(b)
```

A lock supports up to 32 distinct keys and requires **exactly m signatures**.
Extra signatures are rejected. Height bounds are inclusive; nil endpoints are
unbounded. Relative bounds measure height minus the input's origin page.
Signing does not assert that a timelock is satisfied. `ValidateInputs` checks it
against the caller's authenticated records and chain height.

Partial signatures can travel as jam bytes and be parsed independently. Each
signature changes the transaction ID. Merging requires identical notes, locks,
outputs, and fees; conflicting signatures and altered plans are rejected.
See the [executable multisig example](transaction_example_test.go).

## Inspect and validate explicitly

```go
tx, err := nockchain.ParseTransactionV1(wire)
if err != nil { return err }
review, err := tx.Summary()
if err != nil { return err }
if err := tx.VerifySignatures(); err != nil { return err }
if err := tx.ValidateInputs(verifiedNotes, chainHeight); err != nil { return err }
_ = review
```

These operations establish different facts:

| Operation | Checks |
| --- | --- |
| `ParseTransactionV1` | Supported V1 structure, canonical trees, key encoding, lock proofs, and embedded ID |
| `Summary` | Committed outputs, fees, signature hashes, present signers, and fee estimate |
| `OutputV1.Lock` | Output lock metadata matches its committed root |
| `VerifySignatures` | Every signature, key authorization, exact required count, and minimum fee |
| `ValidateInputs` | Supplied input records, full parent hashes, balances, origin heights, and timelocks |

The application establishes input existence, unspent status, canonical chain,
and finality. The library neither fetches chain state nor broadcasts payments.

## Scope and limits

Transactions support V1 lock proofs and V0-to-V1 migration spends. Outputs have
unconstrained source fields. Limits are 64 inputs, 256 output seeds, 32 keys per
lock, 64 entries per metadata map, 2,048 flattened metadata words per output
lock, 65,536 logical transaction nodes, and depth 256.
These limits apply together.
Noun atoms must be below the Goldilocks prime. `Jam`/`Cue` are bounded based-noun
codecs, not arbitrary-precision Nock atom containers.

`FeeParameters` controls the phase height, base rate, witness divisor, and minimum.
At Bythos, metadata is merged per output lock and the witness discount applies.
Before Bythos, metadata is counted per seed and the base rate doubles.
The default fee context is height 54,000; pass `ChainContextAtHeight` or explicit
parameters for the chain being used. Conflicting metadata is rejected.
Base ERC-20 NOCK has **16 decimal places**; its units differ from native nicks.

Private-key arithmetic is **variable-time**. Use offline, trusted signing tools,
not remotely exposed signing services. No independent cryptographic audit is
claimed. See [SECURITY.md](SECURITY.md).

## Build and verify

```sh
go test -race ./...
go vet ./...
go test -run '^$' -fuzz FuzzParseTransactionV1 -fuzztime 10s -parallel 2
./scripts/build-wasm.sh
node web/test.mjs
```

CI checks Go 1.23 and the current stable toolchain, parser fuzz smoke tests, and
compiled WebAssembly. Public fixtures contain 35 wallet vectors, 105 signatures,
13 TIP5 word vectors, seven noun encodings, four single-key transactions, and two
2-of-3 transactions with partial signatures and optional timelocks. Tests compare
complete Rust bytes, IDs, signatures and lock roots. A separate Hoon oracle
checks the same transactions against the canonical engine for validity, input
commitments and minimum fees.

Wallet behavior is checked against the official Hoon source at
[`9bcc26c`](https://github.com/zorp-corp/nockchain/tree/9bcc26c6c57019dfde7f83aad9a9dd4ed5cd7902)
and the shared Rust wallet core at
[`02d1946`](https://github.com/SWPSCO/tx-types/tree/02d194605c475013745cc65b26f1413cd098932e).
The wallet corpus covers all 31 tagged lock leaves, metadata and bridge payloads,
phase-dependent fees, seven planner scenarios, and four V0 migration scenarios
with exact unsigned and signed bytes. Fixture files retain their source pins and
SHA-256 checksums. The Go repository contains the reproducible generators;
normal SDK tests use checked-in data and run offline.

```sh
python3 testdata/reference-generator/generate.py /path/to/tx-types /path/to/nockster
python3 testdata/consensus-generator/generate.py /path/to/nockchain
python3 testdata/wallet-generator/generate.py /path/to/tx-types --check --protocol-corpus testdata/reference.json
# Optional private wallet-export check; the file stays outside version control:
NOCKCHAIN_TEST_KEY=/private/path/test.key go test -run TestLocalWalletExport
```

Regenerating the consensus fixture requires Nockchain’s `hoon` executable.
Normal tests use checked-in fixtures and need no Hoon/Rust toolchain or network.
**Never send funds to public test-vector addresses.**

## Releases

Maintainers publish from `main` with an annotated semantic-version tag:

```sh
git tag -a vX.Y.Z -m 'nockchain-go vX.Y.Z'
git push origin vX.Y.Z
```

The release workflow runs the complete CI matrix before publishing. It verifies
that the tag belongs to `main`, builds and tests the WebAssembly adapter, and
attaches `nockchain-go-vX.Y.Z-wasm.tar.gz` and `SHA256SUMS` to the GitHub release.
The archive includes the matching Go runtime, JavaScript wrapper, type
declarations, browser example, and dependency licenses. Go consumers install
the tagged module directly; this library has no native command-line executable.

MIT licensed. See [LICENSE](LICENSE).
