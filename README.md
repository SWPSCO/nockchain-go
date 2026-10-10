# nockchain-go

Go helpers for Nockchain V1 wallets, receiving addresses, and signed transfers.
The package name is `nockchain`; Go 1.23 or newer is required.

```sh
go get github.com/yapishu/nockchain-go
```

## Generate or restore a wallet

```go
key, recovery, err := nockchain.GenerateWallet("") // optional BIP39 passphrase
if err != nil { return err }
// Store recovery.Words() in an offline backup before receiving funds.
zprv, err := key.Zprv() // private backup; never log
if err != nil { return err }
zpub, err := key.Zpub() // public receiving branch; privacy-sensitive
if err != nil { return err }
address, err := key.Address()
```

`RestoreWallet(phrase, passphrase)` validates an English BIP39 mnemonic and
recovers its master key. `GenerateMnemonic` creates a 24-word phrase;
`SeedFromMnemonic` accepts valid 12, 15, 18, 21, or 24-word phrases and applies
BIP39 Unicode normalization. A wrong passphrase creates a different valid wallet.

`GenerateSeed` creates a random 64-byte seed; `Seed.Key` derives its master key.
`Master` accepts an existing 64-byte seed. `Generate` creates a key directly.
Raw random seeds are backed up as seed bytes or a zprv; they have no recovery
phrase. Keys, seeds, and recovery phrases redact diagnostic formatting. Explicit
export methods return secrets that the caller must protect.

`ParseExtendedKey` accepts a zprv or zpub; `ParsePublicKey` accepts only a zpub.
`key.Derive("m/44'/0'/0'/9000")` follows a path relative to the supplied key.
`key.Public()` returns a key with private material removed. Give each application
a dedicated receiving branch and record its derivation path for recovery.

## Receive with a public extended key

```go
// Reserve this index durably before exposing the address.
receive, err := nockchain.DeriveReceiveAddress(zpub, 42)
if err != nil { return err }
// receive.Address is the sending wallet's destination.
// receive.LockRoot is the indexed single-signature output lock.
```

The helper derives a non-hardened child. The underlying operations are
`ParsePublicKey`, `Child`, `Address`, and `LockAddress`. Allocate indices durably,
never reuse them, and scan the same branch during recovery. A syntactically valid
address or lock root does not prove payment or finality.

## Prepare, review, and sign a transfer

```go
// Obtain notes from trusted chain state and select which ones to spend.
notes := []nockchain.UnspentNote{
    {Name: noteName, LockRoot: inputLock, Nicks: inputValue},
}
plan, err := nockchain.PrepareTransfer(key.Public(), notes,
    []nockchain.Payment{{Address: destination, Amount: "1.25"}},
    nockchain.TransferOptions{})
if err != nil { return err }
review := plan.Summary() // input, payment, fee, and change totals in nicks
// Present review and obtain the wallet user's authorization before signing.
tx, err := plan.Sign(key) // offline; requires the exact reviewed sender key
if err != nil { return err }
id, err := tx.ID()
if err != nil { return err }
wire, err := tx.Jam()
```

`PrepareTransfer` consumes every supplied note, combines repeated recipients,
calculates the minimum fee, and sends change to the sender unless `ChangeAddress`
is set. `FeeNicks` sets an explicit fee. Amount strings are exact native NOCK;
`1 NOCK = 65,536 nicks`. Inexact amounts are rejected. `Summary` returns a detached
copy, so editing it cannot change the signed plan. The library does not select
coins, fetch chain state, submit transactions, or broadcast payments.

`SignTransferV1` is the lower-level API for explicit per-input `SpendPlanV1`
values, fees, outputs, and change. It supports up to 64 inputs and 256 output
seeds, all authorized by one key with plain 1-of-1 PKH locks and full lock proofs.
It validates declared balances, input locks, duplicate notes/recipients, and
minimum fees. Callers establish that inputs exist, are unspent, and have reached
finality. Multisig, timelocks, arbitrary metadata, and bridge deposits are outside
this transfer builder's scope. Fee rules match the pinned Rust reference below;
applications must track network rule changes.

## Protocol primitives

- V1 Cheetah SLIP-10 master and child derivation, including hardened private paths.
- Strict extended-key parsing, checksums, canonical coordinates, and subgroup checks.
- `SignDigest` and `VerifyDigest` for deterministic Cheetah Schnorr signatures.
- TIP5 word/noun hashing, public-key hashes, and single-signature PKH lock roots.
- Immutable based nouns, `Jam`, and `Cue`, with bounded input and logical expansion.
  Atoms must be below the Goldilocks prime; this is not an arbitrary-atom codec.
- `ParseNocks` and `FormatNocks` for exact amounts. Base ERC-20 NOCK uses **16
  decimal places**, with different base units from native Nockchain nicks.

Private-key arithmetic is **variable-time**. Use offline, trusted wallet tooling,
outside request handlers and hostile shared environments. The package has no
independent cryptographic audit. See [SECURITY.md](SECURITY.md).

## Validation

```sh
go test -race ./...
go vet ./...
go test -run '^$' -fuzz FuzzParseExtendedKey -fuzztime 10s
go test -run '^$' -fuzz FuzzParseDigest -fuzztime 10s
go test -run '^$' -fuzz FuzzCue -fuzztime 10s
# Optional local wallet-export check; never commit this file:
NOCKCHAIN_TEST_KEY=/private/path/test.key go test -run TestLocalWalletExport
```

The public corpus contains 35 wallet vectors, 105 signature vectors, 13 TIP5
word vectors, seven noun hashes/encodings, and four signed V1 transactions.
Transaction tests compare complete encoded bytes, signatures, IDs, and minimum
fees against Rust, including multi-input payments, change, and output ordering.
The optional local test verifies a wallet export's phrase, zprv, zpub, address,
and signing without printing or committing its secret material.

Reference versions:

- [SWPSCO/tx-types](https://github.com/SWPSCO/tx-types), commit
  `5f9ab2b38f1685a908f19a0e8f18e7845b3e7f35`: Cheetah, TIP5, and noun trees/codecs.
- [SWPSCO/nockster](https://github.com/SWPSCO/nockster), commit
  `d62110560dd005827ae8a46126c9841c86db0d6a`: `nockster-core` wallet addresses,
  V1 transaction signing, IDs, and fee review.
- [Trezor python-mnemonic](https://github.com/trezor/python-mnemonic/blob/master/vectors.json):
  24 English BIP39 entropy, mnemonic, and seed vectors (`testdata/bip39.json`).

Regenerate Rust fixtures with:

```sh
python3 testdata/reference-generator/generate.py /path/to/tx-types /path/to/nockster
```

The generator requires Rust. Normal builds/tests use the Go toolchain and
checked-in fixtures. All published test seeds are public: **never fund their
addresses**.
