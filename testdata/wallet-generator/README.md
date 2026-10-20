# Wallet reference generator

The generator uses the Rust core pinned at
`02d194605c475013745cc65b26f1413cd098932e` and Hoon fixtures pinned at
`9bcc26c6c57019dfde7f83aad9a9dd4ed5cd7902`.

```sh
python3 testdata/wallet-generator/generate.py ../tx-types
python3 testdata/wallet-generator/generate.py ../tx-types --check --protocol-corpus testdata/reference.json
```

The checkout must match the Rust pin. The script verifies the original Hoon
fixture checksums, then builds a temporary Rust exporter. No ship, signing
service, or private wallet data is used. All seeds are public test values.

`reference.json` includes canonical based-noun payload bytes and Hoon-produced
roots, proof hashes, admission verdicts, metadata hashes, word counts, and fees.
The Hoon wrapper labels can be larger than a field element, so the exporter
extracts payloads before handing them to SDK based-noun codecs. It also compares
canonical JAM for the complete original fixtures, stripping only the Hoon
exporter's terminal eight-byte-word zero padding.

Seven planner scenarios and four V0 migration scenarios run directly through
the Rust planner. They record selection, refunds, fee words, parent hashes, and
exact transaction bytes; migration scenarios also record deterministic signed
bytes. SDK tests consume these expected values without calculating their own
reference answers.

`--protocol-corpus testdata/reference.json` canonicalizes the existing crypto
and transaction corpus JAM fields with the same Rust encoder, retaining the
source pins for its other values. Without `--check`, both requested outputs are
written; with `--check`, the command verifies byte-identical wallet output and
canonical protocol data. Copy both JSON files and the official `.jam` files with
`SHA256SUMS` into the TypeScript and Python repositories after regeneration.
