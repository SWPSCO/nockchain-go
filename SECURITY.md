# Security

## Intended use

Online services accept a **dedicated V1 public extended key** through
`ParsePublicKey`, derive non-hardened children, and keep spending keys offline.
That parser rejects private extended keys, invalid checksums, unsupported
versions, noncanonical coordinates, points outside the curve's prime-order
subgroup, and inconsistent master metadata. Parsing is length-bounded.

Private key generation, derivation, and signing use variable-time arithmetic, including
`math/big` and scalar-dependent branches. They are for offline wallet tools and
tests. They are not constant-time primitives and must not be exposed as a
remote signing or key-derivation service.

`Zprv`, `RecoveryPhrase.Words`, and `Seed.Bytes` deliberately export secrets. Treat their results, seed input, and every
copy of a private key as spending authority. String formatting redacts key
material, but callers remain responsible for storage, logging, backups, and
access control. Go's allocator and garbage collector do not provide a guarantee
that all copies of secret material are erased.

A public extended key is privacy-sensitive. Sharing a non-hardened child private
key together with its parent extended public key can expose the parent private
key. Never export individual receiving private keys to untrusted parties.

Address allocation, recovery paths, payment attribution, canonical-chain checks,
confirmation policy, and transaction replay protection belong to the integrating
application. A syntactically valid address or lock root does not establish
ownership of a payment or its finality.

Transaction construction supports V1 condition trees and V0 migration inputs.
PKH policies require exactly m signatures; timelock and hashlock conditions must
also hold. Fund inputs require an explicit authoritative identity and maturity
policy. Parsing checks bounded structure and the embedded transaction ID;
signature and input-state checks are separate explicit methods. The caller
authenticates complete note records, unspent status, and finality against trusted
chain state. V0 migration parsing requires the complete input records.

Metadata is bounded and immutable. Output metadata authenticates a policy only
when its computed lock matches the committed root. Bridge payload codecs and
fee arithmetic do not establish cross-chain finality or submit Ethereum
transactions. This package does not provide full consensus validation or
transaction submission. Applications supply the correct fee and height context.

WebAssembly uses the same cryptographic implementation and retains its timing
and memory limitations. The JavaScript adapter represents uint64 amounts and
heights as strings to avoid precision loss. Use a trusted execution environment
for signing; a Worker isolates execution but does not make hostile page code safe.

The test corpus checks the canonical Nockchain Hoon engine and interoperability
with pinned Rust wallet implementations. It is not a substitute for an independent cryptographic audit.

## Reporting

Report suspected vulnerabilities privately to the repository owner through
GitHub's private vulnerability reporting when available, or an established
private contact. Do not include real seeds, private extended keys, API tokens,
or identifying wallet data in an issue or reproduction.
