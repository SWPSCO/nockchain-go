# Security

## Intended use

Online services accept a **dedicated V1 public extended key** through
`ParsePublicKey`, derive non-hardened children, and keep spending keys offline.
That parser rejects private extended keys, invalid checksums, unsupported
versions, noncanonical coordinates, points outside the curve's prime-order
subgroup, and inconsistent master metadata. Parsing is length-bounded.

Private key generation and derivation use variable-time arithmetic, including
`math/big` and scalar-dependent branches. They are for offline wallet tools and
tests. They are not constant-time primitives and must not be exposed as a
remote signing or key-derivation service. This package does not sign transactions.

`Zprv` deliberately exports secrets. Treat its result, seed input, and every
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

The test corpus establishes interoperability with pinned reference
implementations. It is not a substitute for an independent cryptographic audit.

## Reporting

Report suspected vulnerabilities privately to the repository owner through
GitHub's private vulnerability reporting when available, or an established
private contact. Do not include real seeds, private extended keys, API tokens,
or identifying wallet data in an issue or reproduction.
