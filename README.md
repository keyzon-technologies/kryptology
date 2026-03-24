# Kryptology — Keyzon Technologies Fork

> **Fork of [coinbase/kryptology](https://github.com/coinbase/kryptology)**
> The original library was archived by Coinbase and is no longer maintained.
> This fork is maintained by [Keyzon Technologies](https://github.com/keyzon-technologies) with focus on
> threshold signatures for Bitcoin, EVM, and Solana — without unnecessary dependencies.

## Scope

This fork is focused exclusively on cryptography for the following networks:

| Network | Curve | Protocol |
|---------|-------|----------|
| Bitcoin, EVM (Ethereum, Polygon…) | secp256k1 | Threshold ECDSA (DKLS19) |
| Solana, Liquid Network | Ed25519 | Threshold EdDSA (FROST) |
| P-256 | NIST P-256 | Standard ECDSA |

BLS12377, BLS12381, and all dependent packages (BLS signatures, BBS+, accumulators)
have been removed — they are not required by any of the target networks.

## What changed in this fork

### Go module

- Renamed from `github.com/coinbase/kryptology` to `github.com/keyzon-technologies/kryptology`.
- All internal imports updated.

### Removed

- GG20 protocol (deprecated by Coinbase).
- BLS12377 and BLS12381 curves and all sub-packages (`pkg/core/curves/native/bls12381/`).
- BLS signatures (`pkg/signatures/bls/`) and BBS+ signatures (`pkg/signatures/bbs/`).
- Cryptographic Accumulators (`pkg/accumulator/`) — depended on BLS12381.
- BLS variants of secret sharing (`pkg/sharing/v1/bls12381*`).
- `PairingScalar` and `PairingPoint` interfaces — no remaining implementations.

### DKLS19 v2 — [`pkg/tecdsa/dkls/v2`](pkg/tecdsa/dkls/v2)

Full implementation of the 2-of-2 threshold signature protocol based on
[[DKLS19]](https://eprint.iacr.org/2019/523.pdf), including DKG, Signing, and Key Refresh.
Improvements over DKLs18 (v1):

- **Nonce hash-binding**: `R = H(R') · D_B + R'` for a tighter UC proof.
- **Fiat–Shamir transcript** with domain separator `"DKLS19_*_v2"` preventing cross-version replay.
- **Gadget vector v2** with independent cSHAKE256 domain separator from v1.
- **Key Refresh** without changing the public key (invariant `sk_A' · sk_B' = sk_A · sk_B`).

#### Security and robustness fixes applied in this fork

| File | Issue | Fix |
|------|-------|-----|
| [`sign/multiply.go`](pkg/tecdsa/dkls/v2/sign/multiply.go) | Secret index `j` leaked in error message — side-channel | Generic error message without `j` |
| [`refresh/refresh.go`](pkg/tecdsa/dkls/v2/refresh/refresh.go) | Division/multiplication by multiplier `k=0` would crash or produce null share | `k.IsZero()` check before using `k` in Alice and Bob |
| [`serializers.go`](pkg/tecdsa/dkls/v2/serializers.go) | `registerCurveTypes()` called on every encode/decode | Refactored with `sync.Once` — registers exactly once |
| [`serializers.go`](pkg/tecdsa/dkls/v2/serializers.go) | `nil` payload passed to decoder produced opaque error | Explicit nil check with descriptive message |
| [`boilerplate.go`](pkg/tecdsa/dkls/v2/boilerplate.go) | `Result()` returned `(nil, nil)` when protocol incomplete — ambiguous | Returns explicit `error` with descriptive message |
| [`dkg/dkg.go`](pkg/tecdsa/dkls/v2/dkg/dkg.go) | `Output()` accessed `receiver.Output` without nil check → panic | Nil guard in `Output()` for `Alice` and `Bob` |
| [`refresh/refresh.go`](pkg/tecdsa/dkls/v2/refresh/refresh.go) | `Output()` accessed `receiver`/`sender` without nil check → panic | Nil guard in `Output()` for `Alice` and `Bob` |
| [`dkg/dkg.go`](pkg/tecdsa/dkls/v2/dkg/dkg.go), [`sign/sign.go`](pkg/tecdsa/dkls/v2/sign/sign.go), [`refresh/refresh.go`](pkg/tecdsa/dkls/v2/refresh/refresh.go) | `NewAlice`/`NewBob` constructors did not validate nil parameters → runtime panic | Nil checks in all constructors |

---

## Quickstart

```sh
go get github.com/keyzon-technologies/kryptology
```

## Documentation

```sh
godoc -http=:6060
# open: http://localhost:6060/pkg/github.com/keyzon-technologies/kryptology/
```

## Developer Setup

**Requirements**: `golang 1.17+`, `make`

```sh
git clone git@github.com:keyzon-technologies/kryptology.git && make
```

## Components

### Curves

Abstraction in [pkg/core/curves/curve.go](pkg/core/curves/curve.go).

| Curve | File | Used by |
|-------|------|---------|
| secp256k1 (K-256) | [k256_curve.go](pkg/core/curves/k256_curve.go) | Bitcoin, EVM |
| Ed25519 | [ed25519_curve.go](pkg/core/curves/ed25519_curve.go) | Solana, Liquid Network |
| NIST P-256 | [p256_curve.go](pkg/core/curves/p256_curve.go) | TLS, FIDO2 |
| Pallas | [pallas_curve.go](pkg/core/curves/pallas_curve.go) | Mina Protocol |

### Protocols

- Oblivious Transfer
  - [Verifiable Simplest OT](pkg/ot/base/simplest)
  - [KOS OT Extension](pkg/ot/extension/kos)
- Threshold ECDSA (secp256k1)
  - [DKLs18 — DKG and Signing](pkg/tecdsa/dkls/v1)
  - [DKLS19 — DKG, Signing and Key Refresh](pkg/tecdsa/dkls/v2) ← **primary**
- Threshold Schnorr / EdDSA (Ed25519)
  - [FROST — DKG](pkg/dkg/frost)
  - [FROST — Signing](pkg/ted25519/frost)
  - [tEd25519 — 2-of-2](pkg/ted25519/ted25519)
- [Bulletproof](pkg/bulletproof)
- [Paillier](pkg/paillier)
- Secret Sharing
  - [Shamir](pkg/sharing/v1/shamir.go)
  - [Pedersen](pkg/sharing/v1/pedersen.go)
  - [Feldman](pkg/sharing/v1/feldman.go)
- [Verifiable Encryption](pkg/verenc)
- [ZKP Schnorr](pkg/zkp/schnorr)

## References

- [[DKLS19] _Threshold ECDSA from ECDSA Assumptions: The Multiparty Case._](https://eprint.iacr.org/2019/523.pdf)
- [[specV5] _One Round Threshold ECDSA for Coinbase._](docs/Coinbase_Pseudocode_v5.pdf)
- [[EL20] _Eliding RSA Group Membership Checks._](docs/rsa-membership.pdf)
- [[P99] _Public-Key Cryptosystems Based on Composite Degree Residuosity Classes._](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf)
