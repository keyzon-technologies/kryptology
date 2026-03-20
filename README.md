# Kryptology — Keyzon Technologies Fork

> **Fork de [coinbase/kryptology](https://github.com/coinbase/kryptology)**
> A biblioteca original foi arquivada pela Coinbase e não é mais mantida por eles.
> Este fork é mantido pela [Keyzon Technologies](https://github.com/keyzon-technologies) com foco em
> produção da implementação DKLS19 (2-of-2 threshold ECDSA).

## O que mudou neste fork

### Renomeação e módulo Go

- Módulo renomeado de `github.com/coinbase/kryptology` para `github.com/keyzon-technologies/kryptology`.
- Todos os imports internos atualizados.
- O protocolo GG20 (deprecado) foi removido.

### DKLS19 v2 — [`pkg/tecdsa/dkls/v2`](pkg/tecdsa/dkls/v2)

Implementação completa do protocolo de assinatura threshold 2-of-2 baseado em
[[DKLS19]](https://eprint.iacr.org/2019/523.pdf), incluindo DKG, Signing e Key Refresh.
Melhorias em relação ao DKLs18 (v1):

- **Hash-binding de nonce**: `R = H(R') · D_B + R'` para prova UC mais apertada.
- **Transcript Fiat–Shamir** com domain separator `"DKLS19_*_v2"` prevenindo replay entre versões.
- **Gadget vector v2** com domain separator cSHAKE256 independente do v1.
- **Key Refresh** sem alteração da chave pública (invariante `sk_A' · sk_B' = sk_A · sk_B`).

#### Correções de segurança e robustez aplicadas neste fork

| Arquivo | Problema | Correção |
|---------|----------|----------|
| [`sign/multiply.go`](pkg/tecdsa/dkls/v2/sign/multiply.go) | Índice secreto `j` vazava em mensagem de erro — side-channel | Mensagem de erro genérica sem `j` |
| [`refresh/refresh.go`](pkg/tecdsa/dkls/v2/refresh/refresh.go) | Divisão/multiplicação pelo multiplicador `k=0` causaria crash ou share nula | Verificação `k.IsZero()` antes de usar `k` em Alice e Bob |
| [`serializers.go`](pkg/tecdsa/dkls/v2/serializers.go) | `registerCurveTypes()` chamada em cada encode/decode | Refatorado com `sync.Once` — registra exatamente uma vez |
| [`serializers.go`](pkg/tecdsa/dkls/v2/serializers.go) | Payload `nil` passado ao decoder gerava erro opaco | Nil check explícito com mensagem descritiva |
| [`boilerplate.go`](pkg/tecdsa/dkls/v2/boilerplate.go) | `Result()` retornava `(nil, nil)` quando protocolo incompleto — ambíguo | Retorna `error` explícito com mensagem descritiva |
| [`dkg/dkg.go`](pkg/tecdsa/dkls/v2/dkg/dkg.go) | `Output()` acessava `receiver.Output` sem checar nil → panic | Nil guard em `Output()` para `Alice` e `Bob` |
| [`refresh/refresh.go`](pkg/tecdsa/dkls/v2/refresh/refresh.go) | `Output()` acessava `receiver`/`sender` sem checar nil → panic | Nil guard em `Output()` para `Alice` e `Bob` |
| [`dkg/dkg.go`](pkg/tecdsa/dkls/v2/dkg/dkg.go), [`sign/sign.go`](pkg/tecdsa/dkls/v2/sign/sign.go), [`refresh/refresh.go`](pkg/tecdsa/dkls/v2/refresh/refresh.go) | Construtores `NewAlice`/`NewBob` não validavam parâmetros nil → panic em runtime | Nil checks em todos os construtores |

---

## Quickstart

```sh
go get github.com/keyzon-technologies/kryptology
```

## Documentação

```sh
godoc -http=:6060
# abra: http://localhost:6060/pkg/github.com/keyzon-technologies/kryptology/
```

## Developer Setup

**Pré-requisitos**: `golang 1.17+`, `make`

```sh
git clone git@github.com:keyzon-technologies/kryptology.git && make
```

## Componentes

### Curvas

Abstração em [pkg/core/curves/curve.go](pkg/core/curves/curve.go).

- [BLS12377](pkg/core/curves/bls12377_curve.go)
- [BLS12381](pkg/core/curves/bls12381_curve.go)
- [Ed25519](pkg/core/curves/ed25519_curve.go)
- [Secp256k1](pkg/core/curves/k256_curve.go)
- [P256](pkg/core/curves/p256_curve.go)
- [Pallas](pkg/core/curves/pallas_curve.go)

### Protocolos

- [Cryptographic Accumulators](pkg/accumulator)
- [Bulletproof](pkg/bulletproof)
- Oblivious Transfer
  - [Verifiable Simplest OT](pkg/ot/base/simplest)
  - [KOS OT Extension](pkg/ot/extension/kos)
- Threshold ECDSA
  - [DKLs18 — DKG e Signing](pkg/tecdsa/dkls/v1)
  - [DKLS19 — DKG, Signing e Key Refresh](pkg/tecdsa/dkls/v2)
- Threshold Schnorr
  - [FROST — DKG](pkg/dkg/frost)
  - [FROST — Signing](pkg/ted25519/frost)
- [Paillier](pkg/paillier)
- Secret Sharing
  - [Shamir](pkg/sharing/shamir.go)
  - [Pedersen](pkg/sharing/pedersen.go)
  - [Feldman](pkg/sharing/feldman.go)
- [Verifiable encryption](pkg/verenc)
- [ZKP Schnorr](pkg/zkp/schnorr)

## Referências

- [[DKLS19] _Threshold ECDSA from ECDSA Assumptions: The Multiparty Case._](https://eprint.iacr.org/2019/523.pdf)
- [[specV5] _One Round Threshold ECDSA for Coinbase._](docs/Coinbase_Pseudocode_v5.pdf)
- [[EL20] _Eliding RSA Group Membership Checks._](docs/rsa-membership.pdf)
- [[P99] _Public-Key Cryptosystems Based on Composite Degree Residuosity Classes._](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.112.4035&rep=rep1&type=pdf)
