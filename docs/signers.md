# Choosing a signer

The signer is the security boundary. `soroauth.Signer` only asks for an address and for a signature `ScVal`; the real difference between implementations is where the private key lives, what trust boundary the signer crosses, and what evidence the repository has for that path.

This repository ships several signer modes. They are all built on the same signing API, but they do not carry the same threat model or the same level of evidence.

## Short answer

- Use `NewEd25519Signer` for a single in-process key in tests, local tools, or a service that already owns the key.
- Use `NewAccountMultiSigner` for a classic Stellar account that requires multiple independent keys.
- Use `NewPasskeySigner` / `NewPasskeySignerFromAssertion` for a browser or WebAuthn-backed wallet contract whose signature shape is defined by that contract.
- Use `NewLedgerSigner`, `NewVaultSigner`, or the KMS adapters when the key must live outside the process.
- Use `remote.NewSigner` only behind authenticated, encrypted transport; the shipped example is intentionally a local reference, not production network security.
- Use `SignerFunc` only when a custom account's `__check_auth` requires a custom `ScVal` and you have reviewed that contract's layout.

## The shipped signer set

| Signer | Threat model it addresses | Evidence and caveats | Recommendation |
|---|---|---|---|
| `NewEd25519Signer` | In-process private key exposure; key compromise via process memory or local filesystem access | Golden vectors and live testnet scenarios prove the classic account shape and the signing flow on real networks | Best for a single key in a trusted process; still not a substitute for a security review |
| `NewAccountMultiSigner` | Single-key compromise on a classic account; threshold-style account policy | Unit-tested and live testnet scenario C proves a 2-of-2 threshold works | Good fit for classic accounts that require several independent keys |
| `NewPasskeySigner` / `NewPasskeySignerFromAssertion` | Browser- or authenticator-backed user signing; phishing and challenge-binding issues | Unit tests and passkey vector checks prove the built-in shape and challenge checks; live passkey scenario exists in e2e | Good for wallet UX and user-presence flows, but the contract must define and verify the exact signature shape |
| `NewLedgerSigner` | Host compromise or malware on the workstation; key stays in hardware | Unit tests cover the APDU protocol and signing checks; no live transaction proof in this repo | Good hardware-custody option when your operational flow is reviewed |
| `NewVaultSigner` | Private key exposure in a local process; keys live in Vault transit | Unit tests cover config validation, key lookup, payload mismatch and signature verification | Good for managed secret custody with Vault policy and rotation controls |
| `adapters/awskms` | Key material never leaves AWS KMS; app is a signer only | Unit-tested adapter; no live e2e proof in this repo | Good for AWS-hosted keys when your IAM, KMS policy, and key rotation are reviewed |
| `adapters/gcpkms` | Key material never leaves Google Cloud KMS; app is a signer only | Unit-tested adapter; no live e2e proof in this repo | Good for GCP-hosted keys when your KMS policy and operational controls are reviewed |
| `remote.NewSigner` | App/server separation; remote signing service handles private key material | Reference example and protocol tests exist; the shipped HTTP server is not production hardened | Only use behind authenticated TLS and an authority model you control |
| `SignerFunc` | Custom account signature rules; future or non-standard signers | No built-in verification; the caller owns the signature format | Only use when you have reviewed the contract and defined the exact `ScVal` format |

## Evidence and the production bar

This repository does not claim that any signer is audited. The library as a whole is still `v0.1.0` and `unaudited`. The ones with real live proof in this repo are the ones used in the live testnet scenarios and golden vectors:

- `NewEd25519Signer`
- `NewAccountMultiSigner`
- passkey signer path
- delegated-signer path

Those paths have direct live transaction evidence in `e2e/RESULTS.md` and corresponding golden-vector checks.

The hardware, remote, Vault, and cloud KMS signers are all well-tested in their own ways, but they are not all proven by the same live e2e path. In particular, do not recommend a signer for production use when the repository has no live e2e evidence for it; the right choice is to require your own operational review and a contract-specific verification path.

## Threat model by signer type

### 1. Single-key in-memory signing

`NewEd25519Signer` keeps the key in the process. This is the simplest model and the easiest to reason about, but it is also the easiest to compromise if the host is compromised or the application is misconfigured.

Use it when:

- the application already owns the signing secret;
- the process is trusted;
- the runtime is short-lived or tightly controlled.

Do not use it when:

- the secret must survive beyond the process boundary;
- you need operator approval or device-level custody;
- the key is not allowed to be extracted by a compromised host.

### 2. Multi-key classic accounts

`NewAccountMultiSigner` solves a different problem: a single compromised key should not grant access. A classic Stellar account can require several signatures and enforce ordering and caps exactly as the host expects.

Use it when:

- the account is a classic account with separate signing keys;
- your policy is threshold-based or separates operator roles;
- you need the host's ordering rules enforced in code.

The most important rule is that the host rejects unordered or duplicate vectors, and this library enforces that before the entry is submitted.

### 3. Passkeys and custom account contracts

A passkey signer is not a classic-account signer. A custom account decides what `ScVal` shape it accepts and what bytes it verifies. The passkey shape is therefore contract-specific, not protocol-defined.

Use it when:

- the account's `__check_auth` is a wallet contract that expects a WebAuthn/P-256 signature shape;
- the browser or authenticator is the trusted source of the challenge and signature;
- you have verified the contract's exact `ScVal` layout and challenge-binding rules.

This repository's passkey path has evidence for the wallet signature shape and for the challenge-binding logic, but it is still not a general-purpose approval layer for every custom wallet contract.

### 4. Hardware signing

`NewLedgerSigner` removes the seed from the host and asks the device to review and sign the payload. That materially reduces the risk of host compromise, but it shifts the trust model to the device, the user, and the wallet app's review flow.

Use it when:

- the operator is physically present or the device review is part of the control plane;
- you need the private key out of the application process from the start;
- your workflow accepts the extra operational steps and the device-specific failure modes.

### 5. Vault, KMS, and remote signers

Vault, AWS KMS, and GCP KMS all aim to keep the key material under somebody else's custody. That is valuable, but the trust boundary changes:

- Vault requires correct policy, token rotation, and key naming.
- AWS and GCP require IAM, key versioning, and key usage policies.
- A remote signer requires authenticated transport and a clear authorization model.

These signers are useful when company policy requires secrets to be outside the application runtime, but they are not magic. They still need operational reviews and contract-specific validation before production use.

## Do not use these as blanket recommendations

The following patterns are useful in local tests or in expert-controlled deployments, but they are not safe blanket recommendations for production without additional review:

- bare in-memory ed25519 keys in long-lived services;
- remote signers without authenticated TLS and explicit authorization;
- custom `SignerFunc` implementations whose format was never reviewed against the contract;
- any signer for which the repository has no live e2e proof and you cannot explain the operational control plane.

## Practical guidance

1. For a single app-owned account key, start with `NewEd25519Signer`.
2. For a classic account that uses multiple keys, use `NewAccountMultiSigner`.
3. For user-owned credentials, use a passkey signer bound to the wallet contract you actually deploy.
4. For operator-controlled custody, choose `NewLedgerSigner` or a KMS/Vault signer and keep the rest of the runtime minimal.
5. For service separation, use `remote.NewSigner` only behind authenticated transport and with a clear trust model for the remote signer.

## Status

All shipped signers are `unaudited` as part of this library's `v0.1.0` status. That is not a recommendation to avoid them; it is a reminder that the difference between a signer type and a safe production deployment is the operating model around the key, not just the Go implementation.
