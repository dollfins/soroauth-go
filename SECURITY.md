# Security policy

## Reporting a vulnerability

**Do not open a public issue.**

Report privately through GitHub Security Advisories:
[github.com/soroauth/soroauth-go/security/advisories/new](https://github.com/soroauth/soroauth-go/security/advisories/new).

Please include what you can: the affected version or commit, what an attacker
achieves, and a reproduction — a failing test, an entry that signs when it
should not, or a payload that differs from the reference implementation.

You will get an acknowledgement within a week. This is a small project with no
paid on-call, so that is a realistic commitment rather than an optimistic one.
If a fix is needed you will be credited in the advisory and the changelog unless
you ask otherwise.

## Context Cancellation Threat Model & Guarantees

**Threat Model:** 
Callers interacting with remote HSMs, hardware tokens, browser extensions, or custom signing RPC services rely on context cancellation and deadlines to bound latency and prevent goroutine or connection leaks. Without strict context propagation and early cancellation checks in `Signer.Sign`, a stalled remote peer, unresponsive hardware device, or slow network socket can hang client goroutines indefinitely.

**Guarantees:**
- Every in-tree signer (`NewEd25519Signer`, `NewAccountMultiSigner`, `NewPasskeySigner`, and `SignerFunc`) inspects `ctx.Done()` before invoking cryptographic signing or downstream callbacks, failing immediately with `context.Canceled` or `context.DeadlineExceeded` if the context is terminated.
- Remote or hardware signer implementations must explicitly document any underlying inability to abort ongoing hardware operations or network requests if cancellation cannot interrupt the physical device or socket.

## Scope

**Signature-correctness bugs are critical.** Anything in these categories should
be reported privately rather than filed publicly:

- A signature produced over the wrong payload: wrong preimage variant, wrong
  network id, wrong nonce, wrong expiration, or an address bound in that is not
  the one the caller named.
- A signature written onto a credential node other than the intended target, or
  onto a node whose address does not match.
- An entry accepted for signing that should have been refused — an
  already-signed node silently overwritten, a delegates array accepted
  out of order or with duplicates, an expiration that disagrees with signatures
  already on the entry.
- Any way to make the library emit an entry whose stored expiration differs from
  the expiration that was signed over.
- A secret reaching stdout, stderr, an error message, a log, or disk. The CLI
  accepts seeds only through a named environment variable and must never print
  one, including on error paths.
- Divergence from the golden vectors that is not a bug in the vectors.

### Remote Signer Retries and Threat Model

When using remote signers via `WithRetry`, the library provides jittered exponential backoff and attempt capping strictly for transient transport errors. Signature rejections (such as signature mismatches, invalid credentials, or explicit refusals) are never retried to prevent hiding real failures or exhausting HSM/KMS quotas.

**Threat model addressed:** Temporary network partitions, transient RPC/KMS downtime, and connection resets during remote signing.

**Explicitly not addressed:** Protection against compromised remote signers, malicious upstream KMS throttling due to high valid transaction volume, or side-channel leakage across retry attempts.

Lower severity, still worth reporting privately if you are unsure: panics
reachable from untrusted input, and denial of service through malformed XDR.

**Out of scope:** the fixture contract in `e2e/contracts/` is test code, not a
product — it has no admin functions, no upgradability and no policy engine by
design, and findings about those absences are not vulnerabilities. Weaknesses in
the Stellar protocol itself belong with the
[Stellar Development Foundation](https://github.com/stellar/stellar-protocol/blob/master/SECURITY.md),
not here.

## Status of this library

**v0.1.0, unaudited.** No third party has reviewed this code. It is proven
byte-for-byte against `@stellar/stellar-sdk@17.1.0` by nine golden vectors, and
proven against a live host by the testnet scenarios in
[e2e/RESULTS.md](e2e/RESULTS.md) — but agreeing with a reference implementation
and being accepted by a host are not the same thing as having been audited, and
neither rules out a class of bug that both implementations share.

Judge it accordingly before signing anything valuable with it, and read the code.

## Supported versions

Only the latest release receives fixes. At v0.1.0 that is the only release.

## Keys in this repository

Every keypair in `testdata/` is derived deterministically from a label committed
in plain text, so those keys are public and anyone can spend from them. They
exist to make signatures reproducible. Never fund them on mainnet. No key used
by the e2e tests is written to disk; they are generated per run and funded by
friendbot on testnet.