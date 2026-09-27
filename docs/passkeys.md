# Signing with passkeys (WebAuthn): a guide

This walks through the full passkey flow — browser ceremony, assertion
transport, soroauth signing, submission — and names the checks that stop each
step from silently signing the wrong thing.

Read this together with the [README](../README.md) (two-pass simulation flow)
and [ARCHITECTURE.md](../ARCHITECTURE.md) (the signing flow and package map).
The passkey path touches three systems — an authenticator, a browser, and your
backend — and its failure modes are non-obvious, which is why this guide
exists.

## Status: what is proven and what is not

Be precise about this before you sign anything valuable:

| Piece | Evidence |
|---|---|
| Preimage, payload, ed25519 signing | Golden vectors (`testdata/vectors/`, byte-identical to `@stellar/stellar-sdk@17.1.0`) and live testnet scenarios (`e2e/RESULTS.md`). |
| WebAssembly signing core | The same golden vectors replayed through the wasm build (`make wasm-check`). |
| **The passkey signature shape in this guide** | **Nothing beyond this guide's example.** No golden vector from a passkey wallet library, no e2e scenario against a live host, no wallet contract tested against. See [Gaps](#gaps). |

The library itself is v0.1.0 and **unaudited**.

## Which wallet contract is the signature shape for?

Unlike a classic Stellar account — whose signature ScVal the host itself
defines (rs-soroban-env,
`soroban-env-host/src/builtin_contracts/account_contract.rs`,
`AccountEd25519Signature`) — a custom account contract's signature shape is
whatever its `__check_auth` says it is. There is no protocol-mandated passkey
shape.

The ScVal built in [Step 3](#step-3-sign-the-entry) targets the example wallet
contract defined at the end of this guide, and nothing else. This repository's
fixture contracts (`e2e/contracts/`) all use `type Signature = ()` — they
authenticate through CAP-71 delegates and decode no P-256 shape at all — so no
wallet contract in this repo has been tested with a passkey signature.
Prior art exists in the ecosystem (for example
[kalepail/passkey-kit](https://github.com/kalepail/passkey-kit), whose wallet
is a Soroban contract with its own signature format), but soroauth has not
been tested against it and this guide does not claim it. If your wallet
defines a different ScVal layout, keep everything else in this guide and swap
the shape.

## Background: what a passkey signature actually is

A WebAuthn assertion never signs an arbitrary payload. It signs exactly

```
authenticatorData || SHA-256(clientDataJSON)        (WebAuthn Level 3, §6.1)
```

with the credential's key — for passkeys, ES256: ECDSA over P-256 with SHA-256
(WebAuthn Level 3, §5.8.2, "Requirements for ES256"). Three consequences drive
everything below:

1. **The challenge is the only link to your transaction.** `clientDataJSON`
   carries the `challenge` the browser was given during the ceremony. If that
   challenge is not the 32-byte payload your entry commits to, the assertion
   proves nothing about your transaction — it was issued for some other
   ceremony and can be replayed against yours. This is the **challenge-binding
   check**, and it is the single most important line in this guide.
2. **The signature is over bytes your backend must reconstruct.** Getting the
   concatenation wrong produces signatures that fail everywhere, or worse,
   that verify against bytes you did not intend.
3. **The flags ride inside the signed bytes.** User presence (UP, bit 0) and
   user verification (UV, bit 2) live in `authenticatorData`'s flags byte,
   byte index 32 (WebAuthn Level 3, §6.1). A software authenticator can
   produce an assertion with neither set; a backend signing a payment should
   require both.

## The flow

```
  browser                                    backend
  ───────                                    ───────
  1. wasm core derives preimage + payload
     from the simulated entry
  2. navigator.credentials.get
     { challenge: payload }  ──── assertion ────►
                                             3. verify: challenge binding,
                                                UP/UV flags, ES256 signature
                                             4. soroauth: build the signature
                                                ScVal, AuthorizeEntry
                                             5. re-simulate (enforce mode),
                                                assemble, sign, submit ◄──┐
  ◄───────────────── UI: done ──────────────────────────────────────────┘
```

Steps 1–2 happen in the browser so it signs bytes it derived itself, instead
of trusting a server to hand over a payload. Steps 3–5 are ordinary backend
code.

### Why step 1 must run in the browser

If the server computes the payload and only asks the authenticator to sign
"whatever", the server chooses what is being approved and the browser ceremony
becomes a rubber stamp: a compromised or buggy server can obtain an assertion
for payload X and attach it to a transaction committing to payload Y. The
challenge-binding check alone does not close this — the browser has to be the
one that derives the payload from the entry it displays. That is what the
wasm core is for; see [Step 0](#step-0-the-browser-derives-the-payload).

## Step 0: the browser derives the payload

The unsigned entry comes from `simulateTransaction` in record mode, exactly as
in the README's Quickstart. In the browser, load the wasm core via
[`@soroauth/wasm`](../wasm/ts/README.md) and derive the bytes:

```ts
const { preimageXdr, payloadHex } = soroauth.preimage(
  entryBase64Xdr,
  validUntilLedger,
  networkPassphrase,
);
```

`payloadHex` is the 32-byte `SHA-256(HashIdPreimage)` the passkey will sign.
The browser should show the user what this entry does — that is the wallet's
job, not soroauth's — and then use the payload as the ceremony's challenge.
Keep the preimage around: a remote or reviewing signer approves the preimage,
not just the digest.

Two entry types have no payload:

- **Source-account entries** (`SOROBAN_CREDENTIALS_SOURCE_ACCOUNT`) are
  covered by the transaction envelope's own signature. soroauth's `preimage`
  fails loudly for them rather than returning empty success — drop them from
  the passkey flow entirely.
- If the entry is on the **delegates arm** (arm 3), the payload is bound to
  the *top-level* address, and every node in the tree signs the same payload.
  A passkey wallet can be a delegate like any other; nothing in the flow below
  changes except that you write the signature with `ForAddress(wallet)`, and
  the entry's expiration becomes fixed once any node is signed (README,
  "Delegates").

## Step 1: the browser ceremony

Illustrative (browser API, not compiled here):

```js
const challenge = Uint8Array.from(
  payloadHex.match(/../g).map((h) => parseInt(h, 16)),
);

const assertion = await navigator.credentials.get({
  publicKey: {
    challenge,                    // ← the payload itself, per this guide's scheme
    rpId: "wallet.example",
    allowCredentials: [{ type: "public-key", id: credentialId }],
    userVerification: "required", // ask the authenticator for UV
    timeout: 60_000,
  },
});
```

Posting `assertion` to the backend is the assertion transport. It is public
data — an assertion authenticates, it does not need to be kept secret — but it
is **single-use**: the host consumes the entry's nonce on-chain (CAP-71-01),
and your backend should refuse a reused challenge + nonce pair, since a replay
that raced a submission would otherwise be signed twice.

The scheme in this guide is **challenge = the 32-byte payload**. A wallet is
free to use a different challenge scheme — but then *the wallet's
`__check_auth`* must do the binding itself, because the generic check below
(“hash `clientDataJSON`, compare to the payload”) would not hold. Pick one and
be consistent between your ceremony and your contract.

## Step 2: receive and verify the assertion

The backend receives the assertion and verifies it before anything is signed.
The snippet below is extracted from compiled source in
`internal/readmesnippets/passkey.go` (`TestPasskeysGuideSnippetsMatchTheirSource`
fails if this guide drifts from it), with the assertion passed in as JSON:

```go
// The browser ceremony produced an assertion. Decode the fields WebAuthn
// defines and nothing else; ignore unknown keys rather than trusting them.
var assertion struct {
    Response struct {
        AuthenticatorData string `json:"authenticatorData"` // base64url, unpadded
        ClientDataJSON    string `json:"clientDataJSON"`    // base64url, unpadded
        Signature         string `json:"signature"`         // base64url, unpadded
    } `json:"response"`
}
if err := json.Unmarshal(assertionJSON, &assertion); err != nil {
    return nil, nil, fmt.Errorf("soroauth: decode assertion: %w", err)
}
rawAuthData, err := base64.RawURLEncoding.DecodeString(assertion.Response.AuthenticatorData)
if err != nil {
    return nil, nil, fmt.Errorf("soroauth: decode authenticatorData: %w", err)
}
rawClientData, err := base64.RawURLEncoding.DecodeString(assertion.Response.ClientDataJSON)
if err != nil {
    return nil, nil, fmt.Errorf("soroauth: decode clientDataJSON: %w", err)
}
rawSig, err := base64.RawURLEncoding.DecodeString(assertion.Response.Signature)
if err != nil {
    return nil, nil, fmt.Errorf("soroauth: decode signature: %w", err)
}
if len(rawAuthData) < 37 {
    return nil, nil, fmt.Errorf("soroauth: authenticatorData is %d bytes, need at least 37", len(rawAuthData))
}

// The challenge-binding check. The authenticator signed
// authenticatorData || SHA-256(clientDataJSON) (WebAuthn §6.1), and
// clientDataJSON carries the challenge the browser was given. If that
// challenge is not the payload this entry commits to, the assertion
// was issued for some other ceremony and proves nothing about this
// transaction — this is the check that stops a captured assertion from
// being replayed against a different payload. Hash the received
// clientDataJSON and compare against the payload being authorized;
// never read a challenge field out of the JSON and hash that instead,
// or an attacker who controls the JSON picks both sides of the compare.
clientDataHash := sha256.Sum256(rawClientData)
if !bytes.Equal(payload[:], clientDataHash[:]) {
    return nil, nil, soroauth.ErrSignatureMismatch
}

// User presence (UP, bit 0) and user verification (UV, bit 2) live in
// authenticatorData's flags byte, byte index 32 (WebAuthn §6.1). A
// software authenticator can produce an assertion with neither set, so
// anything that moves value should require both. NewPasskeySigner
// enforces the same bits again at Sign time; checking here fails before
// the signer is ever invoked.
flags := rawAuthData[32]
if flags&0x01 == 0 {
    return nil, nil, errors.New("soroauth: user presence (UP) not set in assertion")
}
if flags&0x04 == 0 {
    return nil, nil, errors.New("soroauth: user verification (UV) not set in assertion")
}
_ = rawSig // the DER-encoded assertion signature; see "Step 3"
```

The comparison direction is the subtle part. Hash the `clientDataJSON` you
**received** and compare against the payload you are authorizing. Never read a
`challenge` field out of the JSON and hash that instead: an attacker who
controls the JSON then controls both sides of the comparison, and the check
verifies nothing.

Also check what this snippet's narrow JSON decode deliberately does not:
`origin` inside `clientDataJSON` matches the origin the ceremony ran on, and
`type` is `"webauthn.get"`. Those are relying-party checks — they belong in
your backend because only it knows the expected origin (WebAuthn Level 3,
§7.2, "Verifying an authentication assertion").

## Step 3: sign the entry

The ES256 signature is over the signed bytes — `authenticatorData` followed by
`SHA-256(clientDataJSON)` — so verify it against exactly those bytes. The
assertion's `signature` field is DER-encoded; parse it at the WebAuthn
boundary, then use soroauth's P-256 primitives with the resulting raw `(r, s)`
values. `VerifySecp256r1` accepts the fixed-width low-S `r || s` form used by
the Soroban signature value.

```go
// The signature is over the signed bytes — authenticatorData followed by
// SHA-256(clientDataJSON) — not over the payload alone (WebAuthn §6.1).
clientDataHash := sha256.Sum256(clientDataJSON)
signed := append(append([]byte{}, authData...), clientDataHash[:]...)

// The credential public key captured when the passkey was registered;
// ES256 means P-256 (WebAuthn §5.8.2, "Requirements for ES256").
pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: pubX, Y: pubY}
r := new(big.Int).SetBytes(sigR[:])
s := new(big.Int).SetBytes(sigS[:])
if !ecdsa.Verify(pub, signed, r, s) {
    return xdr.SorobanAuthorizationEntry{}, soroauth.ErrSignatureMismatch
}

// The ScVal this guide's example wallet contract decodes in __check_auth.
// The map's keys are symbols in sorted order — the host refuses an
// unsorted ScMap as Error(Object, InvalidInput) (rs-soroban-env issue
// #1510 records how opaque that failure is) — so a hand-rolled shape
// fails there, on-chain, rather than here.
pubRaw := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
pubVal := xdr.ScBytes(pubRaw)
signature := make([]byte, soroauth.Secp256r1SignatureSize)
r.FillBytes(signature[:32])
s.FillBytes(signature[32:])
sigVal := xdr.ScBytes(signature)
keySym := xdr.ScSymbol("public_key")
sigSym := xdr.ScSymbol("signature")
m := xdr.ScMap{
    {Key: xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &keySym}, Val: xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &pubVal}},
    {Key: xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &sigSym}, Val: xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &sigVal}},
}
mapPtr := &m
sigScVal := xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &mapPtr}

// NewPasskeySigner re-checks UP and UV at Sign time and writes the ScVal
// onto every node whose address matches the wallet's.
signer := soroauth.NewPasskeySigner(walletAddress, authData,
    func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
        return sigScVal, nil
    },
    soroauth.RequireUserPresence(true),
    soroauth.RequireUserVerification(true),
)
return soroauth.AuthorizeEntry(ctx, entry, signer, validUntilLedger,
    networkPassphrase, soroauth.ForAddress(walletAddress))
```

What `NewPasskeySigner` does — and deliberately does not do — matters:

- **It checks the UP and UV flags** in the `authenticatorData` you pass it,
  and fails with `ErrVerificationFailed` before invoking your signing
  function if a required flag is missing.
- **It does no cryptographic verification.** The ES256 verification above is
  your responsibility; call `VerifySecp256r1` before returning the ScVal. If
  you skip it, `AuthorizeEntry` will happily write an unverified value into
  the entry — the failure then happens on-chain, after fees.
- **It does not define the ScVal shape.** The signing function you pass
  returns the `ScVal` verbatim; `SignerFunc`'s doc comment applies equally
  here.

`ForAddress(walletAddress)` is not decoration: `AuthorizeEntry` only ever
writes a signature onto nodes whose address equals the target (README,
"Differences from the JS SDK"), and a mismatch returns
`ErrNoMatchingCredentialNode` rather than signing something else.

## Step 4: enforce mode and submission

Signing changes what the transaction costs. A transaction assembled from the
record-mode simulation is rejected on resource fees after the signature is
already on it, so re-simulate in **enforce** mode with the signed entries,
re-assemble, sign the envelope with the payer's key, and submit. The README's
Quickstart and `adapters/walletsdk` document this in detail; the CLI path is
`soroauth sign --entry <base64> --valid-until <n> --network testnet
--secret-env SEED --for <wallet C… address>`, passing the signature the same
way (`--assertion` from a file or stdin was reverted in
a0fc6ce and lands with issues #25/#26 — see [Gaps](#gaps)).

Before submitting, `soroauth inspect --entry <base64>` shows the credential
arm, nonce, expiration, and which nodes are signed — the cheapest check that
the entry you are about to pay fees on is the one you built.

## The example wallet contract's `__check_auth`

The ScVal built in Step 3 decodes against a wallet contract whose
`CustomAccountInterface` implementation reads:

```rust
type Signature = PasskeySig;   // #[contracttype]: { public_key: BytesN<33-ish>, signature: Bytes }
// __check_auth:
//   1. decode the map's two symbol-keyed entries ("public_key" before "signature";
//      the host rejects unsorted ScMaps, so a hand-built shape fails here, on-chain)
//   2. recompute authenticatorData || SHA-256(clientDataJSON) from the Context
//      data your contract design carries, and verify the ES256 signature over it
//      with the stored credential public key
//   3. fail closed on anything else
```

This guide does **not** ship that contract, and no contract with this shape
has been deployed or e2e-tested in this repository. If you write one, note two
protocol facts you will have to design around:

- `__check_auth` receives the payload hash and the contexts, **not** the
  assertion — your contract's design has to carry the bytes it wants to
  verify inside the signature ScVal itself (that is why the example shape
  includes the public key), or recompute them from the contexts.
- The host consumes the entry's nonce before `__check_auth` runs; replay
  protection across submissions is the host's job, but replay of an
  *assertion* within your backend is still yours (Step 2).

## Failure modes checklist

- **Challenge binding skipped** → a captured assertion authorizes a
  different transaction. The check in Step 2 is mandatory, and the browser
  must derive the payload (Step 0), or the check protects nothing.
- **Comparing against a challenge read from the JSON** → attacker-controlled
  on both sides. Hash the received `clientDataJSON`.
- **P-256 confusion**: ES256 is secp256r1 (P-256), not secp256k1. `crypto/ecdsa`
  with `elliptic.P256()`, not the curve the ed25519/`S…` world uses.
- **DER signature fed raw to `ecdsa.Verify`** → parse it (`ecdsa.ParseDERSignature`),
  or take `(r, s)` from a parser; issue #25 will ship one.
- **UP/UV not required for a payment flow** → a software authenticator can
  sign with neither. Require both for anything that moves value.
- **Unsorted ScMap keys** → `Error(Object, InvalidInput)` on-chain, opaque
  without host debug events (rs-soroban-env issue #1510). Build shapes with
  keys in sorted order and test them against `simulateTransaction` first.
- **Forgetting `ForAddress`** → a wallet's credential node carries the
  wallet's C… address; the target must match it or nothing is signed.
- **Skipping enforce mode** → the transaction fails on resource fees with the
  signature already attached. Always re-simulate.
- **Reusing an assertion** → the host consumes the nonce once; your backend
  should still refuse a reused challenge + nonce pair rather than rely on the
  chain to reject the second submission.

## Gaps

soroauth today gives you the payload bytes, the UP/UV guard, and the
entry-writing path. The pieces that would make this flow first-class are
tracked as issues:

- **#25 — parse WebAuthn assertions**: a dependency-free parser with distinct
  errors, including the DER signature and the challenge check. The Step 2
  snippet is the shape of that API.
- **#26 — a full `PasskeySigner`**: the signer described by the backlog —
  takes an assertion, self-verifies like `NewEd25519Signer` does, and targets
  a specific wallet contract's shape.
- **#27 — golden vectors from a real passkey wallet library**, so the ScVal
  shape is proven byte-for-byte rather than asserted in a guide.
- **#28 — a passkey e2e scenario on testnet**, which is the evidence table
  row this guide cannot yet cite.
- **#29 — CLI `--assertion`**: landed in ce2fc47 against an API that did not
  exist, reverted in a0fc6ce, and re-lands when #25 and #26 do.

Until then, this guide is the reference implementation, and its examples are
compiled from `internal/readmesnippets/passkey.go` so they cannot silently rot.

## References

- WebAuthn Level 3 (W3C): §6.1 (`authenticatorData`, flags byte at index 32,
  UP/UV bits), §5.8.2 (ES256 = ECDSA P-256 with SHA-256), §7.2 (verifying an
  authentication assertion).
- CAP-71-01 (address-bound credentials, nonce consumption, delegates),
  CAP-71-02 (delegated signers), CAP-46-11 (the credential framework).
- rs-soroban-env, `soroban-env-host/src/builtin_contracts/account_contract.rs`
  — the host-defined classic-account signature shape, for contrast with
  custom-account shapes; issue #1510 for the unsorted-ScMap failure mode.
- `wasm/ts/README.md` — the browser signing core and its typed wrapper.
- `docs/ISSUE_BACKLOG.md` §1 — the passkey signer backlog entry, including
  the UP/UV security note.
