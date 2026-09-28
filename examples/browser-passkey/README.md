# Browser demo: passkey → signed authorization entry → submitted transaction

A self-contained browser page that signs a Soroban authorization entry with a
WebAuthn passkey, deriving the payload **in the browser** with the
`@soroauth/wasm` signing core, submits the transaction to testnet, and prints
the transaction hash with an explorer link.

This exists so the passkey story has something you can actually run, instead of
a guide you have to translate into code yourself.

## What it does

1. Builds a native-XLM SAC `transfer` from the wallet contract to a destination
   you enter, and simulates it in **record** mode to obtain the unsigned
   authorization entry.
2. Loads `wasm/dist/soroauth.wasm` (built by `wasm/build.sh`) and calls
   `preimage(...)` to derive the `HashIdPreimage` and its 32-byte payload
   locally. No server is asked what to sign.
3. Registers a passkey if there is not one yet, then runs the assertion ceremony
   with **the payload as the WebAuthn challenge**.
4. Verifies the assertion before using it: challenge binding (the challenge in
   the received `clientDataJSON` must be an encoding of the payload — base64url
   with or without padding, standard base64, or hexadecimal), the UP/UV flags,
   and the ES256 signature over `authenticatorData || SHA-256(clientDataJSON)`.
   Comparing `SHA-256(clientDataJSON)` against the payload instead — which an
   earlier revision did, following an earlier revision of
   [`docs/passkeys.md`](../../docs/passkeys.md) — can never hold: the authenticator
   does not sign a hash of the client data as the challenge, it signs
   `authenticatorData || SHA-256(clientDataJSON)` and carries the challenge
   inside that JSON.
5. Builds the signature ScVal — `{ public_key, signature }` with the 65-byte
   uncompressed SEC1 key and the 64-byte `r || s` signature, the shape
   `soroauth.Secp256r1SignatureScVal` emits and the passkey golden vectors in
   `testdata/vectors/passkey` prove against `smart-account-kit` — and calls
   `writeSignature(...)`, which writes it only onto credential nodes whose
   address equals the wallet.
6. Rebuilds the transaction with the signed entry and simulates again in
   **enforce** mode. This pass is not optional: signing changes what the
   transaction costs, so a transaction assembled from the record-mode pass is
   rejected on resource fees *after* the signature is already attached.
7. Submits, polls `getTransaction`, and prints the hash, the ledger result and
   a `stellar.expert` link.

## Who pays the fee

A contract account (`C…`) cannot be a transaction source, so the authorization
entry exists precisely because the wallet authorizes a transaction somebody else
pays for. There is no way around needing a fee payer, so the page offers two:

- **A relayer URL** (preferred): the page POSTs the fully assembled,
  payer-unsigned transaction and the relayer adds the fee-payer signature and
  submits it. No secret ever enters the page. See [the relayer contract](#the-relayer-contract).
- **A testnet fee-payer secret** typed into the page: the self-contained path
  for trying it right now. It is held in memory for the single submission, never
  written to storage, never logged, and never sent anywhere but the signed
  transaction. Use a throwaway testnet key.

### The relayer contract

One endpoint, two fields:

```
POST <relayerUrl>
Content-Type: application/json

{ "transaction_xdr": "<base64 TransactionEnvelope, fee-payer-unsigned>" }

200 OK
{ "hash": "<transaction hash>" }
```

The relayer decodes the envelope, adds the fee-payer signature, calls
`sendTransaction`, and returns the hash. It is the same division of labour as
server-side relaying for a smart-wallet backend: the browser holds the passkey,
the backend holds the fee payer.

## How to run it

The page needs to fetch the WASM file, which a `file://` page usually cannot do,
and WebAuthn requires a secure context (`https://` or `http://localhost`). Build
the core and serve the repository over localhost:

```sh
./wasm/build.sh            # writes wasm/dist/soroauth.wasm + wasm_exec.js
python3 -m http.server 8000
```

Then open `http://localhost:8000/examples/browser-passkey/`.

You also need a **passkey wallet contract deployed on testnet** with a positive
XLM balance, whose `__check_auth` decodes the signature ScVal this page builds.
This demo does not deploy one, and the repository's own fixture contracts
(`e2e/contracts/`) all use `type Signature = ()` — they authenticate through
CAP-71 delegates and decode no P-256 shape — so none of them can be used here.

A passkey created for `localhost` is scoped to `localhost`, so the demo never
touches a real relying party.

## Verification status

**The page has not been run end to end, and cannot be in CI.** It needs a
browser, a platform authenticator, and a deployed passkey wallet contract on
testnet, none of which exist in the build environment.

What *is* checked is `app.test.mjs`, which runs in CI and locally
(`node examples/browser-passkey/app.test.mjs`, or `make demo-check` after
`cd testdata/gen && npm ci`): the SDK calls the flow makes, the credential-arm
walk, the explorer link, the DER-to-compact conversion, and the signature ScVal
shape, all against the same pinned `@stellar/stellar-sdk@17.1.0` the page loads.
It exists because it already caught real bugs that a browser would have shown
as, at best, an unexplained `TypeError`:

- the page was written against the 16.x XDR accessor methods
  (`entry.credentials()`, `credentials.switch().name`, `new xdr.ScSymbol(...)`,
  `new xdr.ScMap(...)`) while importing 17.1.0, whose bindings expose read-only
  properties, a `type` discriminant and factories that take plain values;
- it passed the raw 32-byte X coordinate as `public_key` while
  `Secp256r1SignatureScVal` and the passkey golden vectors both use the 65-byte
  uncompressed SEC1 key;
- its challenge-binding check compared `SHA-256(clientDataJSON)` against the
  payload, which can never hold. `verifyChallengeBinding` now matches the
  challenge string against the encodings of the payload, the way
  `WebAuthnAssertion.VerifyChallenge` does, and the check has cases for both
  accepted spellings and four rejections.

If you run the page and it fails past those checks, that is a bug report worth
filing — the parts that *are* proven (`preimage` and `writeSignature` against
the golden vectors and a live testnet scenario) live in the rest of this
repository, so a failure here most likely points at the ceremony or the wallet
contract, not the core.
