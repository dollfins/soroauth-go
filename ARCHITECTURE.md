# Architecture

soroauth turns an unsigned `SorobanAuthorizationEntry` into a correctly signed
one. This document explains what that involves, how the pieces fit, and which
rules are protocol requirements rather than local choices.

If you are here to pick up an issue, read [CONTRIBUTING.md](CONTRIBUTING.md)
first for setup and the PR checklist. This file is the map.

Every Markdown file here is link-checked by the
[`links` workflow](.github/workflows/links.yml): internal links (between files
in this repository) gate a PR, external links are reported on the weekly
scheduled run and never block one.

## The problem

When a Soroban contract calls `require_auth()` on an address that is **not** the
transaction's source account, the transaction must carry a signed authorization
entry for that address. The entry has two halves:

```
SorobanAuthorizationEntry
├── credentials      who approves, plus nonce, expiration, and signature
└── rootInvocation   the call tree being approved
```

The signer never signs the entry. It signs `SHA-256(XDR(HashIdPreimage))`, and
**which preimage variant applies is decided by the credentials arm**:

| Credentials arm | Value | Preimage variant | Address in signed bytes |
|---|---|---|---|
| `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` | 0 | none — the envelope signature covers it | n/a |
| `SOROBAN_CREDENTIALS_ADDRESS` | 1 | `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` (9) | no |
| `SOROBAN_CREDENTIALS_ADDRESS_V2` | 2 | `..._WITH_ADDRESS` (10) | yes |
| `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` | 3 | `..._WITH_ADDRESS` (10), bound to the **top-level** address | yes |

Arms 1 is CAP-46-11. Arms 2 and 3 are CAP-71-01 and CAP-71-02.

## Signing flow

```
  simulateTransaction (record mode)
            │
            ▼
   unsigned entries ──► Preimage(entry, validUntil, passphrase)
                              │
                              ▼
                        HashIdPreimage
                              │  MarshalBinary
                              ▼
                        Payload() = SHA-256
                              │
                              ▼
                     Signer.Sign(ctx, preimage, payload) ──► ScVal
                              │
                              ▼
              AuthorizeEntry writes the ScVal onto every
              credential node whose address == target
                              │
                              ▼
  simulateTransaction (enforce mode) ──► assemble ──► sign envelope ──► submit
```

Two properties hold throughout and are the reason most of the code exists:

1. **The expiration signed over and the expiration stored must be identical.**
   `AuthorizeEntry` sets both from its `validUntilLedger` argument. If they ever
   diverge the entry looks complete and fails on-chain after fees.
2. **Caller input is never mutated.** Every function returning a modified entry
   deep-copies first via `internal/xdrcopy`, because the go-stellar-sdk XDR
   types are trees of pointers and slices.

## Envelopes

Callers hold transaction envelopes, not loose entries, so every entry-shaped
function has an envelope-shaped counterpart that finds the entries for them:
`EnvelopeEntries` and `InspectEnvelope` (read), `AuthorizeEnvelope` (sign),
`EnvelopePayloads` (what a signer would be approving). Each `EnvelopeEntry`
carries the operation index and entry index it came from, which is what a
caller needs to line a signed entry back up with.

An envelope with no `invokeHostFunction` operation is refused with
`ErrNoInvokeOperation`, never reported as an empty result: "nothing to
authorize" and "nothing I looked for" must not read the same. A fee-bump
envelope is read through to its inner transaction, because a fee-bump
transaction has no operations of its own and it is the inner transaction's
entries the host checks (CAP-15).

Signing entries changes what the transaction costs to run, so the envelope
assembled from the record-mode simulation carries too small a resource fee
and is rejected on-chain after fees are paid. Once the entries are signed the
caller must simulate again in **enforce** mode and submit what that pass
produced. soroauth does not run that pass — it belongs to the caller's
RPC client — and nothing here pretends otherwise; `adapters/walletsdk`
makes a wallet say so in code before it can obtain a submittable envelope.

## Package map

| File | Responsibility |
|---|---|
| `preimage.go` | `Preimage` (variant selection), `Payload` (SHA-256), and `addressCredentials`, the accessor every arm shares |
| `signer.go` | The `Signer` interface, `NewEd25519Signer`, `NewAccountMultiSigner`, `SignerFunc`, and the account signature `ScVal` shape |
| `authorize.go` | `AuthorizeEntry`, the credential-node walk, target matching, and the resign/expiration guards |
| `delegates.go` | `Delegate`, `WithDelegates`, `ValidateDelegateOrder` — the CAP-71-01 tree |
| `invocation.go` | `AuthorizeInvocation` and nonce generation |
| `upgrade.go` | `UpgradeToV2` |
| `verify.go` | `VerifyEntry` → `VerificationReport`: rebuilds the payload from an entry as it stands and decides each classic-account signature, reporting a per-node verdict (`verified`, `unsigned`, `invalid`, `cannot_check`) |
| `inspect.go` | `Inspect` → `EntryInfo`, structural reporting only |
| `batch.go` | `AuthorizeAll`, all-or-nothing |
| `envelope.go` | `EnvelopeEntries`, `InspectEnvelope`, `AuthorizeEnvelope`, `EnvelopePayloads` — the entry-shaped functions applied to a whole `TransactionEnvelope` |
| `expiration.go` | `ExpirationAfter` |
| `address.go` | `ParseAddress` / `FormatAddress` (G… and C… only) |
| `errors.go` | The eleven exported sentinels, plus the three typed address errors (`NoMatchingCredentialNodeError`, `DuplicateDelegateError`, `MissingSignerError`) that wrap them for `errors.As` |
| `internal/xdrcopy` | Deep copy by XDR round-trip |
| `cmd/soroauth` | CLI: `payload`, `sign`, `delegates`, `inspect`, `doctor`, `cross-compile`. `inspect`, `payload` and `sign` take a whole envelope as well as a single entry, and work out which they were handed |
| `remote/` | The HTTP signing protocol: `Request`/`Response`, a reference `Server`, and a client `Signer` that satisfies `soroauth.Signer`. Transmits the preimage, not just the digest; the server recomputes the digest and refuses a mismatch. The root module does not import it |
| `adapters/walletsdk` | A **separate Go module**: the wallet-SDK-shaped adapter. The root module does not import it, so no wallet SDK is a dependency of soroauth |

## Untrusted input

`Inspect` and the CLI are pointed at entries from elsewhere by design, so the
base64 decoder and every recursive walk over an entry are bounded on purpose.
`DecodeAuthorizationEntry` applies 64 levels of nesting and 1 MiB of decoded
input, and returns `ErrDecodeLimit` when either bites. `Inspect`,
`ValidateDelegateOrder`, the credential-node walk in
`AuthorizeEntry`, and `WithDelegates` refuse a tree nested past 64 levels for
the same reason. The values and their rationale live on the constants in
`decode.go`. This does not change any emitted bytes: the limits only bound what
the library is willing to read.

## The delegate model

Under CAP-71-01 an account may authenticate through delegated signers instead of
signing itself. The tree can nest arbitrarily:

```
account  (top-level, signature may be ScvVoid)
├── delegate A
│   └── delegate A1        ← nested, same payload
└── delegate B
```

**Every node signs the same payload**, bound to the *top-level* address. Three
consequences the code enforces:

- One address appearing at two depths is filled by a **single** `AuthorizeEntry`
  call, and both nodes receive byte-identical signatures.
- Once any node is signed the expiration is fixed; signing another node at a
  different `validUntilLedger` is refused.
- Each delegates array is sorted by the **XDR encoding** of the address and
  checked for duplicates within that level. Across levels, repeats are legal.

An unsigned node only fails if the account's `__check_auth` calls
`delegate_account_auth` for it — the host then passes that node's signature to
the delegate (CAP-71-01, *Semantics → `delegate_account_auth`*). The recommended
contract pattern delegates to every listed signer, so treat unsigned nodes as
failing unless you know the account's policy.

## Correctness model

soroauth is evidence-driven. Two independent gates:

**Golden vectors** — `testdata/vectors/*.json`, generated by
`testdata/gen/gen.mjs` against a pinned `@stellar/stellar-sdk@17.1.0`. For each
case `golden_test.go` asserts the preimage bytes, the payload hash, and the
final signed entry are byte-identical to the reference. Delegate vectors also
reproduce `WithDelegates` from the recorded *unsorted* input, so ordering is
proven rather than re-read. CI regenerates and fails on drift.

**Live testnet** — `e2e/` (build tag `e2e`) submits real transactions covering
all three arms, classic multisig, three contract fixtures (`modular-account`,
`session-keys`, `threshold-account`), and deliberate rejections that assert the
*specific* error: the host's for a refused signature, and the contract's own
code for an expired session key or an M-1 threshold. Results in
[e2e/RESULTS.md](e2e/RESULTS.md).

The rejection scenarios matter as much as the acceptances: they are what stop
the accepting scenarios from passing by accident. Two of them originally passed
while proving nothing, which is why every new failure test must assert *which*
failure.

The passkey path — browser ceremony, assertion verification, the challenge-binding
check, and which wallet contract a signature ScVal targets — has its own guide:
[docs/passkeys.md](docs/passkeys.md). Teams replacing hand-rolled signing code
have [docs/migrating.md](docs/migrating.md): pattern mappings, the four JS-SDK
differences, and the byte-identical verification step.

## Non-goals

soroauth is not a transaction builder, an RPC client, a key manager, or a
human-readable "what am I signing" explainer. It consumes go-stellar-sdk's
`txnbuild` and `clients/rpcclient` rather than wrapping them, and `Inspect`
reports structure only. `adapters/walletsdk` is the one place a wallet SDK is
named, and it is a module of its own so that importing soroauth never drags
one along.

## Extending it

- **New signer**: implement `Signer`. The `ScVal` you return is written verbatim.
- **Anything touching the wire format**: cite the CAP and ship a golden vector.
- **New rejection test**: assert the specific host error, not just failure.
