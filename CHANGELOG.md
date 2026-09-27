# Changelog

All notable changes to this project are documented here:

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- `DescribeSignature` and `SignatureShape` report structural descriptions of uncheckable custom account signatures best-effort without upgrading them into verification verdicts. (#63)

- `VerifyAll` batch verification API with configurable concurrency (`WithConcurrency`), reporting per-entry verdicts without aborting the entire batch on individual entry failures. (#62)

- `payload`, `sign` and `delegates` accept `--entry -`, reading the entry from
  standard input, so the subcommands compose in a pipeline:

  ```sh
  soroauth delegates --entry entry.b64 --valid-until 1234567 --delegate GABC... | \
    soroauth sign --entry - --valid-until 1234567 --network testnet --secret-env SEED --for GABC...
  ```

  The value read is trimmed of surrounding whitespace, because every
  subcommand prints its base64 with a trailing newline and the XDR decoder
  refuses a blob carrying one. (#84)

- Every golden vector carries a `schema_version`, written by the generator, and
  `golden_test.go` refuses a vector whose version it does not know rather than
  reading fields that may have moved. (#50)

- `e2e/contracts/policy-account`, a new contract fixture with unit tests: a
  custom account whose `__check_auth` reads the *amount* out of the invocation
  arguments it is being asked to authorize and refuses a transfer that would
  take the account past a per-period limit, with its own
  `SpendingLimitExceeded` error. It is the first fixture that decides on what
  is being authorized rather than only on who signed. Test fixture code, not a
  product: no policies beyond the one limit, no upgradability, not for mainnet.
  Two e2e scenarios drive it against a live host, one within the limit and one
  over it. (#72)

### Added

**Offline verification**

- `VerifyEntry` rebuilds the signing payload from an entry exactly as it
  stands — including the `SignatureExpirationLedger` stored on it — and decides
  every classic-account signature against it, so an entry can be checked
  without submitting it and without paying a fee to find out. It reports a
  verdict per credential node (`verified`, `unsigned`, `invalid`,
  `cannot_check`) across all three address arms and nested delegate trees. A
  custom account's signature is reported as `cannot_check` and never as
  `verified`: only the contract's `__check_auth` defines its validity. Whether a
  key is a signer of the account, and whether enough signers signed, are
  account-state questions the engine cannot see and does not claim to answer.
  (#59)
- The `soroauth verify` subcommand exposes that engine from the shell, with
  `--json`, `--allow-unsigned` for the Void top-level node a delegates-only
  account legitimately has, and a non-zero exit unless every node verified. It
  accepts a whole envelope as well as a single entry. (#60)
- `remote`, a new package, defines an HTTP signing protocol that transmits the
  **preimage** alongside the payload so a remote signer can inspect what it is
  approving rather than blind-signing a digest. It ships a reference `Server`
  that recomputes SHA-256 of the preimage and refuses a mismatched payload, an
  optional `Approver` callback that observes each approval, and a client
  `Signer` that satisfies `soroauth.Signer` and attaches its context to the
  request so cancellation aborts an in-flight call. It has no authentication
  and holds no key store, and is documented as a reference, not a service. The
  root module does not depend on it. (#34)

**Shell completions (`soroauth completions`)**

- New subcommand: `soroauth completions --shell bash|zsh|fish` prints a
  completion script for that shell on stdout (`--json` wraps it with the
  shell name). The scripts complete the subcommands, each subcommand's flags,
  and the enumerable flag values (`--shell`, `--format`, and the `--network`
  shorthands `testnet`/`public`); fish additionally carries each flag's
  description into the tab menu. `--secret-env` is completed by name only:
  the shells never see or complete a variable's value. (#114)
- The scripts are generated from a spec table that is checked, in both
  directions, against the flags each subcommand really registers:
  `TestSpecsMatchTheRealFlagSets` drives every `flag`-based subcommand's real
  flag parsing and fails when the table and the `FlagSet` disagree, so a flag
  added without updating the completions cannot ship silently missing from
  them. (`tui`, which parses its arguments by hand, is checked against its
  own usage text instead.)
- The generated scripts are verified functionally in the test suite: the bash
  script is sourced by real bash and its completion function queried, the
  fish script is sourced by real fish and its `complete` rules queried, and
  the zsh script is `zsh -n`-checked and registered under a real `compinit`.
  All three are deterministic — the same shell always produces byte-identical
  output.

**Delegate plans and stricter batch signing for `AuthorizeAll`**

- `AuthorizeAll` now takes optional `AuthorizeAllOption`s. `WithDelegatePlans`
  wraps a named address's entry in the delegates arm (via `WithDelegates`)
  before signing, so using delegates through the batch helper no longer
  means unpacking the batch, wrapping one entry by hand, and repacking. An
  entry with no plan is signed exactly as before — this is additive, not a
  behavior change — and a plan address that matches no entry in the batch
  is `ErrDelegatePlanUnmatched`, never a silent no-op. (#104)
- `RequireAllSigned` makes `AuthorizeAll` fail with the new
  `ErrUnsignedCredentialNode` if any credential node in the resulting
  batch — including a delegates entry's top-level node — is left
  unsigned. It is opt-in and literal: a delegates-only account that
  deliberately leaves its top-level node `Void` should not pass this
  option for that entry. No migration is needed; existing callers that
  never pass these options see no behavior change, since `AuthorizeAll`'s
  signature only gained a trailing variadic parameter. (#103)

**Nonce tracking**

- `NonceTracker`, with `NewInMemoryNonceTracker`, is a pluggable,
  concurrency-safe helper for avoiding nonce collisions across concurrent
  signing within one process. It is a best-effort local aid, not a
  correctness guarantee — the host remains the sole authority on whether a
  nonce is valid — and is entirely independent of nonce generation:
  nothing in `AuthorizeInvocation` changed, and using a `NonceTracker` is
  opt-in. (#91)

**Protocol version matrix**

- `ArmProtocolVersion` records the Stellar protocol version each
  credential arm's CAP was introduced in (CAP-46-11 → Protocol 20 for the
  source-account and legacy arms; CAP-71-01 / CAP-71-02 → Protocol 27 for
  V2 and the delegates arm), sourced from each CAP's own preamble. The
  README's new "Protocol version support" table documents the same
  numbers, and `TestArmProtocolVersionMatchesTheReadme` fails the normal
  test suite if the two drift. (#92)

**Passkey signing guide**

- `docs/passkeys.md`: an end-to-end guide to the passkey flow — the browser
  ceremony, assertion transport, challenge binding, ES256 verification, and
  submission — with the signature shape stated for one example wallet contract
  and the guide's Go examples extracted from compiling source in
  `internal/readmesnippets/passkey.go` (`TestPasskeysGuideSnippetsMatchTheirSource`
  fails on drift). It states plainly what has on-chain and golden-vector
  evidence behind it and what has none yet: the passkey signature shape is
  proven only by the guide's own example until the assertion parser (#25), the
  full `PasskeySigner` (#26), the wallet-library golden vectors (#27) and the
  passkey e2e scenario (#28) land. (#31)

**The two-pass simulation requirement**

- The README gained a "The two-pass simulation requirement" section: what the
  record pass does, what the enforce pass does, and what goes wrong without the
  second one — a resource-fee failure on-chain after fees, which reads like a
  signature problem but is a pricing problem. It notes that the Go SDK has no
  `assembleTransaction` equivalent, shows the explicit assembly (attaching the
  simulated `SorobanTransactionData` to the operation, per
  `e2e/harness_test.go`), flags the enforcing pass's value as a pre-flight
  check, names the rejection-scenario exception, and commits to linking a
  future `Soroban RPC integration helpers` package once it exists (#110). The
  example is compiled by CI as `internal/readmesnippets/twopass.go` and kept
  byte-identical by `TestReadmeSnippetsMatchTheirSource`.

**Migration guide for hand-rolled signing code**

- `docs/migrating.md`: a guide for teams replacing their own signing code with
  soroauth — a mapping table from common hand-rolled patterns onto soroauth
  calls, the four documented differences from the JS SDK restated at the point
  a migration hits them, a byte-identical verification step (capture the old
  code's output as a baseline, sign the same inputs, compare `MarshalBinary`),
  the four cases where bytes legitimately differ, and a migration checklist.
  Its Go examples are compiled by CI as `internal/readmesnippets/migrate.go`
  and kept byte-identical by `TestGuideSnippetsMatchTheirSource`, which now
  covers the guides under `docs/` the way the README's snippets are covered.
  (#111)

### Added (docs correctness)

- The README's three Go examples (Quickstart, Delegates, the inline
  `AllowResign` snippet) are now extracted verbatim, at test time, from real,
  compiling source in `internal/readmesnippets/`, instead of living only as
  free-standing markdown text nothing checked. `TestReadmeSnippetsMatchTheirSource`
  fails and names the snippet if the README drifts from its source; the
  source itself is compiled by the `go build ./...` / `go vet ./...` CI
  already runs, since it carries no build tag, so a snippet that stops
  compiling fails the same way any other compile error does. See
  CONTRIBUTING.md § Verifying README snippets compile. In the course of this,
  the Quickstart and Delegates examples gained the error checks they were
  previously missing (three unchecked errors in Quickstart; the Delegates
  loop swallowed its error entirely, which would not even have compiled once
  wrapped in a real function — `declared and not used: err`).

### Security

- CI: every GitHub Action is now pinned to a full commit SHA (with the
  version recorded in a trailing comment), replacing mutable tags like
  `@v7`. A retagged or compromised action can no longer silently gain this
  repository's CI permissions. `.github/dependabot.yml` keeps the pins
  current by opening a PR that updates the SHA and its comment together.

### Added

**`--valid-for`: expiration as a lifetime (issue #124)**

- `payload`, `sign` and `delegates` accept `--valid-for <ledgers>` as an
  alternative to the absolute `--valid-until`. `--valid-for` is resolved
  against the current ledger, read from an RPC endpoint given by `--rpc-url`
  or, when that is unset, `SOROAUTH_RPC_URL`. There is no default endpoint:
  resolving an expiration is choosing the chain it is valid on, so an absent
  endpoint is refused with a message naming both ways to set it. The two flags
  are mutually exclusive, `--valid-for 0` is refused as already expired, and
  every refusal stays results-only on stdout in `--json` mode.

  ```sh
  soroauth sign --entry <base64> --valid-for 1000 --network testnet \
    --rpc-url https://soroban-testnet.stellar.org --secret-env SEED
  ```

  **Migration:** none. `--valid-until` is unchanged and remains the way to give
  an absolute ledger; `--valid-for` is additive. No library API and no emitted
  signature or entry bytes change, so golden vectors are unaffected.

**golangci-lint gate (issue #153)**

- `.golangci.yml` adds golangci-lint v2 on top of the existing `gofmt` + `go vet`
  bar, and a `lint` job runs it on every push and PR. The set is
  golangci-lint's standard linters (errcheck, govet, ineffassign, staticcheck,
  unused) plus `bodyclose`, `errorlint` and `misspell`. The config documents
  why each is on and why `gocyclo`/`funlen`/`goimports` are off. One class is
  excluded with a reason: errcheck's checks on `fmt.Fprint*` writes to the
  CLI's own stdout/stderr, where a failed write cannot change the process's
  exit code.
- The findings it raised were fixed rather than suppressed: a dead `newError`,
  an unused `benchmarkValidUntilLedger` and an unused threshold-session field
  were removed; two unused `hookList` methods were deleted; the HTTP body close
  in `doctor` and the ignored `Contribute` returns in tests are now explicit.
  There are no `//nolint` directives.

  **Migration:** none for library callers. The removed identifiers were
  unexported and unused. No emitted signature or entry bytes change.

**Documentation link check (issue #152)**

- `.github/workflows/links.yml` checks every Markdown file's links with lychee.
  Internal links — between files here, including anchors — gate a push to `main`
  and any PR that touches Markdown. External links run on a weekly schedule and
  on `workflow_dispatch` only, and are reported rather than gating, so an
  external page moving or rate-limiting an automated checker never blocks an
  unrelated PR. `lychee.toml` holds the retry and accepted-status settings. The
  check is linked from README § Contributing and ARCHITECTURE.md, and the
  reproduce-locally commands are in CONTRIBUTING.md § Documentation links.

  **Migration:** none. CI and docs only; no library or emitted bytes change.

**`soroauth doctor`**

- New CLI subcommand checking the local environment for the failures that are
  usually the real cause of a confusing `sign` or `payload` error: an old Go
  toolchain, an unreachable RPC endpoint, or a mistyped `--secret-env`
  variable name. Reports each check as pass/fail, with `--json` for
  structured output, and never prints a secret's value — only whether it is
  set. Exit code reflects overall status (0 all passed, 1 something failed).

**Batch verification API (`VerifyAll`)**

- New `VerifyAll` function verifying a slice of Soroban authorization entries in one call, reporting per-entry verdicts. A failure in one entry does not abort the rest. Concurrency is bounded and configurable via `WithConcurrency`. Includes Go doc examples and benchmarks ensuring no regression on the signing/verification path.

  **Migration:** none required.
**Scoped `AllowResign`**

- `AllowResign` now accepts optional addresses:
  `AllowResign(addresses ...string)`. With no arguments it behaves exactly as
  before — the guard is lifted for whatever address the call targets. With one
  or more addresses, the guard is lifted only when the call's target
  (`ForAddress`, or the signer's own `Address()`) is among them; a target that
  is not named still refuses with `ErrAlreadySigned`, even though
  `AllowResign` was passed. This lets a caller replacing one delegate's
  signature grant the override to just that address, instead of every
  already-signed node an `AuthorizeEntry` call in the same batch might touch.
  The delegates arm's expiration guard (§5.4) is unaffected either way: no
  address list can lift it.

  **Migration:** none required. `AllowResign()` with no arguments is
  unchanged, so every existing call site keeps its current behaviour. No
  emitted signature or entry bytes change, so golden vectors are unaffected.

**Typed address errors**

- `NoMatchingCredentialNodeError`, `DuplicateDelegateError` and
  `MissingSignerError`: error types that wrap the existing
  `ErrNoMatchingCredentialNode`, `ErrDuplicateDelegate` and `ErrMissingSigner`
  sentinels and expose the offending address as an `Address` field.
  `errors.Is` keeps matching the sentinels unchanged, and `errors.As`
  recovers the address without parsing the error string:

  ```go
  var addrErr *soroauth.MissingSignerError
  if errors.Is(err, soroauth.ErrMissingSigner) && errors.As(err, &addrErr) {
      log.Printf("no signer for %s", addrErr.Address)
  }
  ```

  **Migration:** none required. Error messages are byte-identical to v0.1.0,
  and every existing `errors.Is(err, Err…)` check continues to work. Callers
  that previously extracted an address by substring-matching the message may
  switch to `errors.As`; that is optional. No emitted signature or entry bytes
  change, so golden vectors are unaffected.

- Go doc examples for each of the three typed errors, showing the
  `errors.Is` + `errors.As` recovery pattern.
- Signing-path benchmarks covering `Preimage`, `Payload`, `AuthorizeEntry` on
  all three arms (legacy, V2, flat delegates, depth-8 delegate chain),
  `AuthorizeAll` over a 12-entry realistic batch, and
  `AuthorizeInvocation`. CI gates allocs/op and B/op against
  `testdata/bench/budgets.json` via `scripts/checkbench`; `ns/op` is reported
  in PRs but never fails the build. See CONTRIBUTING.md § Benchmarks.

**Envelopes end to end**

- `EnvelopeEntries`, `InspectEnvelope`, `AuthorizeEnvelope`, `EnvelopePayloads`
  and `EnvelopeEntry`: the entry-shaped functions applied to a whole
  `TransactionEnvelope`, each entry reported with the operation index and entry
  index it came from. A fee-bump envelope is read through to its inner
  transaction, because a fee-bump transaction has no operations of its own
  (CAP-15). An envelope with no `invokeHostFunction` operation is refused with
  the new `ErrNoInvokeOperation` rather than reported as an empty result, and an
  envelope type this build does not implement with the new
  `ErrUnsupportedEnvelope`. The unwrapping is done in this library rather than
  through `xdr.TransactionEnvelope.Operations()`, which panics on an
  unrecognised envelope type and on a fee-bump envelope whose inner arm is
  empty.
- The CLI's `inspect`, `payload` and `sign` now accept either an authorization
  entry or a whole transaction envelope, and work out which they were handed. A
  lone entry still prints a single JSON object, so existing scripts keep
  working; an envelope prints one report per entry. `sign --for` is refused for
  an envelope, where one target address would be ambiguous.

  **Migration:** none required. No existing function changes behaviour and no
  emitted signature or entry bytes change, so golden vectors are unaffected.

**Delegation fixtures: session keys, and M-of-N**

- Two new contract fixtures under `e2e/contracts/`, each with unit tests:
  `session-keys`, whose delegates are valid only inside their own ledger window,
  and `threshold-account`, which requires M of its N registered signers. Both
  are test fixtures, not products: no policies, no upgradability, not for
  mainnet.
- E2E scenarios F to I drive them against a live host. F proves an in-window
  session key is accepted; G asserts the contract's own `SessionExpired` error
  code for an expired one; H proves an M-of-N account accepts exactly M signed
  delegates, which is the partial-signing case `AuthorizeAll` deliberately
  permits; I asserts the contract's `InsufficientSignatures` code for M-1.
- Both fixtures document the two clocks a session key lives under:
  `signature_expiration_ledger` is checked by the **host**, in
  `verify_and_consume_nonce`, and only after `__check_auth` has returned `Ok`
  (rs-soroban-env-host 27.0.1, `src/auth.rs:2492-2515`, `:2586-2602`); the
  contract's own window is checked by the **contract**, inside `__check_auth`.
  `delegatesFlow` sets the entry's expiration well past the window, so scenario
  G's refusal is the contract's, on the contract's clock, and the test says so.

**`adapters/walletsdk`, a separate module**

- A wallet-SDK-shaped adapter presenting soroauth the way a wallet holds it: an
  envelope and a keypair. It is a Go module of its own, so importing soroauth
  never drags a wallet SDK in, and CI builds and tests it in a job of its own
  because `./...` at the repository root stops at a nested module.
- `NewSigner` (and `FromOKXKeypair` for the worked integration) adapt a wallet
  SDK keypair into a `soroauth.Signer`; `Requirements` answers "what does this
  envelope want from me?" per entry, with `Wanted` and `Signed`; `Sign` signs
  every entry the key owns; `VerifyEntry` and `VerifyEnvelope` check a signature
  that is already present, comparing the **stored public key** rather than
  trusting the address a node is filed under.
- The two-pass simulation requirement is not hidden. `Sign` returns a `Signed`
  whose `Entries` are what the enforce pass needs, and whose `Envelope` refuses
  with `ErrEnforcePassMissing` until `MarkEnforced` records that the pass ran,
  so a wallet cannot obtain a submittable envelope without saying in code that
  the second simulation happened.
- The worked integration is `github.com/okx/go-wallet-sdk`
  (`coins/stellar/keypair.Full`), bound by name in `okx.go`. The adapter writes
  the same `{public_key, signature}` encoding `NewEd25519Signer` writes;
  `TestSignerMatchesNewEd25519Signer` asserts the two are byte-identical for one
  key and payload, which is what keeps the duplicate encoding honest, and
  `TestOKXKeypairEndToEnd` runs a key from that SDK through the whole adapter and
  checks the result against `crypto/ed25519`.

  **Migration:** none required. The root module gains no new dependency; the
  adapter is optional and versioned with its own module path.

### Changed

**Pooled buffers in the entry deep copy**

- `xdrcopy.Copy` — the deep copy every entry-returning function performs
  before writing — no longer allocates a fresh encoding buffer, encoder,
  reader and decoder on each call. The round-trip now reuses one pooled
  `xdr.EncodingBuffer` and one pooled `xdr.BytesDecoder` per call. They are
  transport scratch only: the copied tree is still allocated fresh (which is
  what keeps the no-aliasing guarantee), and a buffer is not returned to the
  pool until the decode has read it. Measured on INTEL XEON PLATINUM 8573C
  (2 vCPU), linux/amd64, `go test -run '^$' -bench . -benchmem`:

  - `BenchmarkXDRCopy/entry`: 26 allocs / 1632 B → 20 allocs / 1064 B
  - `BenchmarkXDRCopy/preimage`: 24 allocs / 1472 B → 18 allocs / 856 B
  - `BenchmarkAuthorizeEntry/v2`: 85 allocs / 5688 B → 73 allocs / 4504 B
  - `BenchmarkAuthorizeAll`: 1501 allocs / 93505 B → 1348 allocs / 77587 B

- The copy now fails closed if the decode step does not consume exactly the
  bytes the encode step produced — the generated `UnmarshalBinary` it
  replaced discarded that count. Two regression fixtures guard the new
  code: one for that partial-round-trip guard, one for concurrent reuse of
  the pooled buffers.
- CI runs the test suite under `-race` (`go test -race ./...`), and the
  `BenchmarkXDRCopy` budgets sit *below* the pre-pooling cost, so reverting
  the pooling fails the build rather than only a local run. See
  CONTRIBUTING.md § Reproducing a budget failure locally.

  **Migration:** none required. Public API unchanged; no emitted signature
  or entry bytes change — all nine golden vectors pass byte-for-byte.

**Scoped `AllowResign`**

- `AllowResign` now accepts optional addresses:
  `AllowResign(addresses ...string)`. With no arguments it behaves exactly as
  before — the guard is lifted for whatever address the call targets. With one
  or more addresses, the guard is lifted only when the call's target
  (`ForAddress`, or the signer's own `Address()`) is among them; a target that
  is not named still refuses with `ErrAlreadySigned`, even though
  `AllowResign` was passed. This lets a caller replacing one delegate's
  signature grant the override to just that address, instead of every
  already-signed node an `AuthorizeEntry` call in the same batch might touch.
  The delegates arm's expiration guard (§5.4) is unaffected either way: no
  address list can lift it.

  **Migration:** none required. `AllowResign()` with no arguments is
  unchanged, so every existing call site keeps its current behaviour. No
  emitted signature or entry bytes change, so golden vectors are unaffected.

**Typed address errors**

- `NoMatchingCredentialNodeError`, `DuplicateDelegateError` and
  `MissingSignerError`: error types that wrap the existing
  `ErrNoMatchingCredentialNode`, `ErrDuplicateDelegate` and `ErrMissingSigner`
  sentinels and expose the offending address as an `Address` field.
  `errors.Is` keeps matching the sentinels unchanged, and `errors.As`
  recovers the address without parsing the error string:

  ```go
  var addrErr *soroauth.MissingSignerError
  if errors.Is(err, soroauth.ErrMissingSigner) && errors.As(err, &addrErr) {
      log.Printf("no signer for %s", addrErr.Address)
  }
  
  **Migration:** none required. Error messages are byte-identical to v0.1.0,
  and every existing `errors.Is(err, Err…)` check continues to work. Callers
  that previously extracted an address by substring-matching the message may
  switch to `errors.As`; that is optional. No emitted signature or entry bytes
  change, so golden vectors are unaffected.

- Go doc examples for each of the three typed errors, showing the
  `errors.Is` + `errors.As` recovery pattern.
- Signing-path benchmarks covering `Preimage`, `Payload`, `AuthorizeEntry` on
  all three arms (legacy, V2, flat delegates, depth-8 delegate chain),
  `AuthorizeAll` over a 12-entry realistic batch, and
  `AuthorizeInvocation`. CI gates allocs/op and B/op against
  `testdata/bench/budgets.json` via `scripts/checkbench`; `ns/op` is reported
  in PRs but never fails the build. See CONTRIBUTING.md § Benchmarks.

**Envelopes end to end**

- `EnvelopeEntries`, `InspectEnvelope`, `AuthorizeEnvelope`, `EnvelopePayloads`
  and `EnvelopeEntry`: the entry-shaped functions applied to a whole
  `TransactionEnvelope`, each entry reported with the operation index and entry
  index it came from. A fee-bump envelope is read through to its inner
  transaction, because a fee-bump transaction has no operations of its own
  (CAP-15). An envelope with no `invokeHostFunction` operation is refused with
  the new `ErrNoInvokeOperation` rather than reported as an empty result, and an
  envelope type this build does not implement with the new
  `ErrUnsupportedEnvelope`. The unwrapping is done in this library rather than
  through `xdr.TransactionEnvelope.Operations()`, which panics on an
  unrecognised envelope type and on a fee-bump envelope whose inner arm is
  empty.
- The CLI's `inspect`, `payload` and `sign` now accept either an authorization
  entry or a whole transaction envelope, and work out which they were handed. A
  lone entry still prints a single JSON object, so existing scripts keep
  working; an envelope prints one report per entry. `sign --for` is refused for
  an envelope, where one target address would be ambiguous.

  **Migration:** none required. No existing function changes behaviour and no
  emitted signature or entry bytes change, so golden vectors are unaffected.

**Delegation fixtures: session keys, and M-of-N**

- Two new contract fixtures under `e2e/contracts/`, each with unit tests:
  `session-keys`, whose delegates are valid only inside their own ledger window,
  and `threshold-account`, which requires M of its N registered signers. Both
  are test fixtures, not products: no policies, no upgradability, not for
  mainnet.
- E2E scenarios F to I drive them against a live host. F proves an in-window
  session key is accepted; G asserts the contract's own `SessionExpired` error
  code for an expired one; H proves an M-of-N account accepts exactly M signed
  delegates, which is the partial-signing case `AuthorizeAll` deliberately
  permits; I asserts the contract's `InsufficientSignatures` code for M-1.
- Both fixtures document the two clocks a session key lives under:
  `signature_expiration_ledger` is checked by the **host**, in
  `verify_and_consume_nonce`, and only after `__check_auth` has returned `Ok`
  (rs-soroban-env-host 27.0.1, `src/auth.rs:2492-2515`, `:2586-2602`); the
  contract's own window is checked by the **contract**, inside `__check_auth`.
  `delegatesFlow` sets the entry's expiration well past the window, so scenario
  G's refusal is the contract's, on the contract's clock, and the test says so.

**`adapters/walletsdk`, a separate module**

- A wallet-SDK-shaped adapter presenting soroauth the way a wallet holds it: an
  envelope and a keypair. It is a Go module of its own, so importing soroauth
  never drags a wallet SDK in, and CI builds and tests it in a job of its own
  because `./...` at the repository root stops at a nested module.
- `NewSigner` (and `FromOKXKeypair` for the worked integration) adapt a wallet
  SDK keypair into a `soroauth.Signer`; `Requirements` answers "what does this
  envelope want from me?" per entry, with `Wanted` and `Signed`; `Sign` signs
  every entry the key owns; `VerifyEntry` and `VerifyEnvelope` check a signature
  that is already present, comparing the **stored public key** rather than
  trusting the address a node is filed under.
- The two-pass simulation requirement is not hidden. `Sign` returns a `Signed`
  whose `Entries` are what the enforce pass needs, and whose `Envelope` refuses
  with `ErrEnforcePassMissing` until `MarkEnforced` records that the pass ran,
  so a wallet cannot obtain a submittable envelope without saying in code that
  the second simulation happened.
- The worked integration is `github.com/okx/go-wallet-sdk`
  (`coins/stellar/keypair.Full`), bound by name in `okx.go`. The adapter writes
  the same `{public_key, signature}` encoding `NewEd25519Signer` writes;
  `TestSignerMatchesNewEd25519Signer` asserts the two are byte-identical for one
  key and payload, which is what keeps the duplicate encoding honest, and
  `TestOKXKeypairEndToEnd` runs a key from that SDK through the whole adapter and
  checks the result against `crypto/ed25519`.

  **Migration:** none required. The root module gains no new dependency; the
  adapter is optional and versioned with its own module path.

### Changed

**Pooled buffers in the entry deep copy**

- `xdrcopy.Copy` — the deep copy every entry-returning function performs
  before writing — no longer allocates a fresh encoding buffer, encoder,
  reader and decoder on each call. The round-trip now reuses one pooled
  `xdr.EncodingBuffer` and one pooled `xdr.BytesDecoder` per call. They are
  transport scratch only: the copied tree is still allocated fresh (which is
  what keeps the no-aliasing guarantee), and a buffer is not returned to the
  pool until the decode has read it. Measured on INTEL XEON PLATINUM 8573C
  (2 vCPU), linux/amd64, `go test -run '^$' -bench . -benchmem`:

  - `BenchmarkXDRCopy/entry`: 26 allocs / 1632 B → 20 allocs / 1064 B
  - `BenchmarkXDRCopy/preimage`: 24 allocs / 1472 B → 18 allocs / 856 B
  - `BenchmarkAuthorizeEntry/v2`: 85 allocs / 5688 B → 73 allocs / 4504 B
  - `BenchmarkAuthorizeAll`: 1501 allocs / 93505 B → 1348 allocs / 77587 B

- The copy now fails closed if the decode step does not consume exactly the
  bytes the encode step produced — the generated `UnmarshalBinary` it
  replaced discarded that count. Two regression fixtures guard the new
  code: one for that partial-round-trip guard, one for concurrent reuse of
  the pooled buffers.
- CI runs the test suite under `-race` (`go test -race ./...`), and the
  `BenchmarkXDRCopy` budgets sit *below* the pre-pooling cost, so reverting
  the pooling fails the build rather than only a local run. See
  CONTRIBUTING.md § Reproducing a budget failure locally.

  **Migration:** none required. Public API unchanged; no emitted signature
  or entry bytes change — all nine golden vectors pass byte-for-byte.

## [0.1.0] — 2026-09-16

First release. Unaudited.

### Added

**Signing payloads**

- `Preimage` builds the `HashIdPreimage` for an entry, choosing the variant from
  the credentials arm: `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` for legacy
  `SOROBAN_CREDENTIALS_ADDRESS` (CAP-46-11), and
  `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` for both
  `SOROBAN_CREDENTIALS_ADDRESS_V2` and
  `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` (CAP-71-01).
- `Payload` returns the 32 bytes a signer signs.

**Signers**

- `Signer` interface, receiving both the preimage and its payload hash so a
  remote or hardware signer can inspect what it is approving.
- `NewEd25519Signer` for a classic account with one key. It verifies its own
  signature before returning it.
- `NewAccountMultiSigner` for a classic account with several keys, sorted
  strictly ascending by raw public key and capped at 20, as the host requires.
  No JS SDK equivalent.
- `SignerFunc` for custom account contracts whose signature shape the caller
  owns.

**Authorizing**

- `AuthorizeEntry` with `ForAddress` and `AllowResign`.
- `AuthorizeInvocation` for building and signing an entry from scratch,
  defaulting to the V2 arm.
- `AuthorizeAll` for signing a batch, all or nothing.
- `UpgradeToV2` for converting an unsigned legacy entry.

**Delegates (CAP-71-01)**

- `Delegate`, `WithDelegates` and `ValidateDelegateOrder`, supporting arbitrarily
  nested trees, sorting every level by the XDR encoding of the address and
  rejecting duplicates within a level.

**Everything else**

- `Inspect` reporting an entry's structure, `ExpirationAfter`, `ParseAddress`
  and `FormatAddress`.
- Nine exported sentinel errors, each with a test that produces it.
- `soroauth` CLI with `payload`, `sign`, `delegates` and `inspect`. Secrets are
  read only from a named environment variable, never a flag value.

### Proven

- Nine golden vectors generated by `@stellar/stellar-sdk@17.1.0` assert that the
  preimage, payload hash and final signed entry are byte-identical to the
  reference, across both networks, legacy and V2 arms, sub-invocation and
  create-contract trees, the int64 nonce edges, and three delegate cases
  including one address at two nesting depths. The delegate vectors reproduce
  `WithDelegates` itself from the recorded unsorted input rather than re-reading
  an entry the reference already built. CI regenerates them on every push and
  fails on drift.
- Six scenarios on Stellar testnet, protocol version 28, covering all three
  address arms plus multisig, and two rejection scenarios that assert the host's
  specific reason. Transaction hashes in [e2e/RESULTS.md](e2e/RESULTS.md).

### Known limitations

- Unaudited.
- The CLI's `delegates` subcommand takes a flat list; nested delegates are
  library-only.
- No secp256r1 / WebAuthn signer. See `docs/ISSUE_BACKLOG.md`.
- `AuthorizeAll` does not require every delegate node to be signed, because it
  cannot know an account's delegation policy. Check `Inspect`'s per-node
  `Signed` flags before submitting.

[0.1.0]: https://github.com/soroauth/soroauth-go/releases/tag/v0.1.0