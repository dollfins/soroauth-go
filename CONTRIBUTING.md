# Contributing

Thanks for looking. This library produces signatures that move money, so the bar
for changes is higher than the size of the codebase suggests. Most of what
follows exists to keep the evidence honest rather than to police style.

## Setup

```sh
git clone https://github.com/soroauth/soroauth-go
cd soroauth-go
go test ./...
```

That is the whole setup for the library and CLI. Go 1.25.0 or later.

Two optional pieces need more:

- **Regenerating golden vectors** needs Node (>= 22.12.0, what
  `@stellar/stellar-sdk@17.1.0` declares).
- **Running the e2e tests** needs Rust 1.93.0 (pinned in
  `e2e/contracts/rust-toolchain.toml`, rustup will fetch it) and
  `stellar-cli` 28.0.0.
- **Working on the wallet SDK adapter** (`adapters/walletsdk`) needs nothing
  extra, but it is a module of its own with its own test loop; see
  [The nested adapter module](#the-nested-adapter-module).
- **Running the Python parity harness** needs Python 3.10+ and the pinned SDK
  in `testdata/parity-python/requirements.txt`; `make parity` creates a venv
  and installs it.
- **Working on the WebAssembly core or the TypeScript wrapper** needs Node
  (the same 22+ the rest of the tooling uses). `make wasm-check` builds the
  module and proves it byte-identical to the golden vectors; `make ts-test`
  typechecks and tests the wrapper package.

## Make targets

The Makefile wraps the common tasks, so the commands below exist in one place
rather than across several documents. Run `make help` for the list.

| Target | What it runs |
|---|---|
| `make` (default) | `fmt`, `vet` and `test` |
| `make fmt` | fails if `gofmt -l .` reports anything |
| `make vet` | `go vet ./...` |
| `make test` | `go test ./...` |
| `make build` | builds the CLI to `bin/soroauth` |
| `make vectors` | `cd testdata/gen && npm ci && node gen.mjs` |
| `make vectors-check` | regenerates the vectors and fails if the committed files changed |
| `make e2e` | builds the test contract with `stellar-cli` and runs `go test -tags e2e -v ./e2e/...` |
| `make parity` | installs the pinned Python SDK into `.venv-parity` and runs the parity harness and its tests |
| `make parity-rust` | runs the Rust stellar-xdr parity harness and its tests (needs Rust 1.93.0) |
| `make wasm` | builds the js/wasm signing core to `wasm/dist/` |
| `make wasm-check` | builds the wasm core and replays every golden vector through it |
| `make ts-test` | typechecks and tests the `@soroauth/wasm` TypeScript package |
| `make clean` | removes `bin/`, the wasm build output and the parity venv |

No target hides a failure. `make fmt` exits non-zero when a file needs
formatting instead of printing a warning, `make vectors-check` exits non-zero
when regeneration changes a committed vector, and `make e2e` refuses to run
without `stellar-cli` rather than failing later with an obscure test error.

## Before you open a pull request

```sh
make            # fmt, vet and test
```

The underlying commands are:

```sh
gofmt -l .        # must print nothing
go vet ./...
golangci-lint run ./...
go test -race ./...
```

CI runs all of these except `golangci-lint`, plus the golden-vector drift check
and the contract build; the signing-path budget check runs on push to main (see
[Benchmarks](#benchmarks)). `golangci-lint` is a local gate only, because pull
requests are capped at three checks — see [Linting](#linting).

The suite runs with `-race` because `internal/xdrcopy` shares encoder and
decoder buffers across calls through `sync.Pool`; without the detector,
`TestCopyConcurrentReuse` would still pass on code that races.

`internal/xdrcopy` also has a round-trip fuzz target, which the same `-race`
reasoning covers: it asserts a copy is byte-identical to its source and shares
no memory with it. Run it locally with

```sh
go test -fuzz=FuzzCopyRoundTrip -fuzztime=30s ./internal/xdrcopy
```

## Linting

The gate is `.golangci.yml`, run locally. There is no `lint` job in
`.github/workflows/ci.yml`: pull requests are capped at three checks, and the
two that gate a merge are `vet and test` and `golden vectors are reproducible`.
Run the linter before you push; a reviewer may also run it.

The config is deliberately small, and each linter in it is there because the
project would actually fix what it reports; the file says which and why, and
which linters are off on purpose. A linter whose findings are all suppressed
should be deleted rather than left as decoration.

The config was verified against `v2.14.0`. Install that version and run it from
the repository root:

```sh
GOBIN="$PWD/.tools" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
./.tools/golangci-lint run ./...
```

`.tools/` is gitignored. `golangci-lint run` prints `0 issues.` and exits 0 when
clean; a finding names the file, the line and the linter. Fix a finding rather
than excluding it. The one documented exception is `fmt.Fprint*` to the CLI's
own stdout/stderr streams, listed under `errcheck.exclude-functions`; adding to
that list needs a reason in the config, not a `//nolint` at the call site.

### The nested adapter module

`adapters/walletsdk` is a Go module of its own, so `./...` from the repository
root does not reach it: the go tool stops at the first directory holding a
`go.mod`. It has its own CI job, and its own loop:

```sh
cd adapters/walletsdk
gofmt -l .
go vet ./...
go test -race ./...
```

It is a separate module on purpose: it is the only place a wallet SDK is
named, and keeping it out of the root module is what stops `go get` of
soroauth from pulling one in. Nothing in the root module may depend on it,
and `TestRootModuleStaysFreeOfWalletSDKs` in the adapter's own tests fails if
a wallet SDK appears in the root `go.mod` or `go.sum`.

Because the two are separate modules, `adapters/walletsdk/go.mod` carries a
`replace` back to the repository root, so the adapter is tested against the
soroauth in this checkout rather than a published version. The root module is
not tagged yet; once it is, the adapter is the module that needs its own
`adapters/walletsdk/vX.Y.Z` tags before anyone outside this repository can
`go get` it.

## Parity harnesses

The golden vectors prove soroauth agrees with `@stellar/stellar-sdk`. They
cannot prove that agreement is *correct*, because a bug shared by both
implementations would be frozen into the vectors. Two harnesses close that gap
by recomputing the vectors with other implementations:

- **Python** (`testdata/parity-python/`), against the separately maintained
  `stellar-sdk` on PyPI. `make parity` imports every vector, rebuilds the
  preimage and payload, and compares. Cases with no preimage (source-account
  entries) are skipped loudly and counted; a run that checks nothing fails.
- **Rust** (`testdata/parity-rust/`), against the separately maintained
  [`stellar-xdr`](https://crates.io/crates/stellar-xdr) crate, which is what
  the Soroban host itself decodes with. `make parity-rust` recomputes every
  vector's preimage and payload and compares; the crate is pinned exactly in
  `Cargo.toml` and `Cargo.lock` and the harness refuses to run against another
  version. Cases with no preimage (source-account entries) are skipped loudly
  and counted, and a run that checks nothing fails.
- **WebAssembly** (`wasm/parity.mjs`), against the wasm build of this same
  library. `make wasm-check` proves the browser build emits the same bytes as
  the native one.

Both are pinned: the Python SDK in `requirements.txt`, the JS SDK in
`testdata/gen/package.json`. **Never edit a vector to make a harness pass.** A
disagreement means one implementation is wrong; open an issue with the protocol
reference (CAP-46-11, CAP-71-01, CAP-71-02) and investigate.

## The WebAssembly core and the TypeScript wrapper

`cmd/soroauthwasm` compiles the signing core to `js/wasm`. It is a thin binding
over the same `soroauth` package the native build uses — it does not reimplement
anything — and it is behind `//go:build js && wasm`, so `go build ./...` visits
it only when you ask for that target. `wasm/build.sh` builds it together with
the matching `wasm_exec.js`.

`wasm/ts` is the `@soroauth/wasm` npm package: a typed wrapper over those
bindings. It is a wrapper, not a second implementation, and its tests run under
jsdom plus a real-wasm integration test.

The interactive TUI (`tui.go`) is excluded from js/wasm builds, because
bubbletea does not compile for that target. The CLI, which is never built for
js/wasm, still has it.

## Benchmarks

The signing path has committed benchmarks in `bench_signing_test.go` covering
`Preimage`, `Payload`, `AuthorizeEntry` on all three arms (legacy, V2,
delegates, including a depth-8 delegate chain), `AuthorizeAll` over a
12-entry, 4-signer batch, and `BenchmarkXDRCopy` — the deep copy in
`internal/xdrcopy` that every entry-returning function performs, in its two
on-path shapes (an authorization entry and a `HashIdPreimage`).

```sh
# Full suite with allocation stats
go test -run '^$' -bench . -benchmem -count=1 .

# One arm
go test -run '^$' -bench 'BenchmarkAuthorizeEntry/delegates' -benchmem .
```

CI runs the same command and gates on **allocs/op and B/op** only, via:

```sh
go test -run '^$' -bench . -benchmem -count=1 . | tee /tmp/bench.out
go run ./scripts/checkbench /tmp/bench.out testdata/bench/budgets.json
```

`ns/op` is reported for humans in PRs (with the machine it came from) but never
fails the build: wall-clock on a shared runner is noise. Allocation counts are
deterministic for a given Go version and are the regression signal.

`testdata/bench/budgets.json` is the committed baseline. Signing-path budgets
carry ~40% headroom over the measured values so a Go minor bump does not flake
CI. If the checker fails:

- If the increase is a bug, fix the bug; do not raise the budget.
- If the increase is intentional, raise the budget in the **same commit** as
  the change and say in the commit body which function got more expensive and
  why that is acceptable.
- Never lower a budget without a fresh local measurement on the machine named
  in the commit body.

When you add a benchmark, add a budget in the same commit. The checker prints
`WARN … no budget` for any benchmark it sees without one, and
`FAIL … benchmark not found` if a budgeted name is missing from the output —
so a renamed benchmark cannot silently drop out of the gate.

### Reproducing a budget failure locally

A CI failure from the `bench` job is a `FAIL` line naming the benchmark and
the budget it exceeded:

```
FAIL BenchmarkXDRCopy/entry   allocs/op 26 > budget 23; B/op 1632 > budget 1250
```

The two commands above, run from the repository root, reproduce it locally —
`checkbench` exits 1 exactly as CI does. Once you can see *which* benchmark
regressed, find out *where* the allocations come from:

```sh
go test -run '^$' -bench BenchmarkXDRCopy -benchmem -count=1 -memprofile /tmp/mem.out .
go tool pprof -alloc_objects -top /tmp/mem.out   # rank by number of allocations
go tool pprof -alloc_space  -top /tmp/mem.out    # rank by bytes
```

The signing-path entries (`AuthorizeEntry`, `AuthorizeAll`) also include
ed25519 signing and SHA-256; `BenchmarkXDRCopy` isolates the deep copy, so a
regression that moves both almost always starts in `internal/xdrcopy`.

The `BenchmarkXDRCopy` budgets are deliberately tighter than the ~40%
policy: they sit **below** what a copy cost before the round-trip buffers
were pooled (issue #108), so reverting that pooling fails this gate instead
of only a local run. If they fail after a change that never touched
`internal/xdrcopy`, profile with the commands above before moving the
number, and if the new cost is justified, raise it in the same commit with
the measurement in the body.

## Verifying README snippets compile

The README's Go examples (Quickstart, Delegates, and the inline `AllowResign`
snippet) are not free-standing markdown text: each is extracted verbatim from a
real, compiling source file in `internal/readmesnippets/`, between a
`// snippet:start <name>` and `// snippet:end <name>` comment pair.
`TestReadmeSnippetsMatchTheirSource` in `readme_test.go` at the repository root
asserts the fenced code block in README.md is byte-identical (modulo
tabs-vs-spaces) to that marked region. The guides under `docs/` —
`passkeys.md`, `migrating.md` — are checked the same way by
`TestGuideSnippetsMatchTheirSource`.

This means two different things can fail, and the test names which:

- **The snippet source stops compiling.** It is an ordinary package with no
  build tag, so `go build ./...` and `go vet ./...` — which CI already runs
  on every push — catch this like any other compile error, naming the file
  and line.
- **The README drifts from its source**, for example a hand-edit to the
  fenced block without updating `internal/readmesnippets/`, or the reverse.
  `TestReadmeSnippetsMatchTheirSource` fails and prints both texts.

To reproduce either failure locally:

```sh
go build ./...                        # catches a snippet that no longer compiles
go test -run TestReadmeSnippets -v .  # catches README/source drift, naming the snippet
```

To change an example, edit the marked region in
`internal/readmesnippets/*.go` and copy it verbatim (as, or converted from,
tabs) into the matching fenced block in README.md. Never edit the fenced
block alone: it is not the source of truth, and the drift test will fail on
the next run.

## Protocol version matrix

`ArmProtocolVersion` (`protocolmatrix.go`) and the README's "Protocol
version support" table both claim the same thing — which Stellar protocol
version each credential arm requires — sourced from each arm's CAP
preamble (CAP-46-11 for the source-account and legacy arms, CAP-71-01 and
CAP-71-02 for V2 and the delegates arm). `TestArmProtocolVersionMatchesTheReadme`
in `protocolmatrix_test.go` parses the README table and fails if its
numbers disagree with `ArmProtocolVersion`, and `TestArmProtocolVersionMatchesTheCAPs`
pins `ArmProtocolVersion` itself to the values read directly from the CAPs.

To reproduce a failure locally:

```sh
go test -run TestArmProtocolVersion -v .
```

Changing a protocol version claim means updating both `protocolmatrix.go`
and the README table together, in the same commit, and citing the CAP text
that justifies the change — never editing one side to make the test pass.

## GitHub Actions are pinned to commit SHAs

Every `uses:` in `.github/workflows/*.yml` names a full commit SHA with the
version in a trailing comment, e.g. `actions/checkout@3d3c42e… # v7`, never a
mutable tag like `@v7`. A major-version tag can be retagged to point at a
different commit; pinning to the SHA means a compromised or retagged action
cannot silently start running with this repository's CI permissions.

Dependabot (`.github/dependabot.yml`) watches the `github-actions` ecosystem
and opens a PR updating both the SHA and its version comment together when a
new release comes out, so the two can never drift apart. To pin a new action
by hand, resolve the tag to a commit first:

```sh
git ls-remote --tags https://github.com/<owner>/<repo> | grep 'refs/tags/v7$'
```

Use the first column's SHA (for an *annotated* tag, `git ls-remote` also
prints a `refs/tags/v7^{}` line — use that dereferenced commit SHA, not the
tag object's own SHA).

## Golden vectors

`testdata/vectors/*.json` are generated, committed artefacts. They are the
evidence that soroauth agrees byte-for-byte with the reference implementation.

**Never edit a vector by hand.** Not to fix a failing test, not to adjust a
field, not for anything. A hand-edited vector is a test that has been made to
agree with the code instead of the other way round, which is precisely the
failure the vectors exist to prevent. CI regenerates them on every push and
fails if the committed files differ, so an edit will be caught — but the reason
not to do it is that it destroys the evidence, not that you will be caught.

To change them, change the generator:

```sh
cd testdata/gen
npm ci
node gen.mjs
```

Then commit the regenerated files together with the generator change.

### Versioning the vector schema and reproducing failures

Every golden vector carries an explicit `schema_version` field (currently `1`). The loader (`golden_test.go`) explicitly checks this version and rejects any unknown or missing schema version rather than guessing or ignoring removed/reinterpreted fields.

- **Bumping the version:** When a protocol change or schema evolution requires altering the structure of golden vectors, increment `schema_version` in both the generator (`testdata/gen/gen.mjs`) and all committed vector JSON files under `testdata/vectors/`, and update the expected version check in `golden_test.go`.
- **Reproducing a failure locally:** If a vector fails schema validation or drifts from the reference implementation, run `go test -run TestGoldenVectors` (or `make vectors-check`) from the repository root. The test suite will fail loudly, naming the vector and the exact mismatch or unsupported schema version.

If a vector disagrees with the Go code, the Go code is wrong until proven
otherwise. If you believe the vector itself is wrong, stop and open an issue
saying why, with the protocol reference — do not change it to make a test pass.

The generator refuses to run against any `@stellar/stellar-sdk` other than the
pinned 17.1.0, since a vector from another build is not evidence about this one.

## Shared fixture deployment harness & running e2e tests

The e2e test suite provides a shared fixture deployment harness (`deployAndFundFixture` on the test `harness`) so individual contract fixtures do not reimplement deployment and funding logic.

To deploy and fund any contract fixture in your own scenarios or local debugging:

```go
deployer := h.newAccount(t, "deployer")
wasmBytes := wasmPath("modular_account")
contractID := h.deployAndFundFixture(t, deployer, wasmBytes, constructorArgs...)
```

## Running the e2e tests

```sh
cd e2e/contracts && stellar contract build
cd ../.. && go test -tags e2e -v ./e2e/...
```

They run against testnet by default; `SOROAUTH_RPC_URL` points them elsewhere.
Accounts are generated at runtime and funded by friendbot. A full run takes
about three minutes.

`e2e/RESULTS.md` is written by a run and only when every scenario ran. Commit it
only from a real, complete run — it is what the README's testnet claims point
at.

See [e2e/README.md](e2e/README.md) for what each scenario proves and why the two
rejection scenarios exist.

## Scheduled e2e runs (CI)

A GitHub Actions workflow (`.github/workflows/e2e.yml`) runs the e2e suite on a
schedule (every 6 hours) and on `workflow_dispatch`. This catches testnet resets,
protocol upgrades, and RPC changes that would otherwise break the suite silently
between releases.

- The workflow **does not** commit `e2e/RESULTS.md` automatically — that remains
  a deliberate act from a verified local run.
- On scheduled failure, the workflow opens a GitHub issue with the run details
  so the regression is visible without digging through logs.
- To reproduce a scheduled failure locally:
  ```sh
  export SOROAUTH_RPC_URL=https://soroban-testnet.stellar.org
  go test -tags e2e -v ./e2e/...
  ```

## Parity reports

The e2e suite writes a machine-readable `parity-report.json` alongside
`RESULTS.md`, listing every scenario with its vector id, implementation,
verdict and observed credential arm, so a parity regression can be read by a
tool rather than by eye.

`TestParityReportRegression` checks that report's shape: a non-zero scenario
count, and a vector id and verdict on every entry. It needs no network — when
no live report is present it reads the committed fixture at
`e2e/testdata/parity_regression.json` — so it runs in CI as a step of the `vet
and test` job, and a regression fails the build rather than only a local run:

```sh
go test -tags e2e -run TestParityReportRegression ./e2e
```

To debug a failure, inspect the generated `parity-report.json` in the
repository root after a full e2e run; it carries the per-scenario verdicts the
test is asserting over.

## Coverage reporting (CI)

The `coverage` job in `.github/workflows/ci-go.yml` measures test coverage,
enforces a floor of **60%**, and publishes the report via Codecov. It runs on
push to `main` and on demand, not on pull requests: pull requests carry only the
three checks the branch ruleset requires.

- Run locally to check your coverage before pushing:
  ```sh
  go test -coverprofile=coverage.out -covermode=atomic ./...
  go tool cover -func=coverage.out | awk '/total/{print $3}'
  ```
- The floor is 60%, and it is a floor set below a measured total rather than an
  aspiration. The 80% it replaced never passed: every push to `main` while it
  was in place reported around 62% and failed. Raise it as tests are added;
  never lower it without a fresh measurement named in the commit body. The
  number in the job (`floor=60`) is the authority; this document follows it.
- The report is visible in the CI logs and on Codecov without digging through
  artifacts.

## Property-based tests

The address package includes property-based tests using [gopter](https://github.com/leanovate/gopter).
These tests generate thousands of random G... and C... addresses and verify:

- ParseAddress/FormatAddress round-trips for both address types
- XDR encoding stability across round-trips
- Rejection of invalid inputs (muxed addresses, secret seeds, liquidity pools,
  claimable balances, malformed base32, corrupted checksums, truncated addresses,
  empty strings)

### Running property tests locally

```sh
# Run the full property test suite (1000 iterations per property)
go test -run TestParseAddressFormatAddressProperty -v ./...

# Run the deterministic subset (100 iterations, fixed seed for CI reproducibility)
go test -run TestParseAddressFormatAddressDeterministic -v ./...

# Run the complementary XDR-level tests
go test -run 'TestParseAddressWithRandomXDR|TestFormatAddressRejectsInvalidXDR' -v ./...
```

### Reproducing a property test failure

If a property test fails, the output will show the seed and the generated value
that causes the failure. To reproduce:

```sh
# 1. Note the seed from the failure output (e.g., "failed with initial seed: 12345")
# 2. Run with that seed:
go test -run TestParseAddressFormatAddressProperty -v -count=1 ./... 2>&1 | head -50

# Or run the deterministic test which uses a fixed seed:
go test -run TestParseAddressFormatAddressDeterministic -v ./...
```

Similarly, to run and reproduce expiration and signature consistency property tests for `AuthorizeEntry` across all address arms and delegate tree depths:

```sh
go test -run TestAuthorizeEntryExpirationProperty -v ./...
```

The deterministic test (`TestParseAddressFormatAddressDeterministic`) runs a
fixed set of 100 iterations per property with seed `0xDEADBEEF` and is the one
executed in CI. If it passes locally but the full property test fails, the
failure is in the extended search space — increase `MinSuccessfulTests` in the
deterministic test to narrow it down.

### Fuzzing ValidateDelegateOrder

`FuzzValidateDelegateOrder` in `delegates_test.go` feeds arbitrary bytes to the
XDR decoder and, for anything that decodes to an entry, asserts that
`ValidateDelegateOrder` neither panics nor accepts a delegate array that is
mis-ordered or carries a duplicate at one level. Its seed corpus is built from a
golden vector, a hand-built well-formed tree, and that tree with one delegate
address overwritten to duplicate its sibling.

The seeds are constructed with `f` passed to the test helpers, which take
`testing.TB`. Do not build a `&testing.T{}` literal to satisfy them: it is an
uninitialised struct, so `Helper()` and `Fatalf()` on it panic instead of
reporting, and a seed that failed to build would take the whole target down
rather than failing it.

The fuzz run itself is not a pull-request check — 30 seconds of fuzzing per push
would slow every review for a target whose job is to find inputs over time. It
runs on push to `main` and on demand, as the `fuzz` job in
`.github/workflows/ci-go.yml`. What a pull request does exercise is the seed
corpus, through the ordinary `go test ./...`.

To run it locally:

```sh
go test -run='^$' -fuzz=FuzzValidateDelegateOrder -fuzztime=30s .

### Fuzzing

The library includes fuzz tests for `Inspect` (`FuzzInspect` in `inspect_test.go`) to ensure arbitrary byte sequences never panic and always return either a valid `EntryInfo` or an error, never a half-populated struct alongside an error.

#### Running fuzz tests locally

```sh
go test -run=^$ -fuzz=FuzzInspect -fuzztime=30s .
```

If a fuzz test fails, Go writes the failing input corpus item to a subdirectory under `testdata/fuzz/`. To reproduce or debug a captured failure:

```sh
go test -run=FuzzInspect/testdata/fuzz/FuzzInspect/<seed-name> .
```

### The fuzz seed corpus

`FuzzValidateDelegateOrder`'s seed corpus is generated from the golden vectors,
which are the entries this library is proven against: every credential arm, a
sub-invocation tree, a create-contract invocation, the int64 nonce edges, and
three delegate shapes including one address at two nesting depths. Seeding from
real entries means the fuzzer's mutations start inside the space of things that
decode, rather than spending its budget discovering what a valid entry looks
like.

Regenerate it from the repository root:

```sh
go run ./cmd/gencorpus
```

The seeds land in `testdata/fuzz/FuzzValidateDelegateOrder/`. That path is not a
choice: Go reads a target's seed corpus from `testdata/fuzz/<TargetName>` and
nowhere else, and each file must be in Go's corpus format (a
`go test fuzz v1` header, then one Go literal per fuzz argument) or it fails the
package's tests instead of being skipped. `gencorpus` writes the decoded entry
bytes, since the target's argument is the `[]byte` it passes to
`UnmarshalBinary`.

Every seed is run by the ordinary suite, as a named subtest — no `-fuzz` flag
needed, so a seed that starts failing fails `go test ./...`:

```sh
go test -run FuzzValidateDelegateOrder -v .
```

```
=== RUN   FuzzValidateDelegateOrder/v2_sub_invocations_0
--- PASS: FuzzValidateDelegateOrder (0.01s)
```

The generator is deterministic, so CI regenerates the corpus and fails on drift,
the same way it does for the vectors themselves. Do not hand-edit a seed: change
the vectors or the generator and regenerate.

For the fuzz *run* — the part that searches for new inputs — see the `fuzz` job
in `.github/workflows/ci-go.yml`, which runs on push to `main` and on demand
rather than on pull requests.

### Capturing regressions

If a property test discovers a bug, capture the failing input as a regression
fixture in `address_test.go` by adding a new table entry to
`TestParseAddressRejects` or `TestParseAddressFormatAddressRoundTrip` with the
exact address string that triggered the failure. This ensures the specific
case remains covered even if the property test parameters change.

## Doc comments on exported identifiers

Every exported const, var, type, func, and method on an exported type needs a
doc comment. `internal/doccheck` enforces this: it walks the module's
first-party packages (skipping `adapters/walletsdk`, which is a nested module
checked by its own CI job) and fails on any exported identifier with none.
`TestRoot_RepoIsClean` in `internal/doccheck/doccheck_test.go` runs it as part
of the normal suite, so `go test ./...` fails the same way CI does.

Reproduce a failure locally:

```
go test ./internal/doccheck/... -run TestRoot_RepoIsClean -v
```

Each line names the file, the line, and the identifier. A const or var block
can be documented either per entry or with one comment above the block (both
count); a method only needs a doc comment when its receiver type is itself
exported, since a method on an unexported type is not reachable through
godoc.

## What a change needs

- **Tests that can fail.** A test that passes for the wrong reason is worse than
  no test, because it reads as evidence. Two of this repo's own tests were
  originally written that way and had to be fixed: a rejection scenario that
  asserted only "the transaction failed" was passing while the transaction ran
  out of instructions and never reached the check it was supposedly about. If
  you add a test that expects a failure, assert *which* failure.
- **A test that proves the guard bites.** Where practical, break the thing
  deliberately, confirm the test fails, and say so in the commit message. Do not
  commit the break.
- **No mutation of caller input.** Every function returning a modified entry
  deep-copies first and has a test proving the input's bytes are unchanged.
- **Errors that name the sentinel.** Wrap with
  `fmt.Errorf("soroauth: <operation>: %w", err)` and match with `errors.Is`.
- **Context is checked and passed down, never dropped.** Every exported
  function that takes a `context.Context` as its first parameter must check
  `ctx.Err()` before doing work — so a cancelled context fails closed even on
  a path that never reaches a signer (a source-account entry, an empty
  batch) — and must pass that same context, unchanged, to every call that can
  block or produce a signature, in particular `Signer.Sign`. Every such
  function has a cancellation test that asserts `context.Canceled` and that
  the signer was not invoked; add one for any new context-taking function.
- **Fail closed.** Where the protocol or the caller's intent is ambiguous,
  refuse and return an error rather than guess. Say which reading you chose in
  the commit message.
- **Cited protocol claims.** Any statement about host behaviour in a doc
  comment, README or commit message needs a source — the CAP, the
  `rs-soroban-env` file and function, or the SDK file and line. Not memory.

## Commit format

Conventional commits, lowercase and imperative:

```
feat(authorize): sign delegate nodes by address
test(golden): cover delegate vectors
docs(readme): write readme
ci: add golden drift job
```

One logical unit per commit — a function and its tests, one CLI subcommand, one
document. Commit bodies carry the evidence: the command you ran and its real
output, or the file and line you read.

A commit that corrects an earlier wrong claim or wrong code is its own commit,
and its body says what was wrong, how it was found, and what changed.

## Security

Do not open a public issue for a signature-correctness or key-handling bug. See
[SECURITY.md](SECURITY.md).

## License

By contributing you agree your contributions are licensed under Apache-2.0.
