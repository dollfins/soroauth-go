# soroauth

soroauth builds, signs and inspects Soroban authorization entries in Go. When a
contract calls `require_auth()` on an address that is not the transaction's
source account, the transaction has to carry a signed `SorobanAuthorizationEntry`
for that address — and the signature is not over the entry, but over a
`HashIdPreimage` whose shape depends on which credential arm is in use. The Go
SDK ships all of those XDR types and none of the code that builds or signs those
preimages. soroauth is that code, for all three address credential arms: legacy
`SOROBAN_CREDENTIALS_ADDRESS`, CAP-71 `SOROBAN_CREDENTIALS_ADDRESS_V2`, and
CAP-71 `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` including nested delegate
trees.

## Install

```sh
go get github.com/soroauth/soroauth-go
```

The CLI:

```sh
go install github.com/soroauth/soroauth-go/cmd/soroauth@latest
```

Requires Go 1.25.0 or later, and `github.com/stellar/go-stellar-sdk` v0.7.3 or
later.

## Common tasks

The same commands [CONTRIBUTING.md](CONTRIBUTING.md) uses are wrapped by the
Makefile, so there is one entry point for the local checks and the generated
artefacts:

```sh
make              # fmt, vet and test (the default)
make build        # build the CLI to bin/soroauth
make vectors      # regenerate testdata/vectors from the pinned JS SDK
make vectors-check # regenerate, then fail if the committed vectors changed
make e2e          # build the test contract and run the live testnet suite
make wasm-budget  # build the wasm core and fail if it is over its size ceiling
```

Every target fails loudly: `make fmt` exits non-zero if any file is not
gofmt-clean, and `make vectors-check` exits non-zero if regeneration changes a
committed vector. `make help` lists the targets.

## Container image

A container image is published on GHCR for every release tag, for CI systems
that need to sign an entry without installing a Go toolchain:

```sh
docker pull ghcr.io/soroauth/soroauth-go:v0.1.0   # or :latest for the newest release

docker run --rm -e SEED=SABC... ghcr.io/soroauth/soroauth-go:v0.1.0 \
  sign --entry <base64> --valid-until 1234567 --network testnet --secret-env SEED
```

The seed is passed the same way it is on the command line: a named
environment variable, read only by `--secret-env`, never a flag value. The
image itself never contains any key material, and nothing bakes a seed into
a layer. That said, an environment variable set on a running container is
visible to anything that can inspect that container (`docker inspect`,
`/proc/<pid>/environ` from the host, a sidecar with the same namespace), the
same as it would be for any other process — treat container secret injection
with the same care you would give a plain environment variable anywhere
else. The image is built from `Dockerfile` at the repository root by
`.github/workflows/release.yml` on every `v*` tag push.

## CLI

Every subcommand that produces output accepts `--json` to emit a single JSON
object (or, for `tree`, either the JSON report or one of its two text
renderings — see below) on stdout. On success the object carries the result
fields; on failure it carries an `error` field. Nothing else is written to
stdout in JSON mode, so scripts can safely pipe the output to `jq` without
stripping usage text. `tui` is the one exception: it is an interactive
terminal program, not something a script drives, so it has no `--json` mode.

| subcommand | success fields | failure field |
|---|---|---|
| `payload` | `preimage`, `payload` | `error` |
| `sign` | `signed_entry` | `error` |
| `delegates` | `wrapped_entry` | `error` |
| `inspect` | (the `EntryInfo` struct — this was already `inspect`'s only output; `--json` is accepted for consistency and does not change it) | `error` |
| `verify` | the report: `credential_type`, `address`, `valid_until_ledger`, `verified`, and `nodes` with a `verdict` per credential node | `error` |
| `tree` | (the `EntryInfo` struct, same shape as `inspect`; without `--json` it prints an ASCII or DOT rendering instead) | `error` |
| `doctor` | `checks`, `ok` | (checks carry their own `pass`/`detail`; see below) |
| `cross-compile` | `target`, `size`, `sha256` (one per line) | `error` |
| `completions` | `shell`, `script` | `error` |

### Worked invocation — JSON output

```sh
# Pipe subcommands together without intermediate shell variables:
./soroauth delegates --entry <base64> --valid-until 1234567 --delegate GAAAA... --json |
  ./soroauth sign --entry - --valid-until 1234567 --network testnet --secret-env SEED --json

# What would this signer have to sign?
SEED=SABC... ./soroauth payload \
  --entry <base64> --valid-until 1234567 --network testnet --json |
  jq -r .payload

# Sign and get the entry back as JSON
SEED=SABC... ./soroauth sign \
  --entry <base64> --valid-until 1234567 --network testnet \
  --secret-env SEED --json |
  jq -r .signed_entry

# Wrap an entry with delegates, JSON out
./soroauth delegates \
  --entry <base64> --valid-until 1234567 \
  --delegate GAAAA... --delegate GBBBB... --json |
  jq -r .wrapped_entry

# Inspect an entry (output is JSON either way) and pick fields out of it
./soroauth inspect --entry <base64> |
  jq -r '"\(.credential_type) \(.address) expires=\(.valid_until_ledger)"'
```

### Tree — render a delegate tree

`inspect` reports an entry's structure as JSON; `tree` renders the same
structure — the delegates-arm tree in particular — as something a person can
read at a glance, either for a terminal or for embedding in docs.

```sh
# Terminal-readable, indented ASCII
./soroauth tree --entry <base64>

# Graphviz DOT, for docs
./soroauth tree --entry <base64> --format dot | dot -Tsvg -o tree.svg

# Structured, same shape as "inspect"
./soroauth tree --entry <base64> --json
```

```
GTOP (unsigned)
├── GA... (signed)
│   └── GA... (unsigned)
└── GB... (unsigned)
```

One address appearing at more than one nesting level is legal under CAP-71-01
(the same key delegating twice in one tree), and `tree` never merges those
occurrences into a single node: each is printed in its own position, with its
own signed/unsigned state, so a repeated address never reads as one node that
somehow got signed twice.

### Verify — check an entry's signatures without submitting it

Every other check is about structure. `verify` is about the signatures: it
rebuilds the payload from the entry as it stands — including the
expiration the entry stores — and checks each signature against it, so an entry
that was tampered with after signing, or signed over a different expiration
than it carries, is caught before it is submitted rather than after fees are
paid.

```sh
./soroauth verify --entry <base64> --network testnet

# Accept the Void top-level node a delegates-only account legitimately has
./soroauth verify --entry <base64> --network testnet --allow-unsigned

# JSON, for scripting
./soroauth verify --entry <base64> --network testnet --json |
  jq -r '.nodes[] | "\(.address) \(.verdict)"'
```

Each credential node is one of four verdicts: `verified`, `unsigned`,
`invalid` (a well-formed signature that does not verify), or `cannot_check`.
The exit code is 4 unless every node verified (with `--allow-unsigned`
tolerating unsigned nodes), so a green result means exactly what it says.

**What it cannot do.** Only a classic account signature — the built-in vector
holding one `{public_key, signature}` map — can be decided offline. A custom
account's signature is whatever its `__check_auth` accepts, and only the
contract can say whether a given value is valid, so any other shape is
reported as `cannot_check` and never as `verified`. Whether the key that signed
is actually a signer of the account, and whether enough signers signed to meet
its threshold, are account-state questions this command cannot see and does not
claim to answer. A green result is evidence that the signatures on the entry
commit to it; it is not a promise the transaction will succeed.

### Doctor — check the local environment for common first-run problems

Most first-run problems are environmental — an unreachable RPC endpoint, a
mistyped secret variable name, a Go toolchain older than this module needs —
and the error from `sign` or `payload` does not say so. `doctor` checks three
things and reports each as pass or fail: never printing a secret, only
whether it is set.

```sh
# Human-readable
./soroauth doctor --rpc-url https://soroban-testnet.stellar.org --secret-env SEED

# JSON
./soroauth doctor --rpc-url https://soroban-testnet.stellar.org --secret-env SEED --json
```

```json
{"checks":[{"name":"go toolchain","pass":true,"detail":"go1.25.4"},{"name":"network","pass":true,"detail":"https://soroban-testnet.stellar.org reachable (HTTP 405)"},{"name":"secret env: SEED","pass":true,"detail":"SEED is set"}],"ok":true}
```

`--secret-env` is optional; when omitted, that check is skipped rather than
reported as a failure. `--rpc-url` defaults to the public testnet RPC, and any
HTTP response — including a non-2xx status — counts the network check as
passing, since it proves DNS, TCP and TLS all worked; only a transport-level
error (DNS failure, connection refused, timeout) fails it. Exit code is 0 when
every check passes, 1 if any fails.

### Cross-compile — build binaries for multiple targets

The `cross-compile` subcommand builds soroauth for any GOOS/GOARCH pair. It is
useful for creating release artifacts or verifying that the codebase compiles
cleanly on all targets.

```sh
# Human-readable output for the default matrix (all 5 release targets)
./soroauth cross-compile

# Build only linux/amd64 and windows/amd64, emit JSON (one object per line)
./soroauth cross-compile --targets linux/amd64,windows/amd64 --json

# Write binaries to a directory instead of just printing metadata
./soroauth cross-compile --targets linux/amd64 --output-dir ./dist
```

Sample JSON output:

```json
{"target":{"goos":"linux","goarch":"amd64","binary":"soroauth"},"size":4190368,"sha256":"1d214924a4717228e2c0b694c4b4d3c3077c29ed036d9b00805e431b4a6e8433"}
{"target":{"goos":"windows","goarch":"amd64","binary":"soroauth.exe"},"size":4308992,"sha256":"d241d7f7ab8ff20215fbb254abc4eb71643408f62cffc3c0989e552801ae75e4"}
```

On error, JSON mode emits a single object to stdout with an `error` field
(and nothing to stderr):

```json
{"target":{"goos":"invalid","goarch":"target","binary":""},"error":"invalid target \"invalid/target\": unknown GOOS/GOARCH"}
```

#### CI cross-compilation matrix

The CI workflow (`.github/workflows/ci.yml`) includes a `cross-compile` job
that runs on every push and PR. It builds for the five release targets in
parallel with a 5-minute timeout per platform:

- `linux/amd64`
- `linux/arm64`
- `darwin/amd64`
- `darwin/arm64`
- `windows/amd64`

The job is build-only (no tests, no artifacts uploaded) and runs a smoke test
(`./soroauth help`) on the native platform to verify the binary runs. Failures
are named by platform in the workflow UI.

To reproduce a CI failure locally:

```sh
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o soroauth-arm64 ./cmd/soroauth
./soroauth-arm64 help
```

### Completions — shell completion for subcommands and flags

`soroauth completions --shell bash|zsh|fish` prints a completion script for
that shell on stdout. The scripts complete the subcommands, each subcommand's
flags, and the enumerable flag values (`--shell`, `--format`, `--network`'s
two named shorthands); fish additionally shows each flag's description in the
tab menu. `--secret-env` is completed by name only — the shells never see or
complete a variable's value.

Install by shell:

```sh
# bash — for the current session only
source <(soroauth completions --shell bash)

# bash — for every future session
soroauth completions --shell bash > ~/.local/share/bash-completion/completions/soroauth

# zsh — write to a directory in $fpath, before compinit runs
soroauth completions --shell zsh > "${fpath[1]}/_soroauth"

# fish — fish loads this automatically in new shells
soroauth completions --shell fish > ~/.config/fish/completions/soroauth.fish
```

The scripts are generated from the same command/flag table the CLI parses, so
a flag added to a subcommand without updating the completions spec fails the
test suite (`TestSpecsMatchTheRealFlagSets`) rather than shipping a completion
script that silently omits it.

### Wasm budget — fail the build when the wasm core outgrows its ceiling

`soroauth wasm-budget` measures the compiled js/wasm signing core and exits
non-zero if it is larger than its budget. The core is downloaded by a browser,
so its size is worth failing on rather than noticing after a release.

```sh
# Measure the built artifact against the default 7 MiB ceiling.
soroauth wasm-budget --out wasm/dist/soroauth.wasm

# Build and measure in one step, with a budget of your own.
soroauth wasm-budget --build-cmd ./wasm/build.sh --budget 6500000

# Report the delta against the last release's size.
soroauth wasm-budget --prev-size 6204087

# Machine-readable, for CI.
soroauth wasm-budget --json
```

```json
{
  "size": 6211959,
  "budget": 7340032,
  "exceeded": false,
  "previous_size": 6204087,
  "delta": 7872
}
```

The default budget is 7 MiB (7340032 bytes), a ceiling set above the size the
build actually produces (6211959 bytes, measured with go1.25.4 on darwin/arm64)
rather than an aspiration. A binary exactly at the budget passes; only one
strictly larger fails. `--prev-size` is optional, and a
negative `delta` means the artifact shrank.

Stdout carries only the result, on the over-budget path too — the diagnostic
goes to stderr — so `soroauth wasm-budget --json | jq .exceeded` works whether
the build passed or failed. `make wasm-budget` runs it against
`wasm/dist/soroauth.wasm` after building both the CLI and the core.

### Release workflow

The project uses a GitHub Actions workflow (`.github/workflows/release.yml`) that
runs on version tags (`v*`). It:

1. Regenerates the golden vectors from the pinned JS SDK and fails if they
   drift (the same check that runs on every push).
2. Builds the CLI for `linux/amd64`, `linux/arm64`, `darwin/amd64`,
   `darwin/arm64`, `windows/amd64`.
3. Creates a GitHub Release whose notes are extracted from `CHANGELOG.md` for
   the tagged version.
4. Attaches all six binaries to the release.

To cut a release:

```sh
# Update CHANGELOG.md with the new version's entries
git tag v0.2.0
git push origin v0.2.0
```

The workflow will refuse to publish if the golden drift check fails, so a
release is only created when the library is provably byte-identical to the
reference implementation.

## Quickstart

Simulation tells you which addresses must authorize a call. Hand those entries
to soroauth, and put the signed ones back on the operation:

```go
sim, err := client.SimulateTransaction(ctx, rpc.SimulateTransactionRequest{
    Transaction: encodedTx,
    AuthMode:    rpc.AuthModeRecord,
})
if err != nil {
    return err
}

entries := make([]xdr.SorobanAuthorizationEntry, 0, len(*sim.Results[0].AuthXDR))
for _, encoded := range *sim.Results[0].AuthXDR {
    var entry xdr.SorobanAuthorizationEntry
    if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
        return err
    }
    entries = append(entries, entry)
}

ledger, err := client.GetLatestLedger(ctx)
if err != nil {
    return err
}
validUntil, err := soroauth.ExpirationAfter(ledger.Sequence, 1000)
if err != nil {
    return err
}

signed, err := soroauth.AuthorizeAll(ctx, entries,
    []soroauth.Signer{soroauth.NewEd25519Signer(sender)},
    validUntil, network.TestNetworkPassphrase)
if err != nil {
    return err // nothing partial is ever returned
}

op.Auth = signed // then re-simulate in enforce mode, assemble, sign, submit
```

This example is compiled by CI as `internal/readmesnippets/quickstart.go` —
see [Verifying README snippets](CONTRIBUTING.md#verifying-readme-snippets-compile).

Source-account entries pass straight through untouched, so you can hand over
everything simulation returned without sorting by arm first.

## The two-pass simulation requirement

The Quickstart comment `// then re-simulate in enforce mode, assemble, sign,
submit` is doing a lot of work. CAP-71-01 needs **two** simulation passes, and
skipping the second is the single most common way to produce a transaction that
builds, signs — and fails on-chain after fees are paid.

**Pass 1 — record mode.** The transaction carries no signatures yet, so the
host *recording* what auth would be needed: it hands back the unsigned
authorization entries and prices resources without having executed any account
contract's `__check_auth`. Signing happens here.

**Pass 2 — enforce mode.** Signing the entries changes what the transaction
costs: a signature ScVal is real memory the host has to hold and check. The
transaction is re-simulated in `AuthModeEnforce` carrying the **signed**
entries, and it is this pass's resource footprint and fee that the submitted
transaction must carry.

**What goes wrong without pass 2.** The envelope assembled from pass 1 carries
the recording pass's resource fee, which is too small once the signatures are
on. The submission is then rejected on-chain for exceeding its resource budget
— a fee-bounded failure that happens *after* fees and after your signers have
approved the entry, and one that reads like a signature problem when it is
really a pricing problem.

**The enforcing pass is also a free pre-flight check.** It executes
`__check_auth` with your real signatures, so a wrong signature shape, a
mis-targeted address, or an unsigned node the contract insists on is caught
locally instead of on-chain.

One deliberate exception: a submission that is *meant* to be rejected skips the
enforcing pass, which would fail locally for the very reason under test. See
[e2e/README.md](e2e/README.md) for how the rejection scenarios handle that.

After the enforcing pass, assemble explicitly — the Go SDK has no
`assembleTransaction` equivalent to the JS SDK's, so the simulated
`SorobanTransactionData` is attached to the operation by hand:

```go
op.Auth = signed

// The enforcing pass simulates a real transaction carrying the signed
// entries, so the host can price the signatures that are actually there.
enforceTx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
    SourceAccount:        source,
    IncrementSequenceNum: true,
    Operations:           []txnbuild.Operation{op},
    BaseFee:              txnbuild.MinBaseFee,
    Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
})
if err != nil {
    return nil, err
}
encoded, err := enforceTx.Base64()
if err != nil {
    return nil, err
}
sim, err := client.SimulateTransaction(ctx, rpc.SimulateTransactionRequest{
    Transaction: encoded,
    AuthMode:    rpc.AuthModeEnforce,
})
if err != nil {
    return nil, err
}
if sim.Error != "" {
    return nil, fmt.Errorf("enforcing simulation failed: %s", sim.Error)
}

// The Go SDK has no assembleTransaction: attach the simulated
// SorobanTransactionData — resources and fee sized with the signed
// entries — to the operation by hand.
var sorobanData xdr.SorobanTransactionData
if err := xdr.SafeUnmarshalBase64(sim.TransactionDataXDR, &sorobanData); err != nil {
    return nil, err
}
op.Ext = xdr.TransactionExt{V: 1, SorobanData: &sorobanData}

assembled, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
    SourceAccount:        source,
    IncrementSequenceNum: true,
    Operations:           []txnbuild.Operation{op},
    BaseFee:              txnbuild.MinBaseFee,
    Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
})
if err != nil {
    return nil, err
}
```

This example is compiled by CI as `internal/readmesnippets/twopass.go` — same
verification story as the Quickstart above.

A `Soroban RPC integration helpers` package (see
`docs/ISSUE_BACKLOG.md`) is planned to lift this flow — both passes, assembly,
the resource fee — into one correct, reusable call. Once it exists, this
section will link it as the preferred alternative to hand-rolling assembly.

Until then, `adapters/walletsdk` enforces this same discipline in code: it
refuses to hand back a submittable envelope unless the enforcing pass ran.

## Credential types

| Arm | Value | Preimage variant | Address in the signed bytes? |
|---|---|---|---|
| `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` | 0 | none — the envelope signature covers it | n/a |
| `SOROBAN_CREDENTIALS_ADDRESS` | 1 | `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION` (9) | no |
| `SOROBAN_CREDENTIALS_ADDRESS_V2` | 2 | `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` (10) | yes |
| `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` | 3 | `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS` (10), bound to the **top-level** address | yes |

The legacy arm is defined by CAP-46-11; V2 and the delegated-signer arm by
CAP-71-01 and CAP-71-02. V2 binds the signer's address into the signed payload,
which closes a narrow replay case: one key shared across several accounts,
combined with a contract that does not itself bind the address into its
arguments.

`UpgradeToV2` converts an unsigned legacy entry to V2. You may need it:
simulation can return either arm, and the RPC's `UseUpgradedAuth` flag is
best-effort — it affects only the recording auth modes and is ignored by
protocol versions whose host cannot emit AddressV2.

## Protocol version support

Each arm's CAP states the protocol version it was introduced in; a network
running an older protocol cannot emit or accept that arm at all.

| Arm | Introduced in | Source |
|---|---|---|
| `SOROBAN_CREDENTIALS_SOURCE_ACCOUNT` | Protocol 20 | CAP-46-11 |
| `SOROBAN_CREDENTIALS_ADDRESS` | Protocol 20 | CAP-46-11 |
| `SOROBAN_CREDENTIALS_ADDRESS_V2` | Protocol 27 | CAP-71-01 |
| `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` | Protocol 27 | CAP-71-02 |

`ArmProtocolVersion` carries this same table in code
(`TestArmProtocolVersionMatchesTheReadme` fails if the two drift), for a
caller that wants to check it programmatically before pointing soroauth at
an older network. soroauth itself makes no RPC call and does not check a
live network's protocol version — the table exists so the requirement is
visible before a confusing on-chain failure, not to enforce it.

## Delegates

Under CAP-71-01 an account can authorize through delegated signers instead of
signing itself. Every node in the tree — the account and every delegate at every
depth — signs **one** payload, bound to the top-level address.

```go
wrapped, err := soroauth.WithDelegates(entry, validUntil,
    []soroauth.Delegate{
        {Address: d1},
        {Address: d2, Nested: []soroauth.Delegate{{Address: d3}}},
    }, nil) // nil top-level signature → ScvVoid, which CAP-71-01 permits
if err != nil {
    return wrapped, err
}

for _, kp := range []*keypair.Full{k1, k2, k3} {
    wrapped, err = soroauth.AuthorizeEntry(ctx, wrapped,
        soroauth.NewEd25519Signer(kp), validUntil, passphrase,
        soroauth.ForAddress(kp.Address()))
    if err != nil {
        return wrapped, err
    }
}
```

This example is compiled by CI as `internal/readmesnippets/delegates.go` — see
[Verifying README snippets](CONTRIBUTING.md#verifying-readme-snippets-compile).

Each delegates array is sorted by the XDR encoding of the address and checked
for duplicates within that level, as CAP-71-01 requires; the same address at two
*different* levels is allowed, and one `AuthorizeEntry` call fills every node
carrying that address.

Because every node commits to the same payload, the expiration is fixed once any
node is signed: signing another node at a different `validUntilLedger` would
leave the entry's signatures disagreeing, so soroauth refuses it.

Replacing one delegate's signature needs `AllowResign`, scoped to that
delegate's address so the override does not also apply to a different call
touching another node in the same entry:

```go
resigned, err := soroauth.AuthorizeEntry(ctx, wrapped, soroauth.NewEd25519Signer(k1),
    validUntil, passphrase, soroauth.ForAddress(d1), soroauth.AllowResign(d1))
```

This example is compiled by CI as `internal/readmesnippets/allowresign.go` —
see [Verifying README snippets](CONTRIBUTING.md#verifying-readme-snippets-compile).

`AllowResign()` with no arguments keeps its original, unscoped meaning: the
guard is lifted for whatever address that call targets. Naming one or more
addresses restricts it to those; a target outside the list still refuses with
`ErrAlreadySigned`. Either way, the expiration guard above is never lifted.

One consequence worth stating plainly: the delegates arm and V2 share the same
address-bound preimage, so the same address, nonce, invocation, expiration and
network produce an **identical payload** on both arms — golden vectors 3 and 6
show exactly that. Replay protection comes from the nonce, which the host
consumes; this is by design under CAP-71-01, not a defect.

`AuthorizeAll` applies every signer matching any node in the tree. It does not
fail when a delegate has no signer, because it cannot know the account's policy.

An unsigned node fails only if the account's `__check_auth` calls
`delegate_account_auth` for that address — the host then runs that delegate's
`__check_auth` with whatever signature the node carries (CAP-71-01,
*Semantics → `delegate_account_auth` function*), and an empty one is not
something a G-account delegate can authenticate with. The pattern the CAP
recommends, and the one soroban-sdk's `delegate_auth` documentation and this
repo's e2e fixture both follow, delegates to *every* listed signer. So unless
you know your account's policy, treat an unsigned node as one that will fail:
check the per-node `Signed` flags from `Inspect` before submitting.

## Expiration

`ExpirationAfter(latestLedger, ledgers)` turns a lifetime into the absolute
ledger an entry must carry. Two things about that number, both read from the
host rather than inferred:

- **It is inclusive.** `verify_and_consume_nonce` rejects only when
  `ledger_seq > live_until_ledger`, so the expiration ledger itself is still
  valid. The JS SDK's doc comment describes the bound as exclusive; the host is
  the authority.
- **There is an upper bound this library cannot enforce.** The host also rejects
  anything above the network's `max_live_until_ledger`. That is a network
  setting, so it is deliberately not hard-coded here — a baked-in constant would
  silently become wrong. Read it from the network if you need the real ceiling.

Zero is refused: by the rule above it is already expired, not permissive.

## CAP-85 / Protocol 28

As of this release (using `github.com/stellar/go-stellar-sdk` v0.7.3), **no changes
are required** for CAP-85 / Protocol 28 support.

Evidence:
- The Go SDK v0.7.3 (released 2026-08-06) does not contain Protocol 28 / CAP-85
  helpers. Its `go.mod` declares `go 1.25.0` and the XDR types are from the
  `go-xdr` module at `v0.0.0-20260806060815-dc590f17552a`, which predates
  Protocol 28.
- Testnet is on Protocol 28 (confirmed via `stellar.expert` and RPC
  `getLedger` responses), but the authorization entry wire format
  (`SorobanAuthorizationEntry`, `SorobanCredentials`, `SorobanDelegateSignature`)
  has not changed in CAP-85. CAP-85 (Protocol 28) introduces new *host
  functions* and *diagnostic events*, not new credential arms or preimage
  variants for Soroban authorization.
- The soroauth codebase has been run against live testnet (see
  [e2e/RESULTS.md](e2e/RESULTS.md)) with no protocol-level failures.

When the Go SDK releases Protocol 28 helpers (expected in a future minor
version), this section will be updated. At that time, if the wire format
changes, a golden vector will be added and an e2e scenario will be run. If
nothing changes, this section will explicitly state that.

## Differences from the JS SDK

soroauth is proven byte-for-byte against `@stellar/stellar-sdk@17.1.0`, and
deviates from it in four deliberate ways.

- **A signature is only ever written to a node whose address matches the
  target** — `ForAddress`, or the signer's own `Address()`. The JS reference
  falls back to the top-level node when no target is given, even if the key
  belongs to someone else. soroauth returns `ErrNoMatchingCredentialNode`
  instead, because a signature on the wrong node is a transaction that pays fees
  and then fails.
- **No default write to the top-level node**, for the same reason.
- **The signer is never invoked when nothing matches.** The zero-match check and
  the already-signed check run *before* signing, so a hardware wallet or remote
  signer is never asked to approve something that is about to be discarded.
- **`AccountMultiSigner`** has no JS equivalent. It signs for a classic account
  with several keys, sorted strictly ascending by raw public key and capped at
  20, which is what the host requires.

soroauth is also stricter in one place: wrapping or upgrading an entry that
already carries a signature returns `ErrAlreadySigned`, where JS silently
discards the old signature. The payload changes under both operations, so that
signature would no longer verify.

## Remote signing over HTTP

The `remote` package defines a small protocol for signing a payload over HTTP,
and ships a reference server plus a client that satisfies `soroauth.Signer`.
The point of the protocol is that the **preimage** is transmitted, not just the
digest, so the remote end can inspect the whole structure it is approving
rather than blind-signing a hash. The server recomputes SHA-256 of the
preimage and refuses a request whose payload does not match, and the client
attaches its context to the request so cancelling it aborts an in-flight call.

```go
server := remote.NewServer(soroauth.NewEd25519Signer(signerKey))
server.Approver = remote.LogApprover(os.Stderr) // record what is approved
http.Handle(remote.Path, server)

signer := remote.NewSigner("http://127.0.0.1:8080", signerKey.Address())
return soroauth.AuthorizeEntry(ctx, unsigned, signer, validUntil, network.TestNetworkPassphrase)
```

It is a reference, not a service: it has no authentication, holds no key store,
and does no rate limiting, so a real deployment must put those in front of it.
Nothing in the root module depends on `remote`.

## Browser and WebAssembly

The signing core builds for `js/wasm`, so a browser can derive the bytes it
signs instead of trusting a server for the payload. This is what makes passkey
signing possible without a round trip that hands over the preimage.

- The module lives in `cmd/soroauthwasm` and is built with `wasm/build.sh`. It
exposes building a preimage, hashing it to a payload, writing an externally
produced signature onto an entry, and a deterministic ed25519 path for tests.
- The `@soroauth/wasm` TypeScript wrapper (in `wasm/ts`) gives that surface real
types, loads from bytes or a URL, and turns every failure into a thrown
`SoroauthError` rather than a numeric code.
- `make wasm-check` proves the wasm build is byte-identical to the golden
vectors; the package's own tests run under jsdom and against the real module.

The wrapper calls through to the same Go code as the native library, so there
is no second implementation of the signing logic to drift.

For the full passkey flow — browser ceremony, assertion verification, and what
is (and is not yet) proven — see [docs/passkeys.md](docs/passkeys.md).
Replacing hand-rolled signing code with soroauth — pattern mappings, the four
differences from the JS SDK, and how to verify the migration produced identical
bytes — is covered in [docs/migrating.md](docs/migrating.md).

## Proven on testnet

Every claim below is backed by a transaction that exists on chain. Full detail,
including raw host errors, is in [e2e/RESULTS.md](e2e/RESULTS.md).

| Scenario | Result | Transaction |
|---|---|---|
| Legacy `ADDRESS` accepted | accepted | [`6d77c01a…`](https://stellar.expert/explorer/testnet/tx/6d77c01affa11766979ad905e68d32a61a6e3daa6a110096ce7bb4698376a182) |
| CAP-71 `ADDRESS_V2` accepted | accepted | [`566dcdac…`](https://stellar.expert/explorer/testnet/tx/566dcdacee95e2e44646099b78de46208f1b1c2b18bc0c818dcdae2349d85661) |
| `AccountMultiSigner` meets a 2-of-2 threshold | accepted | [`9914176a…`](https://stellar.expert/explorer/testnet/tx/9914176a36dd314927aa830930a57c2bd85254a8bef659b1d88e13408a82459f) |
| One signature does **not** meet that threshold | rejected, as it must be | [`5b0b49e7…`](https://stellar.expert/explorer/testnet/tx/5b0b49e75e958feff7152b359039996ca57f28ee371e2207633ec645a7faa6c6) |
| Delegated signers accepted, account itself unsigned | accepted | [`5cd87e73…`](https://stellar.expert/explorer/testnet/tx/5cd87e7397b0936550875944d8f8df217ee75b438a5c706c31565c89cd2ccf2a) |
| An unregistered delegate is refused | rejected, as it must be | [`9afda479…`](https://stellar.expert/explorer/testnet/tx/9afda479a6b5bad8cdefd4c35956aaf2a1ba15e13f394b818a3db8d392f52fdd) |

The two rejection rows matter as much as the acceptances: they assert the host's
specific reason, so the accepting scenarios cannot be passing by accident.

Offline, the golden vectors generated by `@stellar/stellar-sdk@17.1.0` assert
that soroauth's preimage, payload hash and final signed entry are byte-identical
to the reference, and CI regenerates them on every push to catch drift. That
agreement is cross-checked by a third implementation: the Python `stellar-sdk`
recomputes every vector's preimage and payload in CI (`make parity`), so a bug
shared by the Go and JS implementations cannot hide in the vectors.

## Status

**v0.1.0. Unaudited.** The wire format is fixed by the protocol and pinned by
the golden vectors, but this library is new and has not been reviewed by anyone
outside its author. Read the code before you sign anything valuable with it.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Golden vectors are never edited by hand.
Security reports go through [SECURITY.md](SECURITY.md), not the issue tracker.

The Markdown in this repository is link-checked by the
[`links` workflow](.github/workflows/links.yml): internal links gate a PR,
external links are reported on the weekly scheduled run.

## License

Apache-2.0. See [LICENSE](LICENSE).
