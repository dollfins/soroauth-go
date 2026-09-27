# End-to-end tests

These tests prove soroauth against a live Stellar network. They are the evidence
behind the claim that the signatures this library produces are accepted by a
real host — not by a mock, and not only by the JS reference implementation.

They are excluded from the normal test suite by the `e2e` build tag, because
they create accounts, submit transactions, and wait on ledger close.

## Running them

```sh
cd e2e/contracts && stellar contract build    # once, produces the fixture wasm
cd ../.. && go test -tags e2e -v ./e2e/...
```

By default they run against `https://soroban-testnet.stellar.org`. Point them
elsewhere with `SOROAUTH_RPC_URL`. Whatever URL is used is verified with live
`getNetwork`, `getHealth` and `getLatestLedger` calls before anything relies on
it, and the passphrase and protocol version found are logged.

Every account is generated at runtime and funded by friendbot. No key is read
from disk, written to disk, or committed. Nothing here touches mainnet.

A full run takes roughly three minutes, most of it waiting for ledgers to close.

## What each scenario proves

| ID | Scenario | What it proves |
|----|----------|----------------|
| A | Legacy `SOROBAN_CREDENTIALS_ADDRESS` | An entry on the legacy arm, signed by soroauth, is accepted by the host. |
| B | CAP-71 `SOROBAN_CREDENTIALS_ADDRESS_V2` | The address-bound arm is accepted. The test reports whether simulation returned V2 directly or whether `UpgradeToV2` was needed. |
| C | `AccountMultiSigner` | A multi-key signature vector meets a 2-of-2 medium threshold on a classic account. This signer has no JS equivalent, so the golden vectors cannot cover it; this is its proof. |
| D | CAP-71 delegated signers | A `SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES` entry with a `Void` top-level signature and two G-account delegates is accepted, so a contract account authenticates purely through its delegates. |
| E | The host rejects what it should | The same flow with a delegate the account never registered is refused by the contract's `__check_auth` with `UnknownDelegate`. |
| F | Session keys, in window | A CAP-71 delegates entry whose only delegate is a G-account session key, inside the ledger window the `session-keys` contract stored for it, is accepted. |
| G | Session keys, expired | The same flow pointed at a key whose window has closed is refused with the contract's own `SessionExpired` (error 4), on the contract's clock. |
| H | M-of-N, exactly M | A 2-of-3 `threshold-account` is authorized by exactly two signed delegates, so `AuthorizeAll` does not have to sign every delegate for the account to accept. |
| I | M-of-N, M-1 | The same account with one signed delegate is refused with the contract's `InsufficientSignatures` (error 3). |

Several tests exist only to stop the accepting ones passing for the wrong reason:

- **`TestScenarioCRejectsASingleSignature`** signs with one key against a
  threshold of two and requires the host to refuse. Without it, scenario C would
  pass just as happily against an account whose threshold was never raised, and
  would prove nothing about multisig.
- **Scenario E asserts the specific contract error code**, not merely that the
  transaction failed. This matters: an earlier version of the test passed while
  the transaction was actually running out of instructions before `__check_auth`
  was ever reached. Asserting `ContractCode 1` is what makes it prove the thing
  it claims.
- **Scenarios G and I assert the contract's error code** for the same reason, and
  neither is satisfied by "the transaction failed". They also keep the accepting
  halves honest: F proves a window is honoured only because G proves the same
  window is enforced, and H proves partial signing works only because I proves a
  shortfall is caught.

## How a scenario works

CAP-71-01 needs two simulation passes, and the tests follow that:

1. **Simulate in record mode.** The host reports which addresses must authorize
   the call, and hands back unsigned authorization entries.
2. **Sign with soroauth.** For A, B and C this is `AuthorizeAll`. For D and E the
   recorded entry is first wrapped with `WithDelegates`, then each delegate is
   signed with `AuthorizeEntry` and `ForAddress`. F and G use the same flow as D;
   H and I sign only the M delegates they attach, and never touch the rest of the
   registered set, which is the partial-signing case.
3. **Simulate in enforce mode**, carrying the signed entries, so the resource
   fee accounts for the signatures that are actually there.
4. **Assemble** — the Go SDK has no `assembleTransaction`, so the simulated
   `SorobanTransactionData` is attached to the operation explicitly and its
   resource fee set from the simulation's `minResourceFee`.
5. **Sign the envelope** as the payer and submit, then poll until it resolves.

The scenarios that are meant to be rejected skip step 3. That pass would fail
locally for the very reason under test, which would only show that simulation
agrees with the host; the point is to put the transaction in front of the real
host and watch it be refused there, after fees. Because the recording pass never
executed `__check_auth`, its instruction count is too low, so those submissions
are given extra instruction headroom — otherwise they run out of budget before
reaching the rejection under test.

The credential arm reported for each scenario is read back off the envelope that
was actually submitted, by decoding it again, rather than assumed from what the
test meant to build.

## Files

The tests are split by role rather than kept in one file:

| File | Holds |
|------|-------|
| `harness_test.go` | Connecting to and verifying the RPC, funding accounts, building, simulating, assembling, submitting and polling; decoding the submitted envelope's credential arm; rendering host failures and extracting their error details. |
| `transfer_test.go` | The native-SAC `transfer(from, to, amount)` operation builder and small `ScVal`/`ScAddress` helpers. |
| `runner_test.go` | The single scenario runner and its parameter table: the record/sign/enforce/assemble/submit shape shared by every scenario, plus decoded-entry and signed-entry diagnostics. |
| `runner_regression_test.go` | The deterministic regression fixture for rejection-path resource headroom. |
| `scenario_ab_test.go` | Scenarios A and B, including the V2 route decision. |
| `scenario_c_test.go` | Scenario C, the multisig account setup, and the single-signature control. |
| `scenario_de_test.go` | Scenarios D and E and the delegates flow that wraps, signs per address, and submits. Scenarios F to I call the same flow. |
| `scenario_fghi_test.go` | Scenarios F to I: the two session-key scenarios and the two threshold scenarios, each asserting the contract's own error code where it expects a refusal. |
| `deploy_test.go` | Uploading a fixture's wasm, instantiating it with that fixture's constructor arguments, and funding a contract with XLM. Holds the `ScVal` encoders the fixtures' constructors need. |
| `results_test.go` | `TestMain` and the writer that produces `RESULTS.md` from a complete run. |

## The fixture contracts

Three contracts, all custom accounts, each existing only so a scenario has
something to authenticate against. All three are deliberately not products: no
policies, no admin functions, no upgradability, and no way to change the key set
after construction. Do not deploy them to mainnet or use them as smart-account
starting points.

- **`contracts/modular-account`** carries no signature of its own and authorizes
  purely by forwarding to CAP-71 delegated signers. Scenarios D and E.
- **`contracts/session-keys`** registers session keys, each valid only inside its
  own ledger window. Scenarios F and G.
- **`contracts/threshold-account`** requires M of its N registered signers before
  it authenticates anything. Scenarios H and I.
- **`contracts/policy-account`** enforces per-period spending limits by inspecting invocation arguments within `__check_auth`.

Each has its own unit tests: `cargo test -p modular-account`,
`cargo test -p session-keys`, `cargo test -p threshold-account`.

### The two clocks in the session-key fixture

Two different ledgers can invalidate a session-key authorization, and two
different pieces of code check them:

- The entry's own `signature_expiration_ledger` is checked by the **host**, in
  `verify_and_consume_nonce`, which runs only *after* the contract's
  `__check_auth` has returned `Ok`
  (rs-soroban-env-host 27.0.1, `src/auth.rs:2492-2515` and `:2586-2602`).
- The session window is checked by the **contract**, inside `__check_auth`,
  against `env.ledger().sequence()`.

`delegatesFlow` sets `signature_expiration_ledger` roughly a thousand ledgers
ahead, so the host's check is not what refuses scenario G: the refusal is the
contract's, on the contract's clock, and the test asserts that contract error
code. The protocol binds the two clocks to nothing but the order they run in, and
`signature_expiration_ledger` is the only one of them a third party can verify
from the submitted entry alone.

### Why the threshold fixture counts attached delegates

`CustomAccount::get_delegated_signers` returns `Vec<Address>`, not the signatures
(soroban-sdk 27.0.6, `src/custom_account.rs:274`), so the contract counts the
delegates **attached** to the entry and then calls `delegate_auth` for each,
which is where the host checks that each one actually signed. A present but wrong
signature therefore fails there and is never counted as one of the M. The count
cannot be inflated by repeating an address either: the host rejects duplicate or
unsorted delegates before the contract runs
(rs-soroban-env-host 27.0.1, `src/auth.rs:2204-2217` and `:2092-2127`).

## RESULTS.md

`RESULTS.md` is written by a run, never by hand. It is only written when all ten
scenarios ran in the same invocation, so it cannot be a partial record of a
single-scenario run. It carries the date, the network and protocol version, and
for every scenario the transaction hash, the ledger, the credential arm observed
on the submitted envelope, an explorer link, and the raw host error verbatim
where there was one.

Whether a result is labelled "accepted" or "rejected as expected" comes from the
scenario's own `ExpectRejection` field, not from a list of IDs in the writer, so
a new rejection scenario cannot be labelled "accepted" by forgetting to add it
somewhere.
