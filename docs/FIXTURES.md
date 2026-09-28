# E2E Contract Fixtures

These small Soroban contracts give the e2e suite concrete account policies to
exercise against a live host. They are deliberately narrow test fixtures, not
products or production starting points. **None of these contracts is audited
or feature-complete.** Their tests prove only the behavior described here; they
do not establish that the contracts are safe for real funds or deployment.

## Fixture Inventory

| Fixture | Implementation | Path exercised | Evidence |
|---|---|---|---|
| Modular account | [`e2e/contracts/modular-account/src/lib.rs`](../e2e/contracts/modular-account/src/lib.rs) | `__check_auth` requires at least one attached delegate, rejects delegates absent from the constructor's fixed signer list, then calls `delegate_auth` for each registered delegate. The account has no signature of its own. | Live scenarios D and E in [`e2e/scenario_de_test.go`](../e2e/scenario_de_test.go): registered delegates authorize; an unregistered delegate produces `UnknownDelegate`. |
| Session keys | [`e2e/contracts/session-keys/src/lib.rs`](../e2e/contracts/session-keys/src/lib.rs) | `__check_auth` checks that every attached delegate is a registered session key and that the current ledger is within that key's inclusive `[valid_from_ledger, valid_until_ledger]` window, then delegates authentication. | Live scenarios F and G in [`e2e/scenario_fghi_test.go`](../e2e/scenario_fghi_test.go): an in-window key is accepted and an expired one is refused with the fixture's `SessionExpired` error. The entry's own signature expiration is a separate host check. |
| Threshold account | [`e2e/contracts/threshold-account/src/lib.rs`](../e2e/contracts/threshold-account/src/lib.rs) | `__check_auth` verifies attached delegates belong to the fixed signer set, requires at least the constructor's M-of-N threshold, and calls `delegate_auth` for each attached signer. | Live scenarios H and I in [`e2e/scenario_fghi_test.go`](../e2e/scenario_fghi_test.go): exactly M signers succeed; M-1 are refused with `InsufficientSignatures`. |
| Policy account | [`e2e/contracts/policy-account/src/lib.rs`](../e2e/contracts/policy-account/src/lib.rs) | `__check_auth` reads `transfer` arguments from the authorization context, adds the requested amount to the current period's spent amount, rejects spending above the configured limit, records allowed spending, and delegates authentication. | Live testnet flows `TestScenarioPolicyWithinLimit` and `TestScenarioPolicyOverLimit` in [`e2e/scenario_de_test.go`](../e2e/scenario_de_test.go): a within-limit transfer succeeds and an over-limit transfer must return `SpendingLimitExceeded`. |
| Passkey wallet | [`e2e/contracts/passkey-wallet/src/lib.rs`](../e2e/contracts/passkey-wallet/src/lib.rs) | `__check_auth` compares the signature's public key to the constructor-registered P-256 key and asks the host to verify the ES256 signature over the authorization payload. It does not verify a WebAuthn ceremony or bind browser `clientDataJSON`. | Live scenarios J and K in [`e2e/scenario_jk_test.go`](../e2e/scenario_jk_test.go): a valid P-256 payload signature is accepted; a corrupted signature is refused by host cryptographic verification. This is not proof of a complete passkey wallet. |
| Social recovery | [`e2e/contracts/social-recovery/src/lib.rs`](../e2e/contracts/social-recovery/src/lib.rs) | Guardian-authorized `initiate_recovery` records a new signer and a 10-ledger delay; permissionless `execute_recovery` refuses before the delay and rotates the stored signer after it. Its `__check_auth` accepts only the current signer through CAP-71 delegation. | The local unit tests in [`e2e/contracts/social-recovery/src/test.rs`](../e2e/contracts/social-recovery/src/test.rs) cover guardian checks, pending recovery, timelock refusal, and signer rotation. This crate is not a member of the `e2e/contracts` Cargo workspace and has no live e2e scenario wired in; its `__check_auth` path is not covered by those unit tests. |

## Scope And Limits

- Constructor-provided signers, guardians, thresholds, windows, and limits are
  deliberately minimal fixture state. Do not infer production key management,
  recovery governance, or policy design from them.
- The e2e suite verifies selected successful and rejected authorization paths.
  It does not audit these contracts, prove untested behavior, or make them
  suitable for mainnet.
- The passkey-wallet fixture tests payload-signature verification only. A real
  WebAuthn wallet must additionally validate the authenticator assertion and
  bind its challenge to the authorization being approved; see
  [`passkeys.md`](passkeys.md).
- Social recovery is source and unit-test material only at present. It is not
  built by `stellar contract build` from the workspace and is not covered by a
  live network scenario.
