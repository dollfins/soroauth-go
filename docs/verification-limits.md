# What `soroauth verify` Can and Cannot Establish

The `verify` subcommand (and the `VerifyEntry` library function it wraps) performs
**offline, cryptographic verification** of the signatures already present on an
authorization entry. It answers one precise question:

> Do the signatures on this entry verify over the payload that the entry itself
> commits to, given the network and the expiration ledger stored on the entry?

## What a `verified` Result Guarantees

- Every credential node that carries a **classic account signature** — the built-in
  vector holding exactly one `{public_key, signature}` map — has a signature that
  verifies correctly over the payload derived from the entry's own fields:
  credentials arm, nonce, address (for V2 and delegates), invocation tree, and
  the `SignatureExpirationLedger` stored on the entry.
- The entry has not been tampered with after signing: changing any field that
  feeds the preimage (nonce, expiration, invocation, network) would cause the
  payload to change and the verification to fail.
- For the delegates arm, every delegate that signed is reported as verified.
  The top-level node is allowed to be unsigned (Void) when only delegates
  authenticate, per CAP-71-01; such a node is reported as `unsigned`, not
  `invalid`.

## What a `verified` Result Does **Not** Guarantee

| Concern | Why it is not covered offline |
|---------|-------------------------------|
| **The transaction will succeed on-chain** | Verification checks signatures only. It does not check fees, resource limits, contract logic, ledger state, or whether the account's threshold is met. |
| **The signing key is actually a signer of the account** | A classic account signature contains the public key that signed. Whether that key is currently a signer of the account, with enough weight to meet the threshold, is account state that only the ledger knows. |
| **A custom account (smart wallet) accepts the signature** | A node addressed to a `C…` contract, or one whose signature is not the built-in account shape, is reported as `cannot_check`. Only the contract's `__check_auth` defines validity; the host decides at submission time. |
| **The nonce has not been consumed** | Nonces are tracked per-account in the ledger. Offline code cannot know whether a nonce was already used in another transaction that was accepted earlier. |
| **The expiration is still valid at submission time** | The host rejects when `current_ledger > signatureExpirationLedger`. Offline verification rebuilds the payload from the expiration stored on the entry; it cannot know what the ledger sequence will be when the transaction is submitted. |
| **The expiration is not "too late"** | The network enforces a maximum `signatureExpirationLedger` (`max_live_until_ledger`). This is a network setting the library cannot know offline. |
| **The entry is the one that will be submitted** | A caller can verify an entry, then modify it before submission. Only the bytes actually submitted matter. |
| **Delegate policy is satisfied** | A delegates entry may have a policy (e.g., 2-of-3) that requires a specific subset of delegates to sign. Offline verification reports each node individually; it does not evaluate the account's policy. |

## Summary

| Verdict | Meaning |
|---------|---------|
| `verified` | Classic account signature; signature verifies over the entry's payload. |
| `unsigned` | No signature present (Void or empty vector). Legitimate for a delegates top-level node under CAP-71-01. |
| `invalid` | Classic account signature present but does not verify — the entry was tampered with or signed over a different payload. |
| `cannot_check` | Signature shape is not the built-in account shape (custom account, contract node, or unrecognised). Only the contract can decide. |

**Bottom line:** `verify` tells you whether the signatures on the entry are
cryptographically consistent with the entry's own fields. It does not replace
simulation, fee estimation, or on-chain submission. A green result means
"the signatures check out," not "the transaction will succeed."