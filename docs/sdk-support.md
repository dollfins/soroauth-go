# Supported go-stellar-sdk versions

`soroauth` builds on the Go SDK's XDR types and nothing else from it: every
`SorobanAuthorizationEntry` this library signs is a `go-stellar-sdk` struct.
That makes the SDK version a correctness input, not just a build input, so
which versions are supported — and how the pin moves — is stated here rather
than left to `go.mod` alone.

## Current pin and minimum

`go.mod` requires `github.com/stellar/go-stellar-sdk` v0.7.3 (released
2026-08-06), and the README's install floor is "v0.7.3 or later". v0.7.3 is
also the minimum supported version: the authorization-entry wire types come
from the SDK's `go-xdr` dependency
(`v0.0.0-20260806060815-dc590f17552a`), and an older SDK may carry older
shapes of those types. `adapters/walletsdk` names the same v0.7.3 in its own
`go.mod`, with a `replace` back to the repository root so it is tested
against this checkout.

## Upgrade cadence

Upgrades are deliberate and manual. Automation only watches the GitHub
Actions pins (see `.github/dependabot.yml`, which covers the
`github-actions` ecosystem), so an SDK bump is always a reviewed commit.

There is no fixed schedule, and not every SDK release triggers an upgrade.
The pin moves when the SDK ships something this library needs:

- protocol helpers a supported network requires (the README's CAP-85
  section names the pending case: Protocol 28 helpers, when the SDK
  releases them),
- a security fix in the SDK or in the XDR types it carries,
- an XDR change that affects the authorization-entry wire format.

## What an upgrade must prove

An SDK bump is a commit like any other, and it carries the same evidence:

- `make` (fmt, vet, test) is green.
- `make vectors-check` passes: the preimage, payload and signed entry are
  still byte-identical to `@stellar/stellar-sdk@17.1.0`. A vector that
  disagrees means the Go code is wrong until proven otherwise — vectors are
  never edited by hand.
- A bump that touches protocol behaviour also gets a live run (`make e2e`)
  before it lands.
- The change is recorded in `CHANGELOG.md`, and the README floor, the
  CAP-85 section and this page move together in the same commit. A breaking
  SDK change moves soroauth's own version accordingly, since this project
  adheres to Semantic Versioning (see `CHANGELOG.md`).

## For consumers

`go get` resolves the SDK to at least v0.7.3 through Go's version
selection, because this module requires it. This repository's suite proves
the pinned version only; if your module requires a newer SDK, that
combination is outside what CI checks — pin back to the tested version, or
run the suite against yours before signing anything valuable with it.
