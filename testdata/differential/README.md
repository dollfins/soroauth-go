# Differential fuzzing across implementations

The golden vectors in `../vectors/` prove that soroauth reproduces what
`@stellar/stellar-sdk` emits, for the cases someone wrote down. The parity
harnesses in `../parity-python/` and `../parity-rust/` recompute those same
recorded cases with other implementations, which rules out a bug the Go library
and the JS reference share. Neither reaches an entry nobody thought to write.

This harness does. `cmd/difffuzz` generates random, structurally valid Soroban
authorization entries — every credentials arm, delegate trees of random depth,
sub-invocation trees of random depth, random `ScVal` arguments, both nonce signs
and the `int64` edges, three network passphrases — and records the
`HashIdPreimage` and payload soroauth derives from each one. Every recorded
payload is then recomputed by two independent implementations:

| Implementation | Reference | Pinned by |
|---|---|---|
| Go (the recorder) | this library | `go.mod` |
| JS | `@stellar/stellar-sdk` | `package.json`, `package-lock.json` |
| Python | `stellar-sdk` (PyPI) | `../parity-python/requirements.txt` |

All three have to agree. **A divergence is a release blocker, not a test
flake.** It means one of the implementations is wrong, and any of them being
wrong is a signature bug.

## Running it

```sh
make differential
```

or by hand, from the repository root:

```sh
go run ./cmd/difffuzz                                  # regenerate the corpus
cd testdata/differential && npm ci && node verify.mjs   # JS recomputes it
python3 ../parity-python/parity.py --vectors corpus     # Python recomputes it
```

The Python side is the existing parity harness
(`testdata/parity-python/parity.py`) pointed at this corpus with `--vectors`,
so there is only one Python recomputation in the repository rather than two
that could drift apart. It needs the pinned SDK; `make differential` installs
it into `.venv-parity`.

## What the corpus contains

`corpus/` is generated, committed and drift-checked. CI regenerates it with
`go run ./cmd/difffuzz` and fails if the committed files changed, exactly as it
does for the golden vectors.

Each case is a JSON file with the same fields the parity harness already reads
(`unsigned_entry_xdr`, `network_passphrase`, `valid_until_ledger`,
`preimage_xdr`, `payload_hex`) plus a few this harness adds (`schema_version`,
`generator`, `seed`, `index`, `credential_arm`). A reader that does not know
`schema_version` must refuse the case rather than guess.

**Never edit a case by hand.** Regenerate it:

```sh
go run ./cmd/difffuzz
```

The generator is deterministic: a splitmix64 sequence seeded by `--seed`
(default `20260927`), implemented in `cmd/difffuzz` rather than taken from
`math/rand`, whose output sequence is not covered by the Go compatibility
promise. `TestPRNGSequenceIsPinned` pins that sequence, so the committed corpus
cannot change without the change being visible.

## When a divergence is found

Do not edit a case to make a verifier pass, and do not delete it. Freeze it:

```sh
go run ./cmd/difffuzz -freeze testdata/differential/corpus/<case>.json
```

That re-records the case from the entry it carries and writes it into
`regressions/`, which both verifiers check alongside the swept corpus. Freezing
matters because the sweep is a function of `--seed`: without it, the case that
diverged would disappear the next time the seed moved, and the regression would
stop being tested. Then open an issue with the case and the protocol reference
(CAP-46-11, CAP-71-01, CAP-71-02).

`regressions/` is empty until there is something to put in it. The mechanism is
exercised by `TestFreezeCaseWritesARegression`.

## What the harness proves, and what it does not

It proves that, over the entries it generated, the three implementations agree
on the signed bytes. It does **not** prove the entries are entries a network
would accept, and it is not an audit: agreement among three implementations is
strong evidence and it is not the same thing as the host having accepted a
transaction. The live proof is in `../../e2e/RESULTS.md`.

Source-account cases have no preimage — the transaction envelope authenticates
them (CAP-46-11) — so the corpus records neither a preimage nor a payload for
them and both verifiers skip them. Skips are printed on stderr, named, and
counted, and a run that checks nothing exits non-zero, so the harness cannot
pass by doing nothing.
