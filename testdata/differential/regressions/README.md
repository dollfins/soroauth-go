# Frozen divergences

A case lands here when a differential fuzzing run showed the Go, JS and Python
implementations disagreeing on its payload. It is a regression vector: it keeps
being checked by both verifiers (`node verify.mjs` and
`parity.py --vectors regressions`) long after the sweep that found it has moved
on, because the swept corpus is a function of `--seed` and this directory is
not.

Freeze a case with:

```sh
go run ./cmd/difffuzz -freeze <path-to-case.json>
```

which re-records the case from the entry it carries and writes it here with a
`regression_` name prefix. Never edit a frozen case by hand.

This directory is empty until the first divergence. An empty regressions
directory is not a claim that the implementations agree — the swept corpus in
`../corpus/` is where that is checked on every run.
