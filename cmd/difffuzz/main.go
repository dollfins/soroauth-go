// Command difffuzz generates a deterministic corpus of structurally valid
// Soroban authorization entries and records the HashIdPreimage and payload this
// library derives from each one, so the JS and Python reference implementations
// can be checked against them.
//
// Why this exists. The golden vectors in testdata/vectors prove that soroauth
// reproduces what @stellar/stellar-sdk emits, byte for byte, for the cases
// someone wrote down. The parity harnesses in testdata/parity-python and
// testdata/parity-rust recompute those same recorded cases with other
// implementations, which rules out a bug the Go library and the JS reference
// share. Neither reaches an entry nobody thought to write. That is the gap this
// generator closes: it produces random entries across every credentials arm,
// delegate trees of random depth, sub-invocation trees of random depth, random
// ScVal arguments, both nonce signs and the int64 edges, and three network
// passphrases. The JS verifier (testdata/differential/verify.mjs) and the Python
// verifier (testdata/parity-python/parity.py pointed at the corpus) must
// reproduce the recorded payload for every one of them. A disagreement is a
// release blocker, not an expected outcome: see testdata/differential/README.md.
//
// Determinism. Every case is derived from a fixed seed by a splitmix64
// generator implemented in this package. math/rand is deliberately not used:
// its output sequence is not covered by the Go compatibility promise, and the
// committed corpus is only a regression corpus if regenerating it reproduces it
// byte for byte. CI regenerates the corpus and fails on drift, exactly as it
// does for the golden vectors.
//
// The corpus is committed. Never edit a file under testdata/differential by
// hand; regenerate it:
//
//	go run ./cmd/difffuzz
//
// A divergence found by a longer run (a different --seed) is committed under
// testdata/differential/regressions/, which the verifiers check too, so it keeps
// being tested even after the sweep seed moves.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

// The defaults are the committed corpus: its directory, its case count and the
// seed it was generated from. Changing any of them changes the committed files,
// which is a deliberate act that ships with the regenerated corpus.
const (
	defaultOutDir      = "testdata/differential/corpus"
	defaultRegressions = "testdata/differential/regressions"
	defaultCases       = 120
	defaultSeed        = 20260927
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "difffuzz: %v\n", err)
		os.Exit(1)
	}
}

// run parses the flags and writes the corpus, or freezes one case. It returns
// an error rather than exiting so a test can exercise it without a subprocess.
func run(args []string) error {
	flags := flag.NewFlagSet("difffuzz", flag.ContinueOnError)
	outDir := flags.String("out", defaultOutDir, "directory the corpus is written to")
	cases := flags.Int("cases", defaultCases, "how many entries to generate")
	seed := flags.Uint64("seed", defaultSeed, "seed for the deterministic generator")
	freeze := flags.String("freeze", "", "a case file to re-record and commit under --into (see testdata/differential/README.md)")
	into := flags.String("into", defaultRegressions, "directory --freeze writes the regression into")
	if err := flags.Parse(args); err != nil {
		return err
	}

	// --freeze is how a divergence found by a fuzzing run becomes a committed
	// regression vector. It is a mode of its own rather than a flag on the
	// sweep so it can never be run by accident while regenerating the corpus.
	if *freeze != "" {
		path, err := freezeCase(*freeze, *into)
		if err != nil {
			return err
		}
		fmt.Printf("froze %s into %s\n", *freeze, path)
		return nil
	}

	if *cases < len(credentialArms) {
		return fmt.Errorf("--cases is %d, need at least %d so every credentials arm appears",
			*cases, len(credentialArms))
	}

	written, err := generateCorpus(*outDir, *cases, *seed)
	if err != nil {
		return err
	}
	fmt.Printf("wrote %d differential cases into %s (seed %d)\n", written, *outDir, *seed)
	return nil
}

// errNoCases is returned when a generator produced nothing, which would make a
// "successful" run that proves nothing.
var errNoCases = errors.New("the generator produced no cases")
