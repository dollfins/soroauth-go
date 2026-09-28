// Command gencorpus builds the fuzz seed corpora for all fuzz targets
// from the committed golden vectors.
//
// Why generate it rather than hand-write seeds: the golden vectors are the
// entries this library is proven against, so they are exactly the inputs a
// fuzzer should start from — every credential arm, a sub-invocation tree, a
// create-contract invocation, the int64 nonce edges, and three delegate shapes
// including one address at two nesting depths. Starting the fuzzer from real
// entries means its mutations begin inside the space of things that decode,
// instead of spending the budget discovering what a valid entry looks like.
//
// Two details about the output are not free choices:
//
//   - The directory is testdata/fuzz/<TargetName>. Go reads a
//     target's seed corpus from testdata/fuzz/<TargetName>, and only from
//     there; files anywhere else, including directly in testdata/fuzz, are
//     ignored.
//   - The file format is Go's corpus format — the "go test fuzz v1" header
//     followed by one Go literal per fuzz argument — not the raw bytes. A file
//     in that directory that is not in this format fails the package's tests
//     rather than being skipped.
//
// The seed is the decoded entry, not the base64 text, because the target's
// argument is the []byte it hands to UnmarshalBinary.
//
// Run from the repository root:
//
//	go run ./cmd/gencorpus
//
// It is deterministic: the same vectors produce byte-identical corpus files, so
// CI regenerates and fails on drift the same way it does for the vectors.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
)

const (
	vectorsDir = "testdata/vectors"
	fuzzDir    = "testdata/fuzz"
)

// vector is the part of a golden vector this reads: the entry before any
// delegate wrapping, and the entry as it goes to the signer. Both are entries
// the fuzz target can decode, and pre_wrap_entry_xdr is absent from most
// vectors.
type vector struct {
	PreWrapEntryXDR  string `json:"pre_wrap_entry_xdr"`
	UnsignedEntryXDR string `json:"unsigned_entry_xdr"`
}

// targets is the list of fuzz targets that use entry bytes as input.
var targets = []string{
	"FuzzValidateDelegateOrder",
	"FuzzInspect",
	"FuzzPreimage",
	"FuzzDecodeAuthorizationEntry",
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "gencorpus: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	entries, err := os.ReadDir(vectorsDir)
	if err != nil {
		return fmt.Errorf("reading %s: %w", vectorsDir, err)
	}

	// Sorted, so the output does not depend on directory order.
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return fmt.Errorf("no vectors found in %s; run this from the repository root", vectorsDir)
	}

	totalWritten := 0
	for _, target := range targets {
		outDir := filepath.Join(fuzzDir, target)

		// Removed and recreated, so a seed whose vector was deleted or renamed does
		// not linger. A stale seed is not harmless: it is run by every `go test`.
		if err := os.RemoveAll(outDir); err != nil {
			return fmt.Errorf("clearing %s: %w", outDir, err)
		}
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			return fmt.Errorf("creating %s: %w", outDir, err)
		}

		written := 0
		for _, name := range names {
			path := filepath.Join(vectorsDir, name)
			raw, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("reading %s: %w", path, err)
			}

			var v vector
			if err := json.Unmarshal(raw, &v); err != nil {
				return fmt.Errorf("parsing %s: %w", path, err)
			}

			// A malformed vector is an error, not something to skip: a silently
			// skipped vector is a seed the fuzzer never gets, and nothing would
			// say so.
			stem := name[:len(name)-len(".json")]
			for i, encoded := range []string{v.UnsignedEntryXDR, v.PreWrapEntryXDR} {
				if encoded == "" {
					continue
				}
				decoded, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					return fmt.Errorf("decoding entry %d of %s: %w", i, path, err)
				}
				outPath := filepath.Join(outDir, fmt.Sprintf("%s_%d", stem, i))
				if err := os.WriteFile(outPath, corpusFile(decoded), 0o644); err != nil {
					return fmt.Errorf("writing %s: %w", outPath, err)
				}
				written++
			}
		}

		fmt.Printf("wrote %d seeds for %s into %s\n", written, target, outDir)
		totalWritten += written
	}

	// FuzzPayload takes []byte as input but doesn't use entry XDR.
	// We add some basic payload seeds separately.
	if err := writePayloadSeeds(); err != nil {
		return fmt.Errorf("writing payload seeds: %w", err)
	}

	fmt.Printf("total seeds written: %d\n", totalWritten)
	return nil
}

// corpusFile renders one seed in Go's fuzz corpus format: the version header,
// then one Go literal per argument of the fuzz function. All targets take
// a single []byte, so there is one literal.
func corpusFile(data []byte) []byte {
	return []byte("go test fuzz v1\n[]byte(" + strconv.Quote(string(data)) + ")\n")
}

func writePayloadSeeds() error {
	target := "FuzzPayload"
	outDir := filepath.Join(fuzzDir, target)

	if err := os.RemoveAll(outDir); err != nil {
		return fmt.Errorf("clearing %s: %w", outDir, err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", outDir, err)
	}

	seeds := [][]byte{
		{0},
		{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		{0x01, 0x02, 0x03, 0x04},
		{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	}

	for i, seed := range seeds {
		outPath := filepath.Join(outDir, fmt.Sprintf("seed_%d", i))
		if err := os.WriteFile(outPath, corpusFile(seed), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", outPath, err)
		}
	}

	fmt.Printf("wrote %d seeds for %s into %s\n", len(seeds), target, outDir)
	return nil
}
