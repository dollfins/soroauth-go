package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// TestPRNGSequenceIsPinned pins the generator's arithmetic. The committed
// corpus is a function of this sequence, so the sequence is part of the
// artefact: a change to it must fail here and be shipped with a regenerated
// corpus, rather than silently changing what every committed case contains.
//
// The values are the splitmix64 outputs for seed 1, which is the algorithm's
// published definition applied to that seed (see prng's doc comment). Seed 0's
// first output is the published 0xe220a8397b1dcdaf, which is a useful sanity
// check that the constants are the standard ones and not a transcription slip.
func TestPRNGSequenceIsPinned(t *testing.T) {
	if got := newPRNG(0).next(); got != 0xe220a8397b1dcdaf {
		t.Fatalf("splitmix64 seed 0 draw 0 is %#016x, want the published %#016x",
			got, uint64(0xe220a8397b1dcdaf))
	}

	want := []uint64{
		0x910a2dec89025cc1,
		0xbeeb8da1658eec67,
		0xf893a2eefb32555e,
		0x71c18690ee42c90b,
		0x71bb54d8d101b5b9,
		0xc34d0bff90150280,
	}
	rng := newPRNG(1)
	for i, expected := range want {
		if got := rng.next(); got != expected {
			t.Fatalf("splitmix64 seed 1 draw %d is %#016x, want %#016x", i, got, expected)
		}
	}
}

// TestPRNGBytesAreStable checks the byte stream the case builder actually
// consumes is a pure function of the sequence, so two runs of the same seed
// cannot differ.
func TestPRNGBytesAreStable(t *testing.T) {
	first := newPRNG(42).bytes(40)
	second := newPRNG(42).bytes(40)
	if !bytes.Equal(first, second) {
		t.Fatal("bytes() is not deterministic for one seed")
	}
	if len(first) != 40 {
		t.Fatalf("bytes(40) returned %d bytes", len(first))
	}
	// A short request must not consume a whole draw's worth of state, or two
	// different shapes would diverge for no reason.
	if bytes.Equal(newPRNG(42).bytes(8), newPRNG(42).bytes(40)[:8]) == false {
		t.Error("bytes(8) does not prefix bytes(40) for the same seed")
	}
}

func TestGenerateCorpusIsDeterministic(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	for _, dir := range []string{first, second} {
		if _, err := generateCorpus(dir, 12, 7); err != nil {
			t.Fatalf("generateCorpus(%s): %v", dir, err)
		}
	}
	compareCorpusDirs(t, first, second)
}

func TestGenerateCorpusChangesWithTheSeed(t *testing.T) {
	first := t.TempDir()
	second := t.TempDir()
	if _, err := generateCorpus(first, 12, 1); err != nil {
		t.Fatalf("generateCorpus: %v", err)
	}
	if _, err := generateCorpus(second, 12, 2); err != nil {
		t.Fatalf("generateCorpus: %v", err)
	}

	different := false
	entries, err := os.ReadDir(first)
	if err != nil {
		t.Fatalf("reading %s: %v", first, err)
	}
	for _, entry := range entries {
		a, err := os.ReadFile(filepath.Join(first, entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		b, err := os.ReadFile(filepath.Join(second, entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		if !bytes.Equal(a, b) {
			different = true
			break
		}
	}
	if !different {
		t.Error("two seeds produced identical corpora; --seed has no effect")
	}
}

func TestGenerateCorpusCoversEveryArm(t *testing.T) {
	dir := t.TempDir()
	if _, err := generateCorpus(dir, len(credentialArms)*2, 3); err != nil {
		t.Fatalf("generateCorpus: %v", err)
	}

	seen := map[string]int{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, entry := range entries {
		raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		// Unknown fields rejected: the generator and its reader must agree.
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		var doc corpusCase
		if err := decoder.Decode(&doc); err != nil {
			t.Fatalf("decoding %s: %v", entry.Name(), err)
		}
		seen[doc.CredentialArm]++
	}

	for _, arm := range credentialArms {
		if seen[arm] == 0 {
			t.Errorf("no %s case was generated", arm)
		}
	}
}

// TestGenerateCorpusRecordsRecomputableValues is the generator's own
// consistency check: what it records must be what Preimage and Payload produce
// from the entry it recorded.
func TestGenerateCorpusRecordsRecomputableValues(t *testing.T) {
	dir := t.TempDir()
	if _, err := generateCorpus(dir, 12, 11); err != nil {
		t.Fatalf("generateCorpus: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, entry := range entries {
		t.Run(entry.Name(), func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				t.Fatalf("reading %s: %v", entry.Name(), err)
			}
			var doc corpusCase
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("decoding %s: %v", entry.Name(), err)
			}

			var decoded xdr.SorobanAuthorizationEntry
			if err := xdr.SafeUnmarshalBase64(doc.UnsignedEntryXDR, &decoded); err != nil {
				t.Fatalf("decoding the entry: %v", err)
			}

			preimageXDR, payloadHex, err := recordDerived(decoded, doc.ValidUntilLedger, doc.NetworkPassphrase)
			if err != nil {
				t.Fatalf("recordDerived: %v", err)
			}
			if preimageXDR != doc.PreimageXDR || payloadHex != doc.PayloadHex {
				t.Errorf("recorded values do not recompute:\n  recorded preimage %s\n    recomputed    %s\n  recorded payload  %s\n    recomputed      %s",
					doc.PreimageXDR, preimageXDR, doc.PayloadHex, payloadHex)
			}
		})
	}
}

// TestFreezeCaseWritesARegression proves the mechanism a divergence is
// committed through: the frozen file names itself as a regression, records the
// flag it was written with, and carries values that recompute from the entry it
// carries.
func TestFreezeCaseWritesARegression(t *testing.T) {
	source := t.TempDir()
	if _, err := generateCorpus(source, len(credentialArms), 5); err != nil {
		t.Fatalf("generateCorpus: %v", err)
	}

	casePath := filepath.Join(source, "diff_002_address_v2.json")
	into := t.TempDir()
	written, err := freezeCase(casePath, into)
	if err != nil {
		t.Fatalf("freezeCase: %v", err)
	}
	if got, want := filepath.Base(written), "regression_diff_002_address_v2.json"; got != want {
		t.Fatalf("froze to %s, want %s", got, want)
	}

	raw, err := os.ReadFile(written)
	if err != nil {
		t.Fatalf("reading the frozen case: %v", err)
	}
	var doc corpusCase
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		t.Fatalf("decoding the frozen case: %v", err)
	}
	if !strings.HasPrefix(doc.Generator, "cmd/difffuzz --freeze") {
		t.Errorf("frozen generator is %q, want it stamped as a freeze", doc.Generator)
	}

	var decoded xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(doc.UnsignedEntryXDR, &decoded); err != nil {
		t.Fatalf("decoding the frozen entry: %v", err)
	}
	preimageXDR, payloadHex, err := recordDerived(decoded, doc.ValidUntilLedger, doc.NetworkPassphrase)
	if err != nil {
		t.Fatalf("recordDerived: %v", err)
	}
	if preimageXDR != doc.PreimageXDR || payloadHex != doc.PayloadHex {
		t.Error("the frozen case's recorded values do not recompute from its entry")
	}
}

func TestRunRejectsFewerCasesThanArms(t *testing.T) {
	if err := run([]string{"--out", t.TempDir(), "--cases", "2"}); err == nil {
		t.Error("run accepted fewer cases than there are credentials arms")
	}
}

// compareCorpusDirs asserts two corpus directories hold byte-identical cases
// with the same names.
func compareCorpusDirs(t *testing.T, first, second string) {
	t.Helper()

	entries, err := os.ReadDir(first)
	if err != nil {
		t.Fatalf("reading %s: %v", first, err)
	}
	if len(entries) == 0 {
		t.Fatalf("%s is empty", first)
	}

	for _, entry := range entries {
		a, err := os.ReadFile(filepath.Join(first, entry.Name()))
		if err != nil {
			t.Fatalf("reading %s: %v", entry.Name(), err)
		}
		b, err := os.ReadFile(filepath.Join(second, entry.Name()))
		if err != nil {
			t.Fatalf("reading %s from the second run: %v", entry.Name(), err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs between two runs of the same seed", entry.Name())
		}
	}
}
