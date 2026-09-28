package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// WASMBudget is the default maximum size, in bytes, for the compiled js/wasm
// signing core. The core is downloaded by a browser, so its size is worth
// failing a build over rather than noticing after a release; --budget overrides
// it for a caller measuring something else.
//
// This is a ceiling set above a measured size, not an aspiration. The 3 MiB it
// replaced could never have passed, and neither could the 5 MiB the flag
// defaulted to separately:
//
//	$ ./wasm/build.sh && ls -l wasm/dist/soroauth.wasm
//	6211959 wasm/dist/soroauth.wasm
//
// measured 2026-09-26 with go1.25.4 on darwin/arm64. 7 MiB leaves 1128073 bytes
// of headroom, which is room for the toolchain to grow the binary a little
// between releases without a red build that says nothing about the change that
// triggered it.
//
// Lower it as the core shrinks — that is the point of having it — but never
// without a fresh measurement named in the commit body. Go WASM binaries are
// large mostly because of the runtime, so a real reduction means changing what
// the core links, not tightening this number.
const WASMBudget = 7 * 1024 * 1024 // 7 MiB

// WASMBudgetResult is the wasm-budget subcommand's result, and the shape of its
// --json output.
//
// Sizes are bytes, as int64. There is no human-formatted "3.0 MiB" field: that
// needs floating-point division, and this project uses no floats anywhere (a
// float is not exact, and a size that matters is one a script compares, not one
// a person reads).
type WASMBudgetResult struct {
	// Size is the measured size of the artifact, in bytes.
	Size int64 `json:"size"`
	// Budget is the ceiling it was measured against, in bytes.
	Budget int64 `json:"budget"`
	// Exceeded is true when Size is strictly greater than Budget. A binary
	// exactly at the budget passes.
	Exceeded bool `json:"exceeded"`
	// PreviousSize is the --prev-size the delta was computed against, omitted
	// when none was given.
	PreviousSize int64 `json:"previous_size,omitempty"`
	// Delta is Size minus PreviousSize, omitted when no previous size was
	// given. Negative means the artifact shrank.
	Delta int64 `json:"delta,omitempty"`
}

const wasmBudgetUsage = `soroauth wasm-budget — measure the wasm core against a size ceiling.

usage:
  soroauth wasm-budget [--out <path>] [--budget <bytes>] [--prev-size <bytes>] \
                       [--build-cmd <command>] [--json]

Measures the file at --out and exits non-zero if it is larger than --budget.
The default budget is 7 MiB (7340032 bytes); a binary exactly at the budget
passes, and only one strictly larger fails.

With --prev-size, reports the delta against a previous release's size, so a
build that grows can be seen growing rather than only when it crosses the line.

--build-cmd runs a command first, for a caller that wants measuring and building
in one step:

  soroauth wasm-budget --build-cmd ./wasm/build.sh --out wasm/dist/soroauth.wasm

Prints the result to stdout, as text or, with --json, as a JSON object with
fields "size", "budget", "exceeded", "previous_size" and "delta". On the
over-budget path stdout still carries only the result: the diagnostic goes to
stderr, so a script can read stdout without filtering it.

exit codes:
  0  within budget
  1  over budget, or the artifact could not be measured
  2  usage error (invalid flags)
`

// runWASMBudget measures the built wasm artifact against a size ceiling.
//
// stdout carries the result and nothing else, on the failure path too: the
// reason it failed travels in the returned error, which main writes to stderr.
// That split is what lets `soroauth wasm-budget --json | jq` work whether the
// build is over budget or under it.
func runWASMBudget(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("wasm-budget", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		fmt.Fprint(stderr, wasmBudgetUsage)
		fmt.Fprintln(stderr, "\nflags:")
		fs.PrintDefaults()
	}

	jsonOutput := fs.Bool("json", false, "output the result as JSON")
	wasmOut := fs.String("out", "wasm/dist/soroauth.wasm", "path to the wasm artifact to measure")
	budgetBytes := fs.Int64("budget", WASMBudget, "maximum allowed size in bytes")
	prevSize := fs.Int64("prev-size", 0, "previous release's size, for a delta")
	buildCmd := fs.String("build-cmd", "", "command to build the artifact before measuring")

	if err := fs.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}
	if *budgetBytes <= 0 {
		return newErrorf(ExitUsageError, "--budget must be greater than zero, got %d", *budgetBytes)
	}
	if *prevSize < 0 {
		return newErrorf(ExitUsageError, "--prev-size must not be negative, got %d", *prevSize)
	}

	if *buildCmd != "" {
		// Output goes to stderr, not stdout: the build's chatter is not this
		// command's result, and a caller piping stdout to jq must not receive it.
		cmd := exec.Command("sh", "-c", *buildCmd)
		output, err := cmd.CombinedOutput()
		if err != nil {
			if len(output) > 0 {
				fmt.Fprintf(stderr, "%s\n", output)
			}
			return fmt.Errorf("wasm budget: building the artifact: %w", err)
		}
	}

	fi, err := os.Stat(*wasmOut)
	if err != nil {
		return fmt.Errorf("wasm budget: measuring %s: %w", *wasmOut, err)
	}

	result := WASMBudgetResult{
		Size:     fi.Size(),
		Budget:   *budgetBytes,
		Exceeded: fi.Size() > *budgetBytes,
	}
	if *prevSize > 0 {
		result.PreviousSize = *prevSize
		result.Delta = fi.Size() - *prevSize
	}

	if *jsonOutput {
		encoded, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("wasm budget: encoding the result: %w", err)
		}
		fmt.Fprintln(stdout, string(encoded))
	} else {
		fmt.Fprintf(stdout, "size: %d bytes\nbudget: %d bytes\n", result.Size, result.Budget)
		if result.PreviousSize > 0 {
			fmt.Fprintf(stdout, "previous: %d bytes\ndelta: %+d bytes\n", result.PreviousSize, result.Delta)
		}
		if result.Exceeded {
			fmt.Fprintln(stdout, "exceeded: true")
		} else {
			fmt.Fprintln(stdout, "exceeded: false")
		}
	}

	if result.Exceeded {
		return fmt.Errorf("wasm budget: %s is %d bytes, over the %d byte budget by %d",
			*wasmOut, result.Size, result.Budget, result.Size-result.Budget)
	}
	return nil
}
