package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// writeArtifact writes a file of exactly size bytes and returns its path.
func writeArtifact(t *testing.T, size int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.wasm")
	require.NoError(t, os.WriteFile(path, make([]byte, size), 0o644))
	return path
}

func TestWASMBudgetWithinBudget(t *testing.T) {
	tests := []struct {
		name     string
		size     int
		args     []string
		wantJSON WASMBudgetResult
	}{
		{
			name:     "under budget",
			size:     1024,
			args:     []string{"--budget", "2048"},
			wantJSON: WASMBudgetResult{Size: 1024, Budget: 2048, Exceeded: false},
		},
		{
			// The budget is a ceiling, not a limit to stay under: an artifact
			// exactly at it passes, and only one strictly larger fails.
			name:     "exactly at budget",
			size:     2048,
			args:     []string{"--budget", "2048"},
			wantJSON: WASMBudgetResult{Size: 2048, Budget: 2048, Exceeded: false},
		},
		{
			name: "with a previous size, grown",
			size: 1024,
			args: []string{"--budget", "2048", "--prev-size", "512"},
			wantJSON: WASMBudgetResult{
				Size: 1024, Budget: 2048, Exceeded: false, PreviousSize: 512, Delta: 512,
			},
		},
		{
			name: "with a previous size, shrunk",
			size: 1024,
			args: []string{"--budget", "2048", "--prev-size", "4096"},
			wantJSON: WASMBudgetResult{
				Size: 1024, Budget: 2048, Exceeded: false, PreviousSize: 4096, Delta: -3072,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeArtifact(t, tt.size)
			var stdout, stderr bytes.Buffer
			err := runWASMBudget(append([]string{"--out", path, "--json"}, tt.args...), &stdout, &stderr)
			assert.NoError(t, err)

			var got WASMBudgetResult
			require.NoError(t, json.Unmarshal(stdout.Bytes(), &got),
				"stdout must be the JSON result and nothing else, got %q", stdout.String())
			assert.Equal(t, tt.wantJSON, got)
			assert.Empty(t, stderr.String(), "nothing belongs on stderr when the build is within budget")
		})
	}
}

func TestWASMBudgetHumanOutput(t *testing.T) {
	path := writeArtifact(t, 1024)
	var stdout, stderr bytes.Buffer
	err := runWASMBudget([]string{"--out", path, "--budget", "2048", "--prev-size", "1024"}, &stdout, &stderr)
	assert.NoError(t, err)

	out := stdout.String()
	for _, want := range []string{"size: 1024 bytes", "budget: 2048 bytes", "previous: 1024 bytes", "delta: +0 bytes", "exceeded: false"} {
		assert.Contains(t, out, want)
	}
	assert.Empty(t, stderr.String())
}

func TestWASMBudgetExceededReturnsAnError(t *testing.T) {
	path := writeArtifact(t, 2048)
	var stdout, stderr bytes.Buffer
	err := runWASMBudget([]string{"--out", path, "--budget", "1024"}, &stdout, &stderr)

	require.Error(t, err)
	// The error names the shortfall, so a CI log says by how much rather than
	// only that something was too big.
	assert.Contains(t, err.Error(), "2048")
	assert.Contains(t, err.Error(), "1024")
	assert.Contains(t, err.Error(), "over the")
}

// TestWASMBudgetStdoutIsResultsOnlyOnTheFailurePath is the acceptance criterion
// for this subcommand: a script pipes stdout to jq and must get parseable JSON
// whether the build passed or failed. The reason it failed is the returned
// error, which main writes to stderr.
func TestWASMBudgetStdoutIsResultsOnlyOnTheFailurePath(t *testing.T) {
	t.Run("json", func(t *testing.T) {
		path := writeArtifact(t, 4096)
		var stdout, stderr bytes.Buffer
		err := runWASMBudget([]string{"--out", path, "--budget", "1024", "--json"}, &stdout, &stderr)
		require.Error(t, err)

		var got WASMBudgetResult
		require.NoError(t, json.Unmarshal(stdout.Bytes(), &got),
			"stdout must still parse as the JSON result when over budget, got %q", stdout.String())
		assert.Equal(t, WASMBudgetResult{Size: 4096, Budget: 1024, Exceeded: true}, got)

		// Nothing diagnostic leaked into stdout: no banner, no "ERROR", and
		// none of the error's own text.
		assert.NotContains(t, strings.ToLower(stdout.String()), "error")
		assert.NotContains(t, stdout.String(), err.Error())
	})

	t.Run("text", func(t *testing.T) {
		path := writeArtifact(t, 4096)
		var stdout, stderr bytes.Buffer
		err := runWASMBudget([]string{"--out", path, "--budget", "1024"}, &stdout, &stderr)
		require.Error(t, err)

		// Every line is a "key: value" result line, nothing else.
		for _, line := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
			assert.Regexp(t, `^[a-z]+: .+$`, line, "unexpected non-result line on stdout: %q", line)
		}
		assert.Contains(t, stdout.String(), "exceeded: true")
		assert.NotContains(t, strings.ToLower(stdout.String()), "error")
	})
}

func TestWASMBudgetMissingArtifact(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runWASMBudget([]string{"--out", filepath.Join(t.TempDir(), "absent.wasm")}, &stdout, &stderr)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "measuring")
	assert.Empty(t, stdout.String(), "stdout must stay empty when there is no result to report")
}

func TestWASMBudgetRejectsInvalidFlags(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"zero budget", []string{"--budget", "0"}, "--budget must be greater than zero"},
		{"negative budget", []string{"--budget", "-1"}, "--budget must be greater than zero"},
		{"negative previous size", []string{"--prev-size", "-1"}, "--prev-size must not be negative"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeArtifact(t, 16)
			var stdout, stderr bytes.Buffer
			err := runWASMBudget(append([]string{"--out", path}, tt.args...), &stdout, &stderr)

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
			assert.Equal(t, ExitUsageError, ExitCode(err))
			assert.Empty(t, stdout.String())
		})
	}
}

func TestWASMBudgetDefaultBudgetIsTheConstant(t *testing.T) {
	// The flag default and the documented constant were once 5 MiB and 3 MiB
	// respectively, so a caller who passed no --budget got a ceiling the
	// documentation did not mention. They are one value now.
	path := writeArtifact(t, 16)
	var stdout, stderr bytes.Buffer
	require.NoError(t, runWASMBudget([]string{"--out", path, "--json"}, &stdout, &stderr))

	var got WASMBudgetResult
	require.NoError(t, json.Unmarshal(stdout.Bytes(), &got))
	assert.Equal(t, int64(WASMBudget), got.Budget)
	assert.Equal(t, int64(7*1024*1024), got.Budget)

	// And the ceiling is above the artifact the build actually produces: it was
	// measured at 6211959 bytes (go1.25.4, darwin/arm64, 2026-09-26). A budget
	// below that makes `make wasm-budget` fail on a clean checkout, which is
	// what both previous values did.
	assert.Greater(t, int64(WASMBudget), int64(6211959),
		"the default budget must exceed the measured size of the core")
}

func TestWASMBudgetBuildCommandFailureKeepsStdoutClean(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runWASMBudget([]string{"--build-cmd", "echo building; exit 1", "--out", "unused.wasm"}, &stdout, &stderr)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "building the artifact")
	assert.Empty(t, stdout.String(), "a failed build produces no result, so stdout stays empty")
	assert.Contains(t, stderr.String(), "building", "the build's own output belongs on stderr")
}
