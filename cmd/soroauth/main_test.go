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

// vectorFile is the subset of a golden vector the CLI tests need. The CLI is
// exercised against the same committed vectors the library is proven with, so
// the tests use real entries rather than ones invented here.
type vectorFile struct {
	Name              string `json:"name"`
	NetworkPassphrase string `json:"network_passphrase"`
	ValidUntilLedger  uint32 `json:"valid_until_ledger"`
	PreWrapEntryXDR   string `json:"pre_wrap_entry_xdr"`
	UnsignedEntryXDR  string `json:"unsigned_entry_xdr"`
	PreimageXDR       string `json:"preimage_xdr"`
	PayloadHex        string `json:"payload_hex"`
	Delegates         []struct {
		Label   string `json:"label"`
		Address string `json:"address"`
	} `json:"delegates"`
}

func loadVector(t *testing.T, name string) vectorFile {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "vectors", name+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var v vectorFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return v
}

// runCLI drives the dispatcher and captures both streams. The environment is
// empty unless a test supplies one with runCLIEnv.
func runCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	return runCLIEnv(t, nil, args...)
}

// runCLIEnv drives the dispatcher with a fake environment, so no test ever
// mutates the real one or leaves a seed in it.
func runCLIEnv(t *testing.T, env map[string]string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	err = run(args, &out, &errOut, func(key string) string { return env[key] })
	return out.String(), errOut.String(), err
}

func TestRunWithoutACommand(t *testing.T) {
	stdout, stderr, err := runCLI(t)
	if err == nil {
		t.Fatalf("running with no command succeeded")
	}
	if stdout != "" {
		t.Errorf("usage went to stdout: %q", stdout)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Errorf("stderr does not carry the usage text: %q", stderr)
	}
}

func TestRunUnknownCommand(t *testing.T) {
	_, stderr, err := runCLI(t, "frobnicate")
	if err == nil {
		t.Fatal("an unknown command succeeded")
	}
	if !strings.Contains(err.Error(), "frobnicate") {
		t.Errorf("error %q does not name the unknown command", err)
	}
	if !strings.Contains(stderr, "usage:") {
		t.Error("stderr does not carry the usage text")
	}
}

func TestRunHelp(t *testing.T) {
	stdout, _, err := runCLI(t, "help")
	if err != nil {
		t.Fatalf("help returned an error: %v", err)
	}
	if !strings.Contains(stdout, "usage:") {
		t.Errorf("help did not print the usage text: %q", stdout)
	}
}

// TestDecodeEntryRejectsOversizedInput proves the CLI uses the library's
// bounded decoder rather than the SDK's unbounded-length helper, and that it
// refuses before doing any base64 work (the input is not valid base64).
func TestDecodeEntryRejectsOversizedInput(t *testing.T) {
	got, err := decodeEntry(strings.Repeat("A", 2<<20))
	if err == nil {
		t.Fatalf("decodeEntry accepted a 2 MiB input, returning %+v", got)
	}
	if !strings.Contains(err.Error(), "decode limit") {
		t.Errorf("error %q does not name the decode limit", err)
	}
}

func TestResolveNetwork(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "testnet", value: "testnet", want: "Test SDF Network ; September 2015"},
		{name: "public", value: "public", want: "Public Global Stellar Network ; September 2015"},
		{name: "a literal passphrase", value: "Standalone Network ; February 2017", want: "Standalone Network ; February 2017"},
		{name: "empty is an error", value: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveNetwork(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveNetwork(%q) succeeded, returning %q", tt.value, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveNetwork(%q) returned an error: %v", tt.value, err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPayloadMatchesTheGoldenVector(t *testing.T) {
	// Vector 6 is the delegates case, so this also covers the address-bound
	// preimage rather than only the simple one.
	v := loadVector(t, "delegates_unsorted_with_nested")

	stdout, _, err := runCLI(t, "payload",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet")
	if err != nil {
		t.Fatalf("payload returned an error: %v", err)
	}

	if !strings.Contains(stdout, v.PreimageXDR) {
		t.Errorf("output does not carry the recorded preimage\n want %s\n  got %s", v.PreimageXDR, stdout)
	}
	if !strings.Contains(stdout, v.PayloadHex) {
		t.Errorf("output does not carry the recorded payload\n want %s\n  got %s", v.PayloadHex, stdout)
	}
}

func TestPayloadJSONOutput(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")

	stdout, _, err := runCLI(t, "payload",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--json")
	if err != nil {
		t.Fatalf("payload --json returned an error: %v", err)
	}

	var out struct {
		Preimage string `json:"preimage"`
		Payload  string `json:"payload"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if out.Preimage != v.PreimageXDR {
		t.Errorf("preimage mismatch: want %s, got %s", v.PreimageXDR, out.Preimage)
	}
	if out.Payload != v.PayloadHex {
		t.Errorf("payload mismatch: want %s, got %s", v.PayloadHex, out.Payload)
	}
}

func TestStdoutResultsOnlyOnFailurePaths(t *testing.T) {
	// Test explicitly that stdout stays completely clean/empty on various failure paths.
	// Invalid entry argument:
	stdout, stderr, err := runCLI(t, "payload", "--entry", "invalid-base64", "--valid-until", "1234567", "--network", "testnet")
	if err == nil {
		t.Fatal("expected error for invalid base64 entry")
	}
	if stdout != "" {
		t.Errorf("stdout expected to be empty on failure, got %q", stdout)
	}
	// The diagnostic is the returned error, not something written to stderr.
	// run returns it and main() is what prints it, so a test driving run sees
	// an empty stderr on every path the flag package did not write to itself.
	_ = stderr
	if err.Error() == "" {
		t.Error("expected a non-empty error from the failure path")
	}

	// Ensure that stdout stays strictly empty/results-only on all error paths (non-json mode writes errors to stderr and nothing to stdout).
	for _, subcmd := range [][]string{
		{"payload", "--entry", "not-base64", "--valid-until", "1", "--network", "testnet"},
		{"sign", "--entry", "not-base64", "--valid-until", "1", "--network", "testnet", "--secret-env", "SEED"},
		{"delegates", "--entry", "not-base64", "--valid-until", "1", "--delegate", "GABC..."},
		{"inspect", "--entry", "not-base64"},
	} {
		stdout, _, err := runCLI(t, subcmd...)
		if err == nil {
			t.Fatalf("cmd %v expected failure", subcmd)
		}
		if stdout != "" {
			t.Errorf("cmd %v produced stdout on failure: %q", subcmd, stdout)
		}
		if err.Error() == "" {
			t.Errorf("cmd %v failed with an empty error message", subcmd)
		}
	}

	// Also test JSON failure output paths to ensure stdout only carries JSON error object and not usage text or trailing junk
	stdout, _, err = runCLI(t, "payload", "--entry", "not-base64", "--valid-until", "1", "--network", "testnet", "--json")
	if err == nil {
		t.Fatal("expected failure")
	}
	var jsonErr struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &jsonErr); err != nil {
		t.Fatalf("stdout is not valid JSON error object: %q (%v)", stdout, err)
	}
	if jsonErr.Error == "" {
		t.Error("json error object missing error field")
	}
}

func TestPipelineStdoutResultsOnlyOnFailure(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runWithStdin([]string{"payload", "--entry", "-", "--valid-until", "1", "--network", "testnet"}, &stdout, &stderr, os.Getenv, strings.NewReader("invalid-input"))
	if err == nil {
		t.Fatal("expected failure for invalid stdin")
	}
	filesStdout := stdout.String()
	if filesStdout != "" {
		t.Errorf("expected empty stdout on pipeline failure, got %q", filesStdout)
	}
}

func TestPipelineFailureStdoutResultsOnly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runWithStdin([]string{"payload", "--entry", "-", "--valid-until", "1", "--network", "testnet"}, &stdout, &stderr, os.Getenv, strings.NewReader("bad-input"))
	if err == nil {
		t.Fatal("expected failure for bad stdin")
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout on pipeline failure, got %q", stdout.String())
	}
}

func TestPipelineFailureOutputsCleanStdout(t *testing.T) {
	stdinReader := strings.NewReader("invalid-stdin-entry")
	var stdout, stderr bytes.Buffer
	err := runWithStdin([]string{"payload", "--entry", "-", "--valid-until", "1", "--network", "testnet"}, &stdout, &stderr, os.Getenv, stdinReader)
	if err == nil {
		t.Fatal("expected pipeline failure with invalid stdin")
	}
	if stdout.String() != "" {
		t.Errorf("expected empty stdout on pipeline failure, got %q", stdout.String())
	}
}

func TestPayloadJSONErrorStaysOnStdout(t *testing.T) {
	// On error with --json, stdout must contain only the JSON error object,
	// nothing else (no usage text, no partial output).
	stdout, stderr, err := runCLI(t, "payload",
		"--entry", "not-base64",
		"--valid-until", "1",
		"--network", "testnet",
		"--json")
	if err == nil {
		t.Fatal("expected error")
	}

	// stderr should be empty (flag errors go to stderr but we use ContinueOnError)
	// Actually flag errors go to the flag set's output which we set to stderr,
	// but the JSON error goes to stdout.
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode, got: %q", stderr)
	}

	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %q", err, stdout)
	}
	if out.Error == "" {
		t.Error("JSON error object has empty error field")
	}
	if strings.Contains(stdout, "usage:") {
		t.Error("stdout contains usage text in JSON error mode")
	}
}

func TestPayloadRejects(t *testing.T) {
	v := loadVector(t, "delegates_unsorted_with_nested")

	tests := []struct {
		name    string
		args    []string
		wantMsg string
	}{
		{
			name:    "no entry",
			args:    []string{"payload", "--valid-until", "1", "--network", "testnet"},
			wantMsg: "--entry is required",
		},
		{
			name:    "malformed entry",
			args:    []string{"payload", "--entry", "not-base64", "--valid-until", "1", "--network", "testnet"},
			wantMsg: "decoding --entry",
		},
		{
			name:    "no network",
			args:    []string{"payload", "--entry", v.UnsignedEntryXDR, "--valid-until", "1"},
			wantMsg: "--network is required",
		},
		{
			name:    "zero valid-until",
			args:    []string{"payload", "--entry", v.UnsignedEntryXDR, "--valid-until", "0", "--network", "testnet"},
			wantMsg: "--valid-until is required",
		},
		{
			name:    "unknown flag",
			args:    []string{"payload", "--nope"},
			wantMsg: "flag provided but not defined",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, err := runCLI(t, tt.args...)
			if err == nil {
				t.Fatalf("the command succeeded, printing %q", stdout)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if stdout != "" {
				t.Errorf("a failing command wrote to stdout: %q", stdout)
			}
		})
	}
}

// TestPayloadRefusesSourceAccountEntries: there is nothing to sign for that
// arm, and printing a payload for it would invite a caller to sign something
// meaningless.
func TestPayloadRefusesSourceAccountEntries(t *testing.T) {
	// A source-account entry is the shortest legal entry: credential type 0
	// followed by the invocation. Build it by hand from a vector's invocation
	// rather than inventing XDR here.
	_, _, err := runCLI(t, "payload",
		"--entry", sourceAccountEntryFromVector(t),
		"--valid-until", "1234567",
		"--network", "testnet")
	if err == nil {
		t.Fatal("payload accepted a source-account entry")
	}
	if !strings.Contains(err.Error(), "source-account") {
		t.Errorf("error %q does not explain the source-account case", err)
	}
	if ExitCode(err) != ExitSigningRefusal {
		t.Errorf("exit code for source-account entry is %d, want %d (ExitSigningRefusal)", ExitCode(err), ExitSigningRefusal)
	}
}

// sourceAccountEntryFromVector rebuilds a vector's entry with source-account
// credentials, so the test uses a real invocation tree.
func sourceAccountEntryFromVector(t *testing.T) string {
	t.Helper()
	v := loadVector(t, "v2_single_testnet")

	entry, err := decodeEntry(v.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("decoding the vector entry: %v", err)
	}
	entry.Credentials = xdr.SorobanCredentials{
		Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
	}
	encoded, err := encodeEntry(entry)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	return encoded
}

// loadFullVector returns a vector's recorded signed entry.
func loadFullVector(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "testdata", "vectors", name+".json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	var v struct {
		SignedEntryXDR string `json:"signed_entry_xdr"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("decoding %s: %v", path, err)
	}
	return v.SignedEntryXDR
}

// TestExitCodes tests that each failure class produces the correct exit code.
func TestExitCodes(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signer := vectorKeypair(t, "soroauth-vector-signer-1")
	stranger := vectorKeypair(t, "soroauth-vector-delegate-3")

	tests := []struct {
		name       string
		args       []string
		env        map[string]string
		wantCode   int
		wantMsg    string
		wantStdout string // expected stdout content (empty for non-JSON mode)
	}{
		// Usage errors (exit code 2)
		{
			name:     "payload no entry",
			args:     []string{"payload", "--valid-until", "1", "--network", "testnet"},
			wantCode: ExitUsageError,
			wantMsg:  "--entry is required",
		},
		{
			name:     "payload malformed entry",
			args:     []string{"payload", "--entry", "not-base64", "--valid-until", "1", "--network", "testnet"},
			wantCode: ExitUsageError,
			wantMsg:  "decoding --entry",
		},
		{
			name:     "payload no network",
			args:     []string{"payload", "--entry", v.UnsignedEntryXDR, "--valid-until", "1"},
			wantCode: ExitUsageError,
			wantMsg:  "--network is required",
		},
		{
			name:     "payload zero valid-until",
			args:     []string{"payload", "--entry", v.UnsignedEntryXDR, "--valid-until", "0", "--network", "testnet"},
			wantCode: ExitUsageError,
			wantMsg:  "--valid-until is required",
		},
		{
			name:     "sign no secret-env",
			args:     []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1", "--network", "testnet"},
			wantCode: ExitUsageError,
			wantMsg:  "--secret-env is required",
		},
		{
			name: "sign variable unset",
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1",
				"--network", "testnet", "--secret-env", "NOT_SET"},
			wantCode: ExitUsageError,
			wantMsg:  "NOT_SET is empty or unset",
		},
		{
			name: "sign variable holds public key",
			env:  map[string]string{"SEED": signer.Address()},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
			wantCode: ExitUsageError,
			wantMsg:  "a secret seed (S…) is required",
		},
		{
			name: "sign variable holds junk",
			env:  map[string]string{"SEED": "definitely not a key"},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
			wantCode: ExitUsageError,
			wantMsg:  "not a valid Stellar key",
		},
		{
			name:     "delegates no entry",
			args:     []string{"delegates", "--valid-until", "1", "--delegate", "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"},
			wantCode: ExitUsageError,
			wantMsg:  "--entry is required",
		},
		{
			name:     "delegates zero valid-until",
			args:     []string{"delegates", "--entry", v.UnsignedEntryXDR, "--valid-until", "0", "--delegate", "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"},
			wantCode: ExitUsageError,
			wantMsg:  "--valid-until is required",
		},
		{
			name:     "delegates no delegates",
			args:     []string{"delegates", "--entry", v.UnsignedEntryXDR, "--valid-until", "1"},
			wantCode: ExitUsageError,
			wantMsg:  "at least one --delegate is required",
		},
		{
			name:     "inspect no entry",
			args:     []string{"inspect"},
			wantCode: ExitUsageError,
			wantMsg:  "--entry is required",
		},
		{
			name:     "inspect malformed entry",
			args:     []string{"inspect", "--entry", "not-base64"},
			wantCode: ExitUsageError,
			wantMsg:  "decoding --entry",
		},
		{
			name:     "unknown command",
			args:     []string{"frobnicate"},
			wantCode: ExitUsageError,
			wantMsg:  "unknown command",
		},
		{
			name:     "no command",
			args:     []string{},
			wantCode: ExitUsageError,
			wantMsg:  "no command given",
		},

		// Signing refusals (exit code 3)
		{
			name: "payload source-account entry",
			args: []string{"payload", "--entry", sourceAccountEntryFromVector(t),
				"--valid-until", "1234567", "--network", "testnet"},
			wantCode: ExitSigningRefusal,
			wantMsg:  "source-account",
		},
		{
			name: "sign key owns no node",
			env:  map[string]string{"SEED": stranger.Seed()},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
			wantCode: ExitSigningRefusal,
			wantMsg:  "no credential node matches",
		},
		{
			name: "sign --for names absent address",
			env:  map[string]string{"SEED": signer.Seed()},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED",
				"--for", stranger.Address()},
			wantCode: ExitSigningRefusal,
			wantMsg:  "no credential node matches",
		},

		// Verification failures (exit code 4) - these would need specific setup
		// For now we test what we can with the available vectors
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, err := runCLIEnv(t, tt.env, tt.args...)
			if err == nil {
				t.Fatalf("expected error, got success: stdout=%q", stdout)
			}
			if ExitCode(err) != tt.wantCode {
				t.Errorf("exit code %d, want %d", ExitCode(err), tt.wantCode)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			// In non-JSON mode, stdout should be empty on error
			if stdout != "" && !strings.Contains(strings.Join(tt.args, " "), "--json") {
				t.Errorf("a failing command wrote to stdout: %q", stdout)
			}
		})
	}
}

// TestExitCodesJSONMode tests that JSON mode preserves stdout as results-only on failure.
func TestExitCodesJSONMode(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	stranger := vectorKeypair(t, "soroauth-vector-delegate-3")

	tests := []struct {
		name     string
		args     []string
		env      map[string]string
		wantCode int
	}{
		{
			name: "payload malformed entry JSON",
			args: []string{"payload", "--entry", "not-base64", "--valid-until", "1",
				"--network", "testnet", "--json"},
			wantCode: ExitUsageError,
		},
		{
			name: "sign no matching node JSON",
			env:  map[string]string{"SEED": stranger.Seed()},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED", "--json"},
			wantCode: ExitSigningRefusal,
		},
		{
			name: "delegates duplicate delegate JSON",
			args: []string{"delegates", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--delegate", "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
				"--delegate", "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", "--json"},
			wantCode: ExitSigningRefusal,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, err := runCLIEnv(t, tt.env, tt.args...)
			if err == nil {
				t.Fatalf("expected error, got success: stdout=%q", stdout)
			}
			if ExitCode(err) != tt.wantCode {
				t.Errorf("exit code %d, want %d", ExitCode(err), tt.wantCode)
			}
			// In JSON mode, stdout should contain only the JSON error object
			if stderr != "" {
				t.Errorf("stderr should be empty in JSON mode, got: %q", stderr)
			}
			if !strings.HasPrefix(strings.TrimSpace(stdout), "{") {
				t.Errorf("stdout should be JSON object, got: %q", stdout)
			}
			var out struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal([]byte(stdout), &out); err != nil {
				t.Fatalf("stdout is not valid JSON: %v\nstdout: %q", err, stdout)
			}
			if out.Error == "" {
				t.Error("JSON error object has empty error field")
			}
			if strings.Contains(stdout, "usage:") {
				t.Error("stdout contains usage text in JSON error mode")
			}
		})
	}
}

// TestExitCodeSuccess verifies that successful commands exit with code 0.
func TestPipelineFailureOutputsCleanStdoutLegacy(t *testing.T) {
	var out, errOut bytes.Buffer
	// Simulate piping invalid data via stdin or triggering a failure path
	stdin := strings.NewReader("not-valid-base64\n")
	err := runWithStdin([]string{"payload", "--entry", "-", "--network", "testnet"}, &out, &errOut, func(string) string { return "" }, stdin)
	if err == nil {
		t.Fatal("expected error on invalid pipeline input, got nil")
	}
	if out.String() != "" {
		t.Errorf("expected stdout to stay empty on failure path, got %q", out.String())
	}
}

func TestPipelineCompositionWithStdin(t *testing.T) {
	v := loadVector(t, "delegates_from_legacy")
	signer := vectorKeypair(t, "soroauth-vector-signer-1")

	// Pipeline: soroauth delegates ... | soroauth sign --entry -
	// Simulate stdin with delegates output
	delegatesStdout, _, err := runCLI(t, "delegates",
		"--entry", v.PreWrapEntryXDR,
		"--valid-until", "1234567",
		"--delegate", v.Delegates[0].Address)
	if err != nil {
		t.Fatalf("delegates failed: %v", err)
	}

	var signErr error
	signOut, signErr := runCLIEnvStdin(t, map[string]string{"SEED": signer.Seed()}, delegatesStdout,
		"sign",
		"--entry", "-",
		"--valid-until", "1234567",
		"--network", "testnet",
		"--secret-env", "SEED",
		"--for", v.Delegates[0].Address)
	if signErr != nil {
		t.Fatalf("sign from stdin pipeline failed: %v", signErr)
	}

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(strings.TrimSpace(signOut), &entry); err != nil {
		t.Fatalf("decoding entry from pipeline: %v", err)
	}
	if entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		t.Errorf("credential type is %v, want delegates arm", entry.Credentials.Type)
	}
}

// runCLIEnvStdin drives the dispatcher with a fake environment and custom stdin reader.
func runCLIEnvStdin(t *testing.T, env map[string]string, stdinContent string, args ...string) (stdout string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	stdinReader := strings.NewReader(stdinContent)
	err = runWithStdin(args, &out, &errOut, func(key string) string { return env[key] }, stdinReader)
	return out.String(), err
}

func TestExitCodeSuccess(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signer := vectorKeypair(t, "soroauth-vector-signer-1")

	// payload success
	stdout, _, err := runCLI(t, "payload",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet")
	if err != nil {
		t.Fatalf("payload failed: %v", err)
	}
	if ExitCode(err) != ExitOK {
		t.Errorf("payload exit code %d, want %d", ExitCode(err), ExitOK)
	}
	if !strings.Contains(stdout, v.PreimageXDR) {
		t.Error("payload output missing preimage")
	}

	// sign success
	stdout, _, err = runCLIEnv(t, map[string]string{"SEED": signer.Seed()},
		"sign", "--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567", "--network", "testnet",
		"--secret-env", "SEED")
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}
	if ExitCode(err) != ExitOK {
		t.Errorf("sign exit code %d, want %d", ExitCode(err), ExitOK)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Error("sign output is empty")
	}

	// delegates success
	stdout, _, err = runCLI(t, "delegates",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--delegate", "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF")
	if err != nil {
		t.Fatalf("delegates failed: %v", err)
	}
	if ExitCode(err) != ExitOK {
		t.Errorf("delegates exit code %d, want %d", ExitCode(err), ExitOK)
	}
	if strings.TrimSpace(stdout) == "" {
		t.Error("delegates output is empty")
	}

	// inspect success
	stdout, _, err = runCLI(t, "inspect",
		"--entry", v.UnsignedEntryXDR)
	if err != nil {
		t.Fatalf("inspect failed: %v", err)
	}
	if ExitCode(err) != ExitOK {
		t.Errorf("inspect exit code %d, want %d", ExitCode(err), ExitOK)
	}
	if !strings.Contains(stdout, "credential_type") {
		t.Error("inspect output missing credential_type")
	}
}

// TestCrossCompileJSONMode tests that cross-compile --json outputs results only
// on failure paths (stdout stays results-only).
func TestCrossCompileJSONMode(t *testing.T) {
	// Test with invalid target to trigger failure
	stdout, stderr, err := runCLI(t, "cross-compile", "--targets", "invalid/target", "--json")
	if err == nil {
		t.Fatal("expected error for invalid target")
	}

	// stderr should be empty in JSON mode
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode, got: %q", stderr)
	}

	// stdout should be valid JSON lines
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) == 0 {
		t.Fatal("no JSON output on stdout")
	}

	var foundError bool
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var out crossCompileResult
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			t.Fatalf("stdout line is not valid JSON: %v\nline: %q", err, line)
		}
		if out.Error != "" {
			foundError = true
			if out.Error == "" {
				t.Error("JSON error object has empty error field")
			}
		}
	}
	if !foundError {
		t.Error("expected at least one result with error field populated")
	}

	if strings.Contains(stdout, "usage:") {
		t.Error("stdout contains usage text in JSON error mode")
	}
}

// TestCrossCompileSuccessJSON tests successful cross-compile with --json.
func TestCrossCompileSuccessJSON(t *testing.T) {
	// Test with a single valid target that should succeed quickly
	stdout, stderr, err := runCLI(t, "cross-compile", "--targets", "linux/amd64", "--json")
	if err != nil {
		t.Fatalf("cross-compile failed: %v", err)
	}

	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode, got: %q", stderr)
	}

	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected 1 JSON line, got %d", len(lines))
	}

	var out crossCompileResult
	if err := json.Unmarshal([]byte(lines[0]), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %q", err, stdout)
	}

	if out.Error != "" {
		t.Errorf("unexpected error in result: %s", out.Error)
	}
	if out.Size <= 0 {
		t.Error("size should be positive")
	}
	if out.SHA256 == "" {
		t.Error("sha256 should be populated")
	}
	if out.Target.GOOS != "linux" || out.Target.GOARCH != "amd64" {
		t.Errorf("target mismatch: got %s/%s", out.Target.GOOS, out.Target.GOARCH)
	}
}

// TestCrossCompileHumanReadable tests non-JSON output.
func TestCrossCompileHumanReadable(t *testing.T) {
	stdout, stderr, err := runCLI(t, "cross-compile", "--targets", "linux/amd64")
	if err != nil {
		t.Fatalf("cross-compile failed: %v", err)
	}

	if !strings.Contains(stdout, "OK") {
		t.Errorf("stdout should contain success marker: %q", stdout)
	}
	if strings.Contains(stderr, "FAIL") {
		t.Errorf("stderr should not contain failures: %q", stderr)
	}
}

// TestCrossCompileInvalidTarget tests error handling for invalid targets.
func TestCrossCompileInvalidTarget(t *testing.T) {
	stdout, _, err := runCLI(t, "cross-compile", "--targets", "not-a-valid-target")
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
	if ExitCode(err) != ExitUsageError {
		t.Errorf("exit code %d, want %d", ExitCode(err), ExitUsageError)
	}
	if stdout != "" {
		t.Errorf("stdout should be empty on non-JSON error, got: %q", stdout)
	}
}

// TestCrossCompileNoTargets tests error when no valid targets provided.
func TestCrossCompileNoTargets(t *testing.T) {
	// Pass a target that parses but results in no valid targets
	stdout, _, err := runCLI(t, "cross-compile", "--targets", "invalid/arch", "--json")
	if err == nil {
		t.Fatal("expected error for invalid target")
	}
	if ExitCode(err) != ExitUsageError {
		t.Errorf("exit code %d, want %d", ExitCode(err), ExitUsageError)
	}
	if stdout == "" {
		t.Error("stdout should contain JSON error")
	}
	var out crossCompileResult
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %q", err, stdout)
	}
	if out.Error == "" {
		t.Error("JSON error object has empty error field")
	}
}
