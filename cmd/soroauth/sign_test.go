package main

import (
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// vectorKeypair derives a vector's deterministic test keypair from its label.
func vectorKeypair(t *testing.T, label string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatalf("deriving the keypair for %q: %v", label, err)
	}
	return kp
}

func TestSignMatchesTheGoldenVector(t *testing.T) {
	// Vector 3 is signed by a single signer with no --for, which is the
	// simplest thing the subcommand does.
	v := loadVector(t, "v2_single_testnet")
	signer := vectorKeypair(t, "soroauth-vector-signer-1")

	stdout, _, err := runCLIEnv(t, map[string]string{"SEED": signer.Seed()},
		"sign",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--secret-env", "SEED")
	if err != nil {
		t.Fatalf("sign returned an error: %v", err)
	}

	// The vector's signed entry is the reference the library is proven
	// against, so the CLI must produce exactly it.
	signedVector := loadFullVector(t, "v2_single_testnet")
	if got := strings.TrimSpace(stdout); got != signedVector {
		t.Errorf("signed entry differs from the golden vector\n want %s\n  got %s", signedVector, got)
	}
}

func TestSignWritesToTheNodeNamedByFor(t *testing.T) {
	// Vector 6's delegates are each signed with --for, so this covers the
	// path where the signer does not own the top-level node.
	v := loadVector(t, "delegates_unsorted_with_nested")
	if len(v.Delegates) == 0 {
		t.Fatal("the vector records no delegates")
	}

	delegate := v.Delegates[0]
	kp := vectorKeypair(t, delegate.Label)

	stdout, _, err := runCLIEnv(t, map[string]string{"SEED": kp.Seed()},
		"sign",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--secret-env", "SEED",
		"--for", delegate.Address)
	if err != nil {
		t.Fatalf("sign returned an error: %v", err)
	}

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(strings.TrimSpace(stdout), &entry); err != nil {
		t.Fatalf("decoding the signed entry: %v", err)
	}
	if entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		t.Fatalf("arm is %v, want the delegates arm", entry.Credentials.Type)
	}

	// The named delegate is signed and the account is not.
	if entry.Credentials.AddressWithDelegates.AddressCredentials.Signature.Type != xdr.ScValTypeScvVoid {
		t.Error("the top-level node was signed despite --for naming a delegate")
	}
	var signedCount int
	for _, node := range entry.Credentials.AddressWithDelegates.Delegates {
		if node.Signature.Type != xdr.ScValTypeScvVoid {
			signedCount++
		}
	}
	if signedCount != 1 {
		t.Errorf("%d top-level delegates are signed, want 1", signedCount)
	}
}

// TestSignNeverPrintsTheSecret is the §8 rule the whole --secret-env design
// exists for. Every failure mode is driven with a real seed in the environment,
// and no stream may ever contain it.
func TestSignNeverPrintsTheSecret(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signer := vectorKeypair(t, "soroauth-vector-signer-1")
	seed := signer.Seed()
	stranger := vectorKeypair(t, "soroauth-vector-delegate-3")

	cases := []struct {
		name string
		env  map[string]string
		args []string
	}{
		{
			name: "success",
			env:  map[string]string{"SEED": seed},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
		},
		{
			name: "no matching node",
			env:  map[string]string{"SEED": stranger.Seed()},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
		},
		{
			name: "malformed entry",
			env:  map[string]string{"SEED": seed},
			args: []string{"sign", "--entry", "not-base64", "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
		},
		{
			name: "the variable holds a public key",
			env:  map[string]string{"SEED": signer.Address()},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
		},
		{
			name: "the variable holds junk",
			env:  map[string]string{"SEED": "SNOTAREALSEEDATALL"},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, err := runCLIEnv(t, tt.env, tt.args...)
			message := ""
			if err != nil {
				message = err.Error()
			}
			for stream, text := range map[string]string{
				"stdout": stdout, "stderr": stderr, "error": message,
			} {
				for _, secret := range []string{seed, stranger.Seed(), "SNOTAREALSEEDATALL"} {
					if strings.Contains(text, secret) {
						t.Errorf("%s leaked a secret: %q", stream, text)
					}
				}
			}
		})
	}
}

func TestSignRejects(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	seed := vectorKeypair(t, "soroauth-vector-signer-1").Seed()

	tests := []struct {
		name    string
		env     map[string]string
		args    []string
		wantMsg string
	}{
		{
			name:    "no secret-env",
			args:    []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1", "--network", "testnet"},
			wantMsg: "exactly one of --secret-env or --assertion must be provided",
		},
		{
			name: "the variable is unset",
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1",
				"--network", "testnet", "--secret-env", "NOT_SET"},
			wantMsg: "NOT_SET is empty or unset",
		},
		{
			name: "the variable holds a public key",
			env:  map[string]string{"SEED": vectorKeypair(t, "soroauth-vector-signer-1").Address()},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
			wantMsg: "a secret seed (S…) is required",
		},
		{
			name: "the variable holds junk",
			env:  map[string]string{"SEED": "definitely not a key"},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
			wantMsg: "not a valid Stellar key",
		},
		{
			name: "the key owns no node in the entry",
			env:  map[string]string{"SEED": vectorKeypair(t, "soroauth-vector-delegate-3").Seed()},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED"},
			wantMsg: "no credential node matches",
		},
		{
			name: "--for names an address that is not present",
			env:  map[string]string{"SEED": seed},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-until", "1234567",
				"--network", "testnet", "--secret-env", "SEED",
				"--for", vectorKeypair(t, "soroauth-vector-delegate-3").Address()},
			wantMsg: "no credential node matches",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, err := runCLIEnv(t, tt.env, tt.args...)
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

func TestSignJSONOutput(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signer := vectorKeypair(t, "soroauth-vector-signer-1")

	stdout, _, err := runCLIEnv(t, map[string]string{"SEED": signer.Seed()},
		"sign",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--secret-env", "SEED",
		"--json")
	if err != nil {
		t.Fatalf("sign --json returned an error: %v", err)
	}

	var out struct {
		SignedEntry string `json:"signed_entry"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	signedVector := loadFullVector(t, "v2_single_testnet")
	if out.SignedEntry != signedVector {
		t.Errorf("signed entry differs from the golden vector\n want %s\n  got %s", signedVector, out.SignedEntry)
	}
}

func TestSignJSONErrorStaysOnStdout(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")

	// Test with a key that doesn't match any node in the entry
	stranger := vectorKeypair(t, "soroauth-vector-delegate-3")

	stdout, stderr, err := runCLIEnv(t, map[string]string{"SEED": stranger.Seed()},
		"sign",
		"--entry", v.UnsignedEntryXDR,
		"--valid-until", "1234567",
		"--network", "testnet",
		"--secret-env", "SEED",
		"--json")
	if err == nil {
		t.Fatal("expected error for no matching node")
	}

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
