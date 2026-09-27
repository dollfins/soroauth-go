package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// ledgerRPC is a minimal JSON-RPC endpoint that answers getLatestLedger. Using
// a real HTTP server rather than a stubbed client exercises the same rpcclient
// path the command uses, so the test proves the endpoint wiring and not only
// the arithmetic.
type ledgerRPC struct {
	server   *httptest.Server
	calls    atomic.Int64
	sequence uint32
	fail     bool
}

func newLedgerRPC(t *testing.T, sequence uint32) *ledgerRPC {
	t.Helper()
	rpc := &ledgerRPC{sequence: sequence}
	rpc.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rpc.calls.Add(1)

		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad request body", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{"jsonrpc": "2.0", "id": req.ID}
		switch {
		case req.Method != "getLatestLedger":
			resp["error"] = map[string]any{"code": -32601, "message": "unknown method " + req.Method}
		case rpc.fail:
			resp["error"] = map[string]any{"code": -32603, "message": "internal error"}
		default:
			resp["result"] = map[string]any{
				"sequence":        rpc.sequence,
				"id":              strings.Repeat("0", 64),
				"protocolVersion": 28,
				"closeTime":       "0",
			}
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(rpc.server.Close)
	return rpc
}

func TestResolveValidUntil(t *testing.T) {
	fetchOK := func(_ context.Context, _ string) (uint32, error) { return 1000, nil }
	fetchErr := func(_ context.Context, _ string) (uint32, error) {
		return 0, errors.New("connection refused")
	}

	tests := []struct {
		name       string
		validUntil uint64
		validFor   uint64
		rpcURL     string
		fetch      ledgerFetcher
		want       uint32
		wantCode   int
		wantMsg    string
	}{
		{
			name:       "absolute is used as written",
			validUntil: 1234567,
			want:       1234567,
		},
		{
			name:     "relative is added to the current ledger",
			validFor: 100,
			rpcURL:   "http://rpc.invalid",
			fetch:    fetchOK,
			want:     1100,
		},
		{
			name:       "both are refused",
			validUntil: 10,
			validFor:   20,
			rpcURL:     "http://rpc.invalid",
			fetch:      fetchOK,
			wantCode:   ExitUsageError,
			wantMsg:    "mutually exclusive",
		},
		{
			name:     "neither is refused",
			wantCode: ExitUsageError,
			wantMsg:  "--valid-until is required",
		},
		{
			name:     "relative without an endpoint names the flags to set",
			validFor: 100,
			wantCode: ExitUsageError,
			wantMsg:  "--rpc-url",
		},
		{
			name:       "absolute out of range is refused",
			validUntil: uint64(1) << 33,
			wantCode:   ExitUsageError,
			wantMsg:    "out of range",
		},
		{
			name:     "relative out of range is refused",
			validFor: uint64(1) << 33,
			rpcURL:   "http://rpc.invalid",
			fetch:    fetchOK,
			wantCode: ExitUsageError,
			wantMsg:  "out of range",
		},
		{
			name:     "an unreachable endpoint fails closed",
			validFor: 100,
			rpcURL:   "http://rpc.invalid",
			fetch:    fetchErr,
			wantCode: ExitGeneralError,
			wantMsg:  "could not read the current ledger",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fetch := tt.fetch
			if fetch == nil {
				fetch = func(_ context.Context, _ string) (uint32, error) {
					t.Fatal("the ledger fetcher was called when it should not have been")
					return 0, nil
				}
			}

			got, err := resolveValidUntil(context.Background(), tt.validUntil, tt.validFor, tt.rpcURL, fetch)
			if tt.wantCode != 0 {
				if err == nil {
					t.Fatalf("resolveValidUntil succeeded, returning %d", got)
				}
				if ExitCode(err) != tt.wantCode {
					t.Errorf("exit code %d, want %d (error: %v)", ExitCode(err), tt.wantCode, err)
				}
				if !strings.Contains(err.Error(), tt.wantMsg) {
					t.Errorf("error %q does not mention %q", err, tt.wantMsg)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveValidUntil returned an error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

// TestValidForResolvesAgainstRPCEndToEnd drives the CLI from argv to output
// with --valid-for against a real JSON-RPC server, and checks the preimage it
// prints is the one for the resolved absolute ledger. That ties the flag to the
// bytes a signer would approve, not merely to an exit code.
func TestValidForResolvesAgainstRPCEndToEnd(t *testing.T) {
	const latest = 4242
	const ledgers = 50

	rpc := newLedgerRPC(t, latest)
	v := loadVector(t, "v2_single_testnet")

	stdout, stderr, err := runCLI(t, "payload",
		"--entry", v.UnsignedEntryXDR,
		"--valid-for", "50",
		"--network", "testnet",
		"--rpc-url", rpc.server.URL)
	if err != nil {
		t.Fatalf("payload --valid-for returned an error: %v (stderr %q)", err, stderr)
	}
	if rpc.calls.Load() != 1 {
		t.Errorf("the RPC was called %d times, want 1", rpc.calls.Load())
	}

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &entry); err != nil {
		t.Fatalf("decoding the vector entry: %v", err)
	}
	wantPreimage, err := soroauth.Preimage(entry, latest+ledgers, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("computing the expected preimage: %v", err)
	}
	wantB64, err := xdr.MarshalBase64(wantPreimage)
	if err != nil {
		t.Fatalf("encoding the expected preimage: %v", err)
	}

	if !strings.Contains(stdout, wantB64) {
		t.Errorf("preimage for ledger %d is not in the output\n want %s\n  got %s",
			latest+ledgers, wantB64, stdout)
	}
}

// TestValidForHonoursTheEnvironmentEndpoint proves SOROAUTH_RPC_URL is used
// when --rpc-url is absent, which is the same variable the e2e suite reads.
func TestValidForHonoursTheEnvironmentEndpoint(t *testing.T) {
	rpc := newLedgerRPC(t, 900)

	v := loadVector(t, "v2_single_testnet")
	_, _, err := runCLIEnv(t,
		map[string]string{"SOROAUTH_RPC_URL": rpc.server.URL},
		"payload", "--entry", v.UnsignedEntryXDR, "--valid-for", "1", "--network", "testnet")
	if err != nil {
		t.Fatalf("payload --valid-for with SOROAUTH_RPC_URL returned an error: %v", err)
	}
	if rpc.calls.Load() != 1 {
		t.Errorf("the RPC was called %d times, want 1", rpc.calls.Load())
	}
}

func TestValidForFailurePaths(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	rpc := newLedgerRPC(t, 1)
	rpc.fail = true

	tests := []struct {
		name     string
		args     []string
		env      map[string]string
		wantCode int
		wantMsg  string
	}{
		{
			name: "no endpoint at all",
			args: []string{"payload", "--entry", v.UnsignedEntryXDR, "--valid-for", "100",
				"--network", "testnet"},
			wantCode: ExitUsageError,
			wantMsg:  "--rpc-url",
		},
		{
			name: "both flags",
			args: []string{"payload", "--entry", v.UnsignedEntryXDR, "--valid-until", "10",
				"--valid-for", "100", "--network", "testnet"},
			wantCode: ExitUsageError,
			wantMsg:  "mutually exclusive",
		},
		{
			name: "endpoint answers with an error",
			args: []string{"payload", "--entry", v.UnsignedEntryXDR, "--valid-for", "100",
				"--network", "testnet", "--rpc-url", rpc.server.URL},
			wantCode: ExitGeneralError,
			wantMsg:  "could not read the current ledger",
		},
		{
			name: "sign without an endpoint",
			env:  map[string]string{"SEED": vectorKeypair(t, "soroauth-vector-signer-1").Seed()},
			args: []string{"sign", "--entry", v.UnsignedEntryXDR, "--valid-for", "100",
				"--network", "testnet", "--secret-env", "SEED"},
			wantCode: ExitUsageError,
			wantMsg:  "--rpc-url",
		},
		{
			name: "delegates without an endpoint",
			args: []string{"delegates", "--entry", v.UnsignedEntryXDR, "--valid-for", "100",
				"--delegate", "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"},
			wantCode: ExitUsageError,
			wantMsg:  "--rpc-url",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, stderr, err := runCLIEnv(t, tt.env, tt.args...)
			if err == nil {
				t.Fatalf("the command succeeded, printing %q", stdout)
			}
			if ExitCode(err) != tt.wantCode {
				t.Errorf("exit code %d, want %d (error: %v)", ExitCode(err), tt.wantCode, err)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			// Non-JSON mode: nothing but the error may reach stdout.
			if stdout != "" {
				t.Errorf("a failing command wrote to stdout: %q", stdout)
			}
			if stderr != "" && tt.name == "no endpoint at all" {
				t.Errorf("stderr should stay empty for a refused usage path, got %q", stderr)
			}
		})
	}
}

// TestValidForJSONFailureStaysOnStdout is the results-only assertion the issue
// asks for: in --json mode a --valid-for failure writes a single JSON error
// object to stdout and nothing to stderr, so a script piping stdout to jq never
// has to strip usage text.
func TestValidForJSONFailureStaysOnStdout(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")

	stdout, stderr, err := runCLI(t, "payload",
		"--entry", v.UnsignedEntryXDR,
		"--valid-for", "100",
		"--network", "testnet",
		"--json")
	if err == nil {
		t.Fatal("expected a failure without an RPC endpoint")
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode, got %q", stderr)
	}

	var out struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %q", err, stdout)
	}
	if out.Error == "" {
		t.Error("the JSON error object has an empty error field")
	}
	if !strings.Contains(out.Error, "--rpc-url") {
		t.Errorf("the JSON error does not name --rpc-url: %q", out.Error)
	}
	if strings.Contains(stdout, "usage:") {
		t.Error("stdout contains usage text in JSON error mode")
	}
}

// TestValidForJSONSuccessIsResultsOnly mirrors the failure assertion above on
// the success path, so the pairing pins both ends.
func TestValidForJSONSuccessIsResultsOnly(t *testing.T) {
	rpc := newLedgerRPC(t, 777)
	v := loadVector(t, "v2_single_testnet")

	stdout, stderr, err := runCLI(t, "payload",
		"--entry", v.UnsignedEntryXDR,
		"--valid-for", "10",
		"--network", "testnet",
		"--rpc-url", rpc.server.URL,
		"--json")
	if err != nil {
		t.Fatalf("payload --valid-for --json returned an error: %v (stderr %q)", err, stderr)
	}
	if stderr != "" {
		t.Errorf("stderr should be empty in JSON mode, got %q", stderr)
	}

	var out struct {
		Preimage string `json:"preimage"`
		Payload  string `json:"payload"`
		Error    string `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %q", err, stdout)
	}
	if out.Error != "" {
		t.Errorf("success object carried an error field: %q", out.Error)
	}
	if out.Preimage == "" || out.Payload == "" {
		t.Errorf("success object is missing preimage or payload: %q", stdout)
	}
}
