// Package server provides an HTTP verification service for Soroban authorization entries.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Version is set at build time via -ldflags.
var Version = "dev"

const maxRequestBodySize = 1 << 20 // 1 MB

// verifyRequest is the JSON request body for the /verify endpoint.
type verifyRequest struct {
	// Entry is the base64-encoded SorobanAuthorizationEntry or TransactionEnvelope.
	Entry string `json:"entry"`
	// Network is the network passphrase or shorthand (testnet, futurenet, public).
	Network string `json:"network"`
	// ValidUntilLedger is an optional assertion of the expiration the entry carries.
	// If provided and it disagrees with the entry's stored expiration, the response
	// will include an error.
	ValidUntilLedger uint32 `json:"valid_until_ledger,omitempty"`
	// AllowUnsigned allows unsigned nodes (e.g., a Void top-level node in a delegates entry).
	AllowUnsigned bool `json:"allow_unsigned,omitempty"`
}

// verifyResponse is the JSON response for the /verify endpoint.
type verifyResponse struct {
	// Reports is the verification report(s). For a single entry it is one object;
	// for an envelope it is an array with operation_index and entry_index.
	Reports interface{} `json:"reports,omitempty"`
	// Error is set when the request is malformed or verification cannot proceed.
	Error string `json:"error,omitempty"`
}

// nodeOutput represents one credential node's verdict in the JSON report.
type nodeOutput struct {
	Address string `json:"address"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
}

// entryOutput represents one entry's verification report in the JSON output.
type entryOutput struct {
	OperationIndex   int          `json:"operation_index,omitempty"`
	EntryIndex       int          `json:"entry_index,omitempty"`
	CredentialType   string       `json:"credential_type"`
	AddressBound     bool         `json:"address_bound"`
	Address          string       `json:"address,omitempty"`
	ValidUntilLedger uint32       `json:"valid_until_ledger,omitempty"`
	Verified         bool         `json:"verified"`
	Nodes            []nodeOutput `json:"nodes"`
	Note             string       `json:"note,omitempty"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "version" {
		fmt.Printf("soroauth-server %s\n", Version)
		return
	}

	addr := getEnv("ADDR", ":8080")
	readTimeout := getEnvDuration("READ_TIMEOUT", 5*time.Second)
	writeTimeout := getEnvDuration("WRITE_TIMEOUT", 10*time.Second)
	idleTimeout := getEnvDuration("IDLE_TIMEOUT", 120*time.Second)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler)
	mux.HandleFunc("/verify", verifyHandler)

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
		IdleTimeout:  idleTimeout,
	}

	go func() {
		log.Printf("starting server on %s", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server failed: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("server shutdown failed: %v", err)
	}
	log.Println("server stopped")
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"version": Version,
	})
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodySize)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "reading request body: "+err.Error())
		return
	}

	var req verifyRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "parsing JSON: "+err.Error())
		return
	}

	if req.Entry == "" {
		writeError(w, http.StatusBadRequest, "entry is required")
		return
	}
	if req.Network == "" {
		writeError(w, http.StatusBadRequest, "network is required (testnet, futurenet, public, or a literal passphrase)")
		return
	}

	// Resolve network passphrase
	passphrase := resolveNetwork(req.Network)

	// Decode the entry or envelope
	entry, envelope, isEnvelope, err := decodeEntryOrEnvelope(req.Entry)
	if err != nil {
		writeError(w, http.StatusBadRequest, "decoding entry: "+err.Error())
		return
	}

	var reports []entryOutput
	var verifyErr error

	if isEnvelope {
		entries, err := soroauth.EnvelopeEntries(envelope)
		if err != nil {
			writeError(w, http.StatusBadRequest, "envelope has no authorization entries: "+err.Error())
			return
		}
		for _, e := range entries {
			report, err := soroauth.VerifyEntry(e.Entry, passphrase)
			if err != nil {
				verifyErr = err
				break
			}
			if req.ValidUntilLedger != 0 && report.ValidUntilLedger != req.ValidUntilLedger {
				verifyErr = fmt.Errorf("entry carries expiration %d, but valid_until_ledger says %d", report.ValidUntilLedger, req.ValidUntilLedger)
				break
			}
			reports = append(reports, newEntryOutput(report, e.OperationIndex+1, e.EntryIndex+1))
		}
	} else {
		report, err := soroauth.VerifyEntry(entry, passphrase)
		if err != nil {
			verifyErr = err
		} else {
			if req.ValidUntilLedger != 0 && report.ValidUntilLedger != req.ValidUntilLedger {
				verifyErr = fmt.Errorf("entry carries expiration %d, but valid_until_ledger says %d", report.ValidUntilLedger, req.ValidUntilLedger)
			}
			reports = append(reports, newEntryOutput(report, 0, 0))
		}
	}

	if verifyErr != nil {
		writeError(w, http.StatusBadRequest, "verification failed: "+verifyErr.Error())
		return
	}

	// Determine if any node failed verification
	failed := false
	for _, report := range reports {
		for _, node := range report.Nodes {
			switch node.Verdict {
			case string(soroauth.VerdictVerified):
			case string(soroauth.VerdictUnsigned):
				if !req.AllowUnsigned {
					failed = true
				}
			default:
				failed = true
			}
		}
	}

	response := verifyResponse{
		Reports: reports,
	}
	if failed {
		response.Error = "one or more credential nodes did not verify"
	}

	w.Header().Set("Content-Type", "application/json")
	if failed {
		w.WriteHeader(http.StatusUnprocessableEntity)
	}
	_ = json.NewEncoder(w).Encode(response)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(verifyResponse{Error: msg})
}

func newEntryOutput(report soroauth.VerificationReport, opIndex, entryIndex int) entryOutput {
	out := entryOutput{
		CredentialType:   report.CredentialType,
		AddressBound:     report.AddressBound,
		Address:          report.Address,
		ValidUntilLedger: report.ValidUntilLedger,
		Verified:         report.Verified(),
		Note:             report.Note,
		Nodes:            make([]nodeOutput, 0, len(report.Nodes)),
	}
	if opIndex > 0 {
		out.OperationIndex = opIndex
		out.EntryIndex = entryIndex
	}
	for _, node := range report.Nodes {
		out.Nodes = append(out.Nodes, nodeOutput{
			Address: node.Address,
			Verdict: string(node.Verdict),
			Reason:  node.Reason,
		})
	}
	return out
}

func resolveNetwork(value string) string {
	switch value {
	case "testnet":
		return "Test SDF Network ; September 2015"
	case "futurenet":
		return "Test SDF Future Network ; October 2022"
	case "public":
		return "Public Global Stellar Network ; September 2015"
	default:
		return value
	}
}

// decodeEntryOrEnvelope parses the base64 input as either an entry or envelope.
func decodeEntryOrEnvelope(value string) (xdr.SorobanAuthorizationEntry, xdr.TransactionEnvelope, bool, error) {
	// Try as envelope first
	var envelope xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(value, &envelope); err == nil {
		entries, err := soroauth.EnvelopeEntries(envelope)
		if err == nil && len(entries) > 0 {
			// It's an envelope with entries
			return xdr.SorobanAuthorizationEntry{}, envelope, true, nil
		}
	}

	// Try as entry
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(value, &entry); err != nil {
		return xdr.SorobanAuthorizationEntry{}, xdr.TransactionEnvelope{}, false, err
	}

	return entry, xdr.TransactionEnvelope{}, false, nil
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
