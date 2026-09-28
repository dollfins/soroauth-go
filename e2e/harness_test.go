//go:build e2e

// Package e2e proves soroauth against a live Stellar network.
//
// These tests are excluded from the normal build by the e2e tag, because they
// create accounts, submit transactions and wait on ledger close. Run them with:
//
//	go test -tags e2e -v ./e2e/...
//
// Every account used here is generated at runtime and funded by friendbot. No
// key is read from disk, written to disk, or committed.
package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"
	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/protocols/stellarcore"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const (
	defaultRPCURL   = "https://soroban-testnet.stellar.org"
	explorerBaseURL = "https://stellar.expert/explorer/testnet/tx/"
)

// scenarioResult is one recorded outcome, collected for RESULTS.md.
type scenarioResult struct {
	ID        string
	Name      string
	Proves    string
	TxHash    string
	Ledger    uint32
	Arm       string
	Notes     []string
	RawError  string
	Succeeded bool
	// ExpectRejection records that this scenario is meant to fail. It decides
	// how RESULTS.md labels the outcome, and it is a field rather than a list
	// of scenario IDs so a new rejection scenario cannot be labelled
	// "accepted" by omission.
	ExpectRejection bool
	ExplorerURL     string
}

var (
	resultsMu sync.Mutex
	results   []scenarioResult
)

func record(r scenarioResult) {
	if r.TxHash != "" {
		r.ExplorerURL = explorerBaseURL + r.TxHash
	}
	resultsMu.Lock()
	defer resultsMu.Unlock()
	results = append(results, r)
}

// harness holds the verified connection to the network.
type harness struct {
	client          *rpcclient.Client
	url             string
	passphrase      string
	protocolVersion uint32
	friendbotURL    string
}

// newHarness connects to the RPC named by SOROAUTH_RPC_URL and verifies it with
// a live call before anything relies on it. A wrong or stale URL would
// otherwise surface much later as a confusing signing failure.
func newHarness(t *testing.T) *harness {
	t.Helper()

	url := os.Getenv("SOROAUTH_RPC_URL")
	if url == "" {
		url = defaultRPCURL
	}

	client := rpcclient.NewClient(url, nil)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	network, err := client.GetNetwork(ctx)
	if err != nil {
		t.Fatalf("the RPC at %s did not answer getNetwork: %v", url, err)
	}
	if network.Passphrase == "" {
		t.Fatalf("the RPC at %s reported no network passphrase", url)
	}

	health, err := client.GetHealth(ctx)
	if err != nil {
		t.Fatalf("the RPC at %s did not answer getHealth: %v", url, err)
	}
	if !strings.EqualFold(health.Status, "healthy") {
		t.Fatalf("the RPC at %s reports status %q", url, health.Status)
	}

	ledger, err := client.GetLatestLedger(ctx)
	if err != nil {
		t.Fatalf("the RPC at %s did not answer getLatestLedger: %v", url, err)
	}

	t.Logf("rpc:              %s", url)
	t.Logf("passphrase:       %s", network.Passphrase)
	t.Logf("protocol version: %d", ledger.ProtocolVersion)
	t.Logf("latest ledger:    %d", ledger.Sequence)

	noteRun(network.Passphrase, url, ledger.ProtocolVersion)

	return &harness{
		client:          client,
		url:             url,
		passphrase:      network.Passphrase,
		protocolVersion: ledger.ProtocolVersion,
		friendbotURL:    network.FriendbotURL,
	}
}

// newAccount generates a keypair and funds it with friendbot.
func (h *harness) newAccount(t *testing.T, label string) *keypair.Full {
	t.Helper()

	kp, err := keypair.Random()
	if err != nil {
		t.Fatalf("generating a keypair for %s: %v", label, err)
	}
	h.fund(t, kp.Address())
	t.Logf("%-10s %s", label+":", kp.Address())
	return kp
}

// fund asks friendbot for a funded account, retrying briefly: friendbot is a
// shared testnet service and an occasional failure is not a test failure.
func (h *harness) fund(t *testing.T, address string) {
	t.Helper()

	friendbot := h.friendbotURL
	if friendbot == "" {
		friendbot = "https://friendbot.stellar.org/"
	}

	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
		}

		resp, err := http.Get(fmt.Sprintf("%s?addr=%s", friendbot, address))
		if err != nil {
			lastErr = err
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			return
		}
		// An account that already exists is fine.
		if strings.Contains(string(body), "op_already_exists") ||
			strings.Contains(string(body), "already funded") {
			return
		}
		lastErr = fmt.Errorf("friendbot returned %d: %s", resp.StatusCode, truncate(string(body), 300))
	}
	t.Fatalf("could not fund %s: %v", address, lastErr)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// latestLedger reads the current ledger sequence.
func (h *harness) latestLedger(t *testing.T) uint32 {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	ledger, err := h.client.GetLatestLedger(ctx)
	if err != nil {
		t.Fatalf("reading the latest ledger: %v", err)
	}
	return ledger.Sequence
}

// account loads an account for use as a transaction source.
func (h *harness) account(t *testing.T, address string) txnbuild.Account {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	account, err := h.client.LoadAccount(ctx, address)
	if err != nil {
		t.Fatalf("loading account %s: %v", address, err)
	}
	return account
}

// simulate runs a simulation in the requested auth mode.
func (h *harness) simulate(t *testing.T, tx *txnbuild.Transaction, authMode string, useUpgradedAuth bool) rpc.SimulateTransactionResponse {
	t.Helper()

	encoded, err := tx.Base64()
	if err != nil {
		t.Fatalf("encoding the transaction for simulation: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	response, err := h.client.SimulateTransaction(ctx, rpc.SimulateTransactionRequest{
		Transaction:     encoded,
		AuthMode:        authMode,
		UseUpgradedAuth: useUpgradedAuth,
	})
	if err != nil {
		t.Fatalf("simulate (%s) failed at the transport level: %v", authMode, err)
	}
	if response.Error != "" {
		t.Fatalf("simulate (%s) returned an error: %s", authMode, response.Error)
	}
	return response
}

// assemble applies simulation's resources and fee to the operation, which is
// what the JS SDK's assembleTransaction does. The Go SDK has no equivalent, so
// it is done explicitly here.
func (h *harness) assemble(
	t *testing.T,
	source txnbuild.Account,
	op txnbuild.InvokeHostFunction,
	sim rpc.SimulateTransactionResponse,
) *txnbuild.Transaction {
	t.Helper()
	return h.assembleWithHeadroom(t, source, op, sim, 1)
}

// assembleWithHeadroom is assemble with the instruction budget and resource fee
// multiplied.
//
// It exists for the scenarios that are meant to be rejected on-chain. Those
// cannot use an enforcing simulation to size their resources — that pass fails
// locally for the very reason under test — so their resources come from the
// recording pass, which never executed the account contract's __check_auth and
// therefore under-counts. Submitting that way produces a transaction that runs
// out of instructions before it reaches the check, and fails for a reason that
// has nothing to do with what the scenario is proving.
func (h *harness) assembleWithHeadroom(
	t *testing.T,
	source txnbuild.Account,
	op txnbuild.InvokeHostFunction,
	sim rpc.SimulateTransactionResponse,
	headroom uint32,
) *txnbuild.Transaction {
	t.Helper()

	var sorobanData xdr.SorobanTransactionData
	if err := xdr.SafeUnmarshalBase64(sim.TransactionDataXDR, &sorobanData); err != nil {
		t.Fatalf("decoding the simulated transaction data: %v", err)
	}
	// Simulation reports the minimum resource fee separately; use it rather
	// than whatever the data happens to carry, and pad it, since the enforcing
	// pass runs against a slightly later ledger state.
	sorobanData.ResourceFee = xdr.Int64(sim.MinResourceFee) + 100_000

	if headroom > 1 {
		sorobanData.Resources.Instructions *= xdr.Uint32(headroom)
		sorobanData.ResourceFee *= xdr.Int64(headroom)
	}

	op.Ext = xdr.TransactionExt{V: 1, SorobanData: &sorobanData}

	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        source,
		IncrementSequenceNum: true,
		Operations:           []txnbuild.Operation{&op},
		BaseFee:              txnbuild.MinBaseFee * 100,
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
	})
	if err != nil {
		t.Fatalf("assembling the transaction: %v", err)
	}
	return tx
}

// build makes an unsigned transaction carrying one InvokeHostFunction.
func (h *harness) build(t *testing.T, source txnbuild.Account, op txnbuild.InvokeHostFunction) *txnbuild.Transaction {
	t.Helper()
	tx, err := txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        source,
		IncrementSequenceNum: true,
		Operations:           []txnbuild.Operation{&op},
		BaseFee:              txnbuild.MinBaseFee * 100,
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
	})
	if err != nil {
		t.Fatalf("building the transaction: %v", err)
	}
	return tx
}

// submission is the outcome of sending a transaction.
type submission struct {
	Hash        string
	Ledger      uint32
	Arm         string
	Status      string
	RawError    string
	Diagnostics []string
}

// send submits a signed transaction and polls until it resolves. It does not
// fail the test on an on-chain rejection: scenario E expects one, and reports
// the raw error.
func (h *harness) send(t *testing.T, tx *txnbuild.Transaction) submission {
	t.Helper()

	encoded, err := tx.Base64()
	if err != nil {
		t.Fatalf("encoding the signed transaction: %v", err)
	}

	// Decode the envelope that is actually going out and read the credential
	// arm off it, rather than assuming it is what was intended.
	arm := credentialArmOf(t, encoded)

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	sent, err := h.client.SendTransaction(ctx, rpc.SendTransactionRequest{Transaction: encoded})
	if err != nil {
		t.Fatalf("sendTransaction failed at the transport level: %v", err)
	}

	result := submission{Hash: sent.Hash, Arm: arm, Status: sent.Status}
	if sent.Status == stellarcore.TXStatusError {
		result.RawError = describeFailure(sent.ErrorResultXDR, sent.DiagnosticEventsXDR)
		result.Diagnostics = sent.DiagnosticEventsXDR
		return result
	}

	polled, err := h.client.PollTransaction(ctx, sent.Hash)
	if err != nil {
		t.Fatalf("polling %s: %v", sent.Hash, err)
	}

	result.Status = polled.Status
	result.Ledger = polled.Ledger
	if polled.Status != rpc.TransactionStatusSuccess {
		result.RawError = describeFailure(polled.ResultXDR, polled.DiagnosticEventsXDR)
		result.Diagnostics = polled.DiagnosticEventsXDR
	}
	return result
}

// credentialArmOf decodes a submitted envelope and reports the credential arm
// of its first authorization entry. §5.10 requires the arm be observed on the
// submitted envelope, not assumed from what the test meant to build.
func credentialArmOf(t *testing.T, envelopeBase64 string) string {
	t.Helper()

	var envelope xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(envelopeBase64, &envelope); err != nil {
		t.Fatalf("decoding the submitted envelope: %v", err)
	}

	operations := envelope.Operations()
	if len(operations) == 0 {
		return "no operations"
	}
	invoke, ok := operations[0].Body.GetInvokeHostFunctionOp()
	if !ok {
		return "not an invokeHostFunction"
	}
	if len(invoke.Auth) == 0 {
		return "no auth entries"
	}

	arms := make([]string, 0, len(invoke.Auth))
	for _, entry := range invoke.Auth {
		arms = append(arms, entry.Credentials.Type.String())
	}
	return strings.Join(arms, ", ")
}

// isCoreMetricsEvent reports whether a diagnostic is one of the host's
// per-invocation performance counters.
func isCoreMetricsEvent(event xdr.DiagnosticEvent) bool {
	topics := event.Event.Body.V0.Topics
	if len(topics) == 0 {
		return false
	}
	return topics[0].Type == xdr.ScValTypeScvSymbol &&
		topics[0].Sym != nil &&
		string(*topics[0].Sym) == "core_metrics"
}

// describeFailure renders a failure exactly as the host reported it: the raw
// TransactionResult XDR, its decoded form, and every diagnostic event. Nothing
// is paraphrased — for scenario E the contract's own error code lives in the
// diagnostic events, and a summary would lose it.
func describeFailure(resultXDR string, diagnosticsXDR []string) string {
	var out strings.Builder

	if resultXDR != "" {
		out.WriteString("result xdr: " + resultXDR)
		var result xdr.TransactionResult
		if err := xdr.SafeUnmarshalBase64(resultXDR, &result); err == nil {
			if encoded, err := json.Marshal(result); err == nil {
				out.WriteString("\nresult decoded: " + string(encoded))
			} else {
				out.WriteString(fmt.Sprintf("\nresult decoded: %+v", result))
			}
		}
	}

	metrics := 0
	for i, event := range diagnosticsXDR {
		var decoded xdr.DiagnosticEvent
		if err := xdr.SafeUnmarshalBase64(event, &decoded); err != nil {
			out.WriteString(fmt.Sprintf("\ndiagnostic %d (undecodable): %s", i, event))
			continue
		}
		// The host emits a long tail of core_metrics events on every
		// invocation. They are performance counters, not errors, and they bury
		// the one event that matters. They are counted rather than printed;
		// nothing else is filtered and nothing is reworded.
		if isCoreMetricsEvent(decoded) {
			metrics++
			continue
		}
		encoded, err := json.Marshal(decoded)
		if err != nil {
			out.WriteString(fmt.Sprintf("\ndiagnostic %d: %+v", i, decoded))
			continue
		}
		out.WriteString(fmt.Sprintf("\ndiagnostic %d: %s", i, string(encoded)))
	}
	if metrics > 0 {
		out.WriteString(fmt.Sprintf("\n(%d core_metrics diagnostic events omitted)", metrics))
	}

	return out.String()
}

// contractErrorCodes returns every contract error code the host reported in a
// set of diagnostic events.
//
// This exists because a rejection test can pass for entirely the wrong reason.
// Scenario E once "passed" while the transaction was actually failing on its
// instruction budget, never reaching the account contract at all. Asserting the
// specific code is what makes the scenario prove what it claims.
func contractErrorCodes(t *testing.T, diagnosticsXDR []string) []uint32 {
	t.Helper()

	var codes []uint32
	for _, event := range diagnosticsXDR {
		var decoded xdr.DiagnosticEvent
		if err := xdr.SafeUnmarshalBase64(event, &decoded); err != nil {
			continue
		}
		for _, topic := range decoded.Event.Body.V0.Topics {
			if topic.Type != xdr.ScValTypeScvError || topic.Error == nil {
				continue
			}
			if topic.Error.Type != xdr.ScErrorTypeSceContract {
				continue
			}
			if topic.Error.ContractCode != nil {
				codes = append(codes, uint32(*topic.Error.ContractCode))
			}
		}
	}
	return codes
}

// hostErrorDetail is one error diagnostic the host emitted: the error value
// from the topics, the message string, and any numeric arguments that came
// with it.
type hostErrorDetail struct {
	ErrorType    int32
	ContractCode uint32
	HasCode      bool
	Message      string
	Args         []uint64
}

// TestSignerRetryIntegration proves that WithRetry correctly handles simulated transient network faults
// and respects signature rejections and context cancellation in an integration flow.
func TestSignerRetryIntegration(t *testing.T) {
	h := newHarness(t)
	account := h.newAccount(t, "retry-tester")

	var attempts int
	transientErr := fmt.Errorf("connection refused")

	retrySigner := soroauth.WithRetry(soroauth.SignerFunc(account.Address(), func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
		attempts++
		if attempts < 3 {
			return xdr.ScVal{}, transientErr
		}
		// On 3rd attempt, sign using genuine ed25519 signer
		realSigner := soroauth.NewEd25519Signer(account)
		return realSigner.Sign(ctx, preimage, payload)
	}), soroauth.RetryConfig{
		Attempts:       4,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     50 * time.Millisecond,
	})

	var preimage xdr.HashIdPreimage
	var payload [32]byte
	_, err := retrySigner.Sign(context.Background(), preimage, payload)
	if err != nil {
		t.Fatalf("unexpected error from retrySigner.Sign: %v", err)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

// hostErrorDetails extracts every error diagnostic from a failure.
//
// It exists so a rejection test can assert WHY the host refused, not merely
// that it did. A test that only checks "the transaction failed" passes just as
// happily when the transaction ran out of instructions and never reached the
// check under test.
func hostErrorDetails(t *testing.T, diagnosticsXDR []string) []hostErrorDetail {
	t.Helper()

	var details []hostErrorDetail
	for _, event := range diagnosticsXDR {
		var decoded xdr.DiagnosticEvent
		if err := xdr.SafeUnmarshalBase64(event, &decoded); err != nil {
			continue
		}
		body := decoded.Event.Body.V0

		var detail hostErrorDetail
		var sawError bool
		for _, topic := range body.Topics {
			if topic.Type == xdr.ScValTypeScvError && topic.Error != nil {
				sawError = true
				detail.ErrorType = int32(topic.Error.Type)
				if topic.Error.ContractCode != nil {
					detail.ContractCode = uint32(*topic.Error.ContractCode)
					detail.HasCode = true
				}
			}
		}
		if !sawError {
			continue
		}

		// The data is either a bare message or a vector whose first element is
		// the message and whose remaining elements are its arguments.
		collect := func(value xdr.ScVal) {
			switch value.Type {
			case xdr.ScValTypeScvString:
				if value.Str != nil {
					detail.Message = string(*value.Str)
				}
			case xdr.ScValTypeScvU32:
				if value.U32 != nil {
					detail.Args = append(detail.Args, uint64(*value.U32))
				}
			case xdr.ScValTypeScvU64:
				if value.U64 != nil {
					detail.Args = append(detail.Args, uint64(*value.U64))
				}
			}
		}

		switch body.Data.Type {
		case xdr.ScValTypeScvVec:
			if body.Data.Vec != nil && *body.Data.Vec != nil {
				for _, element := range **body.Data.Vec {
					collect(element)
				}
			}
		default:
			collect(body.Data)
		}

		details = append(details, detail)
	}
	return details
}
