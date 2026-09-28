package rpcflow

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// fakeClient records every call the flow makes, so the ordering and the
// contents of each pass can be asserted without a network.
type fakeClient struct {
	calls []string

	simulations []rpc.SimulateTransactionResponse
	simIndex    int
	simErr      error

	// authModes and authCounts record, per simulation, the mode it ran in and
	// how many authorization entries the submitted transaction carried.
	authModes  []string
	authCounts []int

	latest    uint32
	latestErr error

	sendStatus string
	sendErr    error
	pollStatus string

	// sentEnvelope is the envelope that reached SendTransaction.
	sentEnvelope string
}

func (f *fakeClient) SimulateTransaction(_ context.Context, req rpc.SimulateTransactionRequest) (rpc.SimulateTransactionResponse, error) {
	f.calls = append(f.calls, "simulate:"+req.AuthMode)
	f.authModes = append(f.authModes, req.AuthMode)
	f.authCounts = append(f.authCounts, authEntryCount(req.Transaction))
	if f.simErr != nil {
		return rpc.SimulateTransactionResponse{}, f.simErr
	}
	response := f.simulations[f.simIndex]
	if f.simIndex < len(f.simulations)-1 {
		f.simIndex++
	}
	return response, nil
}

func (f *fakeClient) GetLatestLedger(context.Context) (rpc.GetLatestLedgerResponse, error) {
	f.calls = append(f.calls, "latest")
	if f.latestErr != nil {
		return rpc.GetLatestLedgerResponse{}, f.latestErr
	}
	return rpc.GetLatestLedgerResponse{Sequence: f.latest}, nil
}

func (f *fakeClient) SendTransaction(_ context.Context, req rpc.SendTransactionRequest) (rpc.SendTransactionResponse, error) {
	f.calls = append(f.calls, "send")
	f.sentEnvelope = req.Transaction
	if f.sendErr != nil {
		return rpc.SendTransactionResponse{}, f.sendErr
	}
	status := f.sendStatus
	if status == "" {
		status = "PENDING"
	}
	return rpc.SendTransactionResponse{Hash: "abc123", Status: status}, nil
}

func (f *fakeClient) PollTransaction(context.Context, string) (rpc.GetTransactionResponse, error) {
	f.calls = append(f.calls, "poll")
	status := f.pollStatus
	if status == "" {
		status = rpc.TransactionStatusSuccess
	}
	return rpc.GetTransactionResponse{
		TransactionDetails: rpc.TransactionDetails{Status: status, Ledger: 4242},
	}, nil
}

// authEntryCount reports how many authorization entries a base64 transaction's
// first invoke-host-function operation carries.
func authEntryCount(encoded string) int {
	var tx xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(encoded, &tx); err != nil {
		return -1
	}
	ops := tx.Operations()
	if len(ops) == 0 {
		return -1
	}
	invoke, ok := ops[0].Body.GetInvokeHostFunctionOp()
	if !ok {
		return -1
	}
	return len(invoke.Auth)
}

func testKeypair(t testing.TB, label string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatalf("deriving keypair %q: %v", label, err)
	}
	return kp
}

// recordedEntry builds the unsigned address-arm entry a record pass would
// return for the given signer.
func recordedEntry(t testing.TB, signer string) string {
	t.Helper()
	address, err := soroauth.ParseAddress(signer)
	if err != nil {
		t.Fatalf("parsing %q: %v", signer, err)
	}
	var contractID xdr.ContractId
	for i := range contractID {
		contractID[i] = byte(i)
	}
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			Address: &xdr.SorobanAddressCredentials{
				Address:   address,
				Nonce:     7,
				Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &contractID},
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
		},
	}
	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		t.Fatalf("encoding the recorded entry: %v", err)
	}
	return encoded
}

// simResponse builds a simulation response carrying one result with the given
// auth entries and minimum resource fee.
func simResponse(t testing.TB, minFee int64, entries ...string) rpc.SimulateTransactionResponse {
	t.Helper()
	data := xdr.SorobanTransactionData{}
	encoded, err := xdr.MarshalBase64(data)
	if err != nil {
		t.Fatalf("encoding transaction data: %v", err)
	}
	auth := entries
	return rpc.SimulateTransactionResponse{
		TransactionDataXDR: encoded,
		MinResourceFee:     minFee,
		Results:            []rpc.SimulateHostFunctionResult{{AuthXDR: &auth}},
	}
}

func testParams(t testing.TB, client Client) Params {
	t.Helper()
	payer := testKeypair(t, "rpcflow-payer")
	signer := testKeypair(t, "rpcflow-signer")
	var contractID xdr.ContractId
	for i := range contractID {
		contractID[i] = byte(i)
	}
	return Params{
		Source: &txnbuild.SimpleAccount{AccountID: payer.Address(), Sequence: 1},
		Operation: txnbuild.InvokeHostFunction{
			HostFunction: xdr.HostFunction{
				Type: xdr.HostFunctionTypeHostFunctionTypeInvokeContract,
				InvokeContract: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract, ContractId: &contractID},
					FunctionName:    xdr.ScSymbol("transfer"),
				},
			},
			SourceAccount: payer.Address(),
		},
		Signers:           []soroauth.Signer{soroauth.NewEd25519Signer(signer)},
		EnvelopeSigners:   []*keypair.Full{payer},
		NetworkPassphrase: network.TestNetworkPassphrase,
		Client:            client,
		ValidUntilLedger:  1234567,
	}
}

// TestSignAndSubmitRunsBothPassesInOrder is the property this package exists
// for. A live run that succeeds cannot show which pass priced the signatures;
// this can.
func TestSignAndSubmitRunsBothPassesInOrder(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{
			simResponse(t, 100, recordedEntry(t, signer.Address())),
			simResponse(t, 5000, recordedEntry(t, signer.Address())),
		},
	}

	sub, err := SignAndSubmit(context.Background(), testParams(t, client))
	if err != nil {
		t.Fatalf("SignAndSubmit returned an unexpected error: %v", err)
	}

	want := []string{"simulate:" + rpc.AuthModeRecord, "simulate:" + rpc.AuthModeEnforce, "send", "poll"}
	if strings.Join(client.calls, ",") != strings.Join(want, ",") {
		t.Errorf("call order was %v, want %v", client.calls, want)
	}

	// The record pass must carry no entries and the enforcing pass must carry
	// the signed one. If the enforcing pass ran without them, its fee would
	// not have priced the signatures, which is the silent skip this guards.
	if client.authCounts[0] != 0 {
		t.Errorf("the record pass carried %d authorization entries, want 0", client.authCounts[0])
	}
	if client.authCounts[1] != 1 {
		t.Errorf("the enforcing pass carried %d authorization entries, want 1", client.authCounts[1])
	}

	if sub.Status != rpc.TransactionStatusSuccess {
		t.Errorf("status %q, want %q", sub.Status, rpc.TransactionStatusSuccess)
	}
	if sub.Ledger != 4242 {
		t.Errorf("ledger %d, want 4242", sub.Ledger)
	}
}

// TestSignAndSubmitPricesFromTheEnforcingPass proves the submitted fee comes
// from the second simulation, not the first.
func TestSignAndSubmitPricesFromTheEnforcingPass(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{
			simResponse(t, 100, recordedEntry(t, signer.Address())),
			simResponse(t, 5000, recordedEntry(t, signer.Address())),
		},
	}

	if _, err := SignAndSubmit(context.Background(), testParams(t, client)); err != nil {
		t.Fatalf("SignAndSubmit returned an unexpected error: %v", err)
	}

	var envelope xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(client.sentEnvelope, &envelope); err != nil {
		t.Fatalf("decoding the submitted envelope: %v", err)
	}
	v1, ok := envelope.GetV1()
	if !ok {
		t.Fatal("the submitted envelope is not a v1 transaction envelope")
	}
	data, ok := v1.Tx.Ext.GetSorobanData()
	if !ok {
		t.Fatal("the submitted transaction carries no soroban data, so no resource fee was attached")
	}
	want := xdr.Int64(5000 + DefaultResourceFeePadding)
	if got := data.ResourceFee; got != want {
		t.Errorf("resource fee %d, want %d (the enforcing pass's %d plus padding); "+
			"a fee of %d would mean it was priced from the record pass",
			got, want, 5000, 100+DefaultResourceFeePadding)
	}
}

// TestSignAndSubmitSubmitsASignedEnvelope guards the defect the original had:
// a transaction that nothing ever signed, refused for a missing signature in a
// way that reads as an authorization problem.
func TestSignAndSubmitSubmitsASignedEnvelope(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{
			simResponse(t, 100, recordedEntry(t, signer.Address())),
			simResponse(t, 5000, recordedEntry(t, signer.Address())),
		},
	}

	sub, err := SignAndSubmit(context.Background(), testParams(t, client))
	if err != nil {
		t.Fatalf("SignAndSubmit returned an unexpected error: %v", err)
	}

	var envelope xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(client.sentEnvelope, &envelope); err != nil {
		t.Fatalf("decoding the submitted envelope: %v", err)
	}
	if len(envelope.Signatures()) == 0 {
		t.Error("the submitted envelope carries no signature; it would be refused for a missing signature")
	}

	// And the arm is read off the envelope that went out, not assumed.
	if sub.Arm != xdr.SorobanCredentialsTypeSorobanCredentialsAddress.String() {
		t.Errorf("arm %q, want the address arm that was signed", sub.Arm)
	}
}

func TestSignAndSubmitRequiresAnEnvelopeSigner(t *testing.T) {
	client := &fakeClient{}
	p := testParams(t, client)
	p.EnvelopeSigners = nil

	_, err := SignAndSubmit(context.Background(), p)
	if err == nil {
		t.Fatal("SignAndSubmit accepted a call with no envelope signer")
	}
	if !strings.Contains(err.Error(), "EnvelopeSigner") {
		t.Errorf("error %q does not say an envelope signer is required", err)
	}
	if len(client.calls) != 0 {
		t.Errorf("it reached the network before validating: %v", client.calls)
	}
}

func TestSignAndSubmitRejectsMissingRequirements(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Params)
		want   string
	}{
		{"no source", func(p *Params) { p.Source = nil }, "Source"},
		{"no client", func(p *Params) { p.Client = nil }, "Client"},
		{"no passphrase", func(p *Params) { p.NetworkPassphrase = "" }, "NetworkPassphrase"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := testParams(t, &fakeClient{})
			tt.mutate(&p)
			_, err := SignAndSubmit(context.Background(), p)
			if err == nil {
				t.Fatalf("SignAndSubmit accepted a call with %s", tt.name)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not name %s", err, tt.want)
			}
		})
	}
}

// TestSignAndSubmitRefusesASimulationWithNoEntries covers the fail-closed
// reading: signing nothing would hide that the wrong thing was simulated.
func TestSignAndSubmitRefusesASimulationWithNoEntries(t *testing.T) {
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{{
			TransactionDataXDR: "",
			Results:            []rpc.SimulateHostFunctionResult{{AuthXDR: nil}},
		}},
	}

	_, err := SignAndSubmit(context.Background(), testParams(t, client))
	if err == nil {
		t.Fatal("SignAndSubmit accepted a simulation that recorded no authorization entries")
	}
	if !errors.Is(err, soroauth.ErrNoInvokeOperation) {
		t.Errorf("error %v does not wrap ErrNoInvokeOperation", err)
	}
}

// TestSignAndSubmitReportsAnOnChainRejection proves a host refusal is an
// outcome rather than a transport error: the caller still gets the hash and
// the host's own text.
func TestSignAndSubmitReportsAnOnChainRejection(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{
			simResponse(t, 100, recordedEntry(t, signer.Address())),
			simResponse(t, 5000, recordedEntry(t, signer.Address())),
		},
		pollStatus: "FAILED",
	}

	sub, err := SignAndSubmit(context.Background(), testParams(t, client))
	if err != nil {
		t.Fatalf("an on-chain rejection was reported as a call failure: %v", err)
	}
	if sub.Status != "FAILED" {
		t.Errorf("status %q, want FAILED", sub.Status)
	}
	if sub.Hash == "" {
		t.Error("a rejected submission reported no hash, so it cannot be looked up")
	}
}

// TestSignAndSubmitResolvesAnExpirationWhenNoneIsGiven checks the zero-value
// path reads the current ledger rather than signing with an expiration of 0,
// which AuthorizeEntry refuses.
func TestSignAndSubmitResolvesAnExpirationWhenNoneIsGiven(t *testing.T) {
	signer := testKeypair(t, "rpcflow-signer")
	client := &fakeClient{
		simulations: []rpc.SimulateTransactionResponse{
			simResponse(t, 100, recordedEntry(t, signer.Address())),
			simResponse(t, 5000, recordedEntry(t, signer.Address())),
		},
		latest: 1000,
	}
	p := testParams(t, client)
	p.ValidUntilLedger = 0

	if _, err := SignAndSubmit(context.Background(), p); err != nil {
		t.Fatalf("SignAndSubmit returned an unexpected error: %v", err)
	}

	var sawLatest bool
	for _, c := range client.calls {
		if c == "latest" {
			sawLatest = true
		}
	}
	if !sawLatest {
		t.Error("no expiration was given and the current ledger was never read")
	}
}
