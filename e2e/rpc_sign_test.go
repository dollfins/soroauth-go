//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/rpcflow"
)

// TestSignAndSubmitProvesTheRecordAndEnforcePassesRunLive drives rpcflow's
// whole flow against testnet: record, sign, enforce, assemble, sign the
// envelope, send.
//
// What a live run adds over rpcflow's own unit tests is the host's judgement.
// The unit tests prove the enforcing pass carries the signed entries and that
// the submitted fee comes from that pass; they cannot prove the host accepts
// the result. Only a real submission does that, because only the host decides
// whether the fee covers the signatures it had to read.
func TestSignAndSubmitProvesTheRecordAndEnforcePassesRunLive(t *testing.T) {
	h := newHarness(t)
	payer := h.newAccount(t, "rpcflow payer")
	signer := h.newAccount(t, "rpcflow signer")
	to := h.newAccount(t, "rpcflow recipient")

	op := h.transferOp(t,
		scAddressOf(t, signer.Address()),
		scAddressOf(t, to.Address()),
		transferAmount,
		payer.Address(),
	)

	sub, err := rpcflow.SignAndSubmit(context.Background(), rpcflow.Params{
		Source:    h.account(t, payer.Address()),
		Operation: op,
		// The entry signer and the envelope signer are different accounts on
		// purpose: that is the case the two-pass flow exists for. If they were
		// the same, the source-account arm would cover it and no entry would
		// need signing at all.
		Signers:           []soroauth.Signer{soroauth.NewEd25519Signer(signer)},
		EnvelopeSigners:   []*keypair.Full{payer},
		NetworkPassphrase: h.passphrase,
		Client:            h.client,
	})
	if err != nil {
		t.Fatalf("SignAndSubmit returned an unexpected error: %v", err)
	}
	if sub.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("the host rejected the transaction (status %s): %s", sub.Status, sub.RawError)
	}

	// The arm is read back off the submitted envelope, not assumed from what
	// was built, so this asserts what actually went to the network.
	if want := "SorobanCredentialsTypeSorobanCredentialsAddress"; sub.Arm != want {
		t.Errorf("the submitted envelope carried arm %q, want %q", sub.Arm, want)
	}
	if sub.Ledger == 0 {
		t.Error("the transaction succeeded but reported no ledger")
	}

	t.Logf("scenario rpcflow: hash=%s ledger=%d arm=%s", sub.Hash, sub.Ledger, sub.Arm)
	t.Logf("https://stellar.expert/explorer/testnet/tx/%s", sub.Hash)
}
