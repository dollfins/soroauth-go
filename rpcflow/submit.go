// Package rpcflow carries out the two-pass simulation a Soroban transaction
// needs when one of its authorization entries is signed by an address other
// than the transaction source.
//
// # Why this is not in the soroauth package
//
// soroauth signs authorization entries and nothing else. It consumes
// go-stellar-sdk's txnbuild and clients/rpcclient rather than wrapping them,
// and a caller who only wants to sign an entry should not link an RPC client
// to do it. This package is where the RPC-shaped helper lives so that
// importing soroauth stays cheap; importing rpcflow is the opt-in.
//
// # The two passes, and why neither can be skipped
//
// Simulation in record mode answers "which addresses must authorize this
// call" and hands back unsigned authorization entries. Those are signed. The
// transaction is then simulated again in enforce mode, carrying the signed
// entries, because the signatures are bytes the host has to read and charge
// for: a resource fee computed before they existed is too small. Submitting
// with the record pass's fee produces a transaction that is accepted, charged
// for, and then fails during application.
//
// So the order is fixed: record, sign, enforce, assemble from the enforcing
// pass, sign the envelope, send. Skipping the enforcing pass is the silent,
// incorrect shortcut this package exists to make unnecessary.
package rpcflow

import (
	"context"
	"fmt"

	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/protocols/stellarcore"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// Client is the part of a Soroban RPC client this package uses.
// *rpcclient.Client satisfies it.
//
// It is an interface rather than *rpcclient.Client so the flow can be driven
// offline by a test. The two-pass ordering is the thing most worth testing and
// the thing a network test proves least clearly: a live run that succeeds
// cannot show that the enforcing pass was the one that priced the
// signatures, but a fake client that records the calls can.
type Client interface {
	SimulateTransaction(ctx context.Context, request rpc.SimulateTransactionRequest) (rpc.SimulateTransactionResponse, error)
	GetLatestLedger(ctx context.Context) (rpc.GetLatestLedgerResponse, error)
	SendTransaction(ctx context.Context, request rpc.SendTransactionRequest) (rpc.SendTransactionResponse, error)
	PollTransaction(ctx context.Context, txHash string) (rpc.GetTransactionResponse, error)
}

// DefaultLifetimeLedgers is how far ahead signatures are valid when Params
// leaves ValidUntilLedger at zero. Roughly an hour at five seconds a ledger.
//
// There is no cap here on purpose. The host also refuses an expiration above
// its own max_live_until_ledger, a network setting this package cannot know
// offline, so a value that is too far ahead is refused by the network rather
// than silently clamped here.
const DefaultLifetimeLedgers = 720

// DefaultResourceFeePadding is added to the minimum resource fee the enforcing
// pass reports.
//
// The enforcing pass runs against a slightly earlier ledger than the one the
// transaction lands in, so the minimum it reports can be a little low by the
// time the host charges. Anything smaller than this risks a rejection exactly
// when the signatures are about to be paid for; anything much larger just
// moves money for no reason.
const DefaultResourceFeePadding = 100_000

// Submission is the outcome of sending a transaction.
type Submission struct {
	// Hash is the transaction hash the RPC reported.
	Hash string
	// Ledger is the ledger it landed in, zero if it never landed.
	Ledger uint32
	// Arm is the credential arm of the first authorization entry the
	// submitted envelope actually carried, read back by decoding the
	// envelope rather than assumed from what was built.
	Arm string
	// Status is the RPC's last reported status.
	Status string
	// RawError is the host's own error text when the transaction failed. It
	// is never paraphrased.
	RawError string
	// Diagnostics is the diagnostic events XDR the RPC returned, if any.
	Diagnostics []string
}

// Params is everything SignAndSubmit needs.
//
// Source and Operation are taken before the transaction is built, not after:
// txnbuild.Transaction has no exported fields and cannot be taken apart and
// reassembled, and both passes need to rebuild it with different auth entries
// and a different resource fee.
type Params struct {
	// Source is the account that pays for and sequences the transaction.
	Source txnbuild.Account
	// Operation is the invocation to authorize. Its Auth and Ext are set by
	// this package; anything already in them is replaced.
	Operation txnbuild.InvokeHostFunction
	// Signers sign the authorization entries the record pass returns. Every
	// address-arm entry must have one, or AuthorizeAll refuses the batch.
	Signers []soroauth.Signer
	// EnvelopeSigners sign the transaction envelope itself. This is the
	// source account's key, and it is separate from Signers: an entry
	// signature authorizes a call, an envelope signature pays for it.
	EnvelopeSigners []*keypair.Full
	// NetworkPassphrase is the network the entries are signed against. An
	// entry signed for the wrong network is refused by the host.
	NetworkPassphrase string
	// Client is the RPC both passes run against.
	Client Client
	// ValidUntilLedger is the last ledger the entry signatures are valid at.
	// Zero means DefaultLifetimeLedgers past the current ledger.
	ValidUntilLedger uint32
	// BaseFee is the per-operation fee. Zero means txnbuild.MinBaseFee * 100.
	BaseFee int64
	// ResourceFeePadding overrides DefaultResourceFeePadding when non-zero.
	ResourceFeePadding int64
}

// SignAndSubmit runs record, sign, enforce, assemble, sign and send, and
// returns what the RPC accepted.
//
// It never signs on a caller's behalf beyond the Signers and EnvelopeSigners
// given, and it does not fail the call when the host rejects the transaction
// on-chain: a rejection is an outcome, reported in the returned Submission
// with the host's raw error, not a transport failure. A non-nil error means
// the flow could not be completed, not that the transaction was refused.
func SignAndSubmit(ctx context.Context, p Params) (Submission, error) {
	var sub Submission

	if err := p.validate(); err != nil {
		return sub, err
	}

	// 1. Record. The RPC reports which addresses must authorize the call and
	// hands back unsigned authorization entries.
	recordTx, err := p.build(p.Operation)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (record): %w", err)
	}
	recorded, err := p.simulate(ctx, recordTx, rpc.AuthModeRecord)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (record): %w", err)
	}
	entries, err := recordedAuthEntries(recorded)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (record): %w", err)
	}

	// 2. Sign. One expiration for the whole run, resolved once, so the value
	// signed over and the value stored can never disagree.
	validUntil, err := p.expiration(ctx)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (sign): %w", err)
	}
	signedEntries, err := soroauth.AuthorizeAll(ctx, entries, p.Signers, validUntil, p.NetworkPassphrase)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (sign): %w", err)
	}

	// 3. Enforce. Re-simulate carrying the signed entries, so the resource fee
	// accounts for the signatures that are actually going out.
	enforceOp := p.Operation
	enforceOp.Auth = signedEntries
	enforceTx, err := p.build(enforceOp)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (enforce): %w", err)
	}
	enforced, err := p.simulate(ctx, enforceTx, rpc.AuthModeEnforce)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (enforce): %w", err)
	}

	// 4. Assemble from the enforcing pass, which is the one that priced the
	// signatures.
	finalOp := p.Operation
	finalOp.Auth = signedEntries
	if err := p.applyResources(&finalOp, enforced); err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (assemble): %w", err)
	}
	finalTx, err := p.build(finalOp)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (assemble): %w", err)
	}

	// 5. Sign the envelope and send.
	signedTx, err := finalTx.Sign(p.NetworkPassphrase, p.EnvelopeSigners...)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (envelope): %w", err)
	}
	return p.send(ctx, signedTx)
}

func (p Params) validate() error {
	switch {
	case p.Source == nil:
		return fmt.Errorf("soroauth: sign and submit: Source is required")
	case p.Client == nil:
		return fmt.Errorf("soroauth: sign and submit: Client is required")
	case p.NetworkPassphrase == "":
		return fmt.Errorf("soroauth: sign and submit: NetworkPassphrase is required")
	case len(p.EnvelopeSigners) == 0:
		// Without this the transaction goes out unsigned and is refused for a
		// missing signature, which reads as an auth problem and is not one.
		return fmt.Errorf("soroauth: sign and submit: at least one EnvelopeSigner is required to pay for the transaction")
	}
	return nil
}

// build makes an unsigned transaction carrying one InvokeHostFunction.
//
// IncrementSequenceNum is false because every pass builds from the same source
// account state: the record pass, the enforcing pass and the submitted
// transaction are the same transaction priced differently, not three
// transactions. Incrementing per pass would submit a sequence number two ahead
// of the account.
func (p Params) build(op txnbuild.InvokeHostFunction) (*txnbuild.Transaction, error) {
	baseFee := p.BaseFee
	if baseFee == 0 {
		baseFee = txnbuild.MinBaseFee * 100
	}
	return txnbuild.NewTransaction(txnbuild.TransactionParams{
		SourceAccount:        p.Source,
		IncrementSequenceNum: false,
		Operations:           []txnbuild.Operation{&op},
		BaseFee:              baseFee,
		Preconditions:        txnbuild.Preconditions{TimeBounds: txnbuild.NewInfiniteTimeout()},
	})
}

func (p Params) simulate(ctx context.Context, tx *txnbuild.Transaction, mode string) (rpc.SimulateTransactionResponse, error) {
	var zero rpc.SimulateTransactionResponse
	encoded, err := tx.Base64()
	if err != nil {
		return zero, fmt.Errorf("encoding the transaction: %w", err)
	}
	response, err := p.Client.SimulateTransaction(ctx, rpc.SimulateTransactionRequest{
		Transaction: encoded,
		AuthMode:    mode,
	})
	if err != nil {
		return zero, err
	}
	if response.Error != "" {
		return zero, fmt.Errorf("the rpc refused the simulation: %s", response.Error)
	}
	return response, nil
}

// expiration resolves the ledger the signatures are valid until.
func (p Params) expiration(ctx context.Context) (uint32, error) {
	if p.ValidUntilLedger != 0 {
		return p.ValidUntilLedger, nil
	}
	latest, err := p.Client.GetLatestLedger(ctx)
	if err != nil {
		return 0, fmt.Errorf("reading the current ledger to resolve an expiration: %w", err)
	}
	return soroauth.ExpirationAfter(latest.Sequence, DefaultLifetimeLedgers)
}

// applyResources attaches the enforcing pass's footprint and fee to the
// operation.
func (p Params) applyResources(op *txnbuild.InvokeHostFunction, sim rpc.SimulateTransactionResponse) error {
	var data xdr.SorobanTransactionData
	if err := xdr.SafeUnmarshalBase64(sim.TransactionDataXDR, &data); err != nil {
		return fmt.Errorf("decoding the simulated transaction data: %w", err)
	}
	padding := p.ResourceFeePadding
	if padding == 0 {
		padding = DefaultResourceFeePadding
	}
	// Simulation reports the minimum resource fee separately from the data;
	// use the reported minimum rather than whatever the data happens to carry.
	data.ResourceFee = xdr.Int64(sim.MinResourceFee) + xdr.Int64(padding)
	op.Ext = xdr.TransactionExt{V: 1, SorobanData: &data}
	return nil
}

func (p Params) send(ctx context.Context, tx *txnbuild.Transaction) (Submission, error) {
	var sub Submission
	encoded, err := tx.Base64()
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (send): encoding the signed transaction: %w", err)
	}

	// Read the arm off the envelope that is actually going out, rather than
	// assuming it is the one that was built.
	sub.Arm = credentialArmOf(encoded)

	sent, err := p.Client.SendTransaction(ctx, rpc.SendTransactionRequest{Transaction: encoded})
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (send): %w", err)
	}

	sub.Hash, sub.Status = sent.Hash, sent.Status
	if sent.Status == stellarcore.TXStatusError {
		sub.RawError = sent.ErrorResultXDR
		sub.Diagnostics = sent.DiagnosticEventsXDR
		return sub, nil
	}

	polled, err := p.Client.PollTransaction(ctx, sent.Hash)
	if err != nil {
		return sub, fmt.Errorf("soroauth: sign and submit (poll): %w", err)
	}
	sub.Status, sub.Ledger = polled.Status, polled.Ledger
	if polled.Status != rpc.TransactionStatusSuccess {
		sub.RawError = polled.ResultXDR
		sub.Diagnostics = polled.DiagnosticEventsXDR
	}
	return sub, nil
}

// recordedAuthEntries pulls the unsigned authorization entries out of a record
// pass.
//
// A simulation with no results, or with no auth array, is an error rather than
// an empty batch: an invocation that needs no authorization would not be run
// through this helper, so the likely cause is that the wrong thing was
// simulated, and signing nothing would hide that.
func recordedAuthEntries(sim rpc.SimulateTransactionResponse) ([]xdr.SorobanAuthorizationEntry, error) {
	if len(sim.Results) != 1 {
		return nil, fmt.Errorf("the simulation returned %d results, want exactly 1: %w",
			len(sim.Results), soroauth.ErrNoInvokeOperation)
	}
	if sim.Results[0].AuthXDR == nil {
		return nil, fmt.Errorf("the simulation recorded no authorization entries: %w",
			soroauth.ErrNoInvokeOperation)
	}
	encodedEntries := *sim.Results[0].AuthXDR
	entries := make([]xdr.SorobanAuthorizationEntry, 0, len(encodedEntries))
	for i, encoded := range encodedEntries {
		var entry xdr.SorobanAuthorizationEntry
		if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
			return nil, fmt.Errorf("decoding recorded entry %d: %w", i, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// credentialArmOf decodes a submitted envelope and reports the credential arm
// of its first authorization entry, or "" if it carries none.
func credentialArmOf(envelopeBase64 string) string {
	var envelope xdr.TransactionEnvelope
	if err := xdr.SafeUnmarshalBase64(envelopeBase64, &envelope); err != nil {
		return ""
	}
	entries, err := soroauth.EnvelopeEntries(envelope)
	if err != nil || len(entries) == 0 {
		return ""
	}
	return entries[0].Entry.Credentials.Type.String()
}
