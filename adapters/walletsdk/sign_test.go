package walletsdk

import (
	"context"
	"errors"
	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/xdr"
	"strings"
	"testing"
)

// signOnce runs the ordinary wallet flow — sign, record the enforce pass, take
// the envelope — and returns the submittable envelope. Every test that needs a
// signed envelope goes through this, so the enforce pass is never skipped by
// accident in the tests either.
func signOnce(t *testing.T, env xdr.TransactionEnvelope, kp Keypair) (*Signed, xdr.TransactionEnvelope) {
	t.Helper()

	signed, err := Sign(context.Background(), env, kp, testValidUntilLedger, testPassphrase)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signed.MarkEnforced()

	submittable, err := signed.Envelope()
	if err != nil {
		t.Fatalf("Envelope after MarkEnforced: %v", err)
	}
	return signed, submittable
}

// TestSignWithholdsTheEnvelopeUntilTheEnforcePassIsRecorded is the assertion
// behind the package's central promise: a wallet cannot get a submittable
// envelope out of it without saying, in the code, that the second simulation
// pass ran.
//
// Signing entries changes what the transaction costs to run, so an envelope
// assembled from the record-mode simulation carries too small a resource fee.
// Handing that envelope to a wallet that does not know about the second pass
// produces a fee error on-chain, after fees are paid; refusing to hand it over
// produces a local error with a name.
func TestSignWithholdsTheEnvelopeUntilTheEnforcePassIsRecorded(t *testing.T) {
	kp := testKeypair(t, "walletsdk-flow")
	env := testEnvelope(t, invokeOperation(t, testEntry(t, kp.Address(), 1)))
	before := encode(t, env)

	signed, err := Sign(context.Background(), env, kp, testValidUntilLedger, testPassphrase)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if after := encode(t, env); after != before {
		t.Error("Sign modified the caller's envelope, want it left alone")
	}

	entries := signed.Entries()
	if len(entries) != 1 {
		t.Fatalf("Sign reported %d entries, want 1", len(entries))
	}
	if entries[0].OperationIndex != 0 || entries[0].EntryIndex != 0 {
		t.Errorf("the entry is reported as operation %d entry %d, want operation 0 entry 0",
			entries[0].OperationIndex, entries[0].EntryIndex)
	}

	if signed.Enforced() {
		t.Error("the enforce pass is recorded before it ran")
	}
	if _, err := signed.Envelope(); !errors.Is(err, ErrEnforcePassMissing) {
		t.Fatalf("Envelope before MarkEnforced: got %v, want it to wrap %v", err, ErrEnforcePassMissing)
	}

	signed.MarkEnforced()
	if !signed.Enforced() {
		t.Error("MarkEnforced did not record the pass")
	}

	submittable, err := signed.Envelope()
	if err != nil {
		t.Fatalf("Envelope after MarkEnforced: %v", err)
	}
	if err := VerifyEnvelope(submittable, kp, testValidUntilLedger, testPassphrase); err != nil {
		t.Errorf("the signed envelope does not verify: %v", err)
	}
	if err := VerifyEnvelope(env, kp, testValidUntilLedger, testPassphrase); !errors.Is(err, ErrUnreadableSignature) {
		t.Errorf("the unsigned envelope: got %v, want it to wrap %v", err, ErrUnreadableSignature)
	}
}

// TestSignSignsEveryInvokeOperation checks the position reporting across more
// than one operation, including an operation that is not an invoke call: the
// indices must count it, because they are what the caller lines the signed
// entries back up against.
func TestSignSignsEveryInvokeOperation(t *testing.T) {
	kp := testKeypair(t, "walletsdk-multi-operation")
	env := testEnvelope(t,
		paymentOperation(t),
		invokeOperation(t, testEntry(t, kp.Address(), 1), testEntry(t, kp.Address(), 2)),
		invokeOperation(t, testEntry(t, kp.Address(), 3)),
	)

	signed, submittable := signOnce(t, env, kp)

	entries := signed.Entries()
	if len(entries) != 3 {
		t.Fatalf("Sign reported %d entries, want 3", len(entries))
	}
	wantPositions := [][2]int{{1, 0}, {1, 1}, {2, 0}}
	for i, want := range wantPositions {
		if entries[i].OperationIndex != want[0] || entries[i].EntryIndex != want[1] {
			t.Errorf("entry %d is at operation %d entry %d, want operation %d entry %d",
				i, entries[i].OperationIndex, entries[i].EntryIndex, want[0], want[1])
		}
	}

	if err := VerifyEnvelope(submittable, kp, testValidUntilLedger, testPassphrase); err != nil {
		t.Errorf("the signed envelope does not verify: %v", err)
	}
}

// TestSignPassesSourceAccountEntriesThrough covers the arm that has no payload
// of its own: it is reported, not signed, and not dropped.
func TestSignPassesSourceAccountEntriesThrough(t *testing.T) {
	kp := testKeypair(t, "walletsdk-source-account")
	env := testEnvelope(t, invokeOperation(t,
		testSourceAccountEntry(t),
		testEntry(t, kp.Address(), 1),
	))

	signed, submittable := signOnce(t, env, kp)

	entries := signed.Entries()
	if len(entries) != 2 {
		t.Fatalf("Sign reported %d entries, want 2", len(entries))
	}
	if entries[0].Entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
		t.Error("the source-account entry is not reported first")
	}

	if err := VerifyEnvelope(submittable, kp, testValidUntilLedger, testPassphrase); err != nil {
		t.Errorf("VerifyEnvelope on a signed envelope with a source-account entry: %v", err)
	}
}

// TestSignReadsThroughAFeeBumpEnvelope covers CAP-15's shape: a fee-bump
// transaction has no operations of its own, so the entries and the operation
// indices come from the inner transaction, and the envelope that comes back out
// is still the fee-bump one.
func TestSignReadsThroughAFeeBumpEnvelope(t *testing.T) {
	kp := testKeypair(t, "walletsdk-fee-bump")
	inner := testEnvelope(t, invokeOperation(t, testEntry(t, kp.Address(), 1)))
	env := feeBumpEnvelope(t, inner)

	requirements, err := Requirements(env, kp.Address())
	if err != nil {
		t.Fatalf("Requirements on a fee-bump envelope: %v", err)
	}
	if len(requirements) != 1 || requirements[0].OperationIndex != 0 || requirements[0].EntryIndex != 0 {
		t.Fatalf("Requirements reported %+v, want one entry at operation 0 entry 0", requirements)
	}

	signed, submittable := signOnce(t, env, kp)

	entries := signed.Entries()
	if len(entries) != 1 || entries[0].OperationIndex != 0 {
		t.Fatalf("Sign reported %+v, want one entry at operation 0", entries)
	}
	if submittable.Type != xdr.EnvelopeTypeEnvelopeTypeTxFeeBump {
		t.Errorf("the returned envelope is %s, want the fee-bump envelope", submittable.Type)
	}
	if err := VerifyEnvelope(submittable, kp, testValidUntilLedger, testPassphrase); err != nil {
		t.Errorf("VerifyEnvelope on the signed fee-bump envelope: %v", err)
	}
}

// TestSignRefusesAnEntryTheWalletDoesNotOwn states the boundary plainly. Sign
// inherits soroauth.AuthorizeEnvelope's all-or-nothing rule: it will not return
// an envelope half-signed, because entries belonging to other addresses are not
// this wallet's to fill in. A wallet handed an envelope it shares with a
// co-signer hears about it, by address and by position, rather than getting a
// transaction that fails later.
func TestSignRefusesAnEntryTheWalletDoesNotOwn(t *testing.T) {
	ours := testKeypair(t, "walletsdk-owned")
	theirs := testKeypair(t, "walletsdk-not-owned")

	env := testEnvelope(t,
		invokeOperation(t, testEntry(t, ours.Address(), 1)),
		invokeOperation(t, testEntry(t, theirs.Address(), 2)),
	)

	signed, err := Sign(context.Background(), env, ours, testValidUntilLedger, testPassphrase)
	if !errors.Is(err, soroauth.ErrMissingSigner) {
		t.Fatalf("got %v, want it to wrap %v", err, soroauth.ErrMissingSigner)
	}
	if signed != nil {
		t.Error("a refused envelope produced a Signed")
	}
	if !strings.Contains(err.Error(), theirs.Address()) {
		t.Errorf("the error %q does not name the address with no signer", err)
	}
	if !strings.Contains(err.Error(), "operation 1") {
		t.Errorf("the error %q does not name the operation the entry is in", err)
	}
}

func TestSignRefusesAnEnvelopeWithNoInvokeOperation(t *testing.T) {
	kp := testKeypair(t, "walletsdk-no-invoke")

	tests := map[string]xdr.TransactionEnvelope{
		"no operations at all": testEnvelope(t),
		"only a payment":       testEnvelope(t, paymentOperation(t)),
	}

	for name, env := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Sign(context.Background(), env, kp, testValidUntilLedger, testPassphrase)
			if !errors.Is(err, soroauth.ErrNoInvokeOperation) {
				t.Fatalf("got %v, want it to wrap %v", err, soroauth.ErrNoInvokeOperation)
			}

			if _, err := Requirements(env, kp.Address()); !errors.Is(err, soroauth.ErrNoInvokeOperation) {
				t.Errorf("Requirements: got %v, want it to wrap %v", err, soroauth.ErrNoInvokeOperation)
			}
			if err := VerifyEnvelope(env, kp, testValidUntilLedger, testPassphrase); !errors.Is(err, soroauth.ErrNoInvokeOperation) {
				t.Errorf("VerifyEnvelope: got %v, want it to wrap %v", err, soroauth.ErrNoInvokeOperation)
			}
		})
	}
}

// TestSignHonoursContextCancellation proves the keypair is never asked to sign
// once the context is done, which matters most for the hardware and remote
// signers this adapter exists to serve.
func TestSignHonoursContextCancellation(t *testing.T) {
	kp := testKeypair(t, "walletsdk-sign-cancelled")
	probe := stubKeypair{
		address: kp.Address(),
		sign: func([]byte) ([]byte, error) {
			t.Error("the keypair was asked to sign despite a cancelled context")
			return nil, errors.New("must not sign")
		},
	}
	env := testEnvelope(t, invokeOperation(t, testEntry(t, kp.Address(), 1)))

	_, err := Sign(cancelledContext(t), env, probe, testValidUntilLedger, testPassphrase)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want it to wrap %v", err, context.Canceled)
	}
}

// TestRequirementsReportWhatTheWalletOwes checks the wallet's to-do list: one
// Requirement per entry, in operation order, saying whether this key is wanted
// and whether it has already signed.
func TestRequirementsReportWhatTheWalletOwes(t *testing.T) {
	kp := testKeypair(t, "walletsdk-requirements")
	other := testKeypair(t, "walletsdk-requirements-other")

	env := testEnvelope(t,
		paymentOperation(t),
		invokeOperation(t,
			testEntry(t, kp.Address(), 11),
			testEntry(t, other.Address(), 12),
		),
	)

	requirements, err := Requirements(env, kp.Address())
	if err != nil {
		t.Fatalf("Requirements: %v", err)
	}
	if len(requirements) != 2 {
		t.Fatalf("Requirements reported %d entries, want 2", len(requirements))
	}

	ours := requirements[0]
	if ours.OperationIndex != 1 || ours.EntryIndex != 0 {
		t.Errorf("the wallet's entry is at operation %d entry %d, want operation 1 entry 0",
			ours.OperationIndex, ours.EntryIndex)
	}
	if !ours.Wanted {
		t.Error("the wallet's own entry is not reported as wanted")
	}
	if ours.Signed {
		t.Error("an unsigned entry is reported as signed")
	}
	if ours.Address != kp.Address() {
		t.Errorf("the reported address is %s, want %s", ours.Address, kp.Address())
	}
	if ours.Nonce != 11 {
		t.Errorf("the reported nonce is %d, want 11", ours.Nonce)
	}
	if ours.CredentialType != soroauth.CredentialTypeAddressV2 {
		t.Errorf("the reported credential type is %q", ours.CredentialType)
	}
	if ours.RootContract != testContractAddress(t, "walletsdk-contract") || ours.RootFunction != "transfer" {
		t.Errorf("the reported invocation is %s on %s, want transfer on the test contract",
			ours.RootFunction, ours.RootContract)
	}
	if ours.SubInvocations != 1 {
		t.Errorf("the reported sub-invocation count is %d, want 1", ours.SubInvocations)
	}

	somebodyElses := requirements[1]
	if somebodyElses.Wanted {
		t.Error("an entry for another address is reported as wanted")
	}
	if somebodyElses.Signed {
		t.Error("an entry for another address is reported as signed")
	}
	if somebodyElses.Address != other.Address() {
		t.Errorf("the second entry's address is %s, want %s", somebodyElses.Address, other.Address())
	}
	if somebodyElses.EntryIndex != 1 {
		t.Errorf("the second entry's index is %d, want 1", somebodyElses.EntryIndex)
	}
}

// TestRequirementsReportASignedEntry is the other half of the to-do list: after
// the signature is written, the same query says so.
func TestRequirementsReportASignedEntry(t *testing.T) {
	kp := testKeypair(t, "walletsdk-requirements-signed")
	env := testEnvelope(t, invokeOperation(t, testEntry(t, kp.Address(), 1)))

	_, submittable := signOnce(t, env, kp)

	requirements, err := Requirements(submittable, kp.Address())
	if err != nil {
		t.Fatalf("Requirements: %v", err)
	}
	if len(requirements) != 1 {
		t.Fatalf("Requirements reported %d entries, want 1", len(requirements))
	}
	if !requirements[0].Wanted {
		t.Error("the signed entry is no longer reported as wanted")
	}
	if !requirements[0].Signed {
		t.Error("the signed entry is not reported as signed")
	}
	if !requirements[0].TopLevelSigned {
		t.Error("Inspect does not report the top-level node as signed")
	}
}
