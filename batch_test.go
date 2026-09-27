package soroauth

import (
	"context"
	"testing"

	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"strings"
)

// entryForSigner builds an address entry owned by the given test label.
func entryForSigner(t *testing.T, label string, armType xdr.SorobanCredentialsType, nonce int64) xdr.SorobanAuthorizationEntry {
	t.Helper()
	entry := entryForArm(t, armType, nonce)
	address, err := ParseAddress(testKeypair(t, label).Address())
	if err != nil {
		t.Fatalf("parsing %q: %v", label, err)
	}
	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		t.Fatalf("reading credentials: %v", err)
	}
	credentials.Address = address
	return entry
}

func TestAuthorizeAllSignsEveryEntry(t *testing.T) {
	first := "soroauth-batch-1"
	second := "soroauth-batch-2"

	entries := []xdr.SorobanAuthorizationEntry{
		entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 1),
		entryForSigner(t, first, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 2),
		entryForSigner(t, second, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 3),
	}

	sourceBefore, err := entries[0].MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	signed, err := AuthorizeAll(context.Background(), entries, []Signer{
		NewEd25519Signer(testKeypair(t, first)),
		NewEd25519Signer(testKeypair(t, second)),
	}, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll returned an unexpected error: %v", err)
	}
	if len(signed) != len(entries) {
		t.Fatalf("got %d entries back, want %d", len(signed), len(entries))
	}

	// The source-account entry is returned untouched.
	sourceAfter, err := signed[0].MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if !bytes.Equal(sourceBefore, sourceAfter) {
		t.Error("the source-account entry was changed")
	}

	for i, label := range []string{first, second} {
		entry := signed[i+1]
		credentials, err := addressCredentials(entry.Credentials)
		if err != nil {
			t.Fatalf("reading credentials: %v", err)
		}
		if !isSigned(credentials.Signature) {
			t.Fatalf("entry %d was returned unsigned", i+1)
		}
		if credentials.SignatureExpirationLedger != xdr.Uint32(testValidUntilLedger) {
			t.Errorf("entry %d expiration is %d, want %d",
				i+1, credentials.SignatureExpirationLedger, testValidUntilLedger)
		}

		preimage, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
		if err != nil {
			t.Fatalf("rebuilding the preimage: %v", err)
		}
		payload, err := Payload(preimage)
		if err != nil {
			t.Fatalf("rehashing: %v", err)
		}
		parts := decodeAccountSignature(t, credentials.Signature)
		if err := testKeypair(t, label).Verify(payload[:], parts[0].signature); err != nil {
			t.Errorf("entry %d signature does not verify: %v", i+1, err)
		}
	}
}

// TestAuthorizeAllNeverSkipsAnEntry is the rule that matters most here: a
// missing signer must fail the batch, not silently leave an entry unsigned.
func TestAuthorizeAllNeverSkipsAnEntry(t *testing.T) {
	present := "soroauth-batch-1"
	absent := "soroauth-batch-2"

	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, present, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
		entryForSigner(t, absent, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
	}

	got, err := AuthorizeAll(context.Background(), entries,
		[]Signer{NewEd25519Signer(testKeypair(t, present))},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err == nil {
		t.Fatalf("AuthorizeAll skipped an entry instead of failing, returning %d entries", len(got))
	}
	if !errors.Is(err, ErrMissingSigner) {
		t.Errorf("error %q does not match ErrMissingSigner", err)
	}
	if !strings.Contains(err.Error(), testKeypair(t, absent).Address()) {
		t.Errorf("error %q does not name the address with no signer", err)
	}
	if got != nil {
		t.Errorf("AuthorizeAll returned %d entries alongside an error, want nil", len(got))
	}
}

// TestAuthorizeAllIsAllOrNothing: even when earlier entries signed fine, a
// later failure must leave nothing behind.
func TestAuthorizeAllIsAllOrNothing(t *testing.T) {
	good := "soroauth-batch-1"
	bad := "soroauth-batch-2"
	signerError := errors.New("the hardware signer refused")

	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, good, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
		entryForSigner(t, bad, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
	}

	got, err := AuthorizeAll(context.Background(), entries, []Signer{
		NewEd25519Signer(testKeypair(t, good)),
		SignerFunc(testKeypair(t, bad).Address(),
			func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
				return xdr.ScVal{}, signerError
			}),
	}, testValidUntilLedger, network.TestNetworkPassphrase)

	if err == nil {
		t.Fatal("AuthorizeAll succeeded despite a failing signer")
	}
	if !errors.Is(err, signerError) {
		t.Errorf("error %q does not wrap the signer's error", err)
	}
	if got != nil {
		t.Errorf("AuthorizeAll returned %d entries alongside an error, want nil", len(got))
	}
}

// TestAuthorizeAllFillsDelegateTrees applies several signers to one delegates
// entry, each targeted by address.
func TestAuthorizeAllFillsDelegateTrees(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	d1 := testKeypair(t, "soroauth-delegate-1")
	d2 := testKeypair(t, "soroauth-delegate-2")
	nested := testKeypair(t, "soroauth-delegate-nested-1")

	entry, err := WithDelegates(base, testValidUntilLedger, []Delegate{
		{Address: d1.Address(), Nested: []Delegate{{Address: nested.Address()}}},
		{Address: d2.Address()},
	}, nil)
	if err != nil {
		t.Fatalf("building the entry: %v", err)
	}

	signed, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(d1), NewEd25519Signer(d2), NewEd25519Signer(nested)},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll returned an unexpected error: %v", err)
	}

	info, err := Inspect(signed[0])
	if err != nil {
		t.Fatalf("inspecting: %v", err)
	}
	// The account itself never signed: CAP-71-01 allows a Void top-level
	// signature when the delegates carry the authentication.
	if info.TopLevelSigned {
		t.Error("the top-level node was signed even though no signer owns that address")
	}

	var signedNodes int
	var walk func(nodes []NodeInfo)
	walk = func(nodes []NodeInfo) {
		for _, node := range nodes {
			if node.Signed {
				signedNodes++
			}
			walk(node.Nested)
		}
	}
	walk(info.Delegates)
	if signedNodes != 3 {
		t.Errorf("%d delegate nodes are signed, want 3", signedNodes)
	}
}

// TestAuthorizeAllAcceptsDelegatesWithoutATopLevelSigner pins down the
// ambiguity resolved in AuthorizeAll's doc comment: one matching signer
// anywhere in the tree is enough, because requiring the account's own
// signature would break the delegates-only pattern CAP-71-01 allows.

func TestVerifyAllWithOptionsAndEntries(t *testing.T) {
	first := "soroauth-batch-verify-1"
	kp := testKeypair(t, first)
	signer := NewEd25519Signer(kp)
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 10)

	address, err := ParseAddress(kp.Address())
	require.NoError(t, err)
	cred, err := addressCredentials(base.Credentials)
	require.NoError(t, err)
	cred.Address = address

	signedSlice, err := AuthorizeAll(context.Background(), []xdr.SorobanAuthorizationEntry{base}, []Signer{signer}, testValidUntilLedger, network.TestNetworkPassphrase)
	require.NoError(t, err)

	results, err := VerifyAll(context.Background(), signedSlice, network.TestNetworkPassphrase, WithConcurrency(4))
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
}

func TestAuthorizeAllAcceptsDelegatesWithoutATopLevelSigner(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	delegate := testKeypair(t, "soroauth-delegate-1")

	entry, err := WithDelegates(base, testValidUntilLedger,
		[]Delegate{{Address: delegate.Address()}}, nil)
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	signed, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(delegate)},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll rejected a delegates-only entry: %v", err)
	}

	info, err := Inspect(signed[0])
	if err != nil {
		t.Fatalf("inspecting: %v", err)
	}
	if info.TopLevelSigned {
		t.Error("the top-level node was signed")
	}
	if len(info.Delegates) != 1 || !info.Delegates[0].Signed {
		t.Error("the delegate was not signed")
	}
}

// And the other half: a delegates entry nobody can sign must still fail.
func TestAuthorizeAllRejectsDelegatesWithNoMatchingSigner(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	entry, err := WithDelegates(base, testValidUntilLedger,
		[]Delegate{{Address: testKeypair(t, "soroauth-delegate-1").Address()}}, nil)
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	got, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(testKeypair(t, "soroauth-authorize-stranger"))},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err == nil {
		t.Fatal("AuthorizeAll accepted an entry no signer can sign")
	}
	if !errors.Is(err, ErrMissingSigner) {
		t.Errorf("error %q does not match ErrMissingSigner", err)
	}
	if got != nil {
		t.Error("AuthorizeAll returned entries alongside an error")
	}
}

func TestAuthorizeAllDoesNotMutateItsInput(t *testing.T) {
	label := "soroauth-batch-1"
	entries := []xdr.SorobanAuthorizationEntry{
		entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 1),
		entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
	}

	before := make([][]byte, len(entries))
	for i, entry := range entries {
		encoded, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		before[i] = encoded
	}

	signed, err := AuthorizeAll(context.Background(), entries,
		[]Signer{NewEd25519Signer(testKeypair(t, label))},
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll returned an unexpected error: %v", err)
	}

	for i, entry := range entries {
		after, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("re-marshalling: %v", err)
		}
		if !bytes.Equal(before[i], after) {
			t.Errorf("entry %d was mutated\n before %x\n  after %x", i, before[i], after)
		}
	}

	// Writing through a result must not reach the input, including the
	// source-account entry that was only copied.
	for i := range signed {
		signed[i].RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("drain")
	}
	for i, entry := range entries {
		after, err := entry.MarshalBinary()
		if err != nil {
			t.Fatalf("re-marshalling: %v", err)
		}
		if !bytes.Equal(before[i], after) {
			t.Errorf("result %d still shares memory with the input", i)
		}
	}
}

// TestAuthorizeAllRequireAllSignedRejectsAPartiallySignedDelegateTree proves
// RequireAllSigned catches what the default behaviour deliberately lets
// through: a delegate whose signer never matched, in an otherwise fully
// signed tree (including the top-level node, so the unsigned delegate is
// unambiguously the cause).
func TestAuthorizeAllRequireAllSignedRejectsAPartiallySignedDelegateTree(t *testing.T) {
	owner := testKeypair(t, "soroauth-preimage-signer") // entryForArm's account
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	d1 := testKeypair(t, "soroauth-delegate-1")
	d2 := testKeypair(t, "soroauth-delegate-2")

	entry, err := WithDelegates(base, testValidUntilLedger,
		[]Delegate{{Address: d1.Address()}, {Address: d2.Address()}}, nil)
	if err != nil {
		t.Fatalf("building the entry: %v", err)
	}

	got, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(owner), NewEd25519Signer(d1)}, // d2 never signs
		testValidUntilLedger, network.TestNetworkPassphrase, RequireAllSigned())
	if err == nil {
		t.Fatal("AuthorizeAll with RequireAllSigned accepted a partially signed tree")
	}
	if !errors.Is(err, ErrUnsignedCredentialNode) {
		t.Errorf("error %q does not match ErrUnsignedCredentialNode", err)
	}
	if !strings.Contains(err.Error(), d2.Address()) {
		t.Errorf("error %q does not name the unsigned delegate", err)
	}
	if got != nil {
		t.Error("AuthorizeAll returned entries alongside an error")
	}
}

// TestAuthorizeAllRequireAllSignedNoOpOnFullySignedSingleNode proves
// RequireAllSigned is a no-op for the ordinary case: a legacy or V2 entry
// with its one node signed, which is everything AuthorizeAll ever returns
// for those arms.
func TestAuthorizeAllRequireAllSignedNoOpOnFullySignedSingleNode(t *testing.T) {
	label := "soroauth-batch-1"
	entries := []xdr.SorobanAuthorizationEntry{
		entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 1),
		entryForSigner(t, label, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
	}

	got, err := AuthorizeAll(context.Background(), entries,
		[]Signer{NewEd25519Signer(testKeypair(t, label))},
		testValidUntilLedger, network.TestNetworkPassphrase, RequireAllSigned())
	if err != nil {
		t.Fatalf("RequireAllSigned rejected a fully signed batch: %v", err)
	}
	if len(got) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(got), len(entries))
	}
}

// TestAuthorizeAllRequireAllSignedAcceptsAFullySignedDelegateTree is the
// positive half: every node signed, including the top-level node, passes.
// (RequireAllSigned checks the top-level node literally; see its doc
// comment for why a delegates-only account, which leaves that node Void on
// purpose, should not use this option.)
func TestAuthorizeAllRequireAllSignedAcceptsAFullySignedDelegateTree(t *testing.T) {
	owner := testKeypair(t, "soroauth-preimage-signer") // entryForArm's account
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	d1 := testKeypair(t, "soroauth-delegate-1")
	d2 := testKeypair(t, "soroauth-delegate-2")

	entry, err := WithDelegates(base, testValidUntilLedger,
		[]Delegate{{Address: d1.Address()}, {Address: d2.Address()}}, nil)
	if err != nil {
		t.Fatalf("building the entry: %v", err)
	}

	got, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(owner), NewEd25519Signer(d1), NewEd25519Signer(d2)},
		testValidUntilLedger, network.TestNetworkPassphrase, RequireAllSigned())
	if err != nil {
		t.Fatalf("RequireAllSigned rejected a fully signed delegate tree: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
}

// TestAuthorizeAllRequireAllSignedRejectsAnIntentionallyVoidTopLevel pins
// down the documented boundary: RequireAllSigned checks the top-level node
// literally, so a delegates-only entry whose top-level signature is Void on
// purpose (CAP-71-01) is reported as unsigned rather than silently accepted.
func TestAuthorizeAllRequireAllSignedRejectsAnIntentionallyVoidTopLevel(t *testing.T) {
	owner := testKeypair(t, "soroauth-preimage-signer")
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	delegate := testKeypair(t, "soroauth-delegate-1")

	entry, err := WithDelegates(base, testValidUntilLedger,
		[]Delegate{{Address: delegate.Address()}}, nil)
	if err != nil {
		t.Fatalf("building the entry: %v", err)
	}

	got, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(delegate)}, // owner never signs, by design
		testValidUntilLedger, network.TestNetworkPassphrase, RequireAllSigned())
	if err == nil {
		t.Fatal("RequireAllSigned accepted an entry with an intentionally Void top-level node")
	}
	if !errors.Is(err, ErrUnsignedCredentialNode) {
		t.Errorf("error %q does not match ErrUnsignedCredentialNode", err)
	}
	if !strings.Contains(err.Error(), owner.Address()) {
		t.Errorf("error %q does not name the unsigned top-level address", err)
	}
	if got != nil {
		t.Error("AuthorizeAll returned entries alongside an error")
	}
}

// TestAuthorizeAllWithDelegatePlansWrapsTheNamedEntry proves the plan is
// applied before signing: an entry that arrived as plain V2 comes back as
// the delegates arm, with the planned delegate signed.
func TestAuthorizeAllWithDelegatePlansWrapsTheNamedEntry(t *testing.T) {
	owner := testKeypair(t, "soroauth-batch-1")
	delegate := testKeypair(t, "soroauth-delegate-1")
	entry := entryForSigner(t, "soroauth-batch-1", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)

	got, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(delegate)},
		testValidUntilLedger, network.TestNetworkPassphrase,
		WithDelegatePlans(map[string]DelegatePlan{
			owner.Address(): {Delegates: []Delegate{{Address: delegate.Address()}}},
		}))
	if err != nil {
		t.Fatalf("AuthorizeAll with a delegate plan returned an unexpected error: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}

	info, err := Inspect(got[0])
	if err != nil {
		t.Fatalf("inspecting: %v", err)
	}
	if info.CredentialType != CredentialTypeAddressWithDelegates {
		t.Errorf("credential_type = %q, want %q", info.CredentialType, CredentialTypeAddressWithDelegates)
	}
	if len(info.Delegates) != 1 || !info.Delegates[0].Signed {
		t.Error("the planned delegate was not signed")
	}
}

// TestAuthorizeAllWithDelegatePlansLeavesUnplannedEntriesAsIs proves an entry
// with no matching plan key is signed exactly as AuthorizeAll always signed
// it — the plan is additive, never a global behaviour change.
func TestAuthorizeAllWithDelegatePlansLeavesUnplannedEntriesAsIs(t *testing.T) {
	planned := testKeypair(t, "soroauth-batch-1")
	unplanned := testKeypair(t, "soroauth-batch-2")
	delegate := testKeypair(t, "soroauth-delegate-1")

	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, "soroauth-batch-1", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
		entryForSigner(t, "soroauth-batch-2", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
	}

	got, err := AuthorizeAll(context.Background(), entries,
		[]Signer{NewEd25519Signer(delegate), NewEd25519Signer(unplanned)},
		testValidUntilLedger, network.TestNetworkPassphrase,
		WithDelegatePlans(map[string]DelegatePlan{
			planned.Address(): {Delegates: []Delegate{{Address: delegate.Address()}}},
		}))
	if err != nil {
		t.Fatalf("AuthorizeAll returned an unexpected error: %v", err)
	}

	infoPlanned, err := Inspect(got[0])
	if err != nil {
		t.Fatalf("inspecting entry 0: %v", err)
	}
	if infoPlanned.CredentialType != CredentialTypeAddressWithDelegates {
		t.Errorf("entry 0 credential_type = %q, want %q", infoPlanned.CredentialType, CredentialTypeAddressWithDelegates)
	}

	infoUnplanned, err := Inspect(got[1])
	if err != nil {
		t.Fatalf("inspecting entry 1: %v", err)
	}
	if infoUnplanned.CredentialType != CredentialTypeAddressV2 {
		t.Errorf("entry 1 credential_type = %q, want %q (unplanned entries stay as they arrived)",
			infoUnplanned.CredentialType, CredentialTypeAddressV2)
	}
	if !infoUnplanned.TopLevelSigned {
		t.Error("entry 1 (unplanned) was not signed")
	}
}

// TestAuthorizeAllWithDelegatePlansUnmatchedAddressErrors proves a plan for
// an address absent from the batch fails loudly instead of being ignored.
func TestAuthorizeAllWithDelegatePlansUnmatchedAddressErrors(t *testing.T) {
	present := testKeypair(t, "soroauth-batch-1")
	absent := testKeypair(t, "soroauth-batch-2")
	delegate := testKeypair(t, "soroauth-delegate-1")

	entry := entryForSigner(t, "soroauth-batch-1", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)

	got, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(present), NewEd25519Signer(delegate)},
		testValidUntilLedger, network.TestNetworkPassphrase,
		WithDelegatePlans(map[string]DelegatePlan{
			absent.Address(): {Delegates: []Delegate{{Address: delegate.Address()}}},
		}))
	if err == nil {
		t.Fatal("AuthorizeAll accepted a delegate plan for an address absent from the batch")
	}
	if !errors.Is(err, ErrDelegatePlanUnmatched) {
		t.Errorf("error %q does not match ErrDelegatePlanUnmatched", err)
	}
	if !strings.Contains(err.Error(), absent.Address()) {
		t.Errorf("error %q does not name the unmatched plan address", err)
	}
	if got != nil {
		t.Error("AuthorizeAll returned entries alongside an error")
	}
}

func TestAuthorizeAllEmptyBatch(t *testing.T) {
	got, err := AuthorizeAll(context.Background(), nil, nil,
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll returned an unexpected error for an empty batch: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entries for an empty batch", len(got))
	}
}

// exampleV2Entry builds a minimal, unsigned V2 entry for owner, for use in
// package examples that need a real entry without a *testing.T.
func exampleV2Entry(owner *keypair.Full, nonce int64) (xdr.SorobanAuthorizationEntry, error) {
	address, err := ParseAddress(owner.Address())
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	var contractID xdr.ContractId
	for i := range contractID {
		contractID[i] = byte(i)
	}
	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:   address,
				Nonce:     xdr.Int64(nonce),
				Signature: xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: newScVec()},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: &contractID,
					},
					FunctionName: xdr.ScSymbol("transfer"),
				},
			},
		},
	}, nil
}

// ExampleWithDelegatePlans shows AuthorizeAll wrapping one address's entry
// in the delegates arm and signing it, in a single call, from a plan keyed
// by that address.
func ExampleWithDelegatePlans() {
	owner, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-plan-owner")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	delegate, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-plan-delegate")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	entry, err := exampleV2Entry(owner, 1)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	signed, err := AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(delegate)},
		1234567, network.TestNetworkPassphrase,
		WithDelegatePlans(map[string]DelegatePlan{
			owner.Address(): {Delegates: []Delegate{{Address: delegate.Address()}}},
		}))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	info, err := Inspect(signed[0])
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	fmt.Println(info.CredentialType, "delegate signed:", info.Delegates[0].Signed)
	// Output:
	// address_with_delegates delegate signed: true
}

// ExampleRequireAllSigned shows AuthorizeAll rejecting a batch that its
// default behaviour would accept: a delegates entry whose top-level node
// was never signed, once the caller opts into the stricter check.
func ExampleRequireAllSigned() {
	owner, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-require-owner")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	delegate, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-require-delegate")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	base, err := exampleV2Entry(owner, 1)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	entry, err := WithDelegates(base, 1234567, []Delegate{{Address: delegate.Address()}}, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	_, err = AuthorizeAll(context.Background(),
		[]xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(delegate)}, // the account's own key never signs
		1234567, network.TestNetworkPassphrase, RequireAllSigned())
	fmt.Println("rejected:", errors.Is(err, ErrUnsignedCredentialNode))
	// Output:
	// rejected: true
}

func TestVerifyAllAndVerifyEntry(t *testing.T) {
	kp := testKeypair(t, "soroauth-verify-batch")
	parsedAddr := mustParse(t, kp.Address())
	signer := NewEd25519Signer(testKeypair(t, "soroauth-verify-batch"))

	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 1)
	cred, err := addressCredentials(base.Credentials)
	require.NoError(t, err)
	cred.Address = parsedAddr

	signedSlice, err := AuthorizeAll(context.Background(), []xdr.SorobanAuthorizationEntry{base}, []Signer{signer}, 100, network.TestNetworkPassphrase)
	require.NoError(t, err)
	require.NoError(t, err)

	report, err := VerifyEntry(signedSlice[0], network.TestNetworkPassphrase)
	require.NoError(t, err)
	assert.True(t, report.Verified())

	results, err := VerifyAll(context.Background(), signedSlice, network.TestNetworkPassphrase, WithConcurrency(2))
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.NoError(t, results[0].Error)
	reportFromResults, err := VerifyEntry(signedSlice[0], network.TestNetworkPassphrase)
	require.NoError(t, err)
	assert.True(t, reportFromResults.Verified())
}

func TestVerifyAllWithOptionsAndErrors(t *testing.T) {
	kp := testKeypair(t, "soroauth-verify-batch")
	signer := NewEd25519Signer(kp)

	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 10)
	address, err := ParseAddress(kp.Address())
	require.NoError(t, err)
	cred, err := addressCredentials(entry.Credentials)
	require.NoError(t, err)
	cred.Address = address

	signedSlice, err := AuthorizeAll(context.Background(), []xdr.SorobanAuthorizationEntry{entry}, []Signer{signer}, 100, network.TestNetworkPassphrase)
	require.NoError(t, err)

	unsignedEntry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 11)

	entries := []xdr.SorobanAuthorizationEntry{signedSlice[0], unsignedEntry}

	results, err := VerifyAll(context.Background(), entries, network.TestNetworkPassphrase, WithConcurrency(2))
	require.NoError(t, err)
	require.Len(t, results, 2)

	assert.NoError(t, results[0].Error)

	// The second entry is unsigned, and VerifyAll deliberately does not treat
	// that as an error: the loop above only sets Error for a verdict that is
	// neither VerdictVerified nor VerdictUnsigned. That matches the engine's
	// own semantics — CAP-71-01 permits a Void top-level signature when only
	// delegates authenticate, so "unsigned" is a verdict, not a failure.
	assert.NoError(t, results[1].Error)
	assert.Equal(t, 1, results[1].Index)
}
