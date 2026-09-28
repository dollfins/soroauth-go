package soroauth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// wantAddressError is the shared assertion for a typed address error recovered
// with errors.As: the field must carry the address, errors.Is must still match
// the sentinel, and the full message must contain the address.
func wantAddressError(t *testing.T, err error, sentinel error, address string, extract func(error) (string, bool)) {
	t.Helper()

	if err == nil {
		t.Fatal("expected an error, got nil")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("errors.Is(%q, %v) = false, want true", err, sentinel)
	}
	got, ok := extract(err)
	if !ok {
		t.Errorf("errors.As did not recover a typed address error from %q", err)
		return
	}
	if got != address {
		t.Errorf("recovered address %q, want %q", got, address)
	}
	if address != "" && !strings.Contains(err.Error(), address) {
		t.Errorf("error %q does not contain the address %q", err, address)
	}
}

func extractNoMatching(err error) (string, bool) {
	var e *NoMatchingCredentialNodeError
	if !errors.As(err, &e) {
		return "", false
	}
	return e.Address, true
}

func extractDuplicate(err error) (string, bool) {
	var e *DuplicateDelegateError
	if !errors.As(err, &e) {
		return "", false
	}
	return e.Address, true
}

func extractMissing(err error) (string, bool) {
	var e *MissingSignerError
	if !errors.As(err, &e) {
		return "", false
	}
	return e.Address, true
}

func extractUnsigned(err error) (string, bool) {
	var e *UnsignedCredentialNodeError
	if !errors.As(err, &e) {
		return "", false
	}
	return e.Address, true
}

func extractPlanUnmatched(err error) (string, bool) {
	var e *DelegatePlanUnmatchedError
	if !errors.As(err, &e) {
		return "", false
	}
	return e.Address, true
}

// TestNoMatchingCredentialNodeErrorTyped proves errors.As recovers the target
// address from AuthorizeEntry's no-match failure while errors.Is still matches
// the sentinel, and that the message still names the address.
func TestNoMatchingCredentialNodeErrorTyped(t *testing.T) {
	wrong := testKeypair(t, "soroauth-err-wrong-key")
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	_, err := AuthorizeEntry(context.Background(), entry, NewEd25519Signer(wrong),
		testValidUntilLedger, network.TestNetworkPassphrase)
	wantAddressError(t, err, ErrNoMatchingCredentialNode, wrong.Address(), extractNoMatching)

	want := "soroauth: authorize entry: " + wrong.Address() + ": " + ErrNoMatchingCredentialNode.Error()
	if err.Error() != want {
		t.Errorf("message = %q, want %q", err, want)
	}
}

// TestDuplicateDelegateErrorTypedFromWithDelegates proves errors.As recovers
// the duplicated address from WithDelegates while errors.Is still matches.
func TestDuplicateDelegateErrorTypedFromWithDelegates(t *testing.T) {
	dup := testKeypair(t, "soroauth-err-dup-a")
	other := testKeypair(t, "soroauth-err-dup-b")
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 43)

	_, err := WithDelegates(entry, testValidUntilLedger, []Delegate{
		{Address: dup.Address()}, {Address: other.Address()}, {Address: dup.Address()},
	}, nil)
	wantAddressError(t, err, ErrDuplicateDelegate, dup.Address(), extractDuplicate)

	want := "soroauth: with delegates: " + dup.Address() + ": " + ErrDuplicateDelegate.Error()
	if err.Error() != want {
		t.Errorf("message = %q, want %q", err, want)
	}
}

// TestDuplicateDelegateErrorTypedFromValidateOrder proves errors.As recovers
// the duplicated address from ValidateDelegateOrder (and the AuthorizeEntry
// path that calls it) while errors.Is still matches.
func TestDuplicateDelegateErrorTypedFromValidateOrder(t *testing.T) {
	dup := testKeypair(t, "soroauth-err-dup-validate")
	other := testKeypair(t, "soroauth-err-other-validate")
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 44)
	wrapped, err := WithDelegates(entry, testValidUntilLedger, []Delegate{
		{Address: dup.Address()}, {Address: other.Address()},
	}, nil)
	if err != nil {
		t.Fatalf("WithDelegates: %v", err)
	}

	// Replace the sorted tree with two consecutive copies of the same node so
	// the duplicate check (not the ordering check) fires. Building this via
	// WithDelegates is impossible: it rejects duplicates itself.
	dupAddr, err := ParseAddress(dup.Address())
	if err != nil {
		t.Fatalf("parsing the duplicate address: %v", err)
	}
	node := xdr.SorobanDelegateSignature{
		Address:   dupAddr,
		Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
	}
	wrapped.Credentials.AddressWithDelegates.Delegates = []xdr.SorobanDelegateSignature{node, node}

	err = ValidateDelegateOrder(wrapped)
	wantAddressError(t, err, ErrDuplicateDelegate, dup.Address(), extractDuplicate)
	want := "soroauth: validate delegate order: " + dup.Address() + ": " + ErrDuplicateDelegate.Error()
	if err.Error() != want {
		t.Errorf("ValidateDelegateOrder message = %q, want %q", err, want)
	}

	// The same entry through AuthorizeEntry, which calls ValidateDelegateOrder.
	_, err = AuthorizeEntry(context.Background(), wrapped, NewEd25519Signer(dup),
		testValidUntilLedger, network.TestNetworkPassphrase)
	wantAddressError(t, err, ErrDuplicateDelegate, dup.Address(), extractDuplicate)
}

// TestMissingSignerErrorTypedFromAuthorizeAll proves errors.As recovers the
// unsigned entry's address from AuthorizeAll while errors.Is still matches.
func TestMissingSignerErrorTypedFromAuthorizeAll(t *testing.T) {
	present := "soroauth-err-present"
	absent := "soroauth-err-absent"
	entries := []xdr.SorobanAuthorizationEntry{
		entryForSigner(t, present, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1),
		entryForSigner(t, absent, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 2),
	}

	_, err := AuthorizeAll(context.Background(), entries,
		[]Signer{NewEd25519Signer(testKeypair(t, present))},
		testValidUntilLedger, network.TestNetworkPassphrase)
	absentAddr := testKeypair(t, absent).Address()
	wantAddressError(t, err, ErrMissingSigner, absentAddr, extractMissing)

	want := "soroauth: authorize all: entry 1 (" + absentAddr + "): " + ErrMissingSigner.Error()
	if err.Error() != want {
		t.Errorf("message = %q, want %q", err, want)
	}
}

// TestUnsignedCredentialNodeErrorTypedFromAuthorizeAll proves errors.As
// recovers the unsigned node's address from a RequireAllSigned rejection
// while errors.Is still matches.
func TestUnsignedCredentialNodeErrorTypedFromAuthorizeAll(t *testing.T) {
	owner := testKeypair(t, "soroauth-preimage-signer")
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	d1 := testKeypair(t, "soroauth-delegate-1")
	d2 := testKeypair(t, "soroauth-delegate-2")

	entry, err := WithDelegates(base, testValidUntilLedger,
		[]Delegate{{Address: d1.Address()}, {Address: d2.Address()}}, nil)
	if err != nil {
		t.Fatalf("building the entry: %v", err)
	}

	_, err = AuthorizeAll(context.Background(), []xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(owner), NewEd25519Signer(d1)}, // d2 never signs
		testValidUntilLedger, network.TestNetworkPassphrase, RequireAllSigned())
	wantAddressError(t, err, ErrUnsignedCredentialNode, d2.Address(), extractUnsigned)
}

// TestDelegatePlanUnmatchedErrorTypedFromAuthorizeAll proves errors.As
// recovers the unmatched plan address from AuthorizeAll while errors.Is
// still matches.
func TestDelegatePlanUnmatchedErrorTypedFromAuthorizeAll(t *testing.T) {
	present := testKeypair(t, "soroauth-err-present")
	absent := testKeypair(t, "soroauth-err-absent")
	delegate := testKeypair(t, "soroauth-delegate-1")
	entry := entryForSigner(t, "soroauth-err-present", xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)

	_, err := AuthorizeAll(context.Background(), []xdr.SorobanAuthorizationEntry{entry},
		[]Signer{NewEd25519Signer(present), NewEd25519Signer(delegate)},
		testValidUntilLedger, network.TestNetworkPassphrase,
		WithDelegatePlans(map[string]DelegatePlan{
			absent.Address(): {Delegates: []Delegate{{Address: delegate.Address()}}},
		}))
	wantAddressError(t, err, ErrDelegatePlanUnmatched, absent.Address(), extractPlanUnmatched)
}

// TestMissingSignerErrorTypedFromMultiSigner proves errors.As recovers the
// classic account address from NewAccountMultiSigner's zero-key rejection
// while errors.Is still matches.
func TestMissingSignerErrorTypedFromMultiSigner(t *testing.T) {
	account := testKeypair(t, "soroauth-err-multisig-empty").Address()

	_, err := NewAccountMultiSigner(account)
	wantAddressError(t, err, ErrMissingSigner, account, extractMissing)

	want := "soroauth: new account multi signer: " + account + ": " + ErrMissingSigner.Error()
	if err.Error() != want {
		t.Errorf("message = %q, want %q", err, want)
	}
}

// TestTypedErrorsCarrySentinelText: each typed error's Error() is exactly the
// sentinel's text, so call sites that format the address into a surrounding
// message produce byte-identical strings to the pre-typed-error behaviour.
func TestTypedErrorsCarrySentinelText(t *testing.T) {
	const addr = "GB3MMS7QLHQIK6XSMJBXNNV2V3LMKNEPQJMGSPUUY4X5SRLTGBNLPKZM"

	tests := []struct {
		name     string
		err      error
		sentinel error
	}{
		{"no matching credential node", &NoMatchingCredentialNodeError{Address: addr}, ErrNoMatchingCredentialNode},
		{"duplicate delegate", &DuplicateDelegateError{Address: addr}, ErrDuplicateDelegate},
		{"missing signer", &MissingSignerError{Address: addr}, ErrMissingSigner},
		{"unsigned credential node", &UnsignedCredentialNodeError{Address: addr}, ErrUnsignedCredentialNode},
		{"delegate plan unmatched", &DelegatePlanUnmatchedError{Address: addr}, ErrDelegatePlanUnmatched},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.sentinel.Error() {
				t.Errorf("Error() = %q, want sentinel text %q", tt.err.Error(), tt.sentinel.Error())
			}
			if !errors.Is(tt.err, tt.sentinel) {
				t.Error("errors.Is(typed, sentinel) = false, want true")
			}
			if !errors.Is(tt.err, tt.err) {
				t.Error("errors.Is(typed, typed) = false, want true")
			}
			// Double-wrapped the way call sites do: fmt.Errorf("…: %w", typed).
			wrapped := fmt.Errorf("soroauth: example: %w", tt.err)
			if !errors.Is(wrapped, tt.sentinel) {
				t.Errorf("errors.Is(wrapped, sentinel) = false, want true")
			}
		})
	}
}

// Example errors for the three typed address errors. Each shows the
// errors.Is + errors.As pattern a caller uses to recover the address without
// parsing the message.

func ExampleNoMatchingCredentialNodeError() {
	// AuthorizeEntry returns this when the signer's address (or the
	// ForAddress target) matches no credential node in the entry.
	err := fmt.Errorf("soroauth: authorize entry: %s: %w",
		"GBEXAMPLE",
		&NoMatchingCredentialNodeError{Address: "GBEXAMPLE"})

	var addrErr *NoMatchingCredentialNodeError
	if errors.Is(err, ErrNoMatchingCredentialNode) && errors.As(err, &addrErr) {
		fmt.Println("sentinel matched; address =", addrErr.Address)
	}
	// Output:
	// sentinel matched; address = GBEXAMPLE
}

func ExampleDuplicateDelegateError() {
	// WithDelegates and ValidateDelegateOrder return this when one address
	// appears twice within a single delegates array (CAP-71-01 requires
	// strictly increasing order at each level).
	err := fmt.Errorf("soroauth: with delegates: %s: %w",
		"GBEXAMPLE",
		&DuplicateDelegateError{Address: "GBEXAMPLE"})

	var addrErr *DuplicateDelegateError
	if errors.Is(err, ErrDuplicateDelegate) && errors.As(err, &addrErr) {
		fmt.Println("sentinel matched; address =", addrErr.Address)
	}
	// Output:
	// sentinel matched; address = GBEXAMPLE
}

func ExampleMissingSignerError() {
	// AuthorizeAll returns this when an address-arm entry has no signer for
	// its address, naming the entry rather than skipping it.
	err := fmt.Errorf("soroauth: authorize all: entry 1 (%s): %w",
		"GBEXAMPLE",
		&MissingSignerError{Address: "GBEXAMPLE"})

	var addrErr *MissingSignerError
	if errors.Is(err, ErrMissingSigner) && errors.As(err, &addrErr) {
		fmt.Println("sentinel matched; address =", addrErr.Address)
	}
	// Output:
	// sentinel matched; address = GBEXAMPLE
}

func ExampleUnsignedCredentialNodeError() {
	// AuthorizeAll returns this when RequireAllSigned was given and a
	// credential node in the resulting batch carries no signature.
	err := fmt.Errorf("soroauth: authorize all: entry 0 (%s): %w",
		"GBEXAMPLE",
		&UnsignedCredentialNodeError{Address: "GBEXAMPLE"})

	var addrErr *UnsignedCredentialNodeError
	if errors.Is(err, ErrUnsignedCredentialNode) && errors.As(err, &addrErr) {
		fmt.Println("sentinel matched; address =", addrErr.Address)
	}
	// Output:
	// sentinel matched; address = GBEXAMPLE
}

func ExampleDelegatePlanUnmatchedError() {
	// AuthorizeAll returns this when a WithDelegatePlans key matches no
	// entry's top-level address in the batch.
	err := fmt.Errorf("soroauth: authorize all: %s: %w",
		"GBEXAMPLE",
		&DelegatePlanUnmatchedError{Address: "GBEXAMPLE"})

	var addrErr *DelegatePlanUnmatchedError
	if errors.Is(err, ErrDelegatePlanUnmatched) && errors.As(err, &addrErr) {
		fmt.Println("sentinel matched; address =", addrErr.Address)
	}
	// Output:
	// sentinel matched; address = GBEXAMPLE
}
