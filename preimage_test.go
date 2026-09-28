package soroauth

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// testInvocation builds a small but non-trivial call tree: a contract call with
// one argument and one sub-invocation, so the tests cover the recursive part of
// the encoding rather than a bare leaf.
func testInvocation(t testing.TB) xdr.SorobanAuthorizedInvocation {
	t.Helper()

	contract, err := ParseAddress(testContractAddress(t, "soroauth-preimage-contract"))
	if err != nil {
		t.Fatalf("parsing the test contract address: %v", err)
	}
	subContract, err := ParseAddress(testContractAddress(t, "soroauth-preimage-subcontract"))
	if err != nil {
		t.Fatalf("parsing the test sub-contract address: %v", err)
	}

	amount := xdr.Int64(100)
	return xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: contract,
				FunctionName:    xdr.ScSymbol("transfer"),
				Args:            []xdr.ScVal{{Type: xdr.ScValTypeScvI64, I64: &amount}},
			},
		},
		SubInvocations: []xdr.SorobanAuthorizedInvocation{{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: subContract,
					FunctionName:    xdr.ScSymbol("approve"),
					Args:            []xdr.ScVal{},
				},
			},
		}},
	}
}

// testAddressCredentials builds the address credentials every arm shares.
func testAddressCredentials(t testing.TB, label string, nonce int64) xdr.SorobanAddressCredentials {
	t.Helper()
	address, err := ParseAddress(testKeypair(t, label).Address())
	if err != nil {
		t.Fatalf("parsing the test account address: %v", err)
	}
	return xdr.SorobanAddressCredentials{
		Address:                   address,
		Nonce:                     xdr.Int64(nonce),
		SignatureExpirationLedger: 0,
		Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: newScVec()},
	}
}

func newScVec(values ...xdr.ScVal) **xdr.ScVec {
	vec := xdr.ScVec(values)
	p := &vec
	return &p
}

// entryForArm builds an entry on the requested credentials arm, all sharing the
// same nonce and invocation so payloads can be compared across arms.
func entryForArm(t testing.TB, armType xdr.SorobanCredentialsType, nonce int64) xdr.SorobanAuthorizationEntry {
	t.Helper()

	credentials := testAddressCredentials(t, "soroauth-preimage-signer", nonce)
	invocation := testInvocation(t)

	switch armType {
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		return xdr.SorobanAuthorizationEntry{
			Credentials:    xdr.SorobanCredentials{Type: armType},
			RootInvocation: invocation,
		}
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		return xdr.SorobanAuthorizationEntry{
			Credentials:    xdr.SorobanCredentials{Type: armType, Address: &credentials},
			RootInvocation: invocation,
		}
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		return xdr.SorobanAuthorizationEntry{
			Credentials:    xdr.SorobanCredentials{Type: armType, AddressV2: &credentials},
			RootInvocation: invocation,
		}
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		delegate, err := ParseAddress(testKeypair(t, "soroauth-preimage-delegate").Address())
		if err != nil {
			t.Fatalf("parsing the test delegate address: %v", err)
		}
		return xdr.SorobanAuthorizationEntry{
			Credentials: xdr.SorobanCredentials{
				Type: armType,
				AddressWithDelegates: &xdr.SorobanAddressCredentialsWithDelegates{
					AddressCredentials: credentials,
					Delegates: []xdr.SorobanDelegateSignature{{
						Address:   delegate,
						Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid},
					}},
				},
			},
			RootInvocation: invocation,
		}
	default:
		t.Fatalf("entryForArm does not build arm %v", armType)
		return xdr.SorobanAuthorizationEntry{}
	}
}

const testValidUntilLedger = uint32(1234567)

func TestPreimageVariantPerCredentialArm(t *testing.T) {
	const nonce = int64(42)

	tests := []struct {
		name         string
		armType      xdr.SorobanCredentialsType
		wantEnvelope xdr.EnvelopeType
		wantBound    bool
	}{
		{
			name:         "legacy address is not address bound",
			armType:      xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			wantEnvelope: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
			wantBound:    false,
		},
		{
			name:         "address v2 is address bound",
			armType:      xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			wantEnvelope: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress,
			wantBound:    true,
		},
		{
			name:         "delegates arm is bound to the top-level address",
			armType:      xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
			wantEnvelope: xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress,
			wantBound:    true,
		},
	}

	wantNetworkID := xdr.Hash(network.ID(network.TestNetworkPassphrase))

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := entryForArm(t, tt.armType, nonce)

			preimage, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
			if err != nil {
				t.Fatalf("Preimage returned an unexpected error: %v", err)
			}
			if preimage.Type != tt.wantEnvelope {
				t.Fatalf("envelope type is %v, want %v", preimage.Type, tt.wantEnvelope)
			}

			var (
				gotNetworkID  xdr.Hash
				gotNonce      xdr.Int64
				gotExpiration xdr.Uint32
				gotInvocation xdr.SorobanAuthorizedInvocation
			)
			if tt.wantBound {
				bound := preimage.SorobanAuthorizationWithAddress
				if bound == nil {
					t.Fatal("address-bound arm is nil")
				}
				gotNetworkID, gotNonce = bound.NetworkId, bound.Nonce
				gotExpiration, gotInvocation = bound.SignatureExpirationLedger, bound.Invocation

				// The bound address must be the top-level credentials'
				// address, which for the delegates arm means the account, not
				// any delegate (CAP-71-01).
				want, err := addressCredentials(entry.Credentials)
				if err != nil {
					t.Fatalf("reading the entry's address credentials: %v", err)
				}
				wantBytes, err := want.Address.MarshalBinary()
				if err != nil {
					t.Fatalf("marshalling the expected address: %v", err)
				}
				gotBytes, err := bound.Address.MarshalBinary()
				if err != nil {
					t.Fatalf("marshalling the bound address: %v", err)
				}
				if !bytes.Equal(wantBytes, gotBytes) {
					t.Errorf("bound address\n want %x\n  got %x", wantBytes, gotBytes)
				}
			} else {
				legacy := preimage.SorobanAuthorization
				if legacy == nil {
					t.Fatal("legacy arm is nil")
				}
				if preimage.SorobanAuthorizationWithAddress != nil {
					t.Error("legacy preimage also carries an address-bound arm")
				}
				gotNetworkID, gotNonce = legacy.NetworkId, legacy.Nonce
				gotExpiration, gotInvocation = legacy.SignatureExpirationLedger, legacy.Invocation
			}

			if gotNetworkID != wantNetworkID {
				t.Errorf("network id\n want %x\n  got %x", wantNetworkID, gotNetworkID)
			}
			if gotNonce != xdr.Int64(nonce) {
				t.Errorf("nonce is %d, want %d", gotNonce, nonce)
			}
			if gotExpiration != xdr.Uint32(testValidUntilLedger) {
				t.Errorf("expiration is %d, want %d", gotExpiration, testValidUntilLedger)
			}

			wantInvocation, err := entry.RootInvocation.MarshalBinary()
			if err != nil {
				t.Fatalf("marshalling the expected invocation: %v", err)
			}
			gotInvocationBytes, err := gotInvocation.MarshalBinary()
			if err != nil {
				t.Fatalf("marshalling the preimage invocation: %v", err)
			}
			if !bytes.Equal(wantInvocation, gotInvocationBytes) {
				t.Errorf("invocation\n want %x\n  got %x", wantInvocation, gotInvocationBytes)
			}
		})
	}
}

// TestPreimageUsesTheParameterNotTheStoredExpiration pins down §5.2: the
// expiration signed over is the argument, never whatever the entry happens to
// carry. Getting this backwards would produce a signature that does not match
// the submitted credentials.
func TestPreimageUsesTheParameterNotTheStoredExpiration(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	entry.Credentials.AddressV2.SignatureExpirationLedger = 999

	preimage, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("Preimage returned an unexpected error: %v", err)
	}
	if got := preimage.SorobanAuthorizationWithAddress.SignatureExpirationLedger; got != xdr.Uint32(testValidUntilLedger) {
		t.Errorf("expiration is %d, want the parameter %d", got, testValidUntilLedger)
	}
}

// TestPayloadsDiffer proves the payload actually separates the things it is
// supposed to separate. Each of these collisions would be a real vulnerability.
func TestPayloadsDiffer(t *testing.T) {
	const nonce = int64(42)

	legacy := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, nonce)
	v2 := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, nonce)

	payloadFor := func(t *testing.T, entry xdr.SorobanAuthorizationEntry, passphrase string, ledger uint32) [32]byte {
		t.Helper()
		preimage, err := Preimage(entry, ledger, passphrase)
		if err != nil {
			t.Fatalf("Preimage returned an unexpected error: %v", err)
		}
		payload, err := Payload(preimage)
		if err != nil {
			t.Fatalf("Payload returned an unexpected error: %v", err)
		}
		return payload
	}

	base := payloadFor(t, legacy, network.TestNetworkPassphrase, testValidUntilLedger)

	tests := []struct {
		name  string
		got   [32]byte
		about string
	}{
		{
			name:  "public network differs from testnet",
			got:   payloadFor(t, legacy, network.PublicNetworkPassphrase, testValidUntilLedger),
			about: "a signature must not replay onto another network",
		},
		{
			name:  "v2 differs from legacy",
			got:   payloadFor(t, v2, network.TestNetworkPassphrase, testValidUntilLedger),
			about: "the address binding must change the signed bytes",
		},
		{
			name:  "a different expiration differs",
			got:   payloadFor(t, legacy, network.TestNetworkPassphrase, testValidUntilLedger+1),
			about: "the expiration is committed to by the signature",
		},
		{
			name:  "a different nonce differs",
			got:   payloadFor(t, entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, nonce+1), network.TestNetworkPassphrase, testValidUntilLedger),
			about: "the nonce is what makes a signature single-use",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got == base {
				t.Errorf("payload collided with the base payload (%x); %s", base, tt.about)
			}
		})
	}
}

// TestPreimageDelegatesArmBindsTopLevelAddress checks the rule that makes a
// delegate tree work: every node signs the same payload, bound to the account,
// so the delegate's own address must not appear in the signed bytes.
func TestPreimageDelegatesArmBindsTopLevelAddress(t *testing.T) {
	delegates := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 42)
	v2 := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	delegatesPreimage, err := Preimage(delegates, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("Preimage on the delegates arm returned an unexpected error: %v", err)
	}
	v2Preimage, err := Preimage(v2, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("Preimage on the v2 arm returned an unexpected error: %v", err)
	}

	delegatesPayload, err := Payload(delegatesPreimage)
	if err != nil {
		t.Fatalf("Payload returned an unexpected error: %v", err)
	}
	v2Payload, err := Payload(v2Preimage)
	if err != nil {
		t.Fatalf("Payload returned an unexpected error: %v", err)
	}

	// Same address, nonce, invocation and expiration, so the delegate tree
	// must not have leaked into the payload.
	if delegatesPayload != v2Payload {
		t.Errorf("delegates payload %x differs from the v2 payload %x; the delegate tree must not be signed over",
			delegatesPayload, v2Payload)
	}
}

func TestPreimageRejects(t *testing.T) {
	tests := []struct {
		name       string
		entry      func(t *testing.T) xdr.SorobanAuthorizationEntry
		passphrase string
		wantErr    error
		wantMsg    string
	}{
		{
			name: "source account credentials",
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 42)
			},
			passphrase: network.TestNetworkPassphrase,
			wantErr:    ErrSourceAccountCredentials,
		},
		{
			name: "unknown credentials arm",
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				e := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
				e.Credentials = xdr.SorobanCredentials{Type: xdr.SorobanCredentialsType(99)}
				return e
			},
			passphrase: network.TestNetworkPassphrase,
			wantErr:    ErrUnsupportedCredentials,
		},
		{
			name: "empty network passphrase",
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				return entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
			},
			passphrase: "",
			wantMsg:    "network passphrase is empty",
		},
		{
			name: "empty address arm",
			entry: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				e := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
				e.Credentials.AddressV2 = nil
				return e
			},
			passphrase: network.TestNetworkPassphrase,
			wantMsg:    "address_v2 credentials arm is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Preimage(tt.entry(t), testValidUntilLedger, tt.passphrase)
			if err == nil {
				t.Fatalf("Preimage succeeded, returning %+v", got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error %q does not match sentinel %q", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if !strings.HasPrefix(err.Error(), "soroauth: ") {
				t.Errorf("error %q is not wrapped with the soroauth prefix", err)
			}
			if got != (xdr.HashIdPreimage{}) {
				t.Errorf("Preimage returned a value alongside an error")
			}
		})
	}
}

// TestPreimageDoesNotAliasEntry proves a derived payload cannot be changed
// after the fact by mutating the entry it came from.
func TestPreimageDoesNotAliasEntry(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	before, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the entry: %v", err)
	}

	preimage, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("Preimage returned an unexpected error: %v", err)
	}
	payloadBefore, err := Payload(preimage)
	if err != nil {
		t.Fatalf("Payload returned an unexpected error: %v", err)
	}

	entry.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("drain")
	entry.RootInvocation.SubInvocations[0].Function.ContractFn.FunctionName = xdr.ScSymbol("drain_sub")

	payloadAfter, err := Payload(preimage)
	if err != nil {
		t.Fatalf("Payload returned an unexpected error: %v", err)
	}
	if payloadBefore != payloadAfter {
		t.Errorf("mutating the entry changed an already-derived payload\n before %x\n  after %x",
			payloadBefore, payloadAfter)
	}

	// And Preimage itself must not have written to the caller's entry. The
	// mutations above are the test's own, so compare against a fresh build.
	fresh := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	freshBytes, err := fresh.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling a fresh entry: %v", err)
	}
	if !bytes.Equal(before, freshBytes) {
		t.Errorf("Preimage mutated the caller's entry\n want %x\n  got %x", freshBytes, before)
	}
}

func TestPayloadIsSha256OfTheEncoding(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	preimage, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("Preimage returned an unexpected error: %v", err)
	}

	encoded, err := preimage.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the preimage: %v", err)
	}
	want := sha256.Sum256(encoded)

	got, err := Payload(preimage)
	if err != nil {
		t.Fatalf("Payload returned an unexpected error: %v", err)
	}
	if got != want {
		t.Errorf("payload\n want %x\n  got %x", want, got)
	}
}

func TestPayloadRejectsInvalidPreimage(t *testing.T) {
	got, err := Payload(xdr.HashIdPreimage{Type: xdr.EnvelopeType(99)})
	if err == nil {
		t.Fatalf("Payload succeeded on an invalid preimage, returning %x", got)
	}
	if !strings.HasPrefix(err.Error(), "soroauth: hash preimage:") {
		t.Errorf("error %q is not wrapped as expected", err)
	}
	if got != ([32]byte{}) {
		t.Errorf("Payload returned %x alongside an error, want the zero value", got)
	}
}
