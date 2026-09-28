package soroauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// signedEntryFixture is an unsigned entry on the given arm plus the signer that
// owns its top-level address.
func signedEntryFixture(t *testing.T, armType xdr.SorobanCredentialsType) (xdr.SorobanAuthorizationEntry, Signer) {
	t.Helper()
	entry := entryForArm(t, armType, 42)
	signer := NewEd25519Signer(testKeypair(t, "soroauth-preimage-signer"))
	return entry, signer
}

// assertSignatureVerifies checks that the signature stored on the entry really
// signs the payload that entry now commits to. This is the property that
// decides whether the host accepts it.
func assertSignatureVerifies(t *testing.T, entry xdr.SorobanAuthorizationEntry, validUntilLedger uint32, passphrase string) {
	t.Helper()

	preimage, err := Preimage(entry, validUntilLedger, passphrase)
	if err != nil {
		t.Fatalf("rebuilding the preimage: %v", err)
	}
	payload, err := Payload(preimage)
	if err != nil {
		t.Fatalf("rehashing the preimage: %v", err)
	}

	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		t.Fatalf("reading the entry's credentials: %v", err)
	}
	parts := decodeAccountSignature(t, credentials.Signature)
	if len(parts) != 1 {
		t.Fatalf("got %d signatures, want 1", len(parts))
	}

	address, err := FormatAddress(credentials.Address)
	if err != nil {
		t.Fatalf("formatting the credential address: %v", err)
	}
	wantKey, err := rawEd25519Key(address)
	if err != nil {
		t.Fatalf("decoding the credential address: %v", err)
	}
	if !bytes.Equal(parts[0].publicKey, wantKey) {
		t.Errorf("the signature is from %x, but the node names %x", parts[0].publicKey, wantKey)
	}

	kp := testKeypair(t, "soroauth-preimage-signer")
	if err := kp.Verify(payload[:], parts[0].signature); err != nil {
		t.Errorf("the stored signature does not verify against the entry's own payload: %v", err)
	}
}

func TestAuthorizeEntrySignsAddressArms(t *testing.T) {
	tests := []struct {
		name    string
		armType xdr.SorobanCredentialsType
	}{
		{name: "legacy address", armType: xdr.SorobanCredentialsTypeSorobanCredentialsAddress},
		{name: "address v2", armType: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry, signer := signedEntryFixture(t, tt.armType)

			signed, err := AuthorizeEntry(context.Background(), entry, signer,
				testValidUntilLedger, network.TestNetworkPassphrase)
			if err != nil {
				t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
			}

			if signed.Credentials.Type != tt.armType {
				t.Errorf("credentials arm changed to %v, want %v", signed.Credentials.Type, tt.armType)
			}

			credentials, err := addressCredentials(signed.Credentials)
			if err != nil {
				t.Fatalf("reading the signed credentials: %v", err)
			}
			if got := credentials.SignatureExpirationLedger; got != xdr.Uint32(testValidUntilLedger) {
				t.Errorf("expiration is %d, want %d", got, testValidUntilLedger)
			}
			if !isSigned(credentials.Signature) {
				t.Fatal("the credential node was not signed")
			}
			if _, err := signed.MarshalBinary(); err != nil {
				t.Fatalf("the signed entry does not marshal: %v", err)
			}

			assertSignatureVerifies(t, signed, testValidUntilLedger, network.TestNetworkPassphrase)
		})
	}
}

// TestAuthorizeEntryDoesNotMutateItsInput is the §4 requirement: the caller's
// entry must be byte-identical afterwards.
func TestAuthorizeEntryDoesNotMutateItsInput(t *testing.T) {
	arms := []xdr.SorobanCredentialsType{
		xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
	}

	for _, armType := range arms {
		t.Run(armType.String(), func(t *testing.T) {
			entry, signer := signedEntryFixture(t, armType)
			before, err := entry.MarshalBinary()
			if err != nil {
				t.Fatalf("marshalling the entry: %v", err)
			}

			signed, err := AuthorizeEntry(context.Background(), entry, signer,
				testValidUntilLedger, network.TestNetworkPassphrase)
			if err != nil {
				t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
			}

			after, err := entry.MarshalBinary()
			if err != nil {
				t.Fatalf("re-marshalling the entry: %v", err)
			}
			if !bytes.Equal(before, after) {
				t.Errorf("AuthorizeEntry mutated its input\n before %x\n  after %x", before, after)
			}

			// Writing through the result must not reach the input either.
			signed.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("drain")
			rechecked, err := entry.MarshalBinary()
			if err != nil {
				t.Fatalf("re-marshalling the entry: %v", err)
			}
			if !bytes.Equal(before, rechecked) {
				t.Error("the returned entry still shares memory with the input")
			}
		})
	}
}

func TestAuthorizeEntryPassesSourceAccountThrough(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount)
	before, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the entry: %v", err)
	}

	// Deliberately an expiration of zero and a signer for a different
	// address: neither is consulted for this arm.
	signed, err := AuthorizeEntry(context.Background(), entry, signer, 0, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
	}

	after, err := signed.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the result: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the source-account entry was changed\n before %x\n  after %x", before, after)
	}
}

// TestAuthorizeEntryOnlyWritesToTheTargetNode covers soroauth's deliberate
// difference from the JS reference: a key that does not own the node never
// writes to it.
func TestAuthorizeEntryOnlyWritesToTheTargetNode(t *testing.T) {
	entry, _ := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	stranger := NewEd25519Signer(testKeypair(t, "soroauth-authorize-stranger"))

	got, err := AuthorizeEntry(context.Background(), entry, stranger,
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err == nil {
		t.Fatalf("AuthorizeEntry signed with a key that owns no node, returning %+v", got)
	}
	if !errors.Is(err, ErrNoMatchingCredentialNode) {
		t.Errorf("error %q does not match ErrNoMatchingCredentialNode", err)
	}
}

func TestAuthorizeEntryForAddress(t *testing.T) {
	entry, _ := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	nodeOwner := testKeypair(t, "soroauth-preimage-signer")

	t.Run("names the node a foreign signer writes to", func(t *testing.T) {
		// A signer whose own address is different, pointed at the node by
		// ForAddress. The signature bytes are still the node owner's here
		// only because the test reuses that keypair; what matters is that
		// the target, not the signer's address, chose the node.
		signer := SignerFunc(
			testKeypair(t, "soroauth-authorize-stranger").Address(),
			func(_ context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
				signature, err := nodeOwner.Sign(payload[:])
				if err != nil {
					return xdr.ScVal{}, err
				}
				raw, err := rawEd25519Key(nodeOwner.Address())
				if err != nil {
					return xdr.ScVal{}, err
				}
				return scVec(accountSignature(raw, signature)), nil
			})

		signed, err := AuthorizeEntry(context.Background(), entry, signer,
			testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(nodeOwner.Address()))
		if err != nil {
			t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
		}
		assertSignatureVerifies(t, signed, testValidUntilLedger, network.TestNetworkPassphrase)
	})

	t.Run("an address that is not in the entry is an error", func(t *testing.T) {
		signer := NewEd25519Signer(nodeOwner)
		absent := testKeypair(t, "soroauth-authorize-stranger").Address()

		got, err := AuthorizeEntry(context.Background(), entry, signer,
			testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(absent))
		if err == nil {
			t.Fatalf("AuthorizeEntry succeeded for an absent address, returning %+v", got)
		}
		if !errors.Is(err, ErrNoMatchingCredentialNode) {
			t.Errorf("error %q does not match ErrNoMatchingCredentialNode", err)
		}
		if !strings.Contains(err.Error(), absent) {
			t.Errorf("error %q does not name the address that was looked for", err)
		}
	})
}

func TestAuthorizeEntryResignGuard(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)

	signed, err := AuthorizeEntry(context.Background(), entry, signer,
		testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("the first AuthorizeEntry returned an unexpected error: %v", err)
	}

	t.Run("refuses to overwrite by default", func(t *testing.T) {
		got, err := AuthorizeEntry(context.Background(), signed, signer,
			testValidUntilLedger+1, network.TestNetworkPassphrase)
		if err == nil {
			t.Fatalf("AuthorizeEntry overwrote a signature, returning %+v", got)
		}
		if !errors.Is(err, ErrAlreadySigned) {
			t.Errorf("error %q does not match ErrAlreadySigned", err)
		}
	})

	t.Run("allows it with AllowResign", func(t *testing.T) {
		resigned, err := AuthorizeEntry(context.Background(), signed, signer,
			testValidUntilLedger+1, network.TestNetworkPassphrase, AllowResign())
		if err != nil {
			t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
		}
		assertSignatureVerifies(t, resigned, testValidUntilLedger+1, network.TestNetworkPassphrase)

		// The re-signed entry must really differ; a no-op would pass the
		// check above.
		before, err := signed.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		after, err := resigned.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		if bytes.Equal(before, after) {
			t.Error("re-signing produced an identical entry")
		}
	})

	t.Run("an empty vector placeholder is not a signature", func(t *testing.T) {
		// Simulation returns an empty vector as the to-be-filled value, so
		// it must not trip the guard.
		fresh, freshSigner := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
		fresh.Credentials.AddressV2.Signature = scVec()
		if _, err := AuthorizeEntry(context.Background(), fresh, freshSigner,
			testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
			t.Errorf("an empty-vector placeholder was treated as a signature: %v", err)
		}
	})

	t.Run("a void placeholder is not a signature", func(t *testing.T) {
		fresh, freshSigner := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
		fresh.Credentials.AddressV2.Signature = xdr.ScVal{Type: xdr.ScValTypeScvVoid}
		if _, err := AuthorizeEntry(context.Background(), fresh, freshSigner,
			testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
			t.Errorf("a void placeholder was treated as a signature: %v", err)
		}
	})
}

// TestAuthorizeEntryResignGuardScoped is the delegates-arm case AllowResign's
// address scoping exists for: a caller replacing one delegate's signature
// must not thereby be able to overwrite a different, unrelated delegate's
// signature in a separate AuthorizeEntry call against the same entry.
func TestAuthorizeEntryResignGuardScoped(t *testing.T) {
	entry := delegatesFixture(t)
	first := testKeypair(t, "soroauth-delegate-1").Address()
	second := testKeypair(t, "soroauth-delegate-2").Address()

	signed, err := AuthorizeEntry(context.Background(), entry,
		NewEd25519Signer(keypairForAddress(t, first)),
		testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(first))
	if err != nil {
		t.Fatalf("signing the first delegate returned an unexpected error: %v", err)
	}
	signed, err = AuthorizeEntry(context.Background(), signed,
		NewEd25519Signer(keypairForAddress(t, second)),
		testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(second))
	if err != nil {
		t.Fatalf("signing the second delegate returned an unexpected error: %v", err)
	}

	t.Run("resigning the named address is allowed", func(t *testing.T) {
		// A SignerFunc returning a fixed, recognisable ScVal makes the
		// overwrite observable regardless of Ed25519's determinism (signing
		// the same payload twice with the same key produces the same bytes,
		// which would make a real overwrite indistinguishable from a no-op).
		markerBytes := xdr.ScBytes{0xAA, 0xBB}
		marker := xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &markerBytes}
		markerSigner := SignerFunc(first, func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
			return marker, nil
		})

		resigned, err := AuthorizeEntry(context.Background(), signed, markerSigner,
			testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(first),
			AllowResign(first))
		if err != nil {
			t.Fatalf("AuthorizeEntry refused a resign scoped to its own target: %v", err)
		}

		after := signatureAt(t, resigned, first)
		if len(after) != 1 {
			t.Fatalf("got %d signature nodes for %s, want 1", len(after), first)
		}
		if !reflect.DeepEqual(after[0], marker) {
			t.Errorf("the named address was not overwritten with the new signature: got %+v", after[0])
		}

		// The other delegate, not named in the AllowResign scope, must be
		// completely untouched — not just "still signed", but byte-identical.
		beforeOther := signatureAt(t, signed, second)
		afterOther := signatureAt(t, resigned, second)
		if !reflect.DeepEqual(beforeOther, afterOther) {
			t.Error("resigning one address's node changed an unrelated delegate's signature")
		}
	})

	t.Run("resigning an address outside the scope still refuses", func(t *testing.T) {
		got, err := AuthorizeEntry(context.Background(), signed,
			NewEd25519Signer(keypairForAddress(t, second)),
			testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(second),
			AllowResign(first)) // scope names a different address
		if err == nil {
			t.Fatalf("AllowResign(first) let a call targeting second overwrite it, returning %+v", got)
		}
		if !errors.Is(err, ErrAlreadySigned) {
			t.Errorf("error %q does not match ErrAlreadySigned", err)
		}
	})

	t.Run("an unscoped AllowResign still resigns anything, unchanged behaviour", func(t *testing.T) {
		if _, err := AuthorizeEntry(context.Background(), signed,
			NewEd25519Signer(keypairForAddress(t, second)),
			testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(second),
			AllowResign()); err != nil {
			t.Errorf("AllowResign() with no addresses refused a resign: %v", err)
		}
	})

	t.Run("a malformed scope address fails closed", func(t *testing.T) {
		got, err := AuthorizeEntry(context.Background(), signed,
			NewEd25519Signer(keypairForAddress(t, first)),
			testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(first),
			AllowResign("not-an-address"))
		if err == nil {
			t.Fatalf("AuthorizeEntry accepted a malformed AllowResign address, returning %+v", got)
		}
	})

	t.Run("the delegates expiration guard still cannot be lifted by scoping", func(t *testing.T) {
		got, err := AuthorizeEntry(context.Background(), signed,
			NewEd25519Signer(keypairForAddress(t, first)),
			testValidUntilLedger+1, network.TestNetworkPassphrase, ForAddress(first),
			AllowResign(first))
		if err == nil {
			t.Fatalf("a scoped AllowResign lifted the delegates expiration guard, returning %+v", got)
		}
		if !errors.Is(err, ErrInvalidExpiration) {
			t.Errorf("error %q does not match ErrInvalidExpiration", err)
		}
	})
}

// ExampleAllowResign shows AllowResign scoped to one delegate's address.
// Resigning that address is permitted; a separate call resigning a different
// delegate in the same entry is still refused, even though it also passes
// AllowResign, because the scope names someone else.
func ExampleAllowResign() {
	d1, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-delegate-1")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	d2, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-delegate-2")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	account, err := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-example-account")))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	address, err := ParseAddress(account.Address())
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	// Derived inline rather than through testContractAddress: an example has no
	// *testing.T, and a &testing.T{} literal is an uninitialised struct whose
	// Fatalf panics instead of reporting. The example's own error handling
	// below is what it should use anyway.
	contractSeed := sha256.Sum256([]byte("soroauth-example-contract"))
	contractStrkey, err := strkey.Encode(strkey.VersionByteContract, contractSeed[:])
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	contract, err := ParseAddress(contractStrkey)
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:   address,
				Nonce:     1,
				Signature: xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: newScVec()},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: contract,
					FunctionName:    xdr.ScSymbol("transfer"),
					Args:            []xdr.ScVal{},
				},
			},
		},
	}

	const validUntil = 1000
	passphrase := network.TestNetworkPassphrase

	wrapped, err := WithDelegates(entry, validUntil,
		[]Delegate{{Address: d1.Address()}, {Address: d2.Address()}}, nil)
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	ctx := context.Background()
	signed, err := AuthorizeEntry(ctx, wrapped, NewEd25519Signer(d1), validUntil, passphrase, ForAddress(d1.Address()))
	if err != nil {
		fmt.Println("error:", err)
		return
	}
	signed, err = AuthorizeEntry(ctx, signed, NewEd25519Signer(d2), validUntil, passphrase, ForAddress(d2.Address()))
	if err != nil {
		fmt.Println("error:", err)
		return
	}

	_, err = AuthorizeEntry(ctx, signed, NewEd25519Signer(d1), validUntil, passphrase,
		ForAddress(d1.Address()), AllowResign(d1.Address()))
	fmt.Println("resign d1, scoped to d1:", err)

	_, err = AuthorizeEntry(ctx, signed, NewEd25519Signer(d2), validUntil, passphrase,
		ForAddress(d2.Address()), AllowResign(d1.Address()))
	fmt.Println("resign d2, scoped to d1, refused:", errors.Is(err, ErrAlreadySigned))

	// Output:
	// resign d1, scoped to d1: <nil>
	// resign d2, scoped to d1, refused: true
}

func TestAuthorizeEntryRejects(t *testing.T) {
	entry, signer := signedEntryFixture(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2)
	signerError := errors.New("the hardware signer refused")

	tests := []struct {
		name       string
		entry      func(t *testing.T) xdr.SorobanAuthorizationEntry
		signer     Signer
		ledger     uint32
		passphrase string
		wantErr    error
	}{
		{
			name:       "zero expiration",
			entry:      func(*testing.T) xdr.SorobanAuthorizationEntry { return entry },
			signer:     signer,
			ledger:     0,
			passphrase: network.TestNetworkPassphrase,
			wantErr:    ErrInvalidExpiration,
		},
		{
			name: "unknown credentials arm",
			entry: func(*testing.T) xdr.SorobanAuthorizationEntry {
				e := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
				e.Credentials = xdr.SorobanCredentials{Type: xdr.SorobanCredentialsType(99)}
				return e
			},
			signer:     signer,
			ledger:     testValidUntilLedger,
			passphrase: network.TestNetworkPassphrase,
			wantErr:    ErrUnsupportedCredentials,
		},
		{
			name:       "nil signer",
			entry:      func(*testing.T) xdr.SorobanAuthorizationEntry { return entry },
			signer:     nil,
			ledger:     testValidUntilLedger,
			passphrase: network.TestNetworkPassphrase,
			wantErr:    ErrMissingSigner,
		},
		{
			name:       "signer with no address and no ForAddress",
			entry:      func(*testing.T) xdr.SorobanAuthorizationEntry { return entry },
			signer:     NewEd25519Signer(nil),
			ledger:     testValidUntilLedger,
			passphrase: network.TestNetworkPassphrase,
			wantErr:    ErrMissingSigner,
		},
		{
			name:  "the signer fails",
			entry: func(*testing.T) xdr.SorobanAuthorizationEntry { return entry },
			signer: SignerFunc(testKeypair(t, "soroauth-preimage-signer").Address(),
				func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
					return xdr.ScVal{}, signerError
				}),
			ledger:     testValidUntilLedger,
			passphrase: network.TestNetworkPassphrase,
			wantErr:    signerError,
		},
		{
			name:       "empty network passphrase",
			entry:      func(*testing.T) xdr.SorobanAuthorizationEntry { return entry },
			signer:     signer,
			ledger:     testValidUntilLedger,
			passphrase: "",
			wantErr:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AuthorizeEntry(context.Background(), tt.entry(t), tt.signer, tt.ledger, tt.passphrase)
			if err == nil {
				t.Fatalf("AuthorizeEntry succeeded, returning %+v", got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error %q does not match the expected error %q", err, tt.wantErr)
			}
			if !strings.HasPrefix(err.Error(), "soroauth: ") {
				t.Errorf("error %q is not wrapped with the soroauth prefix", err)
			}
			if !reflect.DeepEqual(got, xdr.SorobanAuthorizationEntry{}) {
				t.Error("AuthorizeEntry returned an entry alongside an error")
			}
		})
	}
}

// delegatesFixture builds a signed-nothing delegates entry whose tree is
//
//	account
//	├── delegate-1
//	│   └── delegate-nested-1
//	└── delegate-2
func delegatesFixture(t *testing.T) xdr.SorobanAuthorizationEntry {
	t.Helper()
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	wrapped, err := WithDelegates(base, testValidUntilLedger, []Delegate{
		{
			Address: testKeypair(t, "soroauth-delegate-1").Address(),
			Nested:  []Delegate{{Address: testKeypair(t, "soroauth-delegate-nested-1").Address()}},
		},
		{Address: testKeypair(t, "soroauth-delegate-2").Address()},
	}, nil)
	if err != nil {
		t.Fatalf("building the delegates fixture: %v", err)
	}
	return wrapped
}

// signatureAt walks to a node by address and returns its signature.
func signatureAt(t *testing.T, entry xdr.SorobanAuthorizationEntry, address string) []xdr.ScVal {
	t.Helper()
	parsed, err := ParseAddress(address)
	if err != nil {
		t.Fatalf("parsing %q: %v", address, err)
	}
	want, err := addressBytes(parsed)
	if err != nil {
		t.Fatalf("encoding %q: %v", address, err)
	}

	copied := entry
	nodes, err := credentialNodes(&copied)
	if err != nil {
		t.Fatalf("walking the entry: %v", err)
	}

	var found []xdr.ScVal
	for _, node := range nodes {
		if bytes.Equal(node.encoded, want) {
			found = append(found, *node.signature)
		}
	}
	return found
}

// TestAuthorizeEntrySignsNestedDelegates covers the recursion: a delegate two
// levels down is reachable by ForAddress, and the signature it gets verifies
// against the one payload the whole tree shares.
func TestAuthorizeEntrySignsNestedDelegates(t *testing.T) {
	entry := delegatesFixture(t)

	targets := []string{
		testKeypair(t, "soroauth-preimage-signer").Address(),   // the account itself
		testKeypair(t, "soroauth-delegate-1").Address(),        // a top-level delegate
		testKeypair(t, "soroauth-delegate-nested-1").Address(), // one level deeper
		testKeypair(t, "soroauth-delegate-2").Address(),        // the other branch
	}

	// The payload every node signs, computed once from the unsigned entry.
	preimage, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("building the shared preimage: %v", err)
	}
	payload, err := Payload(preimage)
	if err != nil {
		t.Fatalf("hashing the shared preimage: %v", err)
	}

	signed := entry
	for _, address := range targets {
		signed, err = AuthorizeEntry(context.Background(), signed,
			NewEd25519Signer(keypairForAddress(t, address)),
			testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(address))
		if err != nil {
			t.Fatalf("signing for %s returned an unexpected error: %v", address, err)
		}
	}

	for _, address := range targets {
		found := signatureAt(t, signed, address)
		if len(found) != 1 {
			t.Fatalf("%s: found %d nodes, want 1", address, len(found))
		}
		parts := decodeAccountSignature(t, found[0])
		if len(parts) != 1 {
			t.Fatalf("%s: got %d signatures in the node, want 1", address, len(parts))
		}
		if err := keypairForAddress(t, address).Verify(payload[:], parts[0].signature); err != nil {
			t.Errorf("%s: signature does not verify against the shared payload: %v", address, err)
		}
	}

	if _, err := signed.MarshalBinary(); err != nil {
		t.Fatalf("the fully signed entry does not marshal: %v", err)
	}
}

// TestAuthorizeEntrySignsOneAddressAtTwoLevels is the CAP-71-01 case where the
// same address appears at two depths: a single call must fill both, because
// both nodes commit to the same payload.
func TestAuthorizeEntrySignsOneAddressAtTwoLevels(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	shared := testKeypair(t, "soroauth-delegate-1").Address()
	other := testKeypair(t, "soroauth-delegate-2").Address()

	entry, err := WithDelegates(base, testValidUntilLedger, []Delegate{
		{Address: shared},
		{Address: other, Nested: []Delegate{{Address: shared}}},
	}, nil)
	if err != nil {
		t.Fatalf("building the entry: %v", err)
	}

	if got := signatureAt(t, entry, shared); len(got) != 2 {
		t.Fatalf("the fixture has %d nodes for the shared address, want 2", len(got))
	}

	signed, err := AuthorizeEntry(context.Background(), entry,
		NewEd25519Signer(keypairForAddress(t, shared)),
		testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(shared))
	if err != nil {
		t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
	}

	found := signatureAt(t, signed, shared)
	if len(found) != 2 {
		t.Fatalf("found %d nodes for the shared address, want 2", len(found))
	}
	for i, signature := range found {
		if !isSigned(signature) {
			t.Errorf("node %d was left unsigned by the single call", i)
		}
	}

	// Both nodes must carry identical bytes, since both signed one payload.
	first, err := found[0].MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	second, err := found[1].MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("the two nodes for one address carry different signatures")
	}

	// The other delegate must be untouched.
	if got := signatureAt(t, signed, other); len(got) != 1 || isSigned(got[0]) {
		t.Error("signing the shared address also wrote to an unrelated delegate")
	}
}

func TestAuthorizeEntryDelegatesZeroMatch(t *testing.T) {
	entry := delegatesFixture(t)
	stranger := testKeypair(t, "soroauth-authorize-stranger").Address()

	got, err := AuthorizeEntry(context.Background(), entry,
		NewEd25519Signer(keypairForAddress(t, stranger)),
		testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(stranger))
	if err == nil {
		t.Fatalf("AuthorizeEntry signed for an address outside the tree, returning %+v", got)
	}
	if !errors.Is(err, ErrNoMatchingCredentialNode) {
		t.Errorf("error %q does not match ErrNoMatchingCredentialNode", err)
	}
}

// TestAuthorizeEntryDelegatesExpirationGuard is the §5.4 rule that AllowResign
// deliberately does not lift: once any node in a delegates entry is signed, the
// expiration is fixed, because every node commits to it.
func TestAuthorizeEntryDelegatesExpirationGuard(t *testing.T) {
	entry := delegatesFixture(t)
	first := testKeypair(t, "soroauth-delegate-1").Address()
	second := testKeypair(t, "soroauth-delegate-2").Address()

	partly, err := AuthorizeEntry(context.Background(), entry,
		NewEd25519Signer(keypairForAddress(t, first)),
		testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(first))
	if err != nil {
		t.Fatalf("the first signature returned an unexpected error: %v", err)
	}

	t.Run("a different expiration is refused", func(t *testing.T) {
		got, err := AuthorizeEntry(context.Background(), partly,
			NewEd25519Signer(keypairForAddress(t, second)),
			testValidUntilLedger+1, network.TestNetworkPassphrase, ForAddress(second))
		if err == nil {
			t.Fatalf("AuthorizeEntry invalidated the existing signature, returning %+v", got)
		}
		if !errors.Is(err, ErrInvalidExpiration) {
			t.Errorf("error %q does not match ErrInvalidExpiration", err)
		}
	})

	t.Run("AllowResign does not lift it", func(t *testing.T) {
		got, err := AuthorizeEntry(context.Background(), partly,
			NewEd25519Signer(keypairForAddress(t, second)),
			testValidUntilLedger+1, network.TestNetworkPassphrase, ForAddress(second), AllowResign())
		if err == nil {
			t.Fatalf("AllowResign lifted the expiration guard, returning %+v", got)
		}
		if !errors.Is(err, ErrInvalidExpiration) {
			t.Errorf("error %q does not match ErrInvalidExpiration", err)
		}
	})

	t.Run("the same expiration is allowed", func(t *testing.T) {
		signed, err := AuthorizeEntry(context.Background(), partly,
			NewEd25519Signer(keypairForAddress(t, second)),
			testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(second))
		if err != nil {
			t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
		}
		if got := signatureAt(t, signed, first); len(got) != 1 || !isSigned(got[0]) {
			t.Error("the first signature was lost")
		}
		if got := signatureAt(t, signed, second); len(got) != 1 || !isSigned(got[0]) {
			t.Error("the second signature was not written")
		}
	})
}

// TestAuthorizeEntryValidatesDelegateOrderBeforeSigning proves the check runs
// before the signer is called, not after: a mis-ordered entry must never reach
// a hardware signer or a user prompt.
func TestAuthorizeEntryValidatesDelegateOrderBeforeSigning(t *testing.T) {
	entry := delegatesFixture(t)

	nodes := entry.Credentials.AddressWithDelegates.Delegates
	if len(nodes) != 2 {
		t.Fatalf("the fixture has %d top-level delegates, want 2", len(nodes))
	}
	nodes[0], nodes[1] = nodes[1], nodes[0]

	address := testKeypair(t, "soroauth-delegate-1").Address()
	signer := SignerFunc(address, func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
		t.Error("the signer was called for an entry the host would reject")
		return xdr.ScVal{}, nil
	})

	got, err := AuthorizeEntry(context.Background(), entry, signer,
		testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(address))
	if err == nil {
		t.Fatalf("AuthorizeEntry signed a mis-ordered entry, returning %+v", got)
	}
	if !strings.Contains(err.Error(), "ascending address order") {
		t.Errorf("error %q does not explain the ordering rule", err)
	}
}

// TestAuthorizeEntryDoesNotCallTheSignerWhenNothingMatches is the behaviour
// noted at CP1 and documented in the README: a target that matches no node
// fails before any signing work happens.
func TestAuthorizeEntryDoesNotCallTheSignerWhenNothingMatches(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	stranger := testKeypair(t, "soroauth-authorize-stranger").Address()

	signer := SignerFunc(stranger, func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
		t.Error("the signer was called even though no node matched")
		return xdr.ScVal{}, nil
	})

	if _, err := AuthorizeEntry(context.Background(), entry, signer,
		testValidUntilLedger, network.TestNetworkPassphrase); !errors.Is(err, ErrNoMatchingCredentialNode) {
		t.Errorf("error %v does not match ErrNoMatchingCredentialNode", err)
	}
}

// keypairForAddress recovers the deterministic test keypair behind an address.
func TestAuthorizeEntryExpirationProperty(t *testing.T) {
	armTypes := []xdr.SorobanCredentialsType{
		xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
	}

	expirings := []uint32{0, 1, 42, 1234567, 4294967295}
	Depths := []int{0, 1, 2, 3}

	for _, armType := range armTypes {
		for _, validUntil := range expirings {
			if validUntil == 0 {
				continue
			}
			for _, depth := range Depths {
				name := fmt.Sprintf("arm=%v/exp=%d/depth=%d", armType, validUntil, depth)
				t.Run(name, func(t *testing.T) {
					var entry xdr.SorobanAuthorizationEntry
					var addresses []string

					switch armType {
					case xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
						xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
						entry = entryForArm(t, armType, 123)
						addresses = []string{testKeypair(t, "soroauth-preimage-signer").Address()}

					case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
						base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 123)
						var delegates []Delegate
						curr := &delegates
						for i := 0; i < depth; i++ {
							addr := testKeypair(t, fmt.Sprintf("soroauth-prop-delegate-%d", i)).Address()
							addresses = append(addresses, addr)
							nextDelegates := []Delegate{{Address: addr}}
							*curr = nextDelegates
							curr = &(*curr)[0].Nested
						}

						accountAddr := testKeypair(t, "soroauth-preimage-signer").Address()
						addresses = append([]string{accountAddr}, addresses...)

						var err error
						entry, err = WithDelegates(base, validUntil, delegates, nil)
						if err != nil {
							t.Fatalf("WithDelegates: %v", err)
						}
					}

					// Sign all addresses present in the entry
					currentEntry := entry
					for _, addr := range addresses {
						kp := keypairForAddress(t, addr)
						signer := NewEd25519Signer(kp)
						var err error
						currentEntry, err = AuthorizeEntry(context.Background(), currentEntry, signer, validUntil, network.TestNetworkPassphrase, ForAddress(addr))
						if err != nil {
							t.Fatalf("AuthorizeEntry for %s: %v", addr, err)
						}
					}

					// Verify signature and consistency for the signed entry
					assertSignatureVerifies(t, currentEntry, validUntil, network.TestNetworkPassphrase)
				})
			}
		}
	}
}

func keypairForAddress(t *testing.T, address string) *keypair.Full {
	t.Helper()
	for _, label := range []string{
		"soroauth-preimage-signer",
		"soroauth-preimage-delegate",
		"soroauth-authorize-stranger",
		"soroauth-delegate-1",
		"soroauth-delegate-2",
		"soroauth-delegate-3",
		"soroauth-delegate-nested-1",
		"soroauth-delegate-nested-2",
		"soroauth-prop-delegate-0",
		"soroauth-prop-delegate-1",
		"soroauth-prop-delegate-2",
	} {
		kp := testKeypair(t, label)
		if kp.Address() == address {
			return kp
		}
	}
	t.Fatalf("no test keypair matches %s", address)
	return nil
}
