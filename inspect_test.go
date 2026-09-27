package soroauth

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInspectReportsTheArm(t *testing.T) {
	tests := []struct {
		name      string
		armType   xdr.SorobanCredentialsType
		wantType  string
		wantBound bool
		wantAddr  bool
	}{
		{
			name:      "source account",
			armType:   xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
			wantType:  CredentialTypeSourceAccount,
			wantBound: false,
			wantAddr:  false,
		},
		{
			name:      "legacy address",
			armType:   xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			wantType:  CredentialTypeAddress,
			wantBound: false,
			wantAddr:  true,
		},
		{
			name:      "address v2",
			armType:   xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			wantType:  CredentialTypeAddressV2,
			wantBound: true,
			wantAddr:  true,
		},
		{
			name:      "address with delegates",
			armType:   xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
			wantType:  CredentialTypeAddressWithDelegates,
			wantBound: true,
			wantAddr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Inspect(entryForArm(t, tt.armType, 42))
			if err != nil {
				t.Fatalf("Inspect returned an unexpected error: %v", err)
			}
			if info.CredentialType != tt.wantType {
				t.Errorf("credential type is %q, want %q", info.CredentialType, tt.wantType)
			}
			if info.AddressBound != tt.wantBound {
				t.Errorf("address_bound is %v, want %v", info.AddressBound, tt.wantBound)
			}
			if tt.wantAddr {
				if info.Address == "" {
					t.Error("no address was reported")
				}
				if info.Nonce != 42 {
					t.Errorf("nonce is %d, want 42", info.Nonce)
				}
			} else {
				if info.Address != "" {
					t.Errorf("a source-account entry reported the address %q", info.Address)
				}
				if info.Nonce != 0 {
					t.Errorf("a source-account entry reported the nonce %d", info.Nonce)
				}
			}
		})
	}
}

func TestInspectReportsTheInvocationTree(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	info, err := Inspect(entry)
	if err != nil {
		t.Fatalf("Inspect returned an unexpected error: %v", err)
	}

	wantContract, err := FormatAddress(entry.RootInvocation.Function.ContractFn.ContractAddress)
	if err != nil {
		t.Fatalf("formatting the contract address: %v", err)
	}
	if info.RootContract != wantContract {
		t.Errorf("root contract is %q, want %q", info.RootContract, wantContract)
	}
	if info.RootFunction != "transfer" {
		t.Errorf("root function is %q, want %q", info.RootFunction, "transfer")
	}
	// testInvocation has exactly one sub-invocation, which has none of its own.
	if info.SubInvocations != 1 {
		t.Errorf("sub_invocations is %d, want 1", info.SubInvocations)
	}
}

// TestInspectCountsSubInvocationsRecursively checks the count is over the whole
// tree, not just the root's direct children.
func TestInspectCountsSubInvocationsRecursively(t *testing.T) {
	leaf := func(name string) xdr.SorobanAuthorizedInvocation {
		return xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: mustParse(t, testContractAddress(t, "soroauth-inspect-leaf")),
					FunctionName:    xdr.ScSymbol(name),
				},
			},
		}
	}

	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	// root
	// ├── a
	// │   ├── a1
	// │   └── a2
	// └── b
	//     └── b1
	//         └── b1x
	branchA := leaf("a")
	branchA.SubInvocations = []xdr.SorobanAuthorizedInvocation{leaf("a1"), leaf("a2")}
	deep := leaf("b1")
	deep.SubInvocations = []xdr.SorobanAuthorizedInvocation{leaf("b1x")}
	branchB := leaf("b")
	branchB.SubInvocations = []xdr.SorobanAuthorizedInvocation{deep}
	entry.RootInvocation.SubInvocations = []xdr.SorobanAuthorizedInvocation{branchA, branchB}

	info, err := Inspect(entry)
	if err != nil {
		t.Fatalf("Inspect returned an unexpected error: %v", err)
	}
	if info.SubInvocations != 6 {
		t.Errorf("sub_invocations is %d, want 6 (a, a1, a2, b, b1, b1x)", info.SubInvocations)
	}
}

func TestInspectReportsCreateContractWithoutAFunction(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	entry.RootInvocation = xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn,
			CreateContractHostFn: &xdr.CreateContractArgs{
				ContractIdPreimage: xdr.ContractIdPreimage{
					Type: xdr.ContractIdPreimageTypeContractIdPreimageFromAddress,
					FromAddress: &xdr.ContractIdPreimageFromAddress{
						Address: mustParse(t, testKeypair(t, "soroauth-inspect-deployer").Address()),
					},
				},
				Executable: xdr.ContractExecutable{
					Type:     xdr.ContractExecutableTypeContractExecutableWasm,
					WasmHash: &xdr.Hash{1, 2, 3},
				},
			},
		},
	}

	info, err := Inspect(entry)
	if err != nil {
		t.Fatalf("Inspect returned an unexpected error: %v", err)
	}
	// A create-contract invocation names no contract and no function, and
	// inventing one would be worse than reporting nothing.
	if info.RootContract != "" {
		t.Errorf("root contract is %q, want empty for a create-contract invocation", info.RootContract)
	}
	if info.RootFunction != "" {
		t.Errorf("root function is %q, want empty for a create-contract invocation", info.RootFunction)
	}
	if info.SubInvocations != 0 {
		t.Errorf("sub_invocations is %d, want 0", info.SubInvocations)
	}
}

func TestInspectNodeInfoJSONGolden(t *testing.T) {
	buf := make([]byte, 64)
	shape := DescribeSignature(xdr.ScVal{
		Type:  xdr.ScValTypeScvBytes,
		Bytes: (*xdr.ScBytes)(&buf),
	})
	node := NodeInfo{
		Address: "GBEXAMPLE",
		Signed:  true,
		Shape:   &shape,
	}
	data, err := json.Marshal(node)
	if err != nil {
		fn := t.Fatalf
		fn("marshaling node info: %v", err)
	}
	// Verify JSON serialization includes the Shape field correctly and matches golden schema expectations
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshaling node info: %v", err)
	}
	if _, ok := m["shape"]; !ok {
		t.Error("serialized NodeInfo json is missing 'shape' field")
	}
	if m["address"] != "GBEXAMPLE" {
		t.Errorf("expected address GBEXAMPLE, got %v", m["address"])
	}
	if m["signed"] != true {
		t.Errorf("expected signed true, got %v", m["signed"])
	}
	// Verify backwards compatibility of omitting Shape when nil
	nilShapeNode := NodeInfo{
		Address: "GBEXAMPLE",
		Signed:  false,
	}
	dataNil, err := json.Marshal(nilShapeNode)
	if err != nil {
		t.Fatalf("marshaling node info with nil shape: %v", err)
	}
	var mNil map[string]any
	if err := json.Unmarshal(dataNil, &mNil); err != nil {
		t.Fatalf("unmarshaling node info with nil shape: %v", err)
	}
	if _, ok := mNil["shape"]; ok {
		t.Error("serialized NodeInfo json should omit 'shape' field when nil for backwards compatibility")
	}

	// Test vector ScValTypeScvVec signature description explicitly
	vecVal := xdr.ScVal{Type: xdr.ScValTypeScvVec}
	vecShape := DescribeSignature(vecVal)
	if vecShape.Type != SignatureShapeUnknown {
		t.Errorf("vector shape type is %v, want %v", vecShape.Type, SignatureShapeUnknown)
	}
	if !strings.Contains(vecShape.Description, "vector structure signature") {
		t.Errorf("vector shape description is %q, want it to mention vector structure signature", vecShape.Description)
	}

	// Test nil Bytes pointer safety
	nilBytesVal := xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: nil}
	nilBytesShape := DescribeSignature(nilBytesVal)
	if nilBytesShape.Type != SignatureShapeUnknown {
		t.Errorf("nil bytes shape type is %v, want %v", nilBytesShape.Type, SignatureShapeUnknown)
	}
}

func TestInspectReportsTheDelegateTree(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	d1 := testKeypair(t, "soroauth-delegate-1").Address()
	d2 := testKeypair(t, "soroauth-delegate-2").Address()
	nested := testKeypair(t, "soroauth-delegate-nested-1").Address()

	entry, err := WithDelegates(base, testValidUntilLedger, []Delegate{
		{Address: d1, Nested: []Delegate{{Address: nested}}},
		{Address: d2},
	}, nil)
	if err != nil {
		t.Fatalf("building the entry: %v", err)
	}

	t.Run("unsigned", func(t *testing.T) {
		info, err := Inspect(entry)
		if err != nil {
			t.Fatalf("Inspect returned an unexpected error: %v", err)
		}
		if info.TopLevelSigned {
			t.Error("top_level_signed is true for a void top-level signature")
		}
		if len(info.Delegates) != 2 {
			t.Fatalf("got %d delegates, want 2", len(info.Delegates))
		}
		// Stored order is ascending address order for a valid entry.
		wantOrder := wantAscending(t, []string{d1, d2})
		gotOrder := []string{info.Delegates[0].Address, info.Delegates[1].Address}
		if !reflect.DeepEqual(gotOrder, wantOrder) {
			t.Errorf("delegate order\n want %v\n  got %v", wantOrder, gotOrder)
		}
		for _, node := range info.Delegates {
			if node.Signed {
				t.Errorf("%s is reported as signed before anything was signed", node.Address)
			}
		}

		var foundNested bool
		for _, node := range info.Delegates {
			if len(node.Nested) == 1 {
				foundNested = true
				if node.Nested[0].Address != nested {
					t.Errorf("nested delegate is %q, want %q", node.Nested[0].Address, nested)
				}
				if node.Nested[0].Signed {
					t.Error("the nested delegate is reported as signed")
				}
			}
		}
		if !foundNested {
			t.Error("the nested delegate was not reported")
		}
	})

	t.Run("after signing one delegate", func(t *testing.T) {
		signed, err := AuthorizeEntry(context.Background(), entry,
			NewEd25519Signer(keypairForAddress(t, d2)),
			testValidUntilLedger, network.TestNetworkPassphrase, ForAddress(d2))
		if err != nil {
			t.Fatalf("signing: %v", err)
		}

		info, err := Inspect(signed)
		if err != nil {
			t.Fatalf("Inspect returned an unexpected error: %v", err)
		}
		if info.TopLevelSigned {
			t.Error("top_level_signed became true after signing only a delegate")
		}
		if info.ValidUntilLedger != testValidUntilLedger {
			t.Errorf("valid_until_ledger is %d, want %d", info.ValidUntilLedger, testValidUntilLedger)
		}

		signedCount := 0
		for _, node := range info.Delegates {
			if node.Signed {
				signedCount++
				if node.Address != d2 {
					t.Errorf("%s is reported as signed, but %s was", node.Address, d2)
				}
			}
		}
		if signedCount != 1 {
			t.Errorf("%d delegates are reported as signed, want 1", signedCount)
		}
	})
}

// TestInspectShowsMisorderedDelegates: Inspect reports the stored order rather
// than tidying it, so a bad entry is visible.
func TestInspectShowsMisorderedDelegates(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	entry, err := WithDelegates(base, testValidUntilLedger, []Delegate{
		{Address: testKeypair(t, "soroauth-delegate-1").Address()},
		{Address: testKeypair(t, "soroauth-delegate-2").Address()},
	}, nil)
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	nodes := entry.Credentials.AddressWithDelegates.Delegates
	nodes[0], nodes[1] = nodes[1], nodes[0]

	info, err := Inspect(entry)
	if err != nil {
		t.Fatalf("Inspect returned an unexpected error: %v", err)
	}
	stored := []string{info.Delegates[0].Address, info.Delegates[1].Address}
	sorted := wantAscending(t, stored)
	if reflect.DeepEqual(stored, sorted) {
		t.Error("Inspect sorted the delegates instead of reporting them as stored")
	}
	if err := ValidateDelegateOrder(entry); err == nil {
		t.Error("the fixture is not actually mis-ordered")
	}
}

func TestDescribeSignatureVectorShape(t *testing.T) {
	sig := xdr.ScVal{Type: xdr.ScValTypeScvVec}
	shape := DescribeSignature(sig)
	if shape.Type != SignatureShapeUnknown {
		t.Errorf("got type %v, want %v", shape.Type, SignatureShapeUnknown)
	}
	if shape.Description != "vector structure signature" {
		t.Errorf("got description %q, want %q", shape.Description, "vector structure signature")
	}
}

func TestNodeInfoShapeSerializationGolden(t *testing.T) {
	shape := SignatureShape{
		Type:        SignatureShapePasskey,
		Description: "64-byte binary passkey signature",
	}
	node := NodeInfo{
		Address: "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
		Signed:  true,
		Shape:   &shape,
	}
	data, err := json.Marshal(node)
	if err != nil {
		t.Fatalf("marshaling NodeInfo: %v", err)
	}
	expected := `{"address":"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF","signed":true,"shape":{"type":"passkey","description":"64-byte binary passkey signature"}}`
	if string(data) != expected {
		t.Errorf("NodeInfo JSON serialization mismatch:\n got: %s\nwant: %s", string(data), expected)
	}
}

func TestInspectSerialisesToJSON(t *testing.T) {
	base := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	entry, err := WithDelegates(base, testValidUntilLedger,
		[]Delegate{{Address: testKeypair(t, "soroauth-delegate-1").Address()}}, nil)
	if err != nil {
		t.Fatalf("building: %v", err)
	}

	info, err := Inspect(entry)
	if err != nil {
		t.Fatalf("Inspect returned an unexpected error: %v", err)
	}
	encoded, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("marshalling EntryInfo: %v", err)
	}

	for _, want := range []string{
		`"credential_type":"address_with_delegates"`,
		`"address_bound":true`,
		`"top_level_signed":false`,
		`"sub_invocations":1`,
		`"delegates":[`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("JSON %s does not contain %s", encoded, want)
		}
	}
}

func TestInspectRejects(t *testing.T) {
	emptyArm := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	emptyArm.Credentials.AddressV2 = nil

	emptyFn := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	emptyFn.RootInvocation.Function.ContractFn = nil

	tests := []struct {
		name    string
		entry   xdr.SorobanAuthorizationEntry
		wantErr error
		wantMsg string
	}{
		{
			name: "unknown arm",
			entry: xdr.SorobanAuthorizationEntry{
				Credentials: xdr.SorobanCredentials{Type: xdr.SorobanCredentialsType(99)},
			},
			wantErr: ErrUnsupportedCredentials,
		},
		{
			name:    "empty address arm",
			entry:   emptyArm,
			wantMsg: "address_v2 credentials arm is empty",
		},
		{
			name:    "empty contract_fn arm",
			entry:   emptyFn,
			wantMsg: "contract_fn invocation arm is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Inspect(tt.entry)
			if err == nil {
				t.Fatalf("Inspect succeeded, returning %+v", got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error %q does not match %q", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if !reflect.DeepEqual(got, EntryInfo{}) {
				t.Error("Inspect returned info alongside an error")
			}
		})
	}
}

// mustParse is a test helper for addresses known to be valid.
func mustParse(t *testing.T, address string) xdr.ScAddress {
	t.Helper()
	parsed, err := ParseAddress(address)
	if err != nil {
		t.Fatalf("parsing %q: %v", address, err)
	}
	return parsed
}

func TestDescribeSignatureShapes(t *testing.T) {
	// Void signature
	shapeVoid := DescribeSignature(xdr.ScVal{Type: xdr.ScValTypeScvVoid})
	assert.Equal(t, SignatureShapeUnknown, shapeVoid.Type)

	// Vec signature
	vec := &xdr.ScVec{}
	shapeVec := DescribeSignature(xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &vec})
	assert.Equal(t, SignatureShapeUnknown, shapeVec.Type)

	// Map signature
	m := &xdr.ScMap{}
	shapeMap := DescribeSignature(xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &m})
	assert.Equal(t, SignatureShapeMap, shapeMap.Type)

	// Bytes signature
	b := xdr.ScBytes([]byte{1, 2, 3})
	shapeBytes := DescribeSignature(xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &b})
	assert.Equal(t, SignatureShapeUnknown, shapeBytes.Type)
}

// TestInspectEmptyUnionArms covers the empty-union-arm cases the fuzz target
// cannot reach.
//
// A successfully decoded entry always has its union arm allocated — the XDR
// decoder allocates the arm the discriminant names — so no byte string fed to
// FuzzInspect produces a nil arm. The reachable path is a caller handing Inspect
// a hand-built struct whose discriminant and arm disagree, which is what this
// asserts directly: an error naming which arm was empty, and a zero EntryInfo
// alongside it, never a half-populated one.
func TestInspectEmptyUnionArms(t *testing.T) {
	tests := []struct {
		name    string
		entry   xdr.SorobanAuthorizationEntry
		wantErr string
	}{
		{
			name: "legacy address arm",
			entry: xdr.SorobanAuthorizationEntry{
				Credentials: xdr.SorobanCredentials{
					Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
				},
			},
			wantErr: "address credentials arm is empty",
		},
		{
			name: "v2 arm",
			entry: xdr.SorobanAuthorizationEntry{
				Credentials: xdr.SorobanCredentials{
					Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
				},
			},
			wantErr: "address_v2 credentials arm is empty",
		},
		{
			name: "delegates arm",
			entry: xdr.SorobanAuthorizationEntry{
				Credentials: xdr.SorobanCredentials{
					Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
				},
			},
			wantErr: "address_with_delegates credentials arm is empty",
		},
		{
			name: "contract_fn invocation arm",
			entry: xdr.SorobanAuthorizationEntry{
				Credentials: xdr.SorobanCredentials{
					Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
				},
				RootInvocation: xdr.SorobanAuthorizedInvocation{
					Function: xdr.SorobanAuthorizedFunction{
						Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
					},
				},
			},
			wantErr: "contract_fn invocation arm is empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := Inspect(tt.entry)

			require.Error(t, err, "an empty union arm must be an error, not a partial report")
			assert.Contains(t, err.Error(), tt.wantErr,
				"the error must name which arm was empty")
			assert.Equal(t, EntryInfo{}, info,
				"Inspect must not return a populated EntryInfo alongside an error")
		})
	}
}

func FuzzInspect(f *testing.F) {
	// f is passed to the helpers directly, which take testing.TB. A
	// &testing.T{} literal would be an uninitialised struct: Helper() and
	// Fatalf() on one panic rather than reporting, so a seed that failed to
	// build would take the target down instead of failing it.
	for _, vec := range loadVectors(f) {
		var entry xdr.SorobanAuthorizationEntry
		if err := xdr.SafeUnmarshalBase64(vec.UnsignedEntryXDR, &entry); err == nil {
			raw, err := entry.MarshalBinary()
			if err == nil {
				f.Add(raw)
			}
		}
	}

	baseSeed := entryForArm(f, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	if raw, err := baseSeed.MarshalBinary(); err == nil {
		f.Add(raw)
	}

	// Truncations of a real entry. Each one either fails to decode — which the
	// target returns on — or decodes to something structurally short of what
	// Inspect expects, which is the shape worth reaching. Seeding these is what
	// makes the fuzzer start near the boundary instead of finding it by luck.
	if raw, err := baseSeed.MarshalBinary(); err == nil {
		for _, n := range []int{0, 1, 4, 8, len(raw) / 4, len(raw) / 2, len(raw) - 1} {
			if n >= 0 && n <= len(raw) {
				f.Add(raw[:n])
			}
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var entry xdr.SorobanAuthorizationEntry
		if err := entry.UnmarshalBinary(data); err != nil {
			return
		}
		info, err := Inspect(entry)
		if err != nil {
			if !reflect.DeepEqual(info, EntryInfo{}) {
				t.Errorf("Inspect returned a non-empty EntryInfo alongside an error: %+v, err: %v", info, err)
			}
		}
	})
}
