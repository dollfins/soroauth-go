package soroauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// delegateAddresses returns the addresses of one delegates level, in the order
// they are stored.
func delegateAddresses(t *testing.T, nodes []xdr.SorobanDelegateSignature) []string {
	t.Helper()
	out := make([]string, 0, len(nodes))
	for _, node := range nodes {
		address, err := FormatAddress(node.Address)
		if err != nil {
			t.Fatalf("formatting a delegate address: %v", err)
		}
		out = append(out, address)
	}
	return out
}

// wantAscending returns the addresses sorted the way CAP-71-01 requires, by
// the XDR encoding of the address.
func wantAscending(t *testing.T, addresses []string) []string {
	t.Helper()
	type keyed struct {
		address string
		encoded []byte
	}
	items := make([]keyed, 0, len(addresses))
	for _, address := range addresses {
		parsed, err := ParseAddress(address)
		if err != nil {
			t.Fatalf("parsing %q: %v", address, err)
		}
		encoded, err := addressBytes(parsed)
		if err != nil {
			t.Fatalf("encoding %q: %v", address, err)
		}
		items = append(items, keyed{address: address, encoded: encoded})
	}
	sort.Slice(items, func(i, j int) bool {
		return bytes.Compare(items[i].encoded, items[j].encoded) < 0
	})
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.address)
	}
	return out
}

func TestWithDelegatesSortsEveryLevel(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	d1 := testKeypair(t, "soroauth-delegate-1").Address()
	d2 := testKeypair(t, "soroauth-delegate-2").Address()
	d3 := testKeypair(t, "soroauth-delegate-3").Address()
	n1 := testKeypair(t, "soroauth-delegate-nested-1").Address()
	n2 := testKeypair(t, "soroauth-delegate-nested-2").Address()

	// Deliberately unsorted at both levels.
	unsorted := []Delegate{
		{Address: d3},
		{Address: d1, Nested: []Delegate{{Address: n2}, {Address: n1}}},
		{Address: d2},
	}

	wrapped, err := WithDelegates(entry, testValidUntilLedger, unsorted, nil)
	if err != nil {
		t.Fatalf("WithDelegates returned an unexpected error: %v", err)
	}

	if wrapped.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
		t.Fatalf("credentials arm is %v, want the delegates arm", wrapped.Credentials.Type)
	}

	got := delegateAddresses(t, wrapped.Credentials.AddressWithDelegates.Delegates)
	want := wantAscending(t, []string{d1, d2, d3})
	if !reflect.DeepEqual(got, want) {
		t.Errorf("top level order\n want %v\n  got %v", want, got)
	}

	// Find the node that carries the nested tree and check that level too.
	var nested []xdr.SorobanDelegateSignature
	for _, node := range wrapped.Credentials.AddressWithDelegates.Delegates {
		if len(node.NestedDelegates) > 0 {
			nested = node.NestedDelegates
		}
	}
	if len(nested) != 2 {
		t.Fatalf("got %d nested delegates, want 2", len(nested))
	}
	gotNested := delegateAddresses(t, nested)
	wantNested := wantAscending(t, []string{n1, n2})
	if !reflect.DeepEqual(gotNested, wantNested) {
		t.Errorf("nested level order\n want %v\n  got %v", wantNested, gotNested)
	}

	// The result must satisfy the validator, which is what the host checks.
	if err := ValidateDelegateOrder(wrapped); err != nil {
		t.Errorf("WithDelegates produced an entry its own validator rejects: %v", err)
	}
}

func TestWithDelegatesAllowsTheSameAddressAtDifferentLevels(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)

	shared := testKeypair(t, "soroauth-delegate-1").Address()
	other := testKeypair(t, "soroauth-delegate-2").Address()

	// CAP-71-01 forbids a repeat within one array, not across levels.
	wrapped, err := WithDelegates(entry, testValidUntilLedger, []Delegate{
		{Address: shared},
		{Address: other, Nested: []Delegate{{Address: shared}}},
	}, nil)
	if err != nil {
		t.Fatalf("WithDelegates rejected the same address at two levels: %v", err)
	}
	if err := ValidateDelegateOrder(wrapped); err != nil {
		t.Errorf("ValidateDelegateOrder rejected the same address at two levels: %v", err)
	}

	count := 0
	for _, node := range wrapped.Credentials.AddressWithDelegates.Delegates {
		address, err := FormatAddress(node.Address)
		if err != nil {
			t.Fatalf("formatting: %v", err)
		}
		if address == shared {
			count++
		}
		for _, inner := range node.NestedDelegates {
			innerAddress, err := FormatAddress(inner.Address)
			if err != nil {
				t.Fatalf("formatting: %v", err)
			}
			if innerAddress == shared {
				count++
			}
		}
	}
	if count != 2 {
		t.Errorf("the shared address appears %d times, want 2", count)
	}
}

func TestWithDelegatesRejectsDuplicatesWithinALevel(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	duplicate := testKeypair(t, "soroauth-delegate-1").Address()
	other := testKeypair(t, "soroauth-delegate-2").Address()

	tests := []struct {
		name      string
		delegates []Delegate
	}{
		{
			name:      "at the top level",
			delegates: []Delegate{{Address: duplicate}, {Address: other}, {Address: duplicate}},
		},
		{
			name: "inside a nested level",
			delegates: []Delegate{{
				Address: other,
				Nested:  []Delegate{{Address: duplicate}, {Address: duplicate}},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WithDelegates(entry, testValidUntilLedger, tt.delegates, nil)
			if err == nil {
				t.Fatalf("WithDelegates accepted a duplicate, returning %+v", got)
			}
			if !errors.Is(err, ErrDuplicateDelegate) {
				t.Errorf("error %q does not match ErrDuplicateDelegate", err)
			}
			if !strings.Contains(err.Error(), duplicate) {
				t.Errorf("error %q does not name the duplicated address", err)
			}
			if !reflect.DeepEqual(got, xdr.SorobanAuthorizationEntry{}) {
				t.Error("WithDelegates returned an entry alongside an error")
			}
		})
	}
}

// TestWithDelegatesWrappingLegacyChangesThePayload covers the conversion in
// §5.5: a legacy entry is not address-bound, and wrapping makes it so.
func TestWithDelegatesWrappingLegacyChangesThePayload(t *testing.T) {
	legacy := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddress, 42)

	beforePreimage, err := Preimage(legacy, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("building the pre-wrap preimage: %v", err)
	}
	beforePayload, err := Payload(beforePreimage)
	if err != nil {
		t.Fatalf("hashing the pre-wrap preimage: %v", err)
	}

	wrapped, err := WithDelegates(legacy, testValidUntilLedger,
		[]Delegate{{Address: testKeypair(t, "soroauth-delegate-1").Address()}}, nil)
	if err != nil {
		t.Fatalf("WithDelegates returned an unexpected error: %v", err)
	}

	afterPreimage, err := Preimage(wrapped, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("building the post-wrap preimage: %v", err)
	}
	afterPayload, err := Payload(afterPreimage)
	if err != nil {
		t.Fatalf("hashing the post-wrap preimage: %v", err)
	}

	if beforePreimage.Type != xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization {
		t.Errorf("pre-wrap envelope is %v, want the legacy variant", beforePreimage.Type)
	}
	if afterPreimage.Type != xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress {
		t.Errorf("post-wrap envelope is %v, want the address-bound variant", afterPreimage.Type)
	}
	if beforePayload == afterPayload {
		t.Error("wrapping a legacy entry left the payload unchanged; it must become address-bound")
	}

	// The wrapped entry must keep what it was built from.
	before, err := addressCredentials(legacy.Credentials)
	if err != nil {
		t.Fatalf("reading the legacy credentials: %v", err)
	}
	after, err := addressCredentials(wrapped.Credentials)
	if err != nil {
		t.Fatalf("reading the wrapped credentials: %v", err)
	}
	if after.Nonce != before.Nonce {
		t.Errorf("nonce changed from %d to %d", before.Nonce, after.Nonce)
	}
	beforeAddress, err := addressBytes(before.Address)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	afterAddress, err := addressBytes(after.Address)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	if !bytes.Equal(beforeAddress, afterAddress) {
		t.Error("the wrapped entry names a different address")
	}
	beforeInvocation, err := legacy.RootInvocation.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	afterInvocation, err := wrapped.RootInvocation.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if !bytes.Equal(beforeInvocation, afterInvocation) {
		t.Error("the wrapped entry carries a different invocation tree")
	}
}

func TestWithDelegatesTopLevelSignature(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	delegates := []Delegate{{Address: testKeypair(t, "soroauth-delegate-1").Address()}}

	t.Run("nil stores a void placeholder", func(t *testing.T) {
		wrapped, err := WithDelegates(entry, testValidUntilLedger, delegates, nil)
		if err != nil {
			t.Fatalf("WithDelegates returned an unexpected error: %v", err)
		}
		signature := wrapped.Credentials.AddressWithDelegates.AddressCredentials.Signature
		if signature.Type != xdr.ScValTypeScvVoid {
			t.Errorf("top-level signature is %v, want ScvVoid", signature.Type)
		}
		if isSigned(signature) {
			t.Error("a void placeholder is being treated as a signature")
		}
	})

	t.Run("a value is stored verbatim", func(t *testing.T) {
		want := scBytes([]byte("a custom account signature"))
		wrapped, err := WithDelegates(entry, testValidUntilLedger, delegates, &want)
		if err != nil {
			t.Fatalf("WithDelegates returned an unexpected error: %v", err)
		}
		got := wrapped.Credentials.AddressWithDelegates.AddressCredentials.Signature
		gotBytes, err := got.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		wantBytes, err := want.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		if !bytes.Equal(gotBytes, wantBytes) {
			t.Errorf("top-level signature\n want %x\n  got %x", wantBytes, gotBytes)
		}
	})

	t.Run("a delegate signature is stored verbatim", func(t *testing.T) {
		want := scBytes([]byte("a delegate's signature"))
		wrapped, err := WithDelegates(entry, testValidUntilLedger, []Delegate{
			{Address: testKeypair(t, "soroauth-delegate-1").Address(), Signature: &want},
		}, nil)
		if err != nil {
			t.Fatalf("WithDelegates returned an unexpected error: %v", err)
		}
		got := wrapped.Credentials.AddressWithDelegates.Delegates[0].Signature
		gotBytes, err := got.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		wantBytes, err := want.MarshalBinary()
		if err != nil {
			t.Fatalf("marshalling: %v", err)
		}
		if !bytes.Equal(gotBytes, wantBytes) {
			t.Errorf("delegate signature\n want %x\n  got %x", wantBytes, gotBytes)
		}
	})
}

func TestWithDelegatesRejects(t *testing.T) {
	v2 := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	delegates := []Delegate{{Address: testKeypair(t, "soroauth-delegate-1").Address()}}

	signedEntry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	signedEntry.Credentials.AddressV2.Signature = scVec(
		accountSignature(make([]byte, 32), make([]byte, 64)))

	tests := []struct {
		name      string
		entry     xdr.SorobanAuthorizationEntry
		ledger    uint32
		delegates []Delegate
		wantErr   error
		wantMsg   string
	}{
		{
			name:      "source account credentials",
			entry:     entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount, 42),
			ledger:    testValidUntilLedger,
			delegates: delegates,
			wantErr:   ErrUnsupportedCredentials,
			wantMsg:   "no address to wrap",
		},
		{
			name:      "already a delegates entry",
			entry:     entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates, 42),
			ledger:    testValidUntilLedger,
			delegates: delegates,
			wantErr:   ErrUnsupportedCredentials,
			wantMsg:   "already uses the delegates arm",
		},
		{
			name: "unknown arm",
			entry: xdr.SorobanAuthorizationEntry{
				Credentials:    xdr.SorobanCredentials{Type: xdr.SorobanCredentialsType(99)},
				RootInvocation: v2.RootInvocation,
			},
			ledger:    testValidUntilLedger,
			delegates: delegates,
			wantErr:   ErrUnsupportedCredentials,
		},
		{
			name:      "already signed",
			entry:     signedEntry,
			ledger:    testValidUntilLedger,
			delegates: delegates,
			wantErr:   ErrAlreadySigned,
			wantMsg:   "invalidating the existing signature",
		},
		{
			name:      "zero expiration",
			entry:     v2,
			ledger:    0,
			delegates: delegates,
			wantErr:   ErrInvalidExpiration,
		},
		{
			name:      "a delegate with a muxed address",
			entry:     v2,
			ledger:    testValidUntilLedger,
			delegates: []Delegate{{Address: "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"}},
			wantMsg:   "muxed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := WithDelegates(tt.entry, tt.ledger, tt.delegates, nil)
			if err == nil {
				t.Fatalf("WithDelegates succeeded, returning %+v", got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error %q does not match the expected sentinel %q", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if !strings.HasPrefix(err.Error(), "soroauth: ") {
				t.Errorf("error %q is not wrapped with the soroauth prefix", err)
			}
			if !reflect.DeepEqual(got, xdr.SorobanAuthorizationEntry{}) {
				t.Error("WithDelegates returned an entry alongside an error")
			}
		})
	}
}

// TestWithDelegatesAcceptsPlaceholders makes sure the two unsigned placeholders
// simulation emits are not mistaken for signatures.
func TestWithDelegatesAcceptsPlaceholders(t *testing.T) {
	delegates := []Delegate{{Address: testKeypair(t, "soroauth-delegate-1").Address()}}

	placeholders := map[string]xdr.ScVal{
		"void":         {Type: xdr.ScValTypeScvVoid},
		"empty vector": scVec(),
	}

	for name, placeholder := range placeholders {
		t.Run(name, func(t *testing.T) {
			entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
			entry.Credentials.AddressV2.Signature = placeholder

			if _, err := WithDelegates(entry, testValidUntilLedger, delegates, nil); err != nil {
				t.Errorf("WithDelegates rejected a %s placeholder: %v", name, err)
			}
		})
	}
}

func TestWithDelegatesDoesNotMutateItsInput(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	before, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the entry: %v", err)
	}

	wrapped, err := WithDelegates(entry, testValidUntilLedger,
		[]Delegate{{Address: testKeypair(t, "soroauth-delegate-1").Address()}}, nil)
	if err != nil {
		t.Fatalf("WithDelegates returned an unexpected error: %v", err)
	}

	after, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("re-marshalling the entry: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("WithDelegates mutated its input\n before %x\n  after %x", before, after)
	}

	// Writing through the result must not reach the input either.
	wrapped.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("drain")
	rechecked, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("re-marshalling the entry: %v", err)
	}
	if !bytes.Equal(before, rechecked) {
		t.Error("the wrapped entry still shares memory with the input")
	}
}

func TestValidateDelegateOrder(t *testing.T) {
	entry := entryForArm(t, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	d1 := testKeypair(t, "soroauth-delegate-1").Address()
	d2 := testKeypair(t, "soroauth-delegate-2").Address()

	wellFormed, err := WithDelegates(entry, testValidUntilLedger,
		[]Delegate{{Address: d1, Nested: []Delegate{{Address: d2}}}, {Address: d2}}, nil)
	if err != nil {
		t.Fatalf("building a well-formed entry: %v", err)
	}

	t.Run("accepts a well-formed entry", func(t *testing.T) {
		if err := ValidateDelegateOrder(wellFormed); err != nil {
			t.Errorf("ValidateDelegateOrder rejected a well-formed entry: %v", err)
		}
	})

	t.Run("rejects an out-of-order top level", func(t *testing.T) {
		broken, err := xdrcopyEntry(t, wellFormed)
		if err != nil {
			t.Fatalf("copying: %v", err)
		}
		nodes := broken.Credentials.AddressWithDelegates.Delegates
		if len(nodes) != 2 {
			t.Fatalf("expected 2 top-level delegates, got %d", len(nodes))
		}
		nodes[0], nodes[1] = nodes[1], nodes[0]

		err = ValidateDelegateOrder(broken)
		if err == nil {
			t.Fatal("ValidateDelegateOrder accepted an out-of-order entry")
		}
		if !strings.Contains(err.Error(), "ascending address order") {
			t.Errorf("error %q does not explain the ordering rule", err)
		}
	})

	t.Run("rejects a duplicate within a level", func(t *testing.T) {
		broken, err := xdrcopyEntry(t, wellFormed)
		if err != nil {
			t.Fatalf("copying: %v", err)
		}
		nodes := broken.Credentials.AddressWithDelegates.Delegates
		nodes[1].Address = nodes[0].Address

		err = ValidateDelegateOrder(broken)
		if err == nil {
			t.Fatal("ValidateDelegateOrder accepted a duplicate")
		}
		if !errors.Is(err, ErrDuplicateDelegate) {
			t.Errorf("error %q does not match ErrDuplicateDelegate", err)
		}
	})

	t.Run("recurses into nested levels", func(t *testing.T) {
		d3 := testKeypair(t, "soroauth-delegate-3").Address()
		nestedEntry, err := WithDelegates(entry, testValidUntilLedger,
			[]Delegate{{Address: d1, Nested: []Delegate{{Address: d2}, {Address: d3}}}}, nil)
		if err != nil {
			t.Fatalf("building: %v", err)
		}
		broken, err := xdrcopyEntry(t, nestedEntry)
		if err != nil {
			t.Fatalf("copying: %v", err)
		}
		nested := broken.Credentials.AddressWithDelegates.Delegates[0].NestedDelegates
		if len(nested) != 2 {
			t.Fatalf("expected 2 nested delegates, got %d", len(nested))
		}
		nested[0], nested[1] = nested[1], nested[0]

		if err := ValidateDelegateOrder(broken); err == nil {
			t.Error("ValidateDelegateOrder did not look inside the nested level")
		}
	})

	t.Run("rejects arms that have no delegates", func(t *testing.T) {
		for _, armType := range []xdr.SorobanCredentialsType{
			xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
			xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		} {
			err := ValidateDelegateOrder(entryForArm(t, armType, 42))
			if !errors.Is(err, ErrUnsupportedCredentials) {
				t.Errorf("%v: error %q does not match ErrUnsupportedCredentials", armType, err)
			}
		}
	})
}

// xdrcopyEntry deep-copies an entry so a test can corrupt the copy without
// disturbing the fixture it came from.
func xdrcopyEntry(t testing.TB, entry xdr.SorobanAuthorizationEntry) (xdr.SorobanAuthorizationEntry, error) {
	t.Helper()
	encoded, err := entry.MarshalBinary()
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	var out xdr.SorobanAuthorizationEntry
	if err := out.UnmarshalBinary(encoded); err != nil {
		return xdr.SorobanAuthorizationEntry{}, err
	}
	return out, nil
}

type Vector struct {
	UnsignedEntryXDR string `json:"unsigned_entry_xdr"`
}

func loadVector(t testing.TB, name string) Vector {
	t.Helper()
	path := filepath.Join("testdata", "vectors", name+".json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading vector %s: %v", name, err)
	}
	var v Vector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("unmarshalling vector %s: %v", name, err)
	}
	return v
}

func FuzzValidateDelegateOrder(f *testing.F) {
	// Seed corpus from golden vectors and malformed trees.
	v := loadVector(f, "delegates_unsorted_with_nested")
	var goldEntry xdr.SorobanAuthorizationEntry
	err := xdr.SafeUnmarshalBase64(v.UnsignedEntryXDR, &goldEntry)
	directErr := err == nil
	if directErr {
		f.Add([]byte(v.UnsignedEntryXDR))
	}

	// f is passed to the helpers directly. A &testing.T{} literal would be an
	// uninitialised struct: t.Helper() and t.Fatalf() on one panic rather than
	// reporting, so a seed that failed to build would take the fuzz target
	// down instead of failing it. The helpers take testing.TB, which *testing.F
	// satisfies.
	entry := entryForArm(f, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 42)
	d1 := testKeypair(f, "soroauth-delegate-1").Address()
	d2 := testKeypair(f, "soroauth-delegate-2").Address()

	wellFormed, err := WithDelegates(entry, testValidUntilLedger,
		[]Delegate{{Address: d1, Nested: []Delegate{{Address: d2}}}, {Address: d2}}, nil)
	if err == nil {
		bin, err := wellFormed.MarshalBinary()
		if err == nil {
			f.Add(bin)
		}
	}

	// Add a malformed/duplicate seed bytes
	if err == nil {
		broken, _ := xdrcopyEntry(f, wellFormed)
		if broken.Credentials.AddressWithDelegates.Delegates != nil && len(broken.Credentials.AddressWithDelegates.Delegates) > 1 {
			broken.Credentials.AddressWithDelegates.Delegates[1].Address = broken.Credentials.AddressWithDelegates.Delegates[0].Address
			if bin, err := broken.MarshalBinary(); err == nil {
				f.Add(bin)
			}
		}
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var entry xdr.SorobanAuthorizationEntry
		if err := entry.UnmarshalBinary(data); err != nil {
			return
		}

		// Ensure ValidateDelegateOrder never panics on arbitrary bytes/structures.
		err := ValidateDelegateOrder(entry)
		if err == nil {
			// If ValidateDelegateOrder accepts the entry, every level of delegates
			// must be strictly ascending with no duplicates.
			if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
				checkStrictAscendingLevels(t, entry.Credentials.AddressWithDelegates.Delegates)
			}
		}
	})
}

func checkStrictAscendingLevels(t *testing.T, nodes []xdr.SorobanDelegateSignature) {
	t.Helper()
	if len(nodes) <= 1 {
		for _, node := range nodes {
			checkStrictAscendingLevels(t, node.NestedDelegates)
		}
		return
	}

	for i := 1; i < len(nodes); i++ {
		prevEncoded, err := addressBytes(nodes[i-1].Address)
		if err != nil {
			t.Fatalf("failed encoding previous address: %v", err)
		}
		currEncoded, err := addressBytes(nodes[i].Address)
		if err != nil {
			t.Fatalf("failed encoding current address: %v", err)
		}
		if bytes.Compare(prevEncoded, currEncoded) >= 0 {
			t.Errorf("accepted delegates level is not strictly ascending or contains duplicates")
		}
	}

	for _, node := range nodes {
		checkStrictAscendingLevels(t, node.NestedDelegates)
	}
}
