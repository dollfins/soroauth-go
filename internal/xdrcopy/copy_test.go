package xdrcopy

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"sync"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	xdrcodec "github.com/stellar/go-xdr/xdr3"
)

// testAddress derives a deterministic public test account from a label, the
// scheme every soroauth test uses. These keys are public by construction and
// must never be funded on mainnet.
func testAddress(t *testing.T, label string) xdr.ScAddress {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatalf("deriving keypair for %q: %v", label, err)
	}
	accountID, err := xdr.AddressToAccountId(kp.Address())
	if err != nil {
		t.Fatalf("converting %q to account id: %v", kp.Address(), err)
	}
	return xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeAccount, AccountId: &accountID}
}

// sampleEntry builds an entry that exercises every kind of indirection the XDR
// types use: a union arm behind a pointer (Credentials.AddressV2), a doubly
// indirected slice (ScVal.Vec is **ScVec), a pointer union arm inside the
// invocation (Function.ContractFn), and a recursive slice (SubInvocations).
func sampleEntry(t *testing.T) xdr.SorobanAuthorizationEntry {
	t.Helper()

	sigVec := &xdr.ScVec{{Type: xdr.ScValTypeScvU32, U32: func() *xdr.Uint32 { v := xdr.Uint32(7); return &v }()}}
	signature := xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &sigVec}

	credentials := xdr.SorobanAddressCredentials{
		Address:                   testAddress(t, "soroauth-xdrcopy-account"),
		Nonce:                     xdr.Int64(1234),
		SignatureExpirationLedger: xdr.Uint32(99),
		Signature:                 signature,
	}

	argVal := xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: func() *xdr.ScSymbol { s := xdr.ScSymbol("arg"); return &s }()}

	contractFn := &xdr.InvokeContractArgs{
		ContractAddress: xdr.ScAddress{
			Type:       xdr.ScAddressTypeScAddressTypeContract,
			ContractId: &xdr.ContractId{1, 2, 3},
		},
		FunctionName: xdr.ScSymbol("transfer"),
		Args:         []xdr.ScVal{argVal},
	}

	subFn := &xdr.InvokeContractArgs{
		ContractAddress: xdr.ScAddress{
			Type:       xdr.ScAddressTypeScAddressTypeContract,
			ContractId: &xdr.ContractId{4, 5, 6},
		},
		FunctionName: xdr.ScSymbol("approve"),
		Args:         []xdr.ScVal{},
	}

	return xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type:      xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &credentials,
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type:       xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: contractFn,
			},
			SubInvocations: []xdr.SorobanAuthorizedInvocation{{
				Function: xdr.SorobanAuthorizedFunction{
					Type:       xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
					ContractFn: subFn,
				},
			}},
		},
	}
}

func mustMarshal(t *testing.T, v interface{ MarshalBinary() ([]byte, error) }) []byte {
	t.Helper()
	b, err := v.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling %T: %v", v, err)
	}
	return b
}

func TestCopyIsByteIdentical(t *testing.T) {
	tests := []struct {
		name  string
		build func(t *testing.T) xdr.SorobanAuthorizationEntry
	}{
		{
			name:  "full entry with nested invocations",
			build: sampleEntry,
		},
		{
			name: "source account credentials",
			build: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				e := sampleEntry(t)
				e.Credentials = xdr.SorobanCredentials{
					Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
				}
				return e
			},
		},
		{
			name: "no sub invocations",
			build: func(t *testing.T) xdr.SorobanAuthorizationEntry {
				e := sampleEntry(t)
				e.RootInvocation.SubInvocations = nil
				return e
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := tt.build(t)
			want := mustMarshal(t, original)

			got, err := Copy(original)
			if err != nil {
				t.Fatalf("Copy returned an unexpected error: %v", err)
			}

			if !bytes.Equal(want, mustMarshal(t, got)) {
				t.Errorf("copy is not byte-identical to the original\n want %x\n  got %x", want, mustMarshal(t, got))
			}
		})
	}
}

// TestCopySharesNoMemory is the test that matters: it writes through every
// pointer and slice the copy exposes and proves none of it reaches the
// original. Without a real deep copy, each of these writes would be visible to
// the caller.
func TestCopySharesNoMemory(t *testing.T) {
	original := sampleEntry(t)
	before := mustMarshal(t, original)

	got, err := Copy(original)
	if err != nil {
		t.Fatalf("Copy returned an unexpected error: %v", err)
	}

	if got.Credentials.AddressV2 == original.Credentials.AddressV2 {
		t.Error("copy shares the AddressV2 credentials pointer with the original")
	}
	if got.RootInvocation.Function.ContractFn == original.RootInvocation.Function.ContractFn {
		t.Error("copy shares the ContractFn pointer with the original")
	}

	got.Credentials.AddressV2.Nonce = 4242
	got.Credentials.AddressV2.SignatureExpirationLedger = 1
	(*got.Credentials.AddressV2.Signature.Vec) = &xdr.ScVec{}
	got.RootInvocation.Function.ContractFn.FunctionName = xdr.ScSymbol("drain")
	got.RootInvocation.Function.ContractFn.Args[0] = xdr.ScVal{Type: xdr.ScValTypeScvVoid}
	got.RootInvocation.SubInvocations[0].Function.ContractFn.FunctionName = xdr.ScSymbol("drain_sub")

	after := mustMarshal(t, original)
	if !bytes.Equal(before, after) {
		t.Errorf("mutating the copy changed the original\n before %x\n  after %x", before, after)
	}
}

func TestCopyReturnsErrorForUnmarshalableValue(t *testing.T) {
	// An unset union discriminant has no arm to encode, so the generated
	// EncodeTo refuses it. Copy must surface that rather than hand back a
	// half-built value.
	invalid := xdr.SorobanCredentials{Type: xdr.SorobanCredentialsType(99)}

	got, err := Copy(invalid)
	if err == nil {
		t.Fatalf("Copy succeeded on an invalid union, returning %+v", got)
	}
	if want := "soroauth: xdrcopy: marshal"; !bytes.Contains([]byte(err.Error()), []byte(want)) {
		t.Errorf("error %q does not carry the %q prefix", err, want)
	}
	if got != (xdr.SorobanCredentials{}) {
		t.Errorf("Copy returned %+v alongside an error, want the zero value", got)
	}
}

// underConsume is an XDR value whose decoder deliberately reads back fewer
// bytes than its encoder wrote: EncodeTo produces four bytes, DecodeFrom
// consumes none. Real go-stellar-sdk types are symmetric, but Copy now drives
// DecodeFrom itself, and the generated UnmarshalBinary it replaced threw the
// consumed count away (xdr_generated.go: `_, err := s.DecodeFrom(...)`) —
// so an asymmetric codec would previously have produced a silently truncated
// copy. Copy must fail closed on that instead.
type underConsume struct{ V uint32 }

func (u underConsume) EncodeTo(e *xdrcodec.Encoder) error {
	_, err := e.EncodeUint(u.V)
	return err
}

func (u *underConsume) DecodeFrom(_ *xdrcodec.Decoder, _ uint) (int, error) {
	return 0, nil
}

var _ xdr.EncoderTo = (*underConsume)(nil)
var _ xdr.DecoderFrom = (*underConsume)(nil)

// TestCopyFailsClosedWhenDecodeDoesNotConsumeEveryByte pins the round-trip
// guard: a decode that reads back less than the encode produced is an error
// naming that exact failure, never a partial value.
func TestCopyFailsClosedWhenDecodeDoesNotConsumeEveryByte(t *testing.T) {
	got, err := Copy(underConsume{V: 0x2a})
	if err == nil {
		t.Fatalf("Copy returned %+v with no error although the decode read 0 of the 4 encoded bytes", got)
	}
	if want := "soroauth: xdrcopy: unmarshal"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not carry the %q prefix", err, want)
	}
	if want := "consumed 0 of the 4 encoded bytes"; !strings.Contains(err.Error(), want) {
		t.Errorf("error %q does not say which failure happened; want it to contain %q", err, want)
	}
	if got != (underConsume{}) {
		t.Errorf("Copy returned %+v alongside an error, want the zero value", got)
	}
}

// bigEntry returns a wider entry than sampleEntry (16 distinct sub-invocations
// with arguments, versus one), so the two fixtures used by the concurrency
// test below differ in shape and length and a crossed buffer shows up as
// bytes that do not match either source.
func bigEntry(t *testing.T) xdr.SorobanAuthorizationEntry {
	t.Helper()
	entry := sampleEntry(t)
	subs := make([]xdr.SorobanAuthorizedInvocation, 0, 16)
	for i := 0; i < 16; i++ {
		id := xdr.ContractId{byte(i + 1), 9, 9}
		amount := xdr.Int64(1000 + int64(i))
		subs = append(subs, xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: &id,
					},
					FunctionName: xdr.ScSymbol("poke"),
					Args:         []xdr.ScVal{{Type: xdr.ScValTypeScvI64, I64: &amount}},
				},
			},
		})
	}
	entry.RootInvocation.SubInvocations = subs
	return entry
}

// TestCopyConcurrentReuse is the fixture for the pooling in Copy: the
// transport buffers (encoder buffer, decoder, reader) are shared through
// sync.Pool across calls. If one were handed back before the decode finished
// reading it, or two in-flight copies ever shared one, a concurrent marshal
// would overwrite the bytes being decoded and this test would see either a
// decode error or a copy whose bytes match neither source. The sources are
// re-marshalled afterwards too, to catch a copy that mutated them.
//
// Run it with -race; CI does (the `test` job runs `go test -race ./...`).
func FuzzCopyRoundTrip(f *testing.F) {
	sampleBytes := mustMarshal(&testing.T{}, sampleEntry(&testing.T{}))
	f.Add(sampleBytes)

	f.Fuzz(func(t *testing.T, data []byte) {
		var entry xdr.SorobanAuthorizationEntry
		err := entry.UnmarshalBinary(data)
		if err != nil {
			return
		}

		// If the entry unmarshalled successfully but contains nil pointer union arms
		// that would panic during marshalling, check with a safe marshal first or recover.
		// Specifically, union arms like ContractFn or AddressV2 might be nil if malformed data
		// decoded a discriminant without allocating the arm struct.
		if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2 && entry.Credentials.AddressV2 == nil {
			return
		}
		if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddress && entry.Credentials.Address == nil {
			return
		}
		if entry.RootInvocation.Function.Type == xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn && entry.RootInvocation.Function.ContractFn == nil {
			return
		}

		got, err := Copy(entry)
		if err != nil {
			t.Fatalf("Copy failed on valid entry: %v", err)
		}

		wantBytes := mustMarshal(t, entry)
		gotBytes := mustMarshal(t, got)
		if !bytes.Equal(wantBytes, gotBytes) {
			t.Errorf("fuzz round-trip not byte-identical:\n want %x\n  got %x", wantBytes, gotBytes)
		}
	})
}

func TestCopyConcurrentReuse(t *testing.T) {
	small := sampleEntry(t)
	large := bigEntry(t)
	wantSmall := mustMarshal(t, small)
	wantLarge := mustMarshal(t, large)
	if len(wantLarge) <= 2*len(wantSmall) {
		t.Fatalf("fixture is not meaningfully larger than the other: small %d bytes, large %d bytes",
			len(wantSmall), len(wantLarge))
	}

	const goroutines = 8
	const iterations = 250
	var wg sync.WaitGroup
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				src, want := small, wantSmall
				if (g+i)%2 == 0 {
					src, want = large, wantLarge
				}
				got, err := Copy(src)
				if err != nil {
					t.Errorf("goroutine %d iteration %d: Copy: %v", g, i, err)
					return
				}
				encoded, err := got.MarshalBinary()
				if err != nil {
					t.Errorf("goroutine %d iteration %d: marshalling the copy: %v", g, i, err)
					return
				}
				if !bytes.Equal(encoded, want) {
					t.Errorf("goroutine %d iteration %d: copy is not byte-identical to its source\n want %x\n  got %x",
						g, i, want, encoded)
					return
				}
			}
		}(g)
	}
	wg.Wait()

	if after := mustMarshal(t, small); !bytes.Equal(after, wantSmall) {
		t.Errorf("copying concurrently changed the small source\n before %x\n  after %x", wantSmall, after)
	}
	if after := mustMarshal(t, large); !bytes.Equal(after, wantLarge) {
		t.Errorf("copying concurrently changed the large source\n before %x\n  after %x", wantLarge, after)
	}
}
