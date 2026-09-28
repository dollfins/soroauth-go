package soroauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// Signing-path benchmarks (issue #107).
//
// Coverage required by the issue:
//   - Preimage, Payload
//   - AuthorizeEntry on all three signing arms (legacy, V2, delegates)
//   - AuthorizeAll over a realistic multi-entry, multi-signer batch
//   - a deep delegate tree (recursive walk + deep copy)
//
// ns/op is machine-dependent and is never used as a CI gate. Allocs/op and
// B/op are deterministic for a given Go version and are gated by
// testdata/bench/budgets.json via scripts/checkbench (CI job "bench").
//
// Reproduce locally:
//   go test -run '^$' -bench . -benchmem -count=1 . | tee /tmp/bench.out
//   go run ./scripts/checkbench /tmp/bench.out testdata/bench/budgets.json

// benchKeypair derives a deterministic public test keypair from a label.
func benchKeypair(b *testing.B, label string) *keypair.Full {
	b.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		b.Fatalf("deriving keypair for %q: %v", label, err)
	}
	return kp
}

// benchContractAddress derives a deterministic C… address from a label.
func benchContractAddress(b *testing.B, label string) string {
	b.Helper()
	sum := sha256.Sum256([]byte(label))
	address, err := strkey.Encode(strkey.VersionByteContract, sum[:])
	if err != nil {
		b.Fatalf("encoding contract address for %q: %v", label, err)
	}
	return address
}

// benchInvocation returns a small non-trivial call tree (contract call with
// one argument and one sub-invocation) so Preimage exercises recursive encoding.
func benchInvocation(b *testing.B) xdr.SorobanAuthorizedInvocation {
	b.Helper()
	contract, err := ParseAddress(benchContractAddress(b, "soroauth-bench-contract"))
	if err != nil {
		b.Fatalf("parsing the bench contract address: %v", err)
	}
	sub, err := ParseAddress(benchContractAddress(b, "soroauth-bench-subcontract"))
	if err != nil {
		b.Fatalf("parsing the bench sub-contract address: %v", err)
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
					ContractAddress: sub,
					FunctionName:    xdr.ScSymbol("approve"),
					Args:            []xdr.ScVal{},
				},
			},
		}},
	}
}

// benchAddressEntry builds an unsigned address-arm entry (legacy or V2) for
// signerLabel's account.
func benchAddressEntry(b *testing.B, arm xdr.SorobanCredentialsType, signerLabel string, nonce int64) xdr.SorobanAuthorizationEntry {
	b.Helper()
	addr, err := ParseAddress(benchKeypair(b, signerLabel).Address())
	if err != nil {
		b.Fatalf("parsing the bench signer address: %v", err)
	}
	credentials := xdr.SorobanAddressCredentials{
		Address:   addr,
		Nonce:     xdr.Int64(nonce),
		Signature: xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: newScVec()},
	}
	entry := xdr.SorobanAuthorizationEntry{
		RootInvocation: benchInvocation(b),
	}
	switch arm {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		entry.Credentials = xdr.SorobanCredentials{
			Type:    arm,
			Address: &credentials,
		}
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		entry.Credentials = xdr.SorobanCredentials{
			Type:      arm,
			AddressV2: &credentials,
		}
	default:
		b.Fatalf("benchAddressEntry does not build arm %v", arm)
	}
	return entry
}

// benchDelegateChain builds a delegates-arm entry whose delegate tree is a
// single chain of the requested depth under the top-level account: top → d1 →
// d2 → … → dN. The top-level signature is Void (CAP-71-01 allows it when only
// delegates authenticate).
//
// It returns the wrapped entry, the keypair for the deepest delegate (so a
// caller can force the full recursive node walk with ForAddress), and that
// deepest address.
func benchDelegateChain(b *testing.B, depth int) (xdr.SorobanAuthorizationEntry, *keypair.Full, string) {
	b.Helper()
	if depth < 1 {
		b.Fatalf("delegate chain depth must be >= 1, got %d", depth)
	}

	// Deepest first, so each level's Nested is already built.
	var leaf Delegate
	leafKP := benchKeypair(b, fmt.Sprintf("soroauth-bench-delegate-%d", depth))
	leaf = Delegate{Address: leafKP.Address()}
	for i := depth - 1; i >= 1; i-- {
		kp := benchKeypair(b, fmt.Sprintf("soroauth-bench-delegate-%d", i))
		leaf = Delegate{Address: kp.Address(), Nested: []Delegate{leaf}}
	}

	base := benchAddressEntry(b, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		"soroauth-bench-signer", 42)
	wrapped, err := WithDelegates(base, testValidUntilLedger, []Delegate{leaf}, nil)
	if err != nil {
		b.Fatalf("WithDelegates: %v", err)
	}
	return wrapped, leafKP, leafKP.Address()
}

// benchDeepEntry is the V2 single-signer entry used by Preimage, Payload and
// the single-arm AuthorizeEntry case.
func benchDeepEntry(b *testing.B) xdr.SorobanAuthorizationEntry {
	b.Helper()
	return benchAddressEntry(b, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		"soroauth-bench-signer", 42)
}

// BenchmarkPreimage measures HashIdPreimage construction alone (V2 arm).
func BenchmarkPreimage(b *testing.B) {
	entry := benchDeepEntry(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkPayload measures SHA-256 over the marshaled preimage alone.
func BenchmarkPayload(b *testing.B) {
	entry := benchDeepEntry(b)
	pre, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Payload(pre); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuthorizeEntry measures the full signing path on each of the three
// signing arms: context check, deep copy, preimage, payload hash, Sign, and
// writing the signature onto matching nodes.
func BenchmarkAuthorizeEntry(b *testing.B) {
	ctx := context.Background()

	b.Run("legacy", func(b *testing.B) {
		entry := benchAddressEntry(b, xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			"soroauth-bench-signer", 42)
		signer := NewEd25519Signer(benchKeypair(b, "soroauth-bench-signer"))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := AuthorizeEntry(ctx, entry, signer, testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("v2", func(b *testing.B) {
		entry := benchDeepEntry(b)
		signer := NewEd25519Signer(benchKeypair(b, "soroauth-bench-signer"))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := AuthorizeEntry(ctx, entry, signer, testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
				b.Fatal(err)
			}
		}
	})

	// Small flat delegate tree (3 delegates) — the common case.
	b.Run("delegates", func(b *testing.B) {
		base := benchAddressEntry(b, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			"soroauth-bench-signer", 43)
		d1 := benchKeypair(b, "soroauth-bench-delegate-1")
		d2 := benchKeypair(b, "soroauth-bench-delegate-2")
		d3 := benchKeypair(b, "soroauth-bench-delegate-3")
		entry, err := WithDelegates(base, testValidUntilLedger, []Delegate{
			{Address: d1.Address()},
			{Address: d2.Address()},
			{Address: d3.Address()},
		}, nil)
		if err != nil {
			b.Fatal(err)
		}
		// Sign a delegate so the walk covers top-level + all three nodes.
		signer := NewEd25519Signer(d2)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := AuthorizeEntry(ctx, entry, signer, testValidUntilLedger,
				network.TestNetworkPassphrase, ForAddress(d2.Address())); err != nil {
				b.Fatal(err)
			}
		}
	})

	// Deep chain: the path that recurses through NestedDelegates and
	// deep-copies the whole tree on every call.
	b.Run("delegates_deep", func(b *testing.B) {
		const depth = 8
		entry, leafKP, leafAddr := benchDelegateChain(b, depth)
		signer := NewEd25519Signer(leafKP)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := AuthorizeEntry(ctx, entry, signer, testValidUntilLedger,
				network.TestNetworkPassphrase, ForAddress(leafAddr)); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkXDRCopy measures internal/xdrcopy.Copy, the deep copy every
// entry-returning function performs before writing anything (issue #108).
//
// Two shapes are timed because both are on the signing path:
//
//   - entry: a V2 SorobanAuthorizationEntry with a sub-invocation. This is
//     what AuthorizeEntry copies before it signs.
//   - preimage: the HashIdPreimage Preimage detaches from the entry so a
//     later change to the entry cannot alter a derived payload.
//
// Reproduce a budget failure locally (see CONTRIBUTING.md):
//
//	go test -run '^$' -bench BenchmarkXDRCopy -benchmem -count=1 . | tee /tmp/bench.out
//	go run ./scripts/checkbench /tmp/bench.out testdata/bench/budgets.json
func BenchmarkXDRCopy(b *testing.B) {
	b.Run("entry", func(b *testing.B) {
		entry := benchDeepEntry(b)
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := xdrcopy.Copy(entry); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("preimage", func(b *testing.B) {
		entry := benchDeepEntry(b)
		pre, err := Preimage(entry, testValidUntilLedger, network.TestNetworkPassphrase)
		if err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := xdrcopy.Copy(pre); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// batchSignerLabel is the i-th deterministic signer label for the realistic batch.
func batchSignerLabel(i int) string {
	return fmt.Sprintf("soroauth-bench-batch-signer-%d", i)
}

// benchRealisticBatch builds a 12-entry batch across three arms with four
// signers — the shape a backend might see from one simulateTransaction with
// several require_auth sites.
//
//	x4 legacy, x4 V2, x4 delegates (2 flat delegates each);
//	signers rotate over four accounts so AuthorizeAll has to match each entry.
func benchRealisticBatch(b *testing.B) (entries []xdr.SorobanAuthorizationEntry, signers []Signer) {
	b.Helper()
	const n = 12
	arms := []xdr.SorobanCredentialsType{
		xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
		xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
	}
	entries = make([]xdr.SorobanAuthorizationEntry, 0, n)
	for i := 0; i < n; i++ {
		label := batchSignerLabel(i % 4)
		arm := arms[i%2]
		if i%4 == 3 {
			// Every fourth entry is a small delegates entry.
			base := benchAddressEntry(b, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, label, int64(100+i))
			dA := benchKeypair(b, fmt.Sprintf("soroauth-bench-batch-delegate-a-%d", i))
			dB := benchKeypair(b, fmt.Sprintf("soroauth-bench-batch-delegate-b-%d", i))
			wrapped, err := WithDelegates(base, testValidUntilLedger, []Delegate{
				{Address: dA.Address()},
				{Address: dB.Address()},
			}, nil)
			if err != nil {
				b.Fatal(err)
			}
			entries = append(entries, wrapped)
			continue
		}
		entries = append(entries, benchAddressEntry(b, arm, label, int64(100+i)))
	}

	signers = make([]Signer, 0, 4)
	for i := 0; i < 4; i++ {
		signers = append(signers, NewEd25519Signer(benchKeypair(b, batchSignerLabel(i))))
	}
	return entries, signers
}

// BenchmarkAuthorizeAll measures the batch signing path over a realistic
// 12-entry, 4-signer mix of legacy, V2 and delegates entries.
func BenchmarkAuthorizeAll(b *testing.B) {
	entries, signers := benchRealisticBatch(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := AuthorizeAll(ctx, entries, signers, testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuthorizeBatch measures the bounded-concurrency batch signing
// path over the same 12-entry, 4-signer realistic mix that
// BenchmarkAuthorizeAll does. It is gated by testdata/bench/budgets.json via
// scripts/checkbench (CI job "bench"), with ~40% headroom like the rest of
// the signing path. ns/op is machine-dependent and is never gated.
//
// Reproduce locally:
//
//	go test -run '^$' -bench . -benchmem -count=1 . | tee /tmp/bench.out
//	go run ./scripts/checkbench /tmp/bench.out testdata/bench/budgets.json
func BenchmarkAuthorizeBatch(b *testing.B) {
	entries, signers := benchRealisticBatch(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := AuthorizeBatch(ctx, entries, signers, testValidUntilLedger, network.TestNetworkPassphrase); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkAuthorizeInvocation measures building and signing from scratch (V2).
func BenchmarkAuthorizeInvocation(b *testing.B) {
	signer := NewEd25519Signer(benchKeypair(b, "soroauth-bench-signer"))
	ctx := context.Background()
	params := AuthorizeInvocationParams{
		Signer:            signer,
		Invocation:        benchInvocation(b),
		ValidUntilLedger:  testValidUntilLedger,
		NetworkPassphrase: network.TestNetworkPassphrase,
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := AuthorizeInvocation(ctx, params); err != nil {
			b.Fatal(err)
		}
	}
}
