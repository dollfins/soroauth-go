package soroauth

import (
	"context"
	"testing"

	"fmt"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// BenchmarkDecodeAuthorizationEntry measures the bounded decode of an entry
// that came from somewhere else, which is the path Inspect and the CLI use for
// untrusted input (issue #121).
//
// The three signing-path benchmarks this file once carried (Preimage, Payload
// and AuthorizeEntry) live in bench_signing_test.go, which came from issue #107
// and is the copy that testdata/bench/budgets.json gates; duplicating the names
// here only made the package fail to build.
//
// The entry is built with benchAddressEntry so its bytes have the same shape as
// the signing-path benchmarks' input. ns/op is machine-dependent, and this
// benchmark has no budget entry, so checkbench reports it as a warning rather
// than gating on it.
func BenchmarkDecodeAuthorizationEntry(b *testing.B) {
	entry := benchAddressEntry(b, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
		"soroauth-bench-signer", 42)
	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		b.Fatalf("encoding the benchmark entry: %v", err)
	}
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := DecodeAuthorizationEntry(encoded); err != nil {
			b.Fatalf("DecodeAuthorizationEntry returned an unexpected error: %v", err)
		}
	}
}

// benchFullySignableBatch builds the same 12-entry, three-arm shape as
// bench_signing_test.go's benchRealisticBatch, but with a signer for every
// node RequireAllSigned will check — including each delegates entry's two
// delegates, which benchRealisticBatch's four rotating signers never match
// (by design: BenchmarkAuthorizeAll only needs one match per entry). Reusing
// benchRealisticBatch's own labels for the shared prefix keeps the two
// batches' address-arm entries identical, so BenchmarkAuthorizeAll and
// BenchmarkAuthorizeAllRequireAllSigned differ only by RequireAllSigned's own
// cost, not by a different batch shape.
func benchFullySignableBatch(b *testing.B) (entries []xdr.SorobanAuthorizationEntry, signers []Signer) {
	b.Helper()
	entries, signers = benchRealisticBatch(b)

	for i := 3; i < len(entries); i += 4 {
		dA := benchKeypair(b, fmt.Sprintf("soroauth-bench-batch-delegate-a-%d", i))
		dB := benchKeypair(b, fmt.Sprintf("soroauth-bench-batch-delegate-b-%d", i))
		signers = append(signers, NewEd25519Signer(dA), NewEd25519Signer(dB))
	}
	return entries, signers
}

// BenchmarkAuthorizeAllRequireAllSigned is BenchmarkAuthorizeAll's own
// 12-entry batch shape (bench_signing_test.go), with a signer added for
// every node and RequireAllSigned turned on (issue #103), so the two
// benchmarks can be compared directly: the difference between them is
// RequireAllSigned's post-signing walk plus the extra signers, not a
// different batch. Like BenchmarkDecodeAuthorizationEntry, this has no
// budget entry, so checkbench reports it as a warning only.
func BenchmarkAuthorizeAllRequireAllSigned(b *testing.B) {
	entries, signers := benchFullySignableBatch(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := AuthorizeAll(ctx, entries, signers, testValidUntilLedger, network.TestNetworkPassphrase,
			RequireAllSigned()); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkNonceTrackerReserve measures NewInMemoryNonceTracker's Reserve on
// its common path: a fresh (address, nonce) pair every call, so the map
// keeps growing the way it would in a long-running process (issue #91).
func BenchmarkNonceTrackerReserve(b *testing.B) {
	tracker := NewInMemoryNonceTracker()
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := tracker.Reserve(ctx, "GBEXAMPLE", int64(i)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyEntry(b *testing.B) {
	kp, err := keypair.Random()
	if err != nil {
		b.Fatalf("random keypair: %v", err)
	}
	signer := NewEd25519Signer(kp)
	entry := entryForArm(nil, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)

	address, err := ParseAddress(kp.Address())
	if err != nil {
		b.Fatalf("parse address: %v", err)
	}
	cred, err := addressCredentials(entry.Credentials)
	if err != nil {
		b.Fatalf("credentials: %v", err)
	}
	cred.Address = address

	signedSlice, err := AuthorizeAll(context.Background(), []xdr.SorobanAuthorizationEntry{entry}, []Signer{signer}, 100, network.TestNetworkPassphrase)
	if err != nil {
		b.Fatalf("authorize: %v", err)
	}
	signed := signedSlice[0]

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyEntry(signed, network.TestNetworkPassphrase)
	}
}

func BenchmarkVerifyAll(b *testing.B) {
	kp, err := keypair.Random()
	if err != nil {
		b.Fatalf("random keypair: %v", err)
	}
	signer := NewEd25519Signer(kp)
	entry := entryForArm(nil, xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2, 1)

	address, err := ParseAddress(kp.Address())
	if err != nil {
		b.Fatalf("parse address: %v", err)
	}
	cred, err := addressCredentials(entry.Credentials)
	if err != nil {
		b.Fatalf("credentials: %v", err)
	}
	cred.Address = address

	signedSlice, err := AuthorizeAll(context.Background(), []xdr.SorobanAuthorizationEntry{entry}, []Signer{signer}, 100, network.TestNetworkPassphrase)
	if err != nil {
		b.Fatalf("authorize: %v", err)
	}

	entries := []xdr.SorobanAuthorizationEntry{signedSlice[0], signedSlice[0]}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = VerifyAll(context.Background(), entries, network.TestNetworkPassphrase, WithConcurrency(2))
	}
}

func BenchmarkDescribeSignatureShape(b *testing.B) {
	passkeyBytes := make([]byte, 64)
	sig := xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: (*xdr.ScBytes)(&passkeyBytes)}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = DescribeSignature(sig)
	}
}
