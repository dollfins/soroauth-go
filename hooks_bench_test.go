package soroauth

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func BenchmarkAuthorizeEntryWithHooks(b *testing.B) {
	kp, _ := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-bench-hook")))
	signer := NewEd25519Signer(kp)

	address := signer.Address()
	addr, err := ParseAddress(address)
	if err != nil {
		b.Fatalf("parsing the benchmark signer address: %v", err)
	}

	// AuthorizeEntry deep-copies the entry with an XDR round-trip, so the entry
	// has to be a complete, valid XDR value: the SDK's encoder dereferences
	// ScAddress.AccountId for an account address and ContractFn for a contract
	// call, and panics on the zero values. A fixture with a zero ScAddress and
	// no RootInvocation crashes the benchmark instead of measuring anything, so
	// both are built for real here.
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			Address: &xdr.SorobanAddressCredentials{
				Address:                   addr,
				Nonce:                     1,
				SignatureExpirationLedger: xdr.Uint32(testValidUntilLedger),
				Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			},
		},
		RootInvocation: benchInvocation(b),
	}

	ctx := context.Background()

	// Benchmark without hooks.
	b.Run("no-hook", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = AuthorizeEntry(ctx, entry, signer, testValidUntilLedger, network.TestNetworkPassphrase,
				ForAddress(kp.Address()))
		}
	})

	// Benchmark with no-op hook (zero cost).
	b.Run("noop-hook", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = AuthorizeEntry(ctx, entry, signer, testValidUntilLedger, network.TestNetworkPassphrase,
				ForAddress(kp.Address()), WithHook(NoOpHook{}))
		}
	})

	// Benchmark with tracking hook.
	hook := &trackingHook{}
	b.Run("tracking-hook", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			hook.events = hook.events[:0]
			_, _ = AuthorizeEntry(ctx, entry, signer, testValidUntilLedger, network.TestNetworkPassphrase,
				ForAddress(kp.Address()), WithHook(hook))
		}
	})
}

func BenchmarkThresholdSigner(b *testing.B) {
	kp1, _ := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-bench-thresh-1")))
	kp2, _ := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-bench-thresh-2")))

	signer, _ := NewThresholdSigner(kp1.Address(), 2, kp1.Address(), kp2.Address())
	ctx := context.Background()
	round, _ := signer.Begin(ctx)
	share1 := append([]byte("p1"), []byte(kp1.Seed())[:32]...)
	share2 := append([]byte("p2"), []byte(kp2.Seed())[:32]...)
	_, _ = signer.Contribute(ctx, round, share1)
	_, _ = signer.Contribute(ctx, round, share2)

	b.ResetTimer()
	b.Run("threshold-sign", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = signer.Sign(ctx, xdr.HashIdPreimage{}, [32]byte{})
		}
	})
}

func BenchmarkCoordinatorState(b *testing.B) {
	kp1, _ := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-bench-coord-1")))
	kp2, _ := keypair.FromRawSeed(sha256.Sum256([]byte("soroauth-bench-coord-2")))

	address1, _ := ParseAddress(kp1.Address())
	address2, _ := ParseAddress(kp2.Address())

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates,
			AddressWithDelegates: &xdr.SorobanAddressCredentialsWithDelegates{
				AddressCredentials: xdr.SorobanAddressCredentials{
					Address:                   address1,
					Nonce:                     1,
					SignatureExpirationLedger: xdr.Uint32(testValidUntilLedger),
					Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
				},
				Delegates: []xdr.SorobanDelegateSignature{
					{Address: address1, Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid}},
					{Address: address2, Signature: xdr.ScVal{Type: xdr.ScValTypeScvVoid}},
				},
			},
		},
	}

	coord, _ := NewCoordinator(entry, testValidUntilLedger, network.TestNetworkPassphrase)

	b.ResetTimer()
	b.Run("coordinator-state", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_ = coord.State()
			_ = coord.Remaining()
			_ = coord.SignedCount()
		}
	})
}
