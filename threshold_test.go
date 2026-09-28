package soroauth

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThresholdSigner(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-thresh-account")

	_, err := NewThresholdSigner(kp1.Address(), 0)
	assert.Error(t, err)

	_, err = NewThresholdSigner(kp1.Address(), 1)
	assert.Error(t, err)

	_, err = NewThresholdSigner(kp1.Address(), 1, kp1.Address(), kp1.Address())
	assert.Error(t, err)

	signer, err := NewThresholdSigner(kp1.Address(), 2, kp1.Address(), testKeypair(t, "soroauth-thresh-party-2").Address())
	require.NoError(t, err)
	assert.Equal(t, kp1.Address(), signer.Address())
	assert.False(t, signer.IsComplete())
}

func TestThresholdSignerBeginContribute(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-thresh-bc-1")
	kp2 := testKeypair(t, "soroauth-thresh-bc-2")

	signer, err := NewThresholdSigner(kp1.Address(), 2, kp1.Address(), kp2.Address())
	require.NoError(t, err)

	ctx := context.Background()
	round, err := signer.Begin(ctx)
	require.NoError(t, err)

	seed1 := sha256.Sum256([]byte(kp1.Seed()))
	seed2 := sha256.Sum256([]byte(kp2.Seed()))
	share1 := append([]byte("party1-share"), seed1[:]...)
	sig, err := signer.Contribute(ctx, round, share1)
	require.NoError(t, err)
	assert.Nil(t, sig)
	assert.False(t, signer.IsComplete())

	share2 := append([]byte("party2-share"), seed2[:]...)
	sig, err = signer.Contribute(ctx, round, share2)
	require.NoError(t, err)
	assert.NotNil(t, sig)
	assert.True(t, signer.IsComplete())
}

func TestThresholdSignerSign(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-thresh-sign-1")
	kp2 := testKeypair(t, "soroauth-thresh-sign-2")

	signer, err := NewThresholdSigner(kp1.Address(), 2, kp1.Address(), kp2.Address())
	require.NoError(t, err)

	ctx := context.Background()
	_, err = signer.Sign(ctx, xdr.HashIdPreimage{}, [32]byte{})
	assert.Error(t, err)

	round, _ := signer.Begin(ctx)
	seed1 := sha256.Sum256([]byte(kp1.Seed()))
	seed2 := sha256.Sum256([]byte(kp2.Seed()))
	share1 := append([]byte("party1"), seed1[:]...)
	share2 := append([]byte("party2"), seed2[:]...)
	_, _ = signer.Contribute(ctx, round, share1)
	_, _ = signer.Contribute(ctx, round, share2)

	sig, err := signer.Sign(ctx, xdr.HashIdPreimage{}, [32]byte{})
	require.NoError(t, err)
	assert.NotNil(t, sig)
}

func TestThresholdSignerContextCancellation(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-thresh-ctx-1")
	kp2 := testKeypair(t, "soroauth-thresh-ctx-2")

	signer, err := NewThresholdSigner(kp1.Address(), 2, kp1.Address(), kp2.Address())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = signer.Begin(ctx)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestThresholdPartySigner(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-thresh-party-s-1")

	inner := NewEd25519Signer(kp1)
	party, err := NewThresholdPartySigner(kp1.Address(), inner)
	require.NoError(t, err)
	assert.Equal(t, kp1.Address(), party.Address())
	assert.Equal(t, kp1.Address(), party.Party())
}

func TestThresholdPartySignerContextCancellation(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-thresh-p-ctx")
	inner := NewEd25519Signer(kp1)

	party, err := NewThresholdPartySigner(kp1.Address(), inner)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = party.Sign(ctx, xdr.HashIdPreimage{}, [32]byte{})
	assert.ErrorIs(t, err, context.Canceled)
}

func TestThresholdSignerNoSecretMaterial(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-thresh-nosec")
	kp2 := testKeypair(t, "soroauth-thresh-nosec-2")

	signer, err := NewThresholdSigner(kp1.Address(), 2, kp1.Address(), kp2.Address())
	require.NoError(t, err)

	ctx := context.Background()
	round, _ := signer.Begin(ctx)

	seed := sha256.Sum256([]byte("test"))
	share := append([]byte("test-share"), seed[:]...)
	_, _ = signer.Contribute(ctx, round, share)

	assert.NotEmpty(t, signer.Address())
}

func TestThresholdSignerTooManyParties(t *testing.T) {
	kp1 := testKeypair(t, "soroauth-thresh-many-1")

	var parties []string
	for i := 0; i < 21; i++ {
		parties = append(parties, testKeypair(t, "soroauth-thresh-many-2").Address())
	}

	_, err := NewThresholdSigner(kp1.Address(), 20, parties...)
	assert.Error(t, err)
}
