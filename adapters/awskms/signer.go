package awskms

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// SignerClient is the part of the AWS KMS client used by this adapter. The
// generated *kms.Client satisfies it, while tests can supply a local fake.
type SignerClient interface {
	Sign(context.Context, *kms.SignInput, ...func(*kms.Options)) (*kms.SignOutput, error)
}

type signer struct {
	address      string
	keyID        string
	client       SignerClient
	rawPublicKey []byte
}

// NewSigner returns a soroauth.Signer backed by the Ed25519 KMS key identified
// by keyID. The address must contain the corresponding classic Stellar public
// key. KMS configuration is intentionally owned by the caller: construct the
// client with awsconfig.LoadDefaultConfig (or an explicitly configured
// aws.Config) and pass it here.
func NewSigner(address, keyID string, client SignerClient) (soroauth.Signer, error) {
	if client == nil {
		return nil, fmt.Errorf("awskms: new signer: %w", soroauth.ErrMissingSigner)
	}
	if keyID == "" {
		return nil, fmt.Errorf("awskms: new signer: key id is empty: %w", soroauth.ErrMissingSigner)
	}
	raw, err := strkey.Decode(strkey.VersionByteAccountID, address)
	if err != nil {
		return nil, fmt.Errorf("awskms: new signer: %q is not an account (G…) address: %w", address, err)
	}
	return &signer{address: address, keyID: keyID, client: client, rawPublicKey: raw}, nil
}

func (s *signer) Address() string { return s.address }

// Sign asks AWS KMS to perform EdDSA over the exact 32-byte Soroban payload,
// verifies the returned raw Ed25519 signature locally, and only then builds
// the classic account signature ScVal.
func (s *signer) Sign(ctx context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("awskms: sign: %w", err)
	}
	out, err := s.client.Sign(ctx, &kms.SignInput{
		KeyId:       &s.keyID,
		Message:     payload[:],
		MessageType: types.MessageTypeRaw,
		// The SDK version may not expose the newer EDDSA enum constant yet;
		// the wire value is stable and is the AWS KMS algorithm for an
		// ECC_NIST_EDWARDS key.
		SigningAlgorithm: types.SigningAlgorithmSpec("EDDSA"),
	})
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("awskms: sign: %w", err)
	}
	if out == nil || len(out.Signature) != ed25519.SignatureSize {
		got := 0
		if out != nil {
			got = len(out.Signature)
		}
		return xdr.ScVal{}, fmt.Errorf("awskms: sign: KMS returned a %d-byte signature, want %d: %w",
			got, ed25519.SignatureSize, soroauth.ErrSignatureMismatch)
	}
	if !ed25519.Verify(ed25519.PublicKey(s.rawPublicKey), payload[:], out.Signature) {
		return xdr.ScVal{}, fmt.Errorf("awskms: sign: %w", soroauth.ErrSignatureMismatch)
	}
	value, err := soroauth.Ed25519SignatureScVal(s.rawPublicKey, out.Signature)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("awskms: sign: %w", err)
	}
	return value, nil
}
