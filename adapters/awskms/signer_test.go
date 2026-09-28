package awskms

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const testKeyID = "arn:aws:kms:us-east-1:123456789012:key/test-ed25519"

type fakeKMS struct {
	signature []byte
	err       error
	calls     int
	last      *kms.SignInput
}

func (f *fakeKMS) Sign(_ context.Context, in *kms.SignInput, _ ...func(*kms.Options)) (*kms.SignOutput, error) {
	f.calls++
	f.last = in
	if f.err != nil {
		return nil, f.err
	}
	return &kms.SignOutput{Signature: f.signature}, nil
}

func testKeypair(t *testing.T, label string) *keypair.Full {
	t.Helper()
	seed := sha256.Sum256([]byte(label))
	kp, err := keypair.FromRawSeed(seed)
	if err != nil {
		t.Fatalf("deriving test keypair: %v", err)
	}
	return kp
}

func TestNewSignerRejectsBadInput(t *testing.T) {
	kp := testKeypair(t, "awskms-bad-input")
	client := &fakeKMS{}
	for _, tc := range []struct {
		name    string
		address string
		keyID   string
		client  SignerClient
	}{
		{"nil client", kp.Address(), testKeyID, nil},
		{"empty key id", kp.Address(), "", client},
		{"invalid address", "not-an-account", testKeyID, client},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewSigner(tc.address, tc.keyID, tc.client); err == nil ||
				(tc.name != "invalid address" && !errors.Is(err, soroauth.ErrMissingSigner)) {
				t.Fatalf("NewSigner error = %v", err)
			}
		})
	}
}

func TestSignUsesRawEdDSAAndBuildsVerifiedAccountSignature(t *testing.T) {
	kp := testKeypair(t, "awskms-valid")
	payload := sha256.Sum256([]byte("payload"))
	signature, err := kp.Sign(payload[:])
	if err != nil {
		t.Fatal(err)
	}
	client := &fakeKMS{signature: signature}
	signer, err := NewSigner(kp.Address(), testKeyID, client)
	if err != nil {
		t.Fatal(err)
	}
	got, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != xdr.ScValTypeScvVec || got.Vec == nil {
		t.Fatalf("Sign type = %s, want vector", got.Type)
	}
	if client.calls != 1 || client.last == nil {
		t.Fatalf("KMS calls = %d, want one request", client.calls)
	}
	if client.last.KeyId == nil || *client.last.KeyId != testKeyID {
		t.Errorf("KeyId = %v, want %q", client.last.KeyId, testKeyID)
	}
	if client.last.MessageType != types.MessageTypeRaw || client.last.SigningAlgorithm != types.SigningAlgorithmSpec("EDDSA") {
		t.Errorf("KMS request algorithm/message type = %s/%s, want EDDSA raw", client.last.SigningAlgorithm, client.last.MessageType)
	}
	if string(client.last.Message) != string(payload[:]) {
		t.Error("KMS did not receive the exact payload")
	}
}

func TestSignRejectsInvalidOrDERSignature(t *testing.T) {
	kp := testKeypair(t, "awskms-invalid")
	payload := sha256.Sum256([]byte("payload"))
	for _, signature := range [][]byte{{1, 2, 3}, make([]byte, 70)} {
		signer, err := NewSigner(kp.Address(), testKeyID, &fakeKMS{signature: signature})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload); !errors.Is(err, soroauth.ErrSignatureMismatch) {
			t.Errorf("Sign(%d bytes) error = %v, want ErrSignatureMismatch", len(signature), err)
		}
	}
}

func TestSignPropagatesKMSFailureAndCancellation(t *testing.T) {
	kp := testKeypair(t, "awskms-errors")
	payload := sha256.Sum256([]byte("payload"))
	boom := errors.New("access denied")
	client := &fakeKMS{err: boom}
	signer, err := NewSigner(kp.Address(), testKeyID, client)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload); !errors.Is(err, boom) {
		t.Errorf("Sign error = %v, want %v", err, boom)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := signer.Sign(ctx, xdr.HashIdPreimage{}, payload); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled Sign error = %v, want context.Canceled", err)
	}
	if client.calls != 1 {
		t.Errorf("KMS calls after cancellation = %d, want 1", client.calls)
	}
}
