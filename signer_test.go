package soroauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// lyingKeypair signs correctly and then corrupts the result, while leaving
// Verify genuine. It is the failure the self-verification guard exists to
// catch: a signer that hands back bytes which will not verify on-chain.
type lyingKeypair struct {
	real *keypair.Full
}

func (l lyingKeypair) Address() string { return l.real.Address() }

func (l lyingKeypair) Sign(input []byte) ([]byte, error) {
	signature, err := l.real.Sign(input)
	if err != nil {
		return nil, err
	}
	signature[0] ^= 0xff
	return signature, nil
}

func (l lyingKeypair) Verify(input, signature []byte) error {
	return l.real.Verify(input, signature)
}

// accountSignaturePart is one decoded {public_key, signature} map.
type accountSignaturePart struct {
	publicKey []byte
	signature []byte
}

// decodeAccountSignature asserts the built-in account signature shape and
// returns its parts. It checks the structure the host will decode rather than
// trusting the constructor that built it.
func decodeAccountSignature(t *testing.T, value xdr.ScVal) []accountSignaturePart {
	t.Helper()

	if value.Type != xdr.ScValTypeScvVec {
		t.Fatalf("signature is %v, want a vector", value.Type)
	}
	if value.Vec == nil || *value.Vec == nil {
		t.Fatal("signature vector is nil")
	}

	parts := make([]accountSignaturePart, 0, len(**value.Vec))
	for i, element := range **value.Vec {
		if element.Type != xdr.ScValTypeScvMap {
			t.Fatalf("element %d is %v, want a map", i, element.Type)
		}
		if element.Map == nil || *element.Map == nil {
			t.Fatalf("element %d has a nil map", i)
		}
		entries := **element.Map
		if len(entries) != 2 {
			t.Fatalf("element %d has %d map entries, want 2", i, len(entries))
		}

		var part accountSignaturePart
		wantKeys := []string{"public_key", "signature"}
		for j, entry := range entries {
			if entry.Key.Type != xdr.ScValTypeScvSymbol || entry.Key.Sym == nil {
				t.Fatalf("element %d key %d is %v, want a symbol", i, j, entry.Key.Type)
			}
			// Map entries must be in key order; the host reads them as a
			// struct, and an ScMap is required to be sorted.
			if got := string(*entry.Key.Sym); got != wantKeys[j] {
				t.Fatalf("element %d key %d is %q, want %q", i, j, got, wantKeys[j])
			}
			if entry.Val.Type != xdr.ScValTypeScvBytes || entry.Val.Bytes == nil {
				t.Fatalf("element %d value %d is %v, want bytes", i, j, entry.Val.Type)
			}
			if j == 0 {
				part.publicKey = []byte(*entry.Val.Bytes)
			} else {
				part.signature = []byte(*entry.Val.Bytes)
			}
		}

		if len(part.publicKey) != ed25519.PublicKeySize {
			t.Fatalf("element %d public key is %d bytes, want %d", i, len(part.publicKey), ed25519.PublicKeySize)
		}
		if len(part.signature) != ed25519.SignatureSize {
			t.Fatalf("element %d signature is %d bytes, want %d", i, len(part.signature), ed25519.SignatureSize)
		}
		parts = append(parts, part)
	}
	return parts
}

func testPayload(label string) [32]byte {
	var payload [32]byte
	copy(payload[:], label)
	return payload
}

func TestEd25519SignerProducesTheAccountSignatureShape(t *testing.T) {
	kp := testKeypair(t, "soroauth-signer-ed25519")
	signer := NewEd25519Signer(kp)

	if got := signer.Address(); got != kp.Address() {
		t.Errorf("Address is %q, want %q", got, kp.Address())
	}

	payload := testPayload("soroauth-signer-payload")
	value, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatalf("Sign returned an unexpected error: %v", err)
	}

	// The value goes into a credential node, so it must be legal XDR.
	if _, err := value.MarshalBinary(); err != nil {
		t.Fatalf("marshaling signature ScVal failed: %v", err)
	}

	parts := decodeAccountSignature(t, value)
	if len(parts) != 1 {
		t.Fatalf("got %d signatures, want 1", len(parts))
	}

	wantKey, err := rawEd25519Key(kp.Address())
	if err != nil {
		t.Fatalf("decoding the test public key: %v", err)
	}
	if !bytes.Equal(parts[0].publicKey, wantKey) {
		t.Errorf("public key\n want %x\n  got %x", wantKey, parts[0].publicKey)
	}

	// The signature must actually verify against the payload that was signed.
	if err := kp.Verify(payload[:], parts[0].signature); err != nil {
		t.Errorf("the returned signature does not verify against the payload: %v", err)
	}
}

func TestEd25519SignerRejectsItsOwnBadSignature(t *testing.T) {
	kp := testKeypair(t, "soroauth-signer-ed25519")
	signer := &ed25519Signer{kp: lyingKeypair{real: kp}}

	got, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("soroauth-signer-payload"))
	if err == nil {
		t.Fatalf("Sign accepted a corrupted signature, returning %+v", got)
	}
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("error %q does not match ErrSignatureMismatch", err)
	}
	if got != (xdr.ScVal{}) {
		t.Error("Sign returned a value alongside an error")
	}
}

func TestEd25519SignerWithoutAKeypair(t *testing.T) {
	signer := NewEd25519Signer(nil)

	if got := signer.Address(); got != "" {
		t.Errorf("Address is %q, want an empty string", got)
	}

	got, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("x"))
	if err == nil {
		t.Fatalf("Sign succeeded without a keypair, returning %+v", got)
	}
	if !errors.Is(err, ErrMissingSigner) {
		t.Errorf("error %q does not match ErrMissingSigner", err)
	}
}

func TestSignersHonourContextCancellation(t *testing.T) {
	kp := testKeypair(t, "soroauth-signer-ed25519")
	multi, err := NewAccountMultiSigner(kp.Address(), kp)
	if err != nil {
		t.Fatalf("building the multi signer: %v", err)
	}

	passkeyAuthData := make([]byte, 37)
	passkeyAuthData[32] = 0x01
	passkeySigner := NewPasskeySigner(kp.Address(), passkeyAuthData, func(ctx context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
		if err := ctx.Err(); err != nil {
			return xdr.ScVal{}, err
		}
		return scBytes([]byte("sig")),
			nil
	}, RequireUserPresence(true))

	signers := map[string]Signer{
		"ed25519":  NewEd25519Signer(kp),
		"multisig": multi,
		"passkey":  passkeySigner,
		"func": SignerFunc(kp.Address(), func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
			t.Error("the callback ran despite a cancelled context")
			return xdr.ScVal{}, nil
		}),
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for name, signer := range signers {
		t.Run(name, func(t *testing.T) {
			if _, err := signer.Sign(ctx, xdr.HashIdPreimage{}, testPayload("x")); !errors.Is(err, context.Canceled) {
				t.Errorf("error %v does not match context.Canceled", err)
			}
		})
	}
}

func TestSignerContextCancellationIntegration(t *testing.T) {
	importNetListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("skipping TCP integration test: %v", err)
	}
	defer importNetListener.Close()

	go func() {
		for {
			conn, err := importNetListener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	addr := importNetListener.Addr().String()
	signer := SignerFunc("G...", func(ctx context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
		d := &net.Dialer{}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return xdr.ScVal{}, err
		}
		defer conn.Close()
		return scBytes([]byte("ok")),
			nil
	})

	_, err = signer.Sign(ctx, xdr.HashIdPreimage{}, testPayload("integration"))
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled from cancelled TCP integration signer, got %v", err)
	}
}

func TestAccountMultiSignerOrdersKeysAscending(t *testing.T) {
	account := testKeypair(t, "soroauth-multisig-account")
	// Deliberately unsorted input, and an account whose own key is not among
	// the signers, which a Stellar account is free to do.
	kps := []*keypair.Full{
		testKeypair(t, "soroauth-multisig-key-3"),
		testKeypair(t, "soroauth-multisig-key-1"),
		testKeypair(t, "soroauth-multisig-key-2"),
	}

	signer, err := NewAccountMultiSigner(account.Address(), kps...)
	if err != nil {
		t.Fatalf("NewAccountMultiSigner returned an unexpected error: %v", err)
	}
	if got := signer.Address(); got != account.Address() {
		t.Errorf("Address is %q, want the account %q", got, account.Address())
	}

	payload := testPayload("soroauth-multisig-payload")
	value, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatalf("Sign returned an unexpected error: %v", err)
	}
	if _, err := value.MarshalBinary(); err != nil {
		t.Fatalf("signature does not marshal: %v", err)
	}

	parts := decodeAccountSignature(t, value)
	if len(parts) != len(kps) {
		t.Fatalf("got %d signatures, want %d", len(parts), len(kps))
	}

	for i := 1; i < len(parts); i++ {
		if bytes.Compare(parts[i-1].publicKey, parts[i].publicKey) >= 0 {
			t.Errorf("public keys are not strictly ascending at %d:\n %x\n %x",
				i, parts[i-1].publicKey, parts[i].publicKey)
		}
	}

	// Every key must have signed, and each signature must verify.
	byKey := map[string]*keypair.Full{}
	for _, kp := range kps {
		raw, err := rawEd25519Key(kp.Address())
		if err != nil {
			t.Fatalf("decoding a test public key: %v", err)
		}
		byKey[string(raw)] = kp
	}
	for i, part := range parts {
		kp, ok := byKey[string(part.publicKey)]
		if !ok {
			t.Fatalf("signature %d is from an unexpected key %x", i, part.publicKey)
		}
		if err := kp.Verify(payload[:], part.signature); err != nil {
			t.Errorf("signature %d does not verify: %v", i, err)
		}
		delete(byKey, string(part.publicKey))
	}
	if len(byKey) != 0 {
		t.Errorf("%d keys did not sign", len(byKey))
	}
}

func TestAccountMultiSignerRejects(t *testing.T) {
	account := testKeypair(t, "soroauth-multisig-account").Address()
	kp := testKeypair(t, "soroauth-multisig-key-1")

	tooMany := make([]*keypair.Full, 0, maxAccountSignatures+1)
	for i := 0; i <= maxAccountSignatures; i++ {
		tooMany = append(tooMany, testKeypair(t, fmt.Sprintf("soroauth-multisig-bulk-%d", i)))
	}

	tests := []struct {
		name    string
		account string
		kps     []*keypair.Full
		wantErr error
		wantMsg string
	}{
		{
			name:    "no keys",
			account: account,
			kps:     nil,
			wantErr: ErrMissingSigner,
		},
		{
			name:    "a nil key",
			account: account,
			kps:     []*keypair.Full{kp, nil},
			wantErr: ErrMissingSigner,
			wantMsg: "key 1 is nil",
		},
		{
			name:    "more keys than the host accepts",
			account: account,
			kps:     tooMany,
			wantErr: ErrTooManySignatures,
			wantMsg: "at most 20",
		},
		{
			name:    "duplicate key",
			account: account,
			kps:     []*keypair.Full{kp, testKeypair(t, "soroauth-multisig-key-2"), kp},
			wantMsg: "duplicate signing key",
		},
		{
			name:    "contract address as the account",
			account: testContractAddress(t, "soroauth-multisig-contract"),
			kps:     []*keypair.Full{kp},
			wantMsg: "is not an account (G…) address",
		},
		{
			name:    "malformed account",
			account: "not-an-address",
			kps:     []*keypair.Full{kp},
			wantMsg: "is not an account (G…) address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewAccountMultiSigner(tt.account, tt.kps...)
			if err == nil {
				t.Fatalf("NewAccountMultiSigner succeeded, returning %+v", got)
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error %q does not match the expected sentinel %q", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if got != nil {
				t.Error("NewAccountMultiSigner returned a signer alongside an error")
			}
		})
	}
}

func TestAccountMultiSignerRejectsItsOwnBadSignature(t *testing.T) {
	account := testKeypair(t, "soroauth-multisig-account").Address()
	good := testKeypair(t, "soroauth-multisig-key-1")
	liar := lyingKeypair{real: testKeypair(t, "soroauth-multisig-key-2")}

	signer, err := newAccountMultiSigner(account, good, liar)
	if err != nil {
		t.Fatalf("newAccountMultiSigner returned an unexpected error: %v", err)
	}

	got, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("x"))
	if err == nil {
		t.Fatalf("Sign accepted a corrupted signature, returning %+v", got)
	}
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("error %q does not match ErrSignatureMismatch", err)
	}
	if !strings.Contains(err.Error(), liar.Address()) {
		t.Errorf("error %q does not name the offending key %s", err, liar.Address())
	}
}

func TestSignerFuncReturnsTheValueVerbatim(t *testing.T) {
	address := testContractAddress(t, "soroauth-signerfunc-contract")

	// A shape no built-in signer would produce, to prove nothing is wrapped
	// or rewritten on the way out.
	want := scBytes([]byte("a custom account's own signature format"))

	wantPayload := testPayload("soroauth-signerfunc-payload")
	wantPreimage := xdr.HashIdPreimage{
		Type:                 xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization,
		SorobanAuthorization: &xdr.HashIdPreimageSorobanAuthorization{Nonce: 7},
	}

	var sawPreimage xdr.HashIdPreimage
	var sawPayload [32]byte
	signer := SignerFunc(address, func(_ context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
		sawPreimage, sawPayload = preimage, payload
		return want, nil
	})

	if got := signer.Address(); got != address {
		t.Errorf("Address is %q, want %q", got, address)
	}

	got, err := signer.Sign(context.Background(), wantPreimage, wantPayload)
	if err != nil {
		t.Fatalf("Sign returned an unexpected error: %v", err)
	}

	gotBytes, err := got.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the returned value: %v", err)
	}
	wantBytes, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the expected value: %v", err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Errorf("value was not returned verbatim\n want %x\n  got %x", wantBytes, gotBytes)
	}

	// The callback must receive both the structure and the digest, so a
	// remote signer can inspect what it is approving.
	if sawPayload != wantPayload {
		t.Errorf("callback saw payload %x, want %x", sawPayload, wantPayload)
	}
	if sawPreimage.Type != wantPreimage.Type || sawPreimage.SorobanAuthorization.Nonce != 7 {
		t.Errorf("callback saw preimage %+v, want the one passed in", sawPreimage)
	}
}

func TestSignerFuncPropagatesErrors(t *testing.T) {
	sentinel := errors.New("the remote signer refused")
	signer := SignerFunc("G...", func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
		return xdr.ScVal{}, sentinel
	})

	if _, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("x")); !errors.Is(err, sentinel) {
		t.Errorf("error %v does not wrap the callback's error", err)
	}
}

func TestSignerRetryPolicy(t *testing.T) {
	// Test successful recovery after transient transport errors
	address := testContractAddress(t, "soroauth-retry-contract")
	var attempts int
	transportErr := errors.New("connection reset by peer")

	signer := WithRetry(SignerFunc(address, func(_ context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
		attempts++
		if attempts < 3 {
			return xdr.ScVal{}, transportErr
		}
		return scBytes([]byte("success")), nil
	}), RetryConfig{
		Attempts:       3,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
	})

	val, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("x"))
	if err != nil {
		t.Fatalf("Sign returned unexpected error: %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
	if val.Type == xdr.ScValTypeScvVoid {
		t.Error("returned ScVal is empty")
	}

	// Test that signature rejections are NEVER retried
	var rejectionAttempts int
	rejectionErr := fmt.Errorf("%w: bad sig", ErrSignatureMismatch)
	rejectionSigner := WithRetry(SignerFunc(address, func(_ context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
		rejectionAttempts++
		return xdr.ScVal{}, rejectionErr
	}), RetryConfig{
		Attempts:       5,
		InitialBackoff: 1 * time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
	})

	_, err = rejectionSigner.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("x"))
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("error %v does not wrap ErrSignatureMismatch", err)
	}
	if rejectionAttempts != 1 {
		t.Errorf("rejectionAttempts = %d, want 1; signature rejection must not be retried", rejectionAttempts)
	}

	// Test context cancellation wins over pending retry
	cancelAttempts := 0
	ctx, cancel := context.WithCancel(context.Background())
	cancelSigner := WithRetry(SignerFunc(address, func(_ context.Context, _ xdr.HashIdPreimage, _ [32]byte) (xdr.ScVal, error) {
		cancelAttempts++
		cancel()
		return xdr.ScVal{}, transportErr
	}), RetryConfig{
		Attempts:       5,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
	})

	_, err = cancelSigner.Sign(ctx, xdr.HashIdPreimage{}, testPayload("x"))
	if err == nil {
		t.Fatal("Sign succeeded despite context cancellation")
	}
	if cancelAttempts != 1 {
		t.Errorf("cancelAttempts = %d, want 1; should stop after context cancellation", cancelAttempts)
	}
}

func TestSignerRetryIntegration(t *testing.T) {
	var attempts int
	retrySigner := WithRetry(SignerFunc("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
		attempts++
		if attempts < 3 {
			return xdr.ScVal{}, errors.New("transient")
		}
		return scBytes([]byte("ok")),
			nil
	}), RetryConfig{
		Attempts:       3,
		InitialBackoff: time.Millisecond,
		MaxBackoff:     10 * time.Millisecond,
	})

	val, err := retrySigner.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("x"))
	if err != nil {
		t.Fatalf("Sign unexpected error: %v", err)
	}
	if attempts != 3 {
		t.Errorf("attempts = %d, want 3", attempts)
	}
	if val.Type == xdr.ScValTypeScvVoid {
		t.Error("returned ScVal is empty")
	}
}

func TestSignerFuncWithoutACallback(t *testing.T) {
	got, err := SignerFunc("G...", nil).Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("x"))
	if err == nil {
		t.Fatalf("Sign succeeded without a callback, returning %+v", got)
	}
	if !errors.Is(err, ErrMissingSigner) {
		t.Errorf("error %q does not match ErrMissingSigner", err)
	}
}

func TestPasskeySignerFlags(t *testing.T) {
	validAuthData := func(flags byte) []byte {
		var buf [37]byte
		buf[32] = flags
		return buf[:]
	}

	dummyScVal := scBytes([]byte("passkey-sig"))

	tests := []struct {
		name        string
		authData    []byte
		opts        []PasskeySignerOption
		wantErr     bool
		errContains string
	}{
		{

			name:     "no flags required, empty auth data ok",
			authData: nil,
			opts:     nil,
			wantErr:  false,
		},
		{
			name:     "require UP, flag set (0x01)",
			authData: validAuthData(0x01),
			opts:     []PasskeySignerOption{RequireUserPresence(true)},
			wantErr:  false,
		},
		{
			name:        "require UP, flag missing (0x00)",
			authData:    validAuthData(0x00),
			opts:        []PasskeySignerOption{RequireUserPresence(true)},
			wantErr:     true,
			errContains: "user presence (UP) required",
		},
		{
			name:     "require UV, flag set (0x04)",
			authData: validAuthData(0x04),
			opts:     []PasskeySignerOption{RequireUserVerification(true)},
			wantErr:  false,
		},
		{
			name:        "require UV, flag missing (0x01)",
			authData:    validAuthData(0x01),
			opts:        []PasskeySignerOption{RequireUserVerification(true)},
			wantErr:     true,
			errContains: "user verification (UV) required",
		},
		{
			name:     "require both UP and UV, both set (0x05)",
			authData: validAuthData(0x05),
			opts:     []PasskeySignerOption{RequireUserPresence(true), RequireUserVerification(true)},
			wantErr:  false,
		},
		{
			name:        "require both UP and UV, only UP set (0x01)",
			authData:    validAuthData(0x01),
			opts:        []PasskeySignerOption{RequireUserPresence(true), RequireUserVerification(true)},
			wantErr:     true,
			errContains: "user verification (UV) required",
		},
		{
			name:        "fail closed on short auth data",
			authData:    []byte{0x01, 0x02},
			opts:        []PasskeySignerOption{RequireUserPresence(true)},
			wantErr:     true,
			errContains: "authenticatorData too short",
		},
		{
			name:        "fail closed on nil auth data when required",
			authData:    nil,
			opts:        []PasskeySignerOption{RequireUserPresence(true)},
			wantErr:     true,
			errContains: "authenticatorData too short",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer := NewPasskeySigner("G...", tt.authData, func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
				return dummyScVal, nil
			}, tt.opts...)

			_, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("x"))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Sign() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("error %q does not contain %q", err, tt.errContains)
			}
		})
	}
}

// TestEd25519SignatureScVal proves the exported builder produces byte-identical
// output to NewEd25519Signer for the same key and payload, so an external
// signer adapter can use it without the shape drifting from the in-process one.
func TestEd25519SignatureScVal(t *testing.T) {
	kp := testKeypair(t, "soroauth-scval-builder")
	raw, err := rawEd25519Key(kp.Address())
	if err != nil {
		t.Fatalf("rawEd25519Key: %v", err)
	}
	payload := testPayload("scval")
	signature, err := kp.Sign(payload[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	got, err := Ed25519SignatureScVal(raw, signature)
	if err != nil {
		t.Fatalf("Ed25519SignatureScVal: %v", err)
	}

	want, err := NewEd25519Signer(kp).Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatalf("NewEd25519Signer.Sign: %v", err)
	}
	gotBytes, err := got.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the built ScVal: %v", err)
	}
	wantBytes, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("marshalling the signer's ScVal: %v", err)
	}
	if !bytes.Equal(gotBytes, wantBytes) {
		t.Error("Ed25519SignatureScVal output differs from NewEd25519Signer output")
	}

	for _, tt := range []struct {
		name string
		pub  []byte
		sig  []byte
	}{
		{"short public key", raw[:31], signature},
		{"long public key", append(append([]byte{}, raw...), 0), signature},
		{"short signature", raw, signature[:63]},
		{"long signature", raw, append(append([]byte{}, signature...), 0)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Ed25519SignatureScVal(tt.pub, tt.sig); err == nil {
				t.Error("Ed25519SignatureScVal accepted a wrong-length value, want an error")
			}
		})
	}
}
