package soroauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// testPasskeyKey derives a deterministic P-256 key from a label, the same way
// the ed25519 test keys are derived. Nothing is funded and nothing holds value;
// the point is that a failing test reproduces.
func testPasskeyKey(t *testing.T, label string) *ecdsa.PrivateKey {
	t.Helper()

	seed := sha256.Sum256([]byte(label))
	d := new(big.Int).SetBytes(seed[:])
	d.Mod(d, elliptic.P256().Params().N)
	if d.Sign() == 0 {
		t.Fatalf("derived a degenerate P-256 key for %q", label)
	}
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		D:         d,
	}
}

// testWebAuthnAssertion builds a real ES256 assertion over payload: the
// authenticator data carrying the given flags, a clientDataJSON whose challenge
// is the payload, and a DER signature over
// SHA-256(authenticatorData || SHA-256(clientDataJSON)), which is what WebAuthn
// Level 3 §6.1 has the authenticator sign and §7.2 step 21 has the relying
// party verify.
func testWebAuthnAssertion(t *testing.T, key *ecdsa.PrivateKey, payload [32]byte, flags byte) *WebAuthnAssertion {
	t.Helper()

	authenticatorData := make([]byte, authDataMinLen)
	authenticatorData[32] = flags

	challenge := base64.RawURLEncoding.EncodeToString(payload[:])
	clientData := []byte(`{"type":"webauthn.get","challenge":"` + challenge +
		`","origin":"https://wallet.example"}`)

	assertion := &WebAuthnAssertion{
		AuthenticatorData: authenticatorData,
		ClientDataJSON:    clientData,
		ChallengeString:   challenge,
	}
	digest := sha256.Sum256(assertion.SignedBytes())
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("signing the test assertion: %v", err)
	}
	assertion.Signature = der
	return assertion
}

// passkeySignatureParts is one decoded sorted {public_key, signature} map.
type passkeySignatureParts struct {
	publicKey []byte
	signature []byte
}

// decodePasskeySignature asserts the wallet signature shape and returns its
// parts, checking the structure a __check_auth would decode rather than
// trusting the builder that produced it.
func decodePasskeySignature(t *testing.T, value xdr.ScVal) passkeySignatureParts {
	t.Helper()

	if value.Type != xdr.ScValTypeScvMap || value.Map == nil || *value.Map == nil {
		t.Fatalf("signature is %v, want a map", value.Type)
	}
	entries := **value.Map
	if len(entries) != 2 {
		t.Fatalf("signature map has %d entries, want 2", len(entries))
	}

	wantKeys := []string{"public_key", "signature"}
	var parts passkeySignatureParts
	for i, entry := range entries {
		if entry.Key.Type != xdr.ScValTypeScvSymbol || entry.Key.Sym == nil {
			t.Fatalf("entry %d key is %v, want a symbol", i, entry.Key.Type)
		}
		// An ScMap must be sorted by key, and the host reads it as a struct.
		if got := string(*entry.Key.Sym); got != wantKeys[i] {
			t.Fatalf("entry %d key is %q, want %q", i, got, wantKeys[i])
		}
		if entry.Val.Type != xdr.ScValTypeScvBytes || entry.Val.Bytes == nil {
			t.Fatalf("entry %d value is %v, want bytes", i, entry.Val.Type)
		}
		if i == 0 {
			parts.publicKey = []byte(*entry.Val.Bytes)
		} else {
			parts.signature = []byte(*entry.Val.Bytes)
		}
	}
	return parts
}

// acceptingVerifier reports every signature as valid. It is the lying verifier
// the es256Verifier seam exists for: a guard tested only with correct
// signatures proves nothing about whether it is load-bearing.
type acceptingVerifier struct{}

func (acceptingVerifier) verify(*ecdsa.PublicKey, []byte, *big.Int, *big.Int) bool { return true }

func TestPasskeyAssertionSignerProducesTheWalletSignatureShape(t *testing.T) {
	key := testPasskeyKey(t, "soroauth-passkey-credential")
	wallet := testContractAddress(t, "soroauth-passkey-wallet")
	payload := testPayload("soroauth-passkey-payload")
	assertion := testWebAuthnAssertion(t, key, payload, flagUserPresent|flagUserVerified)

	signer := NewPasskeySignerFromAssertion(wallet, &key.PublicKey, assertion,
		RequireUserPresence(true), RequireUserVerification(true))
	if got := signer.Address(); got != wallet {
		t.Errorf("Address is %q, want %q", got, wallet)
	}

	value, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err != nil {
		t.Fatalf("Sign returned an unexpected error: %v", err)
	}
	// It goes into a credential node, so it must be legal XDR.
	if _, err := value.MarshalBinary(); err != nil {
		t.Fatalf("marshalling the signature ScVal: %v", err)
	}

	parts := decodePasskeySignature(t, value)

	wantPublicKey := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	if !bytes.Equal(parts.publicKey, wantPublicKey) {
		t.Errorf("public key\n want %x\n  got %x", wantPublicKey, parts.publicKey)
	}
	if len(parts.signature) != Secp256r1SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(parts.signature), Secp256r1SignatureSize)
	}

	// The returned signature must verify over exactly the bytes the assertion
	// covers, which is the whole point of reconstructing them.
	digest := sha256.Sum256(assertion.SignedBytes())
	if err := VerifySecp256r1(&key.PublicKey, digest, parts.signature); err != nil {
		t.Errorf("the returned signature does not verify over the assertion's signed bytes: %v", err)
	}
}

// TestPasskeyAssertionSignerBindsTheChallengeToThePayload proves the check that
// makes the signer safe: an assertion made for one payload cannot be attached
// to another.
func TestPasskeyAssertionSignerBindsTheChallengeToThePayload(t *testing.T) {
	key := testPasskeyKey(t, "soroauth-passkey-credential")
	wallet := testContractAddress(t, "soroauth-passkey-wallet")

	assertion := testWebAuthnAssertion(t, key, testPayload("payload it was made for"), flagUserPresent|flagUserVerified)
	signer := NewPasskeySignerFromAssertion(wallet, &key.PublicKey, assertion)

	got, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, testPayload("a different payload"))
	if err == nil {
		t.Fatalf("Sign accepted an assertion made for another payload, returning %+v", got)
	}
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("error %q does not match ErrSignatureMismatch", err)
	}
	if !errors.Is(err, ErrWebAuthnChallengeMismatch) {
		t.Errorf("error %q does not match ErrWebAuthnChallengeMismatch", err)
	}
}

// TestPasskeyAssertionSignerRejectsAForgedSignature is the self-verification
// guard: an assertion whose challenge is right but whose signature was not made
// by the credential's key must not produce a signature value.
func TestPasskeyAssertionSignerRejectsAForgedSignature(t *testing.T) {
	key := testPasskeyKey(t, "soroauth-passkey-credential")
	forger := testPasskeyKey(t, "soroauth-passkey-forger")
	wallet := testContractAddress(t, "soroauth-passkey-wallet")
	payload := testPayload("soroauth-passkey-payload")

	// The challenge binds correctly; only the signature is not the key's.
	assertion := testWebAuthnAssertion(t, forger, payload, flagUserPresent|flagUserVerified)
	signer := NewPasskeySignerFromAssertion(wallet, &key.PublicKey, assertion)

	got, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
	if err == nil {
		t.Fatalf("Sign accepted a forged assertion, returning %+v", got)
	}
	if !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("error %q does not match ErrSignatureMismatch", err)
	}

	// The guard is load-bearing rather than decorative: with a verifier that
	// accepts anything, the same forged assertion does produce a value, so the
	// check above is what stopped it.
	lying := &passkeyAssertionSigner{
		address:   wallet,
		publicKey: &key.PublicKey,
		assertion: assertion,
		verifier:  acceptingVerifier{},
	}
	if _, err := lying.Sign(context.Background(), xdr.HashIdPreimage{}, payload); err != nil {
		t.Fatalf("the accepting verifier did not reach the signing path: %v", err)
	}
}

// TestPasskeyAssertionSignerRejectsATamperedAssertionSignature covers the other
// half of the same guard: a signature whose bytes were altered no longer parses
// as DER or no longer verifies.
func TestPasskeyAssertionSignerRejectsATamperedAssertionSignature(t *testing.T) {
	key := testPasskeyKey(t, "soroauth-passkey-credential")
	wallet := testContractAddress(t, "soroauth-passkey-wallet")
	payload := testPayload("soroauth-passkey-payload")

	assertion := testWebAuthnAssertion(t, key, payload, flagUserPresent|flagUserVerified)
	assertion.Signature = append([]byte{}, assertion.Signature...)
	assertion.Signature[len(assertion.Signature)-1] ^= 0xff
	signer := NewPasskeySignerFromAssertion(wallet, &key.PublicKey, assertion)

	if _, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload); !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("error %v does not match ErrSignatureMismatch", err)
	}
}

func TestPasskeyAssertionSignerRequiresUserPresenceAndVerification(t *testing.T) {
	key := testPasskeyKey(t, "soroauth-passkey-credential")
	wallet := testContractAddress(t, "soroauth-passkey-wallet")
	payload := testPayload("soroauth-passkey-payload")

	tests := []struct {
		name   string
		flags  byte
		opts   []PasskeySignerOption
		wantUP bool
		wantUV bool
	}{
		{name: "both required, both set", flags: flagUserPresent | flagUserVerified,
			opts: []PasskeySignerOption{RequireUserPresence(true), RequireUserVerification(true)}},
		{name: "UP required, not set", flags: flagUserVerified,
			opts: []PasskeySignerOption{RequireUserPresence(true)}},
		{name: "UV required, not set", flags: flagUserPresent,
			opts: []PasskeySignerOption{RequireUserVerification(true)}},
		{name: "neither required, neither set", flags: 0,
			opts: []PasskeySignerOption{RequireUserPresence(false), RequireUserVerification(false)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assertion := testWebAuthnAssertion(t, key, payload, tt.flags)
			signer := NewPasskeySignerFromAssertion(wallet, &key.PublicKey, assertion, tt.opts...)

			_, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload)
			wantErr := (tt.flags&flagUserPresent == 0 && containsRequirement(tt.opts, true)) ||
				(tt.flags&flagUserVerified == 0 && containsRequirement(tt.opts, false))
			if wantErr {
				if !errors.Is(err, ErrVerificationFailed) {
					t.Fatalf("error %v does not match ErrVerificationFailed", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Sign returned an unexpected error: %v", err)
			}
		})
	}
}

// containsRequirement reports whether the options require user presence (up) or
// user verification.
func containsRequirement(opts []PasskeySignerOption, up bool) bool {
	cfg := passkeySignerConfig{}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	if up {
		return cfg.requireUserPresence
	}
	return cfg.requireUserVerification
}

func TestPasskeyAssertionSignerWithoutCredentials(t *testing.T) {
	key := testPasskeyKey(t, "soroauth-passkey-credential")
	wallet := testContractAddress(t, "soroauth-passkey-wallet")
	payload := testPayload("soroauth-passkey-payload")
	assertion := testWebAuthnAssertion(t, key, payload, flagUserPresent|flagUserVerified)

	t.Run("no assertion", func(t *testing.T) {
		signer := NewPasskeySignerFromAssertion(wallet, &key.PublicKey, nil)
		if _, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload); !errors.Is(err, ErrMissingSigner) {
			t.Errorf("error %v does not match ErrMissingSigner", err)
		}
	})

	t.Run("no public key", func(t *testing.T) {
		signer := NewPasskeySignerFromAssertion(wallet, nil, assertion)
		if _, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload); !errors.Is(err, ErrMissingSigner) {
			t.Errorf("error %v does not match ErrMissingSigner", err)
		}
	})

	t.Run("a key that is not P-256", func(t *testing.T) {
		p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatalf("generating a P-384 key: %v", err)
		}
		signer := NewPasskeySignerFromAssertion(wallet, &p384.PublicKey, assertion)
		if _, err := signer.Sign(context.Background(), xdr.HashIdPreimage{}, payload); !errors.Is(err, ErrVerificationFailed) {
			t.Errorf("error %v does not match ErrVerificationFailed", err)
		}
	})
}

func TestPasskeyAssertionSignerHonoursContextCancellation(t *testing.T) {
	key := testPasskeyKey(t, "soroauth-passkey-credential")
	wallet := testContractAddress(t, "soroauth-passkey-wallet")
	payload := testPayload("soroauth-passkey-payload")
	assertion := testWebAuthnAssertion(t, key, payload, flagUserPresent|flagUserVerified)

	signer := NewPasskeySignerFromAssertion(wallet, &key.PublicKey, assertion)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := signer.Sign(ctx, xdr.HashIdPreimage{}, payload); !errors.Is(err, context.Canceled) {
		t.Errorf("error %v does not match context.Canceled", err)
	}
}

// TestPasskeyAssertionSignerEndToEnd proves the signer works through the
// ordinary signing path, which is what the issue asks for: AuthorizeEntry with
// ForAddress(wallet), against an entry whose credential node carries the
// wallet's C… address.
func TestPasskeyAssertionSignerEndToEnd(t *testing.T) {
	key := testPasskeyKey(t, "soroauth-passkey-credential")
	wallet := testContractAddress(t, "soroauth-passkey-wallet")
	walletAddress, err := ParseAddress(wallet)
	if err != nil {
		t.Fatalf("parsing the wallet address: %v", err)
	}

	entry := xdr.SorobanAuthorizationEntry{
		RootInvocation: testInvocation(t),
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   walletAddress,
				Nonce:                     xdr.Int64(7),
				SignatureExpirationLedger: 0,
				Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: newScVec()},
			},
		},
	}
	const validUntil = uint32(987654)

	// The assertion is made for the payload the entry commits to, which is the
	// whole ceremony: the browser derives it, the authenticator signs it.
	preimage, err := Preimage(entry, validUntil, network.TestNetworkPassphrase)
	if err != nil {
		t.Fatalf("building the preimage: %v", err)
	}
	payload, err := Payload(preimage)
	if err != nil {
		t.Fatalf("hashing the preimage: %v", err)
	}
	assertion := testWebAuthnAssertion(t, key, payload, flagUserPresent|flagUserVerified)

	before, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("encoding the input entry: %v", err)
	}

	signer := NewPasskeySignerFromAssertion(wallet, &key.PublicKey, assertion,
		RequireUserPresence(true), RequireUserVerification(true))
	signed, err := AuthorizeEntry(context.Background(), entry, signer, validUntil,
		network.TestNetworkPassphrase, ForAddress(wallet))
	if err != nil {
		t.Fatalf("AuthorizeEntry returned an unexpected error: %v", err)
	}

	// The wallet's node carries the wallet's shape, and it verifies.
	if signed.Credentials.AddressV2 == nil {
		t.Fatal("the signed entry lost its address_v2 credentials")
	}
	parts := decodePasskeySignature(t, signed.Credentials.AddressV2.Signature)
	digest := sha256.Sum256(assertion.SignedBytes())
	if err := VerifySecp256r1(&key.PublicKey, digest, parts.signature); err != nil {
		t.Errorf("the written signature does not verify: %v", err)
	}
	// The expiration signed over is the expiration written in.
	if got := uint32(signed.Credentials.AddressV2.SignatureExpirationLedger); got != validUntil {
		t.Errorf("signature expiration is %d, want %d", got, validUntil)
	}

	// And the caller's entry is untouched.
	after, err := entry.MarshalBinary()
	if err != nil {
		t.Fatalf("re-encoding the input entry: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("AuthorizeEntry mutated its input\n before %x\n  after %x", before, after)
	}
}

func TestParseDERECDSASignature(t *testing.T) {
	key := testPasskeyKey(t, "soroauth-passkey-credential")
	digest := sha256.Sum256([]byte("soroauth DER signature"))
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	r, s, err := ParseDERECDSASignature(der)
	if err != nil {
		t.Fatalf("ParseDERECDSASignature rejected a real signature: %v", err)
	}
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Error("the parsed scalars do not verify")
	}
	// The low-S normalisation the wire form needs must still verify.
	normalised := normalizeP256LowS(s, elliptic.P256().Params().N)
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, normalised) {
		t.Error("the low-S normalised scalars do not verify")
	}

	order := elliptic.P256().Params().N
	for _, tt := range []struct {
		name      string
		signature []byte
	}{
		{name: "empty", signature: nil},
		{name: "truncated", signature: der[:len(der)-1]},
		{name: "trailing bytes", signature: append(append([]byte{}, der...), 0x00)},
		{name: "not DER at all", signature: []byte("not a signature")},
		{name: "zero scalar", signature: mustDERSignature(t, big.NewInt(0), s)},
		{name: "r at the curve order", signature: mustDERSignature(t, order, s)},
		{name: "negative s", signature: mustDERSignature(t, r, new(big.Int).Neg(s))},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := ParseDERECDSASignature(tt.signature); err == nil {
				t.Error("ParseDERECDSASignature accepted an invalid signature")
			}
		})
	}
}

// mustDERSignature encodes r and s as the DER ECDSA-Sig-Value the parser
// expects, so a bad scalar can be handed to it.
func mustDERSignature(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(struct {
		R *big.Int
		S *big.Int
	}{R: r, S: s})
	if err != nil {
		t.Fatalf("encoding a DER signature: %v", err)
	}
	return encoded
}
