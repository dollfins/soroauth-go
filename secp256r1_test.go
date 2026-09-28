package soroauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"

	"github.com/stellar/go-stellar-sdk/xdr"
)

func testP256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	x, y := elliptic.P256().ScalarBaseMult([]byte{1})
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y},
		D:         big.NewInt(1),
	}
}

func TestSecp256r1SignAndVerify(t *testing.T) {
	key := testP256Key(t)
	payload := sha256.Sum256([]byte("passkey payload"))
	signature, err := SignSecp256r1(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(signature) != Secp256r1SignatureSize {
		t.Fatalf("signature length = %d, want %d", len(signature), Secp256r1SignatureSize)
	}
	_, s, err := ParseSecp256r1Signature(signature)
	if err != nil {
		t.Fatal(err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)) > 0 {
		t.Fatal("SignSecp256r1 returned a high-S signature")
	}
	if err := VerifySecp256r1(&key.PublicKey, payload, signature); err != nil {
		t.Fatalf("VerifySecp256r1: %v", err)
	}

	wrongPayload := sha256.Sum256([]byte("different payload"))
	if err := VerifySecp256r1(&key.PublicKey, wrongPayload, signature); !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("wrong payload error = %v, want ErrSignatureMismatch", err)
	}
}

func TestSecp256r1RejectsHighSAndMalformedSignatures(t *testing.T) {
	key := testP256Key(t)
	payload := sha256.Sum256([]byte("passkey payload"))
	signature, err := SignSecp256r1(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	r, s, err := ParseSecp256r1Signature(signature)
	if err != nil {
		t.Fatal(err)
	}
	highS := new(big.Int).Sub(elliptic.P256().Params().N, s)
	high := marshalSecp256r1Signature(r, highS)
	if err := VerifySecp256r1(&key.PublicKey, payload, high); !errors.Is(err, ErrSignatureMismatch) {
		t.Errorf("high-S error = %v, want ErrSignatureMismatch", err)
	}
	for _, malformed := range [][]byte{nil, make([]byte, 63), make([]byte, 65)} {
		if _, _, err := ParseSecp256r1Signature(malformed); err == nil {
			t.Errorf("ParseSecp256r1Signature(%d bytes) succeeded", len(malformed))
		}
	}
}

func TestSecp256r1SignatureScValUsesSortedKeysAndFixedEncoding(t *testing.T) {
	key := testP256Key(t)
	payload := sha256.Sum256([]byte("passkey payload"))
	signature, err := SignSecp256r1(key, payload)
	if err != nil {
		t.Fatal(err)
	}
	value, err := Secp256r1SignatureScVal(&key.PublicKey, signature)
	if err != nil {
		t.Fatal(err)
	}
	if value.Type != xdr.ScValTypeScvMap || value.Map == nil || *value.Map == nil {
		t.Fatalf("ScVal = %s, want map", value.Type)
	}
	entries := **value.Map
	if len(entries) != 2 {
		t.Fatalf("map entries = %d, want 2", len(entries))
	}
	if *entries[0].Key.Sym != "public_key" || *entries[1].Key.Sym != "signature" {
		t.Fatalf("map keys = %q, %q, want public_key, signature", *entries[0].Key.Sym, *entries[1].Key.Sym)
	}
	if len(*entries[0].Val.Bytes) != Secp256r1PublicKeySize || len(*entries[1].Val.Bytes) != Secp256r1SignatureSize {
		t.Fatalf("map byte lengths = %d, %d, want %d, %d", len(*entries[0].Val.Bytes), len(*entries[1].Val.Bytes), Secp256r1PublicKeySize, Secp256r1SignatureSize)
	}
}
