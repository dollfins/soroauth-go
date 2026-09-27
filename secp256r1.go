package soroauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/stellar/go-stellar-sdk/xdr"
)

const (
	// Secp256r1PublicKeySize is the size of an uncompressed SEC1 P-256 key:
	// 0x04 followed by the fixed-width X and Y coordinates.
	Secp256r1PublicKeySize = 65
	// Secp256r1SignatureSize is the fixed-width r || s representation used by
	// the passkey signature ScVal (32 bytes for each scalar).
	Secp256r1SignatureSize = 64
)

// SignSecp256r1 signs an already-hashed 32-byte payload with a P-256 key.
// It returns the fixed-width raw r || s representation used by
// Secp256r1SignatureScVal. The low-S form is always emitted so one logical
// signature has one wire representation.
func SignSecp256r1(privateKey *ecdsa.PrivateKey, payload [32]byte) ([]byte, error) {
	if !validP256PrivateKey(privateKey) {
		return nil, fmt.Errorf("soroauth: secp256r1 sign: invalid P-256 private key")
	}
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, payload[:])
	if err != nil {
		return nil, fmt.Errorf("soroauth: secp256r1 sign: %w", err)
	}
	s = normalizeP256LowS(s, privateKey.Curve.Params().N)
	return marshalSecp256r1Signature(r, s), nil
}

// VerifySecp256r1 verifies a fixed-width raw r || s P-256 signature over an
// already-hashed 32-byte payload. High-S signatures are rejected instead of
// silently normalised, which prevents two encodings of the same signature
// being accepted by different consumers.
func VerifySecp256r1(publicKey *ecdsa.PublicKey, payload [32]byte, signature []byte) error {
	if !validP256PublicKey(publicKey) {
		return fmt.Errorf("soroauth: secp256r1 verify: invalid P-256 public key")
	}
	r, s, err := ParseSecp256r1Signature(signature)
	if err != nil {
		return fmt.Errorf("soroauth: secp256r1 verify: %w", err)
	}
	if s.Cmp(new(big.Int).Rsh(new(big.Int).Set(publicKey.Curve.Params().N), 1)) > 0 {
		return fmt.Errorf("soroauth: secp256r1 verify: high-S signature: %w", ErrSignatureMismatch)
	}
	if !ecdsa.Verify(publicKey, payload[:], r, s) {
		return fmt.Errorf("soroauth: secp256r1 verify: %w", ErrSignatureMismatch)
	}
	return nil
}

// ParseSecp256r1Signature parses the raw fixed-width r || s format.
func ParseSecp256r1Signature(signature []byte) (*big.Int, *big.Int, error) {
	if len(signature) != Secp256r1SignatureSize {
		return nil, nil, fmt.Errorf("signature is %d bytes, want %d", len(signature), Secp256r1SignatureSize)
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	n := elliptic.P256().Params().N
	if r.Sign() <= 0 || r.Cmp(n) >= 0 || s.Sign() <= 0 || s.Cmp(n) >= 0 {
		return nil, nil, errors.New("signature scalars are outside the P-256 range")
	}
	return r, s, nil
}

// Secp256r1SignatureScVal builds the sorted symbol-keyed passkey signature
// map used by a custom Soroban account: {public_key: bytes, signature: bytes}.
// The public key is uncompressed SEC1 and the signature is raw low-S r || s.
func Secp256r1SignatureScVal(publicKey *ecdsa.PublicKey, signature []byte) (xdr.ScVal, error) {
	if !validP256PublicKey(publicKey) {
		return xdr.ScVal{}, errors.New("soroauth: secp256r1 signature scval: invalid P-256 public key")
	}
	if _, _, err := ParseSecp256r1Signature(signature); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: secp256r1 signature scval: %w", err)
	}
	publicBytes := elliptic.Marshal(elliptic.P256(), publicKey.X, publicKey.Y)
	return xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: mapPtr(xdr.ScMap{
		{Key: scSymbol("public_key"), Val: scBytes(publicBytes)},
		{Key: scSymbol("signature"), Val: scBytes(signature)},
	})}, nil
}

func mapPtr(value xdr.ScMap) **xdr.ScMap {
	p := &value
	return &p
}

func marshalSecp256r1Signature(r, s *big.Int) []byte {
	result := make([]byte, Secp256r1SignatureSize)
	r.FillBytes(result[:32])
	s.FillBytes(result[32:])
	return result
}

func normalizeP256LowS(s, order *big.Int) *big.Int {
	result := new(big.Int).Set(s)
	half := new(big.Int).Rsh(new(big.Int).Set(order), 1)
	if result.Cmp(half) > 0 {
		result.Sub(order, result)
	}
	return result
}

func validP256PrivateKey(key *ecdsa.PrivateKey) bool {
	return key != nil && key.Curve == elliptic.P256() && key.D != nil &&
		key.D.Sign() > 0 && key.D.Cmp(key.Curve.Params().N) < 0 && validP256PublicKey(&key.PublicKey)
}

func validP256PublicKey(key *ecdsa.PublicKey) bool {
	return key != nil && key.Curve == elliptic.P256() && key.X != nil && key.Y != nil &&
		key.Curve.IsOnCurve(key.X, key.Y)
}
