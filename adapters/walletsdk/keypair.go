package walletsdk

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
	"reflect"
)

// isNilKeypair reports whether kp is nil, or holds a nil pointer.
//
// The second case matters: a nil *keypair.Full inside a non-nil interface is
// not caught by a plain nil check, and every method on it would panic. Since
// NewSigner has an error to return, it can refuse both.
// Keypair is the signing and verification half of an ed25519 keypair, in the
// shape a wallet SDK provides it.
//
// *coins/stellar/keypair.Full from github.com/okx/go-wallet-sdk satisfies it as
// it stands: Address, Sign([]byte) ([]byte, error) and
// Verify([]byte, []byte) error are three of the methods on its KP interface.
//
// It is deliberately three methods wide. A wallet SDK that can hand out an
// address and sign and verify 32 bytes can be adopted through NewSigner without
// an adapter written against its concrete types.
type Keypair interface {
	// Address is the G… account address the signature belongs to. It is the
	// address whose credential nodes the signature is written onto, so a
	// C… address is rejected by NewSigner.
	Address() string

	// Sign returns the raw 64-byte ed25519 signature over input. input is the
	// 32-byte payload hash, which is what the host verifies against.
	Sign(input []byte) ([]byte, error)

	// Verify reports whether signature is a valid signature over input by the
	// key behind Address. The host's built-in account contract verifies exactly
	// this, so a keypair that cannot verify what it signed is not usable here.
	Verify(input, signature []byte) error
}

// isNilKeypair reports whether kp is nil, or holds a nil pointer.
//
// The second case matters: a nil *keypair.Full inside a non-nil interface is
// not caught by a plain nil check, and every method on it would panic. Since
// NewSigner has an error to return, it can refuse both.
func isNilKeypair(kp Keypair) bool {
	if kp == nil {
		return true
	}
	value := reflect.ValueOf(kp)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Ptr, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// scSymbol builds an ScVal symbol, the type contract map keys must use.
func scSymbol(s string) xdr.ScVal {
	symbol := xdr.ScSymbol(s)
	return xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &symbol}
}

// scBytes builds an ScVal byte string.
func scBytes(b []byte) xdr.ScVal {
	value := xdr.ScBytes(b)
	return xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &value}
}

// scVec builds an ScVal vector.
func scVec(values ...xdr.ScVal) xdr.ScVal {
	vec := xdr.ScVec(values)
	p := &vec
	return xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &p}
}

// accountSignature builds the single {public_key, signature} map that the host
// decodes as one AccountEd25519Signature.
//
// The host's struct is
//
//	pub(crate) struct AccountEd25519Signature {
//	    pub(crate) public_key: BytesN<32>,
//	    pub(crate) signature: BytesN<64>,
//	}
//
// (rs-soroban-env soroban-env-host 27.0.1,
// src/builtin_contracts/account_contract.rs:64). Keys are symbols, and the
// entries are written in key order — "public_key" before "signature" — because
// an ScMap is required to be sorted by key.
//
// This is a second copy of the encoding soroauth.NewEd25519Signer performs. It
// is kept honest by TestSignerMatchesNewEd25519Signer, which asserts the ScVals
// the two paths produce for the same key and payload are byte-identical; that
// assertion is the reason this duplication is acceptable rather than a drift
// risk.
func accountSignature(rawPublicKey, signature []byte) xdr.ScVal {
	m := xdr.ScMap{
		{Key: scSymbol("public_key"), Val: scBytes(rawPublicKey)},
		{Key: scSymbol("signature"), Val: scBytes(signature)},
	}
	p := &m
	return xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &p}
}

// rawEd25519Key returns the 32 raw public key bytes behind a G… address.
func rawEd25519Key(address string) ([]byte, error) {
	raw, err := strkey.Decode(strkey.VersionByteAccountID, address)
	if err != nil {
		return nil, fmt.Errorf("%q is not an account (G…) address: %w", address, err)
	}
	return raw, nil
}

// walletSigner is a soroauth.Signer backed by a Keypair.
type walletSigner struct {
	kp      Keypair
	address string
	raw     []byte
}

// NewSigner adapts a wallet SDK keypair into a soroauth.Signer.
//
// The Signer it returns produces the built-in account signature shape: a vector
// holding one {public_key, signature} map, which is what a classic Stellar
// account's __check_auth decodes. That shape is not verified by the library
// that consumes it, so this one verifies its own signature against the payload
// before returning it, the way soroauth.NewEd25519Signer does: one verification
// is cheap compared to a damaged key or a faulty SDK producing a signature that
// is only discovered on-chain, after fees are paid.
//
// A keypair whose signing key does not match its address, or an address that is
// not a G… account, is refused here rather than at submission.
func NewSigner(kp Keypair) (soroauth.Signer, error) {
	if isNilKeypair(kp) {
		return nil, fmt.Errorf("walletsdk: new signer: %w", soroauth.ErrMissingSigner)
	}
	address := kp.Address()
	raw, err := rawEd25519Key(address)
	if err != nil {
		return nil, fmt.Errorf("walletsdk: new signer: %w", err)
	}
	return &walletSigner{kp: kp, address: address, raw: raw}, nil
}

func (s *walletSigner) Address() string { return s.address }

// Sign signs the payload hash and returns the account signature vector.
//
// ctx is checked before the keypair is touched and is not passed on: a wallet
// SDK's Sign takes only the bytes to sign, so there is nothing downstream for a
// context to reach. Checking it here still matters, because it means a cancelled
// context fails closed without the keypair being asked to sign anything.
func (s *walletSigner) Sign(ctx context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("walletsdk: sign: %w", err)
	}

	signature, err := s.kp.Sign(payload[:])
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("walletsdk: sign %s: %w", s.address, err)
	}
	if len(signature) != ed25519.SignatureSize {
		return xdr.ScVal{}, fmt.Errorf("walletsdk: sign %s: %d-byte signature, want %d: %w",
			s.address, len(signature), ed25519.SignatureSize, soroauth.ErrSignatureMismatch)
	}
	if err := s.kp.Verify(payload[:], signature); err != nil {
		return xdr.ScVal{}, fmt.Errorf("walletsdk: sign %s: %w", s.address, soroauth.ErrSignatureMismatch)
	}

	return scVec(accountSignature(s.raw, signature)), nil
}
