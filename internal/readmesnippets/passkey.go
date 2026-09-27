package readmesnippets

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// pubX and pubY stand in for the P-256 credential public key captured when
// the passkey was registered; a real caller reads them from its own storage.
var (
	pubX, pubY = new(big.Int).SetBytes([]byte("pubkey-x-placeholder")), new(big.Int).SetBytes([]byte("pubkey-y-placeholder"))
)

// PasskeyParse backs docs/passkeys.md's "Step 2" section. See Quickstart's doc
// comment for how the snippet markers relate to markdown fenced blocks. It is
// never called; it exists only to be compiled, so the guide's examples cannot
// rot. The returned signedBytes and clientDataHash are what the "Step 3"
// snippet verifies.
func PasskeyParse(payload [32]byte, assertionJSON []byte) (authData, signedBytes []byte, err error) {
	// snippet:start passkey-parse
	// The browser ceremony produced an assertion. Decode the fields WebAuthn
	// defines and nothing else; ignore unknown keys rather than trusting them.
	var assertion struct {
		Response struct {
			AuthenticatorData string `json:"authenticatorData"` // base64url, unpadded
			ClientDataJSON    string `json:"clientDataJSON"`    // base64url, unpadded
			Signature         string `json:"signature"`         // base64url, unpadded
		} `json:"response"`
	}
	if err := json.Unmarshal(assertionJSON, &assertion); err != nil {
		return nil, nil, fmt.Errorf("soroauth: decode assertion: %w", err)
	}
	rawAuthData, err := base64.RawURLEncoding.DecodeString(assertion.Response.AuthenticatorData)
	if err != nil {
		return nil, nil, fmt.Errorf("soroauth: decode authenticatorData: %w", err)
	}
	rawClientData, err := base64.RawURLEncoding.DecodeString(assertion.Response.ClientDataJSON)
	if err != nil {
		return nil, nil, fmt.Errorf("soroauth: decode clientDataJSON: %w", err)
	}
	rawSig, err := base64.RawURLEncoding.DecodeString(assertion.Response.Signature)
	if err != nil {
		return nil, nil, fmt.Errorf("soroauth: decode signature: %w", err)
	}
	if len(rawAuthData) < 37 {
		return nil, nil, fmt.Errorf("soroauth: authenticatorData is %d bytes, need at least 37", len(rawAuthData))
	}

	// The challenge-binding check. The authenticator signed
	// authenticatorData || SHA-256(clientDataJSON) (WebAuthn §6.1), and
	// clientDataJSON carries the challenge the browser was given. If that
	// challenge is not the payload this entry commits to, the assertion
	// was issued for some other ceremony and proves nothing about this
	// transaction — this is the check that stops a captured assertion from
	// being replayed against a different payload. Hash the received
	// clientDataJSON and compare against the payload being authorized;
	// never read a challenge field out of the JSON and hash that instead,
	// or an attacker who controls the JSON picks both sides of the compare.
	clientDataHash := sha256.Sum256(rawClientData)
	if !bytes.Equal(payload[:], clientDataHash[:]) {
		return nil, nil, soroauth.ErrSignatureMismatch
	}

	// User presence (UP, bit 0) and user verification (UV, bit 2) live in
	// authenticatorData's flags byte, byte index 32 (WebAuthn §6.1). A
	// software authenticator can produce an assertion with neither set, so
	// anything that moves value should require both. NewPasskeySigner
	// enforces the same bits again at Sign time; checking here fails before
	// the signer is ever invoked.
	flags := rawAuthData[32]
	if flags&0x01 == 0 {
		return nil, nil, errors.New("soroauth: user presence (UP) not set in assertion")
	}
	if flags&0x04 == 0 {
		return nil, nil, errors.New("soroauth: user verification (UV) not set in assertion")
	}
	_ = rawSig // the DER-encoded assertion signature; see "Step 3"
	// snippet:end passkey-parse

	signedBytes = append(append([]byte{}, rawAuthData...), clientDataHash[:]...)
	return rawAuthData, signedBytes, nil
}

// PasskeySignExample backs docs/passkeys.md's "Step 3" section. The parts the
// caller already has stand in as parameters: the credential public key stored
// at registration, the decoded assertion pieces from PasskeyParse, and the
// assertion signature's raw (r, s) halves — DER parsing is deliberately out of
// scope here; parse it at the WebAuthn boundary before using the P-256
// primitives below.
func PasskeySignExample(
	ctx context.Context,
	entry xdr.SorobanAuthorizationEntry,
	walletAddress string,
	validUntilLedger uint32,
	networkPassphrase string,
	authData, clientDataJSON []byte,
	sigR, sigS [32]byte,
) (xdr.SorobanAuthorizationEntry, error) {
	// snippet:start passkey-sign
	// The signature is over the signed bytes — authenticatorData followed by
	// SHA-256(clientDataJSON) — not over the payload alone (WebAuthn §6.1).
	clientDataHash := sha256.Sum256(clientDataJSON)
	signed := append(append([]byte{}, authData...), clientDataHash[:]...)

	// The credential public key captured when the passkey was registered;
	// ES256 means P-256 (WebAuthn §5.8.2, "Requirements for ES256").
	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: pubX, Y: pubY}
	r := new(big.Int).SetBytes(sigR[:])
	s := new(big.Int).SetBytes(sigS[:])
	if !ecdsa.Verify(pub, signed, r, s) {
		return xdr.SorobanAuthorizationEntry{}, soroauth.ErrSignatureMismatch
	}

	// The ScVal this guide's example wallet contract decodes in __check_auth.
	// The map's keys are symbols in sorted order — the host refuses an
	// unsorted ScMap as Error(Object, InvalidInput) (rs-soroban-env issue
	// #1510 records how opaque that failure is) — so a hand-rolled shape
	// fails there, on-chain, rather than here.
	pubRaw := elliptic.Marshal(elliptic.P256(), pub.X, pub.Y)
	pubVal := xdr.ScBytes(pubRaw)
	signature := make([]byte, soroauth.Secp256r1SignatureSize)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	sigVal := xdr.ScBytes(signature)
	keySym := xdr.ScSymbol("public_key")
	sigSym := xdr.ScSymbol("signature")
	m := xdr.ScMap{
		{Key: xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &keySym}, Val: xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &pubVal}},
		{Key: xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &sigSym}, Val: xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &sigVal}},
	}
	mapPtr := &m
	sigScVal := xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &mapPtr}

	// NewPasskeySigner re-checks UP and UV at Sign time and writes the ScVal
	// onto every node whose address matches the wallet's.
	signer := soroauth.NewPasskeySigner(walletAddress, authData,
		func(context.Context, xdr.HashIdPreimage, [32]byte) (xdr.ScVal, error) {
			return sigScVal, nil
		},
		soroauth.RequireUserPresence(true),
		soroauth.RequireUserVerification(true),
	)
	return soroauth.AuthorizeEntry(ctx, entry, signer, validUntilLedger,
		networkPassphrase, soroauth.ForAddress(walletAddress))
	// snippet:end passkey-sign
}
