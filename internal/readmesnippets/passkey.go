package readmesnippets

import (
	"context"
	"crypto/ecdsa"
	"errors"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// PasskeyParse backs docs/passkeys.md's "Step 2" section. See Quickstart's doc
// comment for how the snippet markers relate to markdown fenced blocks. It is
// never called; it exists only to be compiled, so the guide's examples cannot
// rot.
func PasskeyParse(payload [32]byte, assertionJSON []byte) (*soroauth.WebAuthnAssertion, error) {
	// snippet:start passkey-parse
	// The assertion is untrusted input: it arrives from a browser, a network
	// hop, or a file. ParseWebAuthnAssertionForPayload decodes the fields
	// WebAuthn defines, ignores members it did not ask for, and requires that
	// the challenge the authenticator signed is the payload this entry
	// commits to. An assertion made for some other challenge belongs to a
	// different ceremony, and attaching it to this entry would authorize the
	// wrong transaction (WebAuthn Level 3, §7.2 step 11).
	assertion, err := soroauth.ParseWebAuthnAssertionForPayload(assertionJSON, payload)
	if err != nil {
		return nil, err
	}

	// User presence (UP, bit 0) and user verification (UV, bit 2) live in the
	// flags byte at index 32 of the authenticator data (WebAuthn Level 3,
	// §6.1). A software authenticator can produce an assertion with neither
	// set, so anything that moves value should require both. The signer
	// enforces the same bits again at Sign time; checking here refuses before
	// the signer is ever invoked.
	if !assertion.UserPresent() {
		return nil, errors.New("soroauth: user presence (UP) not set in assertion")
	}
	if !assertion.UserVerified() {
		return nil, errors.New("soroauth: user verification (UV) not set in assertion")
	}
	// snippet:end passkey-parse

	return assertion, nil
}

// PasskeySignExample backs docs/passkeys.md's "Step 3" section. The parts the
// caller already has stand in as parameters: the entry being authorized, the
// wallet's C… address, the credential public key captured when the passkey was
// registered, and the parsed assertion from PasskeyParse.
func PasskeySignExample(
	ctx context.Context,
	entry xdr.SorobanAuthorizationEntry,
	walletAddress string,
	validUntilLedger uint32,
	networkPassphrase string,
	publicKey *ecdsa.PublicKey,
	assertion *soroauth.WebAuthnAssertion,
) (xdr.SorobanAuthorizationEntry, error) {
	// snippet:start passkey-sign
	// NewPasskeySignerFromAssertion verifies the assertion against the payload
	// at Sign time — the challenge binding first, then the ES256 signature
	// over SHA-256(authenticatorData || SHA-256(clientDataJSON)) (WebAuthn
	// Level 3, §6.1 and §7.2 step 21) — and only then produces the signature
	// value. It cannot return a signature for an assertion that does not
	// verify, so there is no separate verification step for the caller to
	// forget.
	signer := soroauth.NewPasskeySignerFromAssertion(walletAddress, publicKey, assertion,
		soroauth.RequireUserPresence(true),
		soroauth.RequireUserVerification(true),
	)

	// ForAddress(walletAddress) is not decoration: AuthorizeEntry only ever
	// writes a signature onto a credential node whose address equals the
	// target, and returns ErrNoMatchingCredentialNode when none does, rather
	// than signing something the key holder did not intend.
	return soroauth.AuthorizeEntry(ctx, entry, signer, validUntilLedger,
		networkPassphrase, soroauth.ForAddress(walletAddress))
	// snippet:end passkey-sign
}
