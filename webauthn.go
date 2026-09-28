package soroauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// authDataMinLen is the length of the fixed prefix of the WebAuthn
// authenticator data, before any attested credential data or extensions.
//
// WebAuthn Level 2 §6.1, "Authenticator Data", defines the layout as
//
//	rpIdHash        (32 bytes)
//	flags           ( 1 byte )
//	signCount       ( 4 bytes)
//	attestedCredentialData (variable, iff the AT flag is set)
//	extensions      (variable, iff the ED flag is set)
//
// so the shortest authenticator data that still carries its flags is 37 bytes.
// The passkey signer's user-presence and user-verification checks read the
// flags at index 32, which only exists once this many bytes are present.
const authDataMinLen = 37

// WebAuthn assertion flags, from the single byte at offset 32 of the
// authenticator data (WebAuthn Level 2 §6.1, "Flags").
const (
	// flagUserPresent is bit 0 (UP): the user touched the authenticator.
	flagUserPresent = 0x01
	// flagUserVerified is bit 2 (UV): the user was verified, e.g. by
	// biometric or PIN.
	flagUserVerified = 0x04
)

// WebAuthnAssertion is the parsed form of a WebAuthn assertion, the
// PublicKeyCredential that navigator.credentials.get() resolves with once it
// has been serialized with PublicKeyCredential.toJSON().
//
// The member names and nesting come from WebAuthn Level 2 §5.1.4,
// "Authenticator Assertion Response JSON serialization", which defines
// response.clientDataJSON, response.authenticatorData and response.signature
// as base64url (unpadded) strings.
//
// What the fields mean for signing:
//
//   - a passkey wallet's contract does not verify a signature over the payload
//     directly. It verifies it over AuthenticatorData || SHA-256(ClientDataJSON),
//     so both byte strings have to survive the trip to the contract unchanged.
//   - Challenge is the value the authenticator actually signed, decoded back
//     from ClientDataJSON. VerifyChallenge compares it against the soroauth
//     payload; if the two differ, the assertion belongs to a different
//     ceremony and must not be attached to this entry.
type WebAuthnAssertion struct {
	// AuthenticatorData is the raw authenticator data (WebAuthn Level 2 §6.1).
	AuthenticatorData []byte
	// ClientDataJSON is the raw client data JSON the browser produced
	// (WebAuthn Level 2 §5.8.1). Its bytes are hashed into what was signed,
	// so it is kept verbatim rather than re-encoded.
	ClientDataJSON []byte
	// Signature is the raw assertion signature bytes.
	Signature []byte
	// ChallengeString is the challenge exactly as it appeared in
	// ClientDataJSON, before any decoding. It is the value the browser
	// ceremony signed, and therefore the value VerifyChallenge compares
	// against the payload; it is kept verbatim because changing it would
	// break the client data hash it is embedded in, and because a caller
	// reporting a mismatch wants to say what was found.
	ChallengeString string
}

// Flags returns the authenticator data's flags byte (WebAuthn Level 2 §6.1).
//
// ParseWebAuthnAssertion guarantees at least 37 bytes, so this byte exists for
// any assertion the parser returned. UserPresent and UserVerified report the
// two bits callers most often need to enforce.
func (a *WebAuthnAssertion) Flags() byte {
	if a == nil || len(a.AuthenticatorData) <= 32 {
		return 0
	}
	return a.AuthenticatorData[32]
}

// UserPresent reports whether the user-presence bit (UP, bit 0) is set in the
// authenticator data.
func (a *WebAuthnAssertion) UserPresent() bool {
	return a.Flags()&flagUserPresent != 0
}

// UserVerified reports whether the user-verification bit (UV, bit 2) is set in
// the authenticator data.
func (a *WebAuthnAssertion) UserVerified() bool {
	return a.Flags()&flagUserVerified != 0
}

// SignedBytes returns the byte string the assertion's signature is computed
// over: the authenticator data followed by SHA-256(clientDataJSON).
//
// WebAuthn Level 3 §6.1 defines exactly that concatenation as what a signature
// covers, and §7.2 step 21 has the relying party hash it once more with the
// credential's algorithm before verifying. For a passkey the algorithm is
// ES256, so a caller verifies the assertion's DER signature over
// SHA-256(SignedBytes()). Returning the unhashed concatenation rather than the
// digest is deliberate: hashing is the verification step, and a caller that
// wants to inspect what it is verifying should see the same bytes the
// authenticator signed.
//
// It is a copy, so a caller cannot change the assertion through it.
func (a *WebAuthnAssertion) SignedBytes() []byte {
	if a == nil {
		return nil
	}
	clientDataHash := sha256.Sum256(a.ClientDataJSON)
	signed := make([]byte, 0, len(a.AuthenticatorData)+len(clientDataHash))
	signed = append(signed, a.AuthenticatorData...)
	return append(signed, clientDataHash[:]...)
}

// webAuthnAssertionJSON is the wire shape of a serialized PublicKeyCredential
// (WebAuthn Level 2 §5.1.4). Fields this library does not need are omitted;
// encoding/json ignores unknown members, and the parser never trusts a member
// it did not ask for.
type webAuthnAssertionJSON struct {
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string  `json:"clientDataJSON"`
		AuthenticatorData string  `json:"authenticatorData"`
		Signature         string  `json:"signature"`
		UserHandle        *string `json:"userHandle"`
	} `json:"response"`
}

// clientDataJSON is the client data the browser signed over (WebAuthn Level 2
// §5.8.1). Only the members the challenge check needs are decoded.
type clientDataJSON struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

// ParseWebAuthnAssertion parses a serialized WebAuthn assertion into the parts
// a Soroban passkey wallet needs.
//
// It is dependency-free: base64url and JSON decoding are standard library.
//
// The assertion is untrusted input — it comes from a browser, a network hop, or
// a file — so every field is required and every decode failure is an error.
// Nothing is defaulted:
//
//   - malformed JSON in the assertion, or in its clientDataJSON, is
//     ErrWebAuthnMalformedJSON;
//   - a missing or empty response.clientDataJSON, response.authenticatorData,
//     response.signature, or challenge is ErrWebAuthnMissingField;
//   - a field whose base64url does not decode is ErrWebAuthnMalformedField;
//   - authenticator data shorter than its 37-byte fixed prefix is
//     ErrWebAuthnTruncatedAuthenticatorData.
//
// A credential whose type is present and not "public-key" is refused, because
// the rest of this parser decodes the public-key assertion response shape; an
// absent type is accepted, since some serializers omit it.
func ParseWebAuthnAssertion(raw []byte) (*WebAuthnAssertion, error) {
	if len(raw) == 0 {
		return nil, fmt.Errorf("soroauth: parse webauthn assertion: %w", ErrWebAuthnMalformedJSON)
	}

	var credential webAuthnAssertionJSON
	if err := json.Unmarshal(raw, &credential); err != nil {
		return nil, fmt.Errorf("soroauth: parse webauthn assertion: %w", ErrWebAuthnMalformedJSON)
	}
	if credential.Type != "" && credential.Type != "public-key" {
		return nil, fmt.Errorf("soroauth: parse webauthn assertion: credential type %q: %w",
			credential.Type, ErrWebAuthnMalformedField)
	}

	assertion := &WebAuthnAssertion{}

	authenticatorData, err := decodeAssertionField(credential.Response.AuthenticatorData, "authenticatorData")
	if err != nil {
		return nil, err
	}
	if len(authenticatorData) == 0 {
		return nil, missingFieldError("authenticatorData")
	}
	if len(authenticatorData) < authDataMinLen {
		return nil, fmt.Errorf("soroauth: parse webauthn assertion: authenticatorData is %d bytes, need at least %d: %w",
			len(authenticatorData), authDataMinLen, ErrWebAuthnTruncatedAuthenticatorData)
	}
	assertion.AuthenticatorData = authenticatorData

	clientData, err := decodeAssertionField(credential.Response.ClientDataJSON, "clientDataJSON")
	if err != nil {
		return nil, err
	}
	if len(clientData) == 0 {
		return nil, missingFieldError("clientDataJSON")
	}
	assertion.ClientDataJSON = clientData

	signature, err := decodeAssertionField(credential.Response.Signature, "signature")
	if err != nil {
		return nil, err
	}
	if len(signature) == 0 {
		return nil, missingFieldError("signature")
	}
	assertion.Signature = signature

	var clientDataFields clientDataJSON
	if err := json.Unmarshal(clientData, &clientDataFields); err != nil {
		return nil, fmt.Errorf("soroauth: parse webauthn assertion: clientDataJSON: %w", ErrWebAuthnMalformedJSON)
	}
	if clientDataFields.Challenge == "" {
		return nil, missingFieldError("challenge")
	}
	if !isDecodableChallenge(clientDataFields.Challenge) {
		return nil, fmt.Errorf("soroauth: parse webauthn assertion: challenge: %w", ErrWebAuthnMalformedField)
	}
	assertion.ChallengeString = clientDataFields.Challenge

	return assertion, nil
}

// ParseWebAuthnAssertionForPayload parses an assertion and then requires that
// the challenge it carries equals payload, the 32-byte hash soroauth signs.
//
// It is the two-step parse-then-verify for callers who already have the
// payload, and it exists so that forgetting the second step is not an option:
// an assertion that parses but was made for a different challenge is exactly
// the failure this guards against.
func ParseWebAuthnAssertionForPayload(raw []byte, payload [32]byte) (*WebAuthnAssertion, error) {
	assertion, err := ParseWebAuthnAssertion(raw)
	if err != nil {
		return nil, err
	}
	if err := assertion.VerifyChallenge(payload[:]); err != nil {
		return nil, err
	}
	return assertion, nil
}

// VerifyChallenge checks that the challenge the authenticator signed equals
// expected.
//
// It compares ChallengeString against the encodings a serialized challenge is
// legitimately written in — base64url (WebAuthn Level 2 §5.8.1, the canonical
// one, with and without padding), standard base64, and hexadecimal — rather
// than decoding the string first. Decoding is ambiguous: a 64-character
// hexadecimal string is also valid base64url, and would decode to the wrong
// bytes under a fixed order. Matching against known encodings of expected has
// no such ambiguity, and each candidate is compared in constant time
// (crypto/subtle) because a challenge is a value an attacker who can observe
// timing would like to steer toward one they can predict.
//
// This is the binding between the browser ceremony and this Soroban entry:
// WebAuthn Level 2 §7.1 step 11 requires the relying party to compare the
// challenge in the client data against the challenge it issued, and the
// challenge is how the ceremony is tied to one specific payload. A mismatch is
// ErrWebAuthnChallengeMismatch.
func (a *WebAuthnAssertion) VerifyChallenge(expected []byte) error {
	if a == nil || len(expected) == 0 {
		return fmt.Errorf("soroauth: verify webauthn challenge: %w", ErrWebAuthnChallengeMismatch)
	}

	hexLower := hex.EncodeToString(expected)
	candidates := []string{
		base64.RawURLEncoding.EncodeToString(expected),
		base64.URLEncoding.EncodeToString(expected),
		base64.RawStdEncoding.EncodeToString(expected),
		base64.StdEncoding.EncodeToString(expected),
		hexLower,
		strings.ToUpper(hexLower),
	}
	for _, candidate := range candidates {
		if subtle.ConstantTimeCompare([]byte(candidate), []byte(a.ChallengeString)) == 1 {
			return nil
		}
	}
	return fmt.Errorf("soroauth: verify webauthn challenge: %w", ErrWebAuthnChallengeMismatch)
}

// missingFieldError builds the ErrWebAuthnMissingField error for one field.
func missingFieldError(field string) error {
	return fmt.Errorf("soroauth: parse webauthn assertion: %s: %w", field, ErrWebAuthnMissingField)
}

// decodeAssertionField decodes one base64url transport field of the assertion.
// An empty string is left to the caller to classify as missing rather than
// malformed, so that the two failures stay distinct.
func decodeAssertionField(value, field string) ([]byte, error) {
	if value == "" {
		return nil, nil
	}
	decoded, err := decodeBase64Loose(value)
	if err != nil {
		return nil, fmt.Errorf("soroauth: parse webauthn assertion: %s: %w", field, ErrWebAuthnMalformedField)
	}
	return decoded, nil
}

// isDecodableChallenge reports whether a challenge string is at least a
// well-formed encoding of some bytes: base64url, standard base64 (either with
// or without padding), or hexadecimal. It is a shape check, not a check that
// the value is the right one — VerifyChallenge does that.
func isDecodableChallenge(value string) bool {
	if _, err := decodeBase64Loose(value); err == nil {
		return true
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// decodeBase64Loose decodes base64url or standard base64, with or without
// padding. It accepts the encodings found in the wild; it does not accept
// anything that is not base64 at all.
func decodeBase64Loose(value string) ([]byte, error) {
	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var lastErr error
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			return decoded, nil
		}
		lastErr = err
	}
	return nil, lastErr
}
