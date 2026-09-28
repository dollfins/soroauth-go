package soroauth

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"sort"
	"strings"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// maxAccountSignatures is the number of signatures the host accepts in a
// classic account's signature vector.
//
// The host's own constant is MAX_ACCOUNT_SIGNATURES = 20 (rs-soroban-env
// soroban-env-host/src/builtin_contracts/account_contract.rs:25), enforced at
// :185 with "too many account signers". Exceeding it fails on-chain after fees
// are paid, so it is refused here instead.
const maxAccountSignatures = 20

// Signer produces the ScVal written verbatim into a credential node's
// signature field.
//
// The shape of that ScVal is defined by the account being authorized, not by
// this library: a classic Stellar account expects a vector of
// {public_key, signature} maps, while a custom account contract's __check_auth
// may expect anything at all. That is why Sign returns an ScVal rather than raw
// signature bytes.
type Signer interface {
	// Address is the G… or C… address whose credential node this signature
	// belongs to. AuthorizeEntry writes the result only onto nodes carrying
	// this address, unless the caller overrides it with ForAddress.
	Address() string

	// Sign receives both the preimage and its 32-byte payload hash. The
	// preimage is passed so a remote or hardware signer can inspect the whole
	// structure it is approving rather than blind-signing a digest; the
	// payload is passed so a signer that only accepts a digest does not have
	// to re-derive it.
	//
	// Context Cancellation Guarantee:
	// Implementers MUST honour ctx.Done() cancellation and return ctx.Err()
	// promptly if the context is cancelled before or during signing. Remote,
	// hardware, or custom signers that wrap non-interruptible network or
	// device operations must explicitly document any inability to abort an
	// ongoing hardware transaction or network request.
	Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error)
}

// ed25519Keypair is the part of keypair.Full that signing needs. It exists so
// that the self-verification guard below can be tested: a test can supply a
// keypair whose Sign returns a signature that does not match, while Verify
// stays the genuine implementation, which is exactly the failure the guard is
// there to catch. *keypair.Full satisfies it.
type ed25519Keypair interface {
	Address() string
	Sign(input []byte) ([]byte, error)
	Verify(input, signature []byte) error
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
// (rs-soroban-env soroban-env-host/src/builtin_contracts/account_contract.rs:64).
// Keys are symbols, and the entries are written in key order — "public_key"
// before "signature" — because an ScMap is required to be sorted by key.
func accountSignature(rawPublicKey, signature []byte) xdr.ScVal {
	m := xdr.ScMap{
		{Key: scSymbol("public_key"), Val: scBytes(rawPublicKey)},
		{Key: scSymbol("signature"), Val: scBytes(signature)},
	}
	p := &m
	return xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &p}
}

// Ed25519SignatureScVal builds the signature value written into a classic
// account's credential node: a vector holding one {public_key, signature} map,
// with a 32-byte raw public key and a 64-byte ed25519 signature.
//
// It is exported because an adapter that signs through an external service — a
// cloud KMS, a remote signer — has to produce exactly this shape without being
// a keypair, and building it in two places is how the two drift. The map keys
// are symbols in key order, "public_key" before "signature", because the host
// decodes it as AccountEd25519Signature (rs-soroban-env
// soroban-env-host/src/builtin_contracts/account_contract.rs:64), which is the
// same shape NewEd25519Signer writes.
//
// The two lengths are checked rather than trusted: a value that is not this
// size would be rejected on-chain after fees were paid, so it is refused here.
func Ed25519SignatureScVal(rawPublicKey, signature []byte) (xdr.ScVal, error) {
	if len(rawPublicKey) != ed25519.PublicKeySize {
		return xdr.ScVal{}, fmt.Errorf("soroauth: ed25519 signature scval: public key is %d bytes, want %d",
			len(rawPublicKey), ed25519.PublicKeySize)
	}
	if len(signature) != ed25519.SignatureSize {
		return xdr.ScVal{}, fmt.Errorf("soroauth: ed25519 signature scval: signature is %d bytes, want %d",
			len(signature), ed25519.SignatureSize)
	}
	return scVec(accountSignature(rawPublicKey, signature)), nil
}

// rawEd25519Key returns the 32 raw public key bytes behind a G… address.
func rawEd25519Key(address string) ([]byte, error) {
	raw, err := strkey.Decode(strkey.VersionByteAccountID, address)
	if err != nil {
		return nil, fmt.Errorf("%q is not an account (G…) address: %w", address, err)
	}
	return raw, nil
}

// ed25519Signer signs for a classic account with a single signing key.
type ed25519Signer struct {
	kp ed25519Keypair
}

// NewEd25519Signer returns a Signer for a classic Stellar account whose
// signing key is kp, producing the built-in account signature shape:
// a vector holding one {public_key, signature} map.
//
// The signature is verified against the payload before it is returned, and a
// mismatch is reported as ErrSignatureMismatch. One verification is cheap
// compared to what it catches — a damaged key, a faulty signer, or corrupted
// memory producing a signature that would otherwise be discovered only when
// the transaction fails on-chain, after fees are paid.
//
// A nil keypair is reported when Sign is called rather than at construction,
// because the signature of this constructor has no error to return.
func NewEd25519Signer(kp *keypair.Full) Signer {
	if kp == nil {
		// Storing a nil *keypair.Full in the interface would leave it
		// non-nil and panic on first use.
		return &ed25519Signer{}
	}
	return &ed25519Signer{kp: kp}
}

func (s *ed25519Signer) Address() string {
	if s.kp == nil {
		return ""
	}
	return s.kp.Address()
}

func (s *ed25519Signer) Sign(ctx context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign ed25519: %w", err)
	}
	if s.kp == nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign ed25519: %w", ErrMissingSigner)
	}

	signature, err := s.kp.Sign(payload[:])
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign ed25519: %w", err)
	}
	if err := s.kp.Verify(payload[:], signature); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign ed25519: %w", ErrSignatureMismatch)
	}

	rawPublicKey, err := rawEd25519Key(s.kp.Address())
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign ed25519: %w", err)
	}

	return scVec(accountSignature(rawPublicKey, signature)), nil
}

// accountMultiSigner signs for a classic account with several signing keys.
type accountMultiSigner struct {
	account string
	keys    []multiSignerKey
}

type multiSignerKey struct {
	kp  ed25519Keypair
	raw []byte
}

// NewAccountMultiSigner returns a Signer for a classic Stellar account that
// requires several signatures to meet its medium threshold. account is the
// G… address being authorized, which may differ from every key's own address:
// a Stellar account's signers are not required to include its master key.
//
// The keys are sorted at construction, strictly ascending by raw 32-byte public
// key, because the host walks the vector and rejects it unless each key
// compares strictly greater than the one before it — the loop errors with
// "public keys are not ordered" otherwise (rs-soroban-env
// soroban-env-host/src/builtin_contracts/account_contract.rs:204-211). That
// same rule is why duplicate keys are rejected here: a repeat is never
// strictly ascending.
//
// Zero keys is refused as ErrMissingSigner, because the host rejects an empty
// vector outright ("no account signatures found", account_contract.rs:196).
// More than 20 keys is refused as ErrTooManySignatures (see
// maxAccountSignatures).
//
// This signer has no equivalent in the JS SDK, so it is not covered by the
// golden vectors. It is proven by unit tests and by e2e scenario C, which
// submits a transfer from a two-signer account on testnet.
func NewAccountMultiSigner(account string, kps ...*keypair.Full) (Signer, error) {
	keys := make([]ed25519Keypair, 0, len(kps))
	for i, kp := range kps {
		if kp == nil {
			return nil, fmt.Errorf("soroauth: new account multi signer: key %d is nil: %w", i, ErrMissingSigner)
		}
		keys = append(keys, kp)
	}
	return newAccountMultiSigner(account, keys...)
}

// newAccountMultiSigner carries the logic, over the testable seam.
func newAccountMultiSigner(account string, kps ...ed25519Keypair) (Signer, error) {
	if _, err := rawEd25519Key(account); err != nil {
		return nil, fmt.Errorf("soroauth: new account multi signer: %w", err)
	}
	if len(kps) == 0 {
		return nil, fmt.Errorf("soroauth: new account multi signer: %s: %w", account,
			&MissingSignerError{Address: account})
	}
	if len(kps) > maxAccountSignatures {
		return nil, fmt.Errorf("soroauth: new account multi signer: %d keys, the host accepts at most %d: %w",
			len(kps), maxAccountSignatures, ErrTooManySignatures)
	}

	keys := make([]multiSignerKey, 0, len(kps))
	for i, kp := range kps {
		if kp == nil {
			return nil, fmt.Errorf("soroauth: new account multi signer: key %d is nil: %w", i, ErrMissingSigner)
		}
		raw, err := rawEd25519Key(kp.Address())
		if err != nil {
			return nil, fmt.Errorf("soroauth: new account multi signer: %w", err)
		}
		keys = append(keys, multiSignerKey{kp: kp, raw: raw})
	}

	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i].raw, keys[j].raw) < 0
	})
	for i := 1; i < len(keys); i++ {
		if bytes.Equal(keys[i-1].raw, keys[i].raw) {
			return nil, fmt.Errorf("soroauth: new account multi signer: duplicate signing key %s",
				keys[i].kp.Address())
		}
	}

	return &accountMultiSigner{account: account, keys: keys}, nil
}

func (s *accountMultiSigner) Address() string { return s.account }

func (s *accountMultiSigner) Sign(ctx context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign account multisig: %w", err)
	}

	signatures := make([]xdr.ScVal, 0, len(s.keys))
	for _, key := range s.keys {
		if err := ctx.Err(); err != nil {
			return xdr.ScVal{}, fmt.Errorf("soroauth: sign account multisig: %w", err)
		}
		signature, err := key.kp.Sign(payload[:])
		if err != nil {
			return xdr.ScVal{}, fmt.Errorf("soroauth: sign account multisig: %s: %w", key.kp.Address(), err)
		}
		if err := key.kp.Verify(payload[:], signature); err != nil {
			return xdr.ScVal{}, fmt.Errorf("soroauth: sign account multisig: %s: %w",
				key.kp.Address(), ErrSignatureMismatch)
		}
		signatures = append(signatures, accountSignature(key.raw, signature))
	}

	return scVec(signatures...), nil
}

// PasskeySignerOption configures options for passkey signers.
type PasskeySignerOption func(*passkeySignerConfig)

type passkeySignerConfig struct {
	requireUserPresence     bool
	requireUserVerification bool
}

// RequireUserPresence returns a PasskeySignerOption that insists on user presence (UP, bit 0 of authenticatorData).
func RequireUserPresence(required bool) PasskeySignerOption {
	return func(cfg *passkeySignerConfig) {
		cfg.requireUserPresence = required
	}
}

// RequireUserVerification returns a PasskeySignerOption that insists on user verification (UV, bit 2 of authenticatorData).
func RequireUserVerification(required bool) PasskeySignerOption {
	return func(cfg *passkeySignerConfig) {
		cfg.requireUserVerification = required
	}
}

// ErrVerificationFailed is returned when passkey assertion verification fails (e.g. required UP or UV flags are missing).
var ErrVerificationFailed = errors.New("verification failed")

// NewPasskeySigner returns a Signer for passkey / WebAuthn assertions, validating user presence (UP) and user verification (UV) flags from the authenticator data when requested.
// By default, neither UP nor UV is required (off by default).
func NewPasskeySigner(address string, authenticatorData []byte, fn func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error), opts ...PasskeySignerOption) Signer {
	var cfg passkeySignerConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return &signerFunc{
		address: address,
		fn: func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
			if cfg.requireUserPresence || cfg.requireUserVerification {
				if len(authenticatorData) < 37 {
					return xdr.ScVal{}, fmt.Errorf("soroauth: passkey signer: authenticatorData too short (%d bytes): %w", len(authenticatorData), ErrVerificationFailed)
				}
				flags := authenticatorData[32]
				up := (flags & 0x01) != 0
				uv := (flags & 0x04) != 0
				if cfg.requireUserPresence && !up {
					return xdr.ScVal{}, fmt.Errorf("soroauth: passkey signer: user presence (UP) required but not set in flags 0x%02x: %w", flags, ErrVerificationFailed)
				}
				if cfg.requireUserVerification && !uv {
					return xdr.ScVal{}, fmt.Errorf("soroauth: passkey signer: user verification (UV) required but not set in flags 0x%02x: %w", flags, ErrVerificationFailed)
				}
			}
			if fn == nil {
				return xdr.ScVal{}, fmt.Errorf("soroauth: passkey sign: %w", ErrMissingSigner)
			}
			return fn(ctx, preimage, payload)
		},
	}
}

// es256Verifier verifies an ES256 signature -- ECDSA over P-256 with SHA-256
// (WebAuthn Level 3 §5.8.2) -- over a digest that has already been hashed.
//
// It is the passkey analogue of ed25519Keypair: a seam, not an abstraction for
// its own sake. The self-verification guard in passkeyAssertionSigner is there
// to catch a signature that will not verify, and a guard tested only with
// correct signatures proves nothing. A test supplies a verifier that returns
// true unconditionally and asserts the guard still refuses, which is exactly
// the failure the guard exists to catch.
type es256Verifier interface {
	verify(publicKey *ecdsa.PublicKey, digest []byte, r, s *big.Int) bool
}

// realES256Verifier is the verifier production uses: crypto/ecdsa's own P-256
// check.
type realES256Verifier struct{}

func (realES256Verifier) verify(publicKey *ecdsa.PublicKey, digest []byte, r, s *big.Int) bool {
	return ecdsa.Verify(publicKey, digest, r, s)
}

// passkeyAssertionSigner is the full passkey (WebAuthn) signer: it holds the
// credential's public key and a parsed assertion, verifies the assertion at
// Sign time, and only then produces the wallet's signature value.
type passkeyAssertionSigner struct {
	address   string
	publicKey *ecdsa.PublicKey
	assertion *WebAuthnAssertion
	cfg       passkeySignerConfig
	verifier  es256Verifier
}

// NewPasskeySignerFromAssertion returns a Signer for a passkey (WebAuthn) smart
// wallet: it verifies the assertion against the payload it is asked to sign and
// returns the ScVal such a wallet's __check_auth decodes.
//
// It differs from NewPasskeySigner in what it takes and in what it promises.
// NewPasskeySigner takes a callback and checks the user-presence and
// user-verification flags; the caller owns the signature and any cryptographic
// verification of it. This constructor takes the parsed assertion (see
// ParseWebAuthnAssertion) and the credential's P-256 public key, and verifies
// the assertion itself before returning anything, the way NewEd25519Signer
// verifies its own output. There is no way to call it such that an unverified
// assertion produces a signature.
//
// Sign performs, in order:
//
//  1. the user-presence (UP, bit 0) and user-verification (UV, bit 2) flag
//     checks the options request, reading the flags byte at offset 32 of the
//     authenticator data (WebAuthn Level 3 §6.1), and failing with
//     ErrVerificationFailed;
//  2. the challenge-binding check: the challenge embedded in the assertion's
//     clientDataJSON must be the payload about to be signed, or the assertion
//     belongs to some other ceremony and is refused (WebAuthn Level 3 §7.2 step
//     11). The failure wraps both ErrSignatureMismatch and
//     ErrWebAuthnChallengeMismatch;
//  3. the ES256 signature check, over SHA-256(authenticatorData ||
//     SHA-256(clientDataJSON)) (WebAuthn Level 3 §6.1 and §7.2 step 21), with
//     the DER-encoded assertion signature parsed by ParseDERECDSASignature. A
//     signature that does not verify is ErrSignatureMismatch.
//
// The value it returns is {public_key, signature} with a sorted symbol-keyed
// map: the uncompressed SEC1 P-256 public key, and the signature in the
// fixed-width low-S r || s form Secp256r1SignatureScVal builds.
//
// Which contract that shape is for. Unlike a classic Stellar account, whose
// signature ScVal the host itself defines
// (rs-soroban-env/src/builtin_contracts/account_contract.rs), a custom
// account's signature shape is whatever its __check_auth says it is. There is
// no protocol-mandated passkey shape. This one targets the example wallet
// contract in docs/passkeys.md, and nothing else: a wallet with a different
// layout should keep this signer's verification and swap the returned ScVal,
// or use SignerFunc. Nothing in this repository deploys or tests a contract
// that decodes this shape.
//
// The assertion is supplied by the caller; this type never performs a WebAuthn
// ceremony itself. A nil assertion or public key is reported as ErrMissingSigner
// when Sign is called, because the constructor's signature has no error to
// return.
func NewPasskeySignerFromAssertion(
	address string,
	publicKey *ecdsa.PublicKey,
	assertion *WebAuthnAssertion,
	opts ...PasskeySignerOption,
) Signer {
	var cfg passkeySignerConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	return &passkeyAssertionSigner{
		address:   address,
		publicKey: publicKey,
		assertion: assertion,
		cfg:       cfg,
		verifier:  realES256Verifier{},
	}
}

func (s *passkeyAssertionSigner) Address() string { return s.address }

func (s *passkeyAssertionSigner) Sign(ctx context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign passkey: %w", err)
	}
	if s.assertion == nil || s.publicKey == nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign passkey: %w", ErrMissingSigner)
	}
	if !validP256PublicKey(s.publicKey) {
		return xdr.ScVal{}, fmt.Errorf(
			"soroauth: sign passkey: credential public key is not an uncompressed P-256 key: %w",
			ErrVerificationFailed)
	}

	if s.cfg.requireUserPresence || s.cfg.requireUserVerification {
		flags := s.assertion.Flags()
		if s.cfg.requireUserPresence && flags&flagUserPresent == 0 {
			return xdr.ScVal{}, fmt.Errorf(
				"soroauth: sign passkey: user presence (UP) required but not set in flags 0x%02x: %w",
				flags, ErrVerificationFailed)
		}
		if s.cfg.requireUserVerification && flags&flagUserVerified == 0 {
			return xdr.ScVal{}, fmt.Errorf(
				"soroauth: sign passkey: user verification (UV) required but not set in flags 0x%02x: %w",
				flags, ErrVerificationFailed)
		}
	}

	// The challenge is the only thing tying the ceremony to this transaction.
	// Writing both sentinels means a caller can match whichever it thinks in:
	// the signature is refused, and the reason is that the challenge differed.
	if err := s.assertion.VerifyChallenge(payload[:]); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign passkey: %w: %w",
			ErrSignatureMismatch, ErrWebAuthnChallengeMismatch)
	}

	digest := sha256.Sum256(s.assertion.SignedBytes())
	r, sScalar, err := ParseDERECDSASignature(s.assertion.Signature)
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign passkey: %w", ErrSignatureMismatch)
	}

	verifier := s.verifier
	if verifier == nil {
		verifier = realES256Verifier{}
	}
	if !verifier.verify(s.publicKey, digest[:], r, sScalar) {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign passkey: %w", ErrSignatureMismatch)
	}

	// The wire form is low-S, so the same logical signature has one encoding.
	lowS := normalizeP256LowS(sScalar, elliptic.P256().Params().N)
	value, err := Secp256r1SignatureScVal(s.publicKey, marshalSecp256r1Signature(r, lowS))
	if err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign passkey: %w", err)
	}
	return value, nil
}

// signerFunc adapts a plain function to the Signer interface.
type signerFunc struct {
	address string
	fn      func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error)
}

// RetryConfig holds configuration for retrying network/remote signer calls.
type RetryConfig struct {
	// Attempts is the maximum number of attempts (e.g. 3 means 1 initial try + 2 retries).
	// If 0, defaults to 1 (no retries).
	Attempts int
	// InitialBackoff is the starting backoff duration between attempts.
	InitialBackoff time.Duration
	// MaxBackoff is the upper bound for backoff duration.
	MaxBackoff time.Duration
}

// IsSignatureRejection reports whether an error represents a signature rejection or refusal
// that should never be retried (e.g. signature mismatch, invalid credentials, refusal).
func IsSignatureRejection(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrSignatureMismatch) || errors.Is(err, ErrMissingSigner) || errors.Is(err, ErrTooManySignatures) {
		return true
	}
	// Also check string signatures or custom rejection markers
	s := err.Error()
	return strings.Contains(s, "signature mismatch") || strings.Contains(s, "refused") || strings.Contains(s, "unsupported")
}

// WithRetry wraps a Signer with a jittered exponential backoff retry policy for transport errors.
// Retries only occur on network/transport errors; signature rejections are never retried.
// Context cancellation or timeout immediately terminates retries.
func WithRetry(signer Signer, cfg RetryConfig) Signer {
	if cfg.Attempts <= 0 {
		cfg.Attempts = 1
	}
	return &retriedSigner{
		inner: signer,
		cfg:   cfg,
	}
}

type retriedSigner struct {
	inner Signer
	cfg   RetryConfig
}

func (s *retriedSigner) Address() string {
	return s.inner.Address()
}

func (s *retriedSigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	attempts := s.cfg.Attempts
	if attempts <= 0 {
		attempts = 1
	}

	backoffDur := s.cfg.InitialBackoff
	if backoffDur <= 0 {
		backoffDur = 50 * time.Millisecond
	}
	maxBackoff := s.cfg.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = 1 * time.Second
	}

	var lastErr error
	for i := 1; i <= attempts; i++ {
		if err := ctx.Err(); err != nil {
			return xdr.ScVal{}, fmt.Errorf("soroauth: retry sign: %w", err)
		}

		val, err := s.inner.Sign(ctx, preimage, payload)
		if err == nil {
			return val, nil
		}

		lastErr = err

		// Never retry signature rejections
		if IsSignatureRejection(err) {
			return xdr.ScVal{}, err
		}

		// If this was the last attempt, break and return error
		if i >= attempts {
			break
		}

		if err := ctx.Err(); err != nil {
			return xdr.ScVal{}, fmt.Errorf("soroauth: retry sign cancelled: %w", err)
		}

		if err := ctx.Err(); err != nil {
			return xdr.ScVal{}, fmt.Errorf("soroauth: retry sign cancelled: %w", err)
		}

		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		var jitter time.Duration
		if backoffDur/4 > 0 {
			jitter = time.Duration(rng.Int63n(int64(backoffDur / 4)))
		}
		sleepDur := backoffDur + jitter
		if sleepDur > maxBackoff {
			sleepDur = maxBackoff
		}

		timer := time.NewTimer(sleepDur)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return xdr.ScVal{}, fmt.Errorf("soroauth: retry sign cancelled: %w", ctx.Err())
		case <-timer.C:
		}

		if err := ctx.Err(); err != nil {
			return xdr.ScVal{}, fmt.Errorf("soroauth: retry sign cancelled: %w", err)
		}

		if err := ctx.Err(); err != nil {
			return xdr.ScVal{}, fmt.Errorf("soroauth: retry sign cancelled: %w", err)
		}

		backoffDur *= 2
		if backoffDur > maxBackoff {
			backoffDur = maxBackoff
		}
	}

	return xdr.ScVal{}, lastErr
}

// SignerFunc adapts a function to the Signer interface, for custom account
// contracts — smart wallets, and passkey or secp256r1 signers — whose
// __check_auth expects a signature shape this library does not know.
//
// The ScVal the function returns is written into the credential node verbatim,
// with no wrapping added. Nothing about it is or can be verified here: the
// caller owns both the shape and the correctness of what they return. Signers
// whose shape is known, such as NewEd25519Signer, do verify themselves.
func SignerFunc(address string, fn func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error)) Signer {
	return &signerFunc{address: address, fn: fn}
}

func (s *signerFunc) Address() string { return s.address }

func (s *signerFunc) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign func: %w", err)
	}
	if s.fn == nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: sign func: %w", ErrMissingSigner)
	}
	return s.fn(ctx, preimage, payload)
}
