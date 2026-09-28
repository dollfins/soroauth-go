//go:build e2e

package e2e

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// passkeyRejectionHeadroom is the multiplier scenario K applies to the
// recording pass's instruction budget and resource fee.
//
// It is larger than rejectionHeadroom because scenario K's refusal is not a
// contract error: the host's own secp256r1 verification fails, which the host
// escalates to a VM trap, and paying for that verification is most of the
// transaction's cost. Measured on 2026-09-27 against testnet at the default
// multiplier of 6: the recording pass supplied 2,774,226 instructions and the
// invocation needed 3,454,949, so the host reported a budget failure
// (`ScErrorTypeSceBudget`, "operation instructions exceeds amount specified")
// instead of the P-256 one. 20 leaves roughly 9.2M instructions, comfortably
// past the measured requirement.
const passkeyRejectionHeadroom = 20

// p256Key generates the P-256 credential key a passkey wallet authenticates.
//
// It is generated at runtime and never written to disk, like every other key in
// these tests.
func p256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a P-256 credential key: %v", err)
	}
	return key
}

// sec1PublicKey encodes the credential public key the way the fixture's
// constructor and `__check_auth` expect it: uncompressed SEC-1, 65 bytes.
func sec1PublicKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	encoded := elliptic.Marshal(elliptic.P256(), key.X, key.Y)
	if len(encoded) != soroauth.Secp256r1PublicKeySize {
		t.Fatalf("encoded public key is %d bytes, want %d",
			len(encoded), soroauth.Secp256r1PublicKeySize)
	}
	return encoded
}

// passkeyWalletSigner builds the soroauth signer that authorizes a passkey
// wallet's entry, exercising the whole passkey path the library ships:
// `NewPasskeySigner` with its user-presence and user-verification guards,
// `SignSecp256r1` for the ES256 signature, and `Secp256r1SignatureScVal` for
// the ScVal shape.
//
// There is no browser ceremony in a Go test, so the authenticator data is
// synthesised: 37 bytes, the minimum WebAuthn Level 2 §6.1 defines, with the
// UP and UV flag bits set at index 32. The signer is asked to require both,
// which is the guard `docs/passkeys.md` tells callers to use for anything that
// moves value — so this scenario fails before signing anything if that guard
// ever stops working.
//
// corruptSignature flips the low bit of `s` after signing. The scalar stays in
// range and low-S is preserved, so the host parses the signature and then fails
// to verify it. That is scenario K's refusal.
func passkeyWalletSigner(wallet string, key *ecdsa.PrivateKey, corruptSignature bool) soroauth.Signer {
	authenticatorData := make([]byte, 37)
	authenticatorData[32] = 0x01 | 0x04 // UP | UV

	return soroauth.NewPasskeySigner(wallet, authenticatorData,
		func(_ context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
			signature, err := soroauth.SignSecp256r1(key, payload)
			if err != nil {
				return xdr.ScVal{}, err
			}
			if corruptSignature {
				signature[soroauth.Secp256r1SignatureSize-1] ^= 0x01
			}
			return soroauth.Secp256r1SignatureScVal(&key.PublicKey, signature)
		},
		soroauth.RequireUserPresence(true),
		soroauth.RequireUserVerification(true),
	)
}

// passkeyWalletSetup is the shared arrangement for scenarios J and K: a funded
// passkey wallet holding XLM, the key it authenticates, and the transfer that
// spends from it. The payer is not the wallet, so the transfer cannot fall back
// to source-account authorization.
type passkeyWalletSetup struct {
	harness  *harness
	payer    *keypair.Full
	to       *keypair.Full
	key      *ecdsa.PrivateKey
	deployed deployment
	op       txnbuild.InvokeHostFunction
}

func setupPasskeyWallet(t *testing.T) passkeyWalletSetup {
	t.Helper()

	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	to := h.newAccount(t, "recipient B")
	key := p256Key(t)

	deployed := h.deployPasskeyWallet(t, payer, sec1PublicKey(t, key))
	h.fundContract(t, payer, deployed.ContractAddress, transferAmount*5)

	op := h.transferOp(t, scAddressOf(t, deployed.ContractAddress), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())

	return passkeyWalletSetup{
		harness:  h,
		payer:    payer,
		to:       to,
		key:      key,
		deployed: deployed,
		op:       op,
	}
}

// passkeyNotes is the block of facts RESULTS.md carries for both scenarios, so
// the two records cannot disagree about what was deployed.
func (s passkeyWalletSetup) notes(t *testing.T, arm string) []string {
	t.Helper()

	return []string{
		"passkey-wallet contract: " + s.deployed.ContractAddress,
		"wasm upload tx: " + s.deployed.UploadTxHash,
		"contract deploy tx: " + s.deployed.CreateTxHash,
		"wasm hash: " + s.deployed.WasmHash,
		"Credential public key (uncompressed SEC-1): " + hexOf(sec1PublicKey(t, s.key)),
		"Credential arm observed on the submitted envelope: " + arm,
		"The signature ScVal is {public_key, signature} in sorted symbol order, built by soroauth.Secp256r1SignatureScVal; the signature is raw low-S r || s over the 32-byte payload.",
	}
}

// TestScenarioJ proves a passkey wallet path is accepted by a live host: a
// custom account that verifies an ES256 (P-256) signature over the
// authorization payload accepts an entry soroauth signed.
func TestScenarioJ(t *testing.T) {
	setup := setupPasskeyWallet(t)

	result := runScenario(t, setup.harness, scenarioSpec{
		payer:        setup.payer,
		op:           setup.op,
		upgradedAuth: true,
		signers: []soroauth.Signer{
			passkeyWalletSigner(setup.deployed.ContractAddress, setup.key, false),
		},
	})

	t.Logf("contract:  %s", setup.deployed.ContractAddress)
	t.Logf("deploy tx: %s", setup.deployed.CreateTxHash)
	t.Logf("tx hash:   %s", result.Hash)
	t.Logf("ledger:    %d", result.Ledger)
	t.Logf("arm:       %s", result.Arm)
	t.Logf("link:      %s%s", explorerBaseURL, result.Hash)

	record(scenarioResult{
		ID:        "J",
		Name:      "a P-256 passkey signature is accepted live",
		Proves:    "A custom account that verifies an ES256 (P-256) signature over the authorization payload accepts an entry signed by soroauth's passkey signer.",
		TxHash:    result.Hash,
		Ledger:    result.Ledger,
		Arm:       result.Arm,
		Succeeded: result.Status == rpc.TransactionStatusSuccess,
		RawError:  result.RawError,
		Notes: append(setup.notes(t, result.Arm),
			"Signed through soroauth.NewPasskeySigner with RequireUserPresence and RequireUserVerification both set, using soroauth.SignSecp256r1 and soroauth.Secp256r1SignatureScVal.",
		),
	})

	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("scenario J failed on-chain (status %s):\n%s", result.Status, result.RawError)
	}

	// The arm is read back off the envelope that was submitted, not assumed.
	// Either address arm carries the same payload the wallet verifies, and the
	// recording pass asks for the upgraded one on a best-effort basis only
	// (go-stellar-sdk, protocols/rpc/simulate_transaction.go), so a failure to
	// upgrade is not a failure of this scenario.
	switch result.Arm {
	case "SorobanCredentialsTypeSorobanCredentialsAddressV2",
		"SorobanCredentialsTypeSorobanCredentialsAddress":
		// Both are the address credential the wallet authorizes.
	default:
		t.Errorf("submitted envelope carried credentials arm %q, want an address arm "+
			"(the transfer must not have fallen back to source-account auth)", result.Arm)
	}
}

// TestScenarioK proves the host refuses what it should: the same wallet and the
// same transfer, but with a corrupted P-256 signature. The host's own
// verification is what refuses it, and the test asserts that specific error
// rather than merely that the transaction failed.
func TestScenarioK(t *testing.T) {
	setup := setupPasskeyWallet(t)

	result := runScenario(t, setup.harness, scenarioSpec{
		payer:         setup.payer,
		op:            setup.op,
		upgradedAuth:  true,
		expectFailure: true,
		headroom:      passkeyRejectionHeadroom,
		signers: []soroauth.Signer{
			passkeyWalletSigner(setup.deployed.ContractAddress, setup.key, true),
		},
	})

	t.Logf("contract:  %s", setup.deployed.ContractAddress)
	t.Logf("deploy tx: %s", setup.deployed.CreateTxHash)
	t.Logf("tx hash:   %s", result.Hash)
	t.Logf("status:    %s", result.Status)
	t.Logf("arm:       %s", result.Arm)
	t.Logf("RAW ERROR:\n%s", result.RawError)

	record(scenarioResult{
		ID:              "K",
		Name:            "the host rejects a corrupt P-256 signature",
		Proves:          "A P-256 signature that does not verify is refused by the host's own secp256r1 verification, reported as a Crypto/InvalidInput failure, and the transfer does not happen.",
		TxHash:          result.Hash,
		Ledger:          result.Ledger,
		Arm:             result.Arm,
		Succeeded:       result.Status != rpc.TransactionStatusSuccess,
		ExpectRejection: true,
		RawError:        result.RawError,
		Notes: append(setup.notes(t, result.Arm),
			"The credential public key is the registered one; only the signature's low bit of s is flipped, so the refusal isolates the verification and is not the wallet's own UnknownKey comparison.",
		),
	})

	if result.Status == rpc.TransactionStatusSuccess {
		t.Fatal("the host accepted a corrupted P-256 signature; scenario K proves nothing if this succeeds")
	}
	if result.RawError == "" {
		t.Error("no raw error was captured, so there is nothing to report")
	}

	// Assert which failure, not merely that there was one. A transaction can
	// fail for many reasons that have nothing to do with the signature under
	// test, and scenario E once did exactly that (see e2e/README.md).
	details := hostErrorDetails(t, result.Diagnostics)
	refusedByP256Verification := false
	for _, detail := range details {
		if detail.ErrorType == int32(xdr.ScErrorTypeSceCrypto) &&
			strings.Contains(detail.Message, "secp256r1") {
			refusedByP256Verification = true
		}
	}
	if !refusedByP256Verification {
		t.Errorf("the host reported %+v, want a %s failure whose message names the "+
			"secp256r1 verification; the transaction failed, but not for the reason this "+
			"scenario is about", details, xdr.ScErrorTypeSceCrypto)
	} else {
		t.Logf("host error detail confirmed: %+v", details)
	}

	// The host names the operation that failed. If a future protocol release
	// stops reporting the message, this fails loudly rather than letting the
	// scenario pass on the error type alone.
	if !strings.Contains(result.RawError, "failed secp256r1 verification") {
		t.Errorf("the raw error does not report \"failed secp256r1 verification\", so it is "+
			"not clear the refusal came from P-256 verification:\n%s", result.RawError)
	}
}
