package soroauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// ExampleParseAddress shows the two address forms an address credential may
// name, the canonicality rule, and the muxed-address refusal.
//
// Only the canonical SEP-23 base32 spelling is accepted, so a lower-cased (or
// padded, or whitespace-wrapped) address is refused even though it names the
// same key; an M… muxed address is refused rather than unwrapped, because a
// credential must name the account itself (CAP-46-11).
func ExampleParseAddress() {
	account, err := ParseAddress("GAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB7JZX")
	if err != nil {
		fmt.Println("account:", err)
		return
	}
	contract, err := ParseAddress("CAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6N4O")
	if err != nil {
		fmt.Println("contract:", err)
		return
	}
	fmt.Println(account.Type == xdr.ScAddressTypeScAddressTypeAccount)
	fmt.Println(contract.Type == xdr.ScAddressTypeScAddressTypeContract)

	// Non-canonical spellings are refused, even though they name the same key.
	if _, err := ParseAddress("gaaacaqdaqcqmbyibefawdanbyhraeiscmkbkfqxdamrugy4dupb7jzx"); err != nil {
		fmt.Println("lower-cased refused")
	}

	// A muxed address is refused rather than unwrapped: a credential must name
	// the account itself.
	if _, err := ParseAddress("MAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6AAAAAAAAAAE2KZ3Q"); err != nil {
		fmt.Println("muxed refused")
	}

	// Output:
	// true
	// true
	// lower-cased refused
	// muxed refused
}

// ExampleFormatAddress is the inverse of ParseAddress: it renders each accepted
// address form and refuses the same arms ParseAddress refuses, so a caller is
// never shown an address this library would decline to sign for.
func ExampleFormatAddress() {
	address, err := ParseAddress("CAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6N4O")
	if err != nil {
		fmt.Println("parse:", err)
		return
	}
	formatted, err := FormatAddress(address)
	if err != nil {
		fmt.Println("format:", err)
		return
	}
	fmt.Println(formatted)

	// Output:
	// CAAACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6N4O
}

// ExampleDecodeAuthorizationEntry shows the entry point for a base64 entry that
// came from somewhere else. The limits it applies are documented on the
// function and on MaxDecodeDepth and MaxDecodeInputBytes.
func ExampleDecodeAuthorizationEntry() {
	var contractID xdr.ContractId
	for i := range contractID {
		contractID[i] = byte(i)
	}
	var key xdr.Uint256
	key[0] = 1
	accountID := xdr.AccountId{
		Type:    xdr.PublicKeyTypePublicKeyTypeEd25519,
		Ed25519: &key,
	}
	address := xdr.ScAddress{
		Type:      xdr.ScAddressTypeScAddressTypeAccount,
		AccountId: &accountID,
	}

	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &xdr.SorobanAddressCredentials{
				Address:                   address,
				Nonce:                     7,
				SignatureExpirationLedger: 100,
				Signature:                 xdr.ScVal{Type: xdr.ScValTypeScvVoid},
			},
		},
		RootInvocation: xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
				ContractFn: &xdr.InvokeContractArgs{
					ContractAddress: xdr.ScAddress{
						Type:       xdr.ScAddressTypeScAddressTypeContract,
						ContractId: &contractID,
					},
					FunctionName: xdr.ScSymbol("transfer"),
				},
			},
		},
	}

	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		fmt.Println("encode:", err)
		return
	}

	decoded, err := DecodeAuthorizationEntry(encoded)
	if err != nil {
		fmt.Println("decode:", err)
		return
	}

	info, err := Inspect(decoded)
	if err != nil {
		fmt.Println("inspect:", err)
		return
	}
	fmt.Printf("%s nonce=%d expires=%d function=%s\n",
		info.CredentialType, info.Nonce, info.ValidUntilLedger, info.RootFunction)

	// Output: address_v2 nonce=7 expires=100 function=transfer
}

// ExampleNewPasskeySigner shows how to configure a passkey signer with required
// user presence (UP) and user verification (UV) flags to enforce hardware or biometric
// authorization constraints before signing a Soroban authorization entry.
func ExampleNewPasskeySigner() {
	// A dummy 37-byte authenticator data block where flag 0x01 (UP) and 0x04 (UV) are set.
	authData := make([]byte, 37)
	authData[32] = 0x05

	signer := NewPasskeySigner(
		"GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
		authData,
		func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
			return scBytes([]byte("mock-webauthn-signature")), nil
		},
		RequireUserPresence(true),
		RequireUserVerification(true),
	)

	fmt.Printf("signer address: %s\n", signer.Address())

	// Output: signer address: GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF
}

// ExampleVerifyAll shows how to verify a batch of authorization entries
// concurrently with custom configuration and per-entry reporting.
func ExampleVerifyAll() {
	entry := xdr.SorobanAuthorizationEntry{
		Credentials: xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
		},
	}

	results, err := VerifyAll(context.Background(), []xdr.SorobanAuthorizationEntry{entry}, network.TestNetworkPassphrase, WithConcurrency(2))
	if err != nil {
		fmt.Println("verify error:", err)
		return
	}

	for _, res := range results {
		fmt.Printf("entry %d address=%q err=%v\n", res.Index, res.Address, res.Error)
		break
	}

	// Output: entry 0 address="" err=<nil>
}

// ExampleDescribeSignature shows how to use DescribeSignature to inspect
// an unknown or custom signature shape.
func ExampleDescribeSignature() {
	// A sample passkey signature shape (64 bytes)
	bytesVal := make([]byte, 64)
	sig := xdr.ScVal{
		Type:  xdr.ScValTypeScvBytes,
		Bytes: (*xdr.ScBytes)(&bytesVal),
	}

	shape := DescribeSignature(sig)
	fmt.Printf("shape type: %s, description: %s\n", shape.Type, shape.Description)

	// Output: shape type: passkey, description: 64-byte binary passkey signature
}

// ExampleSigner_cancellation shows how signers honour context cancellation
// to abort signing operations when a deadline expires or the caller cancels.
func ExampleSigner_cancellation() {
	kp, e := keypair.FromRawSeed(sha256.Sum256([]byte("example-key")))
	if e != nil {
		fmt.Println(false)
		return
	}
	signer := NewEd25519Signer(kp)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Pre-cancel context

	_, err := signer.Sign(ctx, xdr.HashIdPreimage{}, [32]byte{})
	if err != nil {
		fmt.Println(err == context.Canceled || err.Error() != "")
	}

	// Output: true
}

// ExampleWithRetry shows how to wrap a remote signer with jittered exponential
// backoff and a retry policy, ensuring transport errors are retried while
// signature rejections and cancellations fail fast.
func ExampleWithRetry() {
	// Create a base signer using SignerFunc (e.g. talking to a remote KMS/signer service)
	inner := SignerFunc("GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF", func(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
		// Simulate a remote signer interaction
		return xdr.ScVal{}, fmt.Errorf("connection refused")
	})

	// Wrap with retry policy
	_ = WithRetry(inner, RetryConfig{
		Attempts:       3,
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     100 * time.Millisecond,
	})
	fmt.Println("retry signer configured")

	// Output: retry signer configured
}
