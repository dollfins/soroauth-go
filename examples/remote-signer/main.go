package main

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
	"github.com/soroauth/soroauth-go/remote"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "remote signer example:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	key, err := keypair.Random()
	if err != nil {
		return fmt.Errorf("generate demo signing key: %w", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("listen on loopback: %w", err)
	}
	defer listener.Close()

	server := remote.NewServer(soroauth.NewEd25519Signer(key))
	server.Approver = func(approval remote.Approval) {
		inspectPreimage(approval)
	}
	httpServer := &http.Server{Handler: server}
	go func() {
		_ = httpServer.Serve(listener)
	}()
	defer httpServer.Close()

	client := remote.NewSigner("http://"+listener.Addr().String(), key.Address())
	contractID := xdr.ContractId(sha256.Sum256([]byte("remote-signer-example-contract")))
	invocation := xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: xdr.ScAddress{
					Type:       xdr.ScAddressTypeScAddressTypeContract,
					ContractId: &contractID,
				},
				FunctionName: xdr.ScSymbol("approve"),
				Args:         []xdr.ScVal{},
			},
		},
	}

	fmt.Printf("client: requesting a signature for %s\n", key.Address())
	entry, err := soroauth.AuthorizeInvocation(ctx, soroauth.AuthorizeInvocationParams{
		Signer:            client,
		Invocation:        invocation,
		ValidUntilLedger:  1234567,
		NetworkPassphrase: network.TestNetworkPassphrase,
	})
	if err != nil {
		return fmt.Errorf("authorize invocation through remote signer: %w", err)
	}

	report, err := soroauth.VerifyEntry(entry, network.TestNetworkPassphrase)
	if err != nil {
		return fmt.Errorf("verify remotely signed entry: %w", err)
	}
	if !report.Verified() {
		return fmt.Errorf("remote signature did not verify: %+v", report.Nodes)
	}
	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		return fmt.Errorf("encode signed entry: %w", err)
	}
	fmt.Println("client: signature verified")
	fmt.Printf("signed entry XDR (base64): %s\n", encoded)
	return nil
}

func inspectPreimage(approval remote.Approval) {
	encoded, err := xdr.MarshalBase64(approval.Preimage)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server: encode inspected preimage: %v\n", err)
		return
	}
	fmt.Println("server: inspected decoded preimage before signing")
	fmt.Printf("  address: %s\n", approval.Address)
	fmt.Printf("  variant: %s\n", approval.Preimage.Type)
	fmt.Printf("  payload: %x\n", approval.Payload)
	fmt.Printf("  preimage XDR (base64): %s\n", encoded)

	var invocation xdr.SorobanAuthorizedInvocation
	switch approval.Preimage.Type {
	case xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorization:
		if approval.Preimage.SorobanAuthorization != nil {
			invocation = approval.Preimage.SorobanAuthorization.Invocation
			fmt.Printf("  nonce: %d\n", approval.Preimage.SorobanAuthorization.Nonce)
			fmt.Printf("  valid until ledger: %d\n", approval.Preimage.SorobanAuthorization.SignatureExpirationLedger)
		}
	case xdr.EnvelopeTypeEnvelopeTypeSorobanAuthorizationWithAddress:
		if approval.Preimage.SorobanAuthorizationWithAddress != nil {
			invocation = approval.Preimage.SorobanAuthorizationWithAddress.Invocation
			fmt.Printf("  nonce: %d\n", approval.Preimage.SorobanAuthorizationWithAddress.Nonce)
			fmt.Printf("  valid until ledger: %d\n", approval.Preimage.SorobanAuthorizationWithAddress.SignatureExpirationLedger)
		}
	}
	if invocation.Function.ContractFn != nil {
		contract, err := soroauth.FormatAddress(invocation.Function.ContractFn.ContractAddress)
		if err != nil {
			fmt.Fprintf(os.Stderr, "server: format inspected contract address: %v\n", err)
			return
		}
		fmt.Printf("  invocation: %s.%s\n", contract, invocation.Function.ContractFn.FunctionName)
	}
}
