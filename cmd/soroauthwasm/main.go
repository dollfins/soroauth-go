//go:build js && wasm

// Command soroauthwasm compiles the soroauth signing core to WebAssembly and
// exposes it to JavaScript on globalThis.soroauth.
//
// Rationale for the exported API surface:
//   - preimage: derives the signing HashIdPreimage and its 32-byte SHA-256 payload
//     locally in the browser, eliminating reliance on a trusted server.
//   - payload: hashes an already constructed preimage (base64 XDR) to its 32-byte
//     digest, supporting remote signers without entry reconstruction.
//   - writeSignature: writes an externally produced signature ScVal onto target
//     credential nodes, maintaining strict isolation of signing keys.
//   - authorizeWithSeed: provides a deterministic test and local demo path using
//     an in-memory raw ed25519 seed.
//
// Why this exists: passkey signing happens in the browser, and the browser
// should derive the bytes it signs rather than trust a server to hand them
// over. This binary is the smallest surface that makes that possible -- build a
// preimage, hash it to a payload, and write an externally produced signature
// back onto an entry. It is not a second implementation: every function here
// calls the same code the native library and CLI call, so the bytes cannot
// drift between the two.
//
// The whole package is behind `//go:build js && wasm`, so it is not compiled
// for any other target and `go build ./...` skips it on the host. CI builds it
// for js/wasm explicitly (see the wasm job in .github/workflows/ci.yml).
//
// Calling convention: every exported function returns an object
//
//	{ "ok": true,  ...result fields }        on success
//	{ "ok": false, "error": "message" }      on failure
//
// The TypeScript wrapper in wasm/ts turns a false `ok` into a thrown Error so
// callers never have to branch on a numeric code.
package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"syscall/js"

	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"
)

func main() {
	// Hold the js.Func values in a package-level slice: a js.Func that is only
	// reachable through the JS object can still be collected, and a collected
	// callback makes the next JS call fail with "invalid callback".
	functions := []js.Func{
		js.FuncOf(preimage),
		js.FuncOf(payload),
		js.FuncOf(writeSignature),
		js.FuncOf(authorizeWithSeed),
	}
	bindings = functions

	js.Global().Set("soroauth", js.ValueOf(map[string]any{
		"preimage":          functions[0],
		"payload":           functions[1],
		"writeSignature":    functions[2],
		"authorizeWithSeed": functions[3],
	}))

	// Keep the program alive so the callbacks remain callable from JS.
	select {}
}

// bindings keeps every exported js.Func reachable for the lifetime of the
// program.
var bindings []js.Func

// ok builds the success envelope.
func ok(fields map[string]any) map[string]any {
	out := map[string]any{"ok": true}
	for k, v := range fields {
		out[k] = v
	}
	return out
}

// fail builds the failure envelope. The message is the wrapped library error,
// which already names the operation, so the caller sees exactly what failed.
func fail(err error) map[string]any {
	return map[string]any{"ok": false, "error": err.Error()}
}

// decodeEntry parses a base64 XDR SorobanAuthorizationEntry.
func decodeEntry(b64 string) (xdr.SorobanAuthorizationEntry, error) {
	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(b64, &entry); err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: wasm: decoding entry: %w", err)
	}
	return entry, nil
}

// encodeEntry marshals an entry to base64 XDR.
func encodeEntry(entry xdr.SorobanAuthorizationEntry) (string, error) {
	raw, err := entry.MarshalBinary()
	if err != nil {
		return "", fmt.Errorf("soroauth: wasm: encoding entry: %w", err)
	}
	return base64.StdEncoding.EncodeToString(raw), nil
}

// options turns an optional target address into AuthorizeEntry options.
func options(forAddress string) []soroauth.AuthorizeOption {
	if forAddress == "" {
		return nil
	}
	return []soroauth.AuthorizeOption{soroauth.ForAddress(forAddress)}
}

// preimage(entryB64, validUntilLedger, networkPassphrase) ->
//
//	{ok, preimageXdr, payloadHex} | {ok:false, error}
//
// Source-account entries have no preimage (the envelope authenticates them), so
// they come back as a failure naming that, rather than an empty-but-successful
// result a caller might sign accidentally.
func preimage(this js.Value, args []js.Value) any {
	if len(args) != 3 {
		return fail(fmt.Errorf("soroauth: wasm: preimage expects 3 arguments"))
	}
	entry, err := decodeEntry(args[0].String())
	if err != nil {
		return fail(err)
	}
	p, err := soroauth.Preimage(entry, uint32(args[1].Int()), args[2].String())
	if err != nil {
		return fail(err)
	}
	raw, err := p.MarshalBinary()
	if err != nil {
		return fail(fmt.Errorf("soroauth: wasm: marshalling preimage: %w", err))
	}
	payload, err := soroauth.Payload(p)
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{
		"preimageXdr": base64.StdEncoding.EncodeToString(raw),
		"payloadHex":  hex.EncodeToString(payload[:]),
	})
}

// payload(preimageXdrBase64) -> {ok, payloadHex} | {ok:false, error}
//
// The separate entry point matters for remote signers: a service that receives
// only a preimage can return the exact bytes it expects to be signed without
// reconstructing the entry.
func payload(this js.Value, args []js.Value) any {
	if len(args) != 1 {
		return fail(fmt.Errorf("soroauth: wasm: payload expects 1 argument"))
	}
	var p xdr.HashIdPreimage
	if err := xdr.SafeUnmarshalBase64(args[0].String(), &p); err != nil {
		return fail(fmt.Errorf("soroauth: wasm: decoding preimage: %w", err))
	}
	digest, err := soroauth.Payload(p)
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"payloadHex": hex.EncodeToString(digest[:])})
}

// writeSignature(entryB64, validUntilLedger, networkPassphrase, forAddress,
// signatureScvalB64) -> {ok, entryB64} | {ok:false, error}
//
// This is the browser path: the signature bytes are produced elsewhere (a
// passkey, a remote signer) and this writes the produced ScVal onto every node
// whose address matches. An empty forAddress means "the entry's own
// top-level address".
func writeSignature(this js.Value, args []js.Value) any {
	if len(args) != 5 {
		return fail(fmt.Errorf("soroauth: wasm: writeSignature expects 5 arguments"))
	}
	entry, err := decodeEntry(args[0].String())
	if err != nil {
		return fail(err)
	}
	var signature xdr.ScVal
	if err := xdr.SafeUnmarshalBase64(args[4].String(), &signature); err != nil {
		return fail(fmt.Errorf("soroauth: wasm: decoding signature scval: %w", err))
	}

	forAddress := args[3].String()
	signerAddress := forAddress
	if signerAddress == "" {
		signerAddress, err = topLevelAddress(entry)
		if err != nil {
			return fail(err)
		}
	}
	signer := soroauth.SignerFunc(signerAddress, func(
		context.Context, xdr.HashIdPreimage, [32]byte,
	) (xdr.ScVal, error) {
		return signature, nil
	})

	signed, err := soroauth.AuthorizeEntry(
		context.Background(), entry, signer,
		uint32(args[1].Int()), args[2].String(), options(forAddress)...,
	)
	if err != nil {
		return fail(err)
	}
	encoded, err := encodeEntry(signed)
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"entryB64": encoded})
}

// authorizeWithSeed(entryB64, validUntilLedger, networkPassphrase, seedHex,
// forAddress) -> {ok, entryB64} | {ok:false, error}
//
// A convenience path for deterministic signers (conformance tests, and browser
// demos that hold a raw key in memory). It derives an ed25519 key from a raw
// 32-byte seed and signs exactly as the native library does.
func authorizeWithSeed(this js.Value, args []js.Value) any {
	if len(args) != 5 {
		return fail(fmt.Errorf("soroauth: wasm: authorizeWithSeed expects 5 arguments"))
	}
	entry, err := decodeEntry(args[0].String())
	if err != nil {
		return fail(err)
	}
	seedBytes, err := hex.DecodeString(strings.TrimSpace(args[3].String()))
	if err != nil {
		return fail(fmt.Errorf("soroauth: wasm: decoding seed: %w", err))
	}
	if len(seedBytes) != 32 {
		return fail(fmt.Errorf("soroauth: wasm: seed must be 32 bytes, got %d", len(seedBytes)))
	}
	var seed [32]byte
	copy(seed[:], seedBytes)
	kp, err := keypair.FromRawSeed(seed)
	if err != nil {
		return fail(fmt.Errorf("soroauth: wasm: deriving keypair: %w", err))
	}

	signed, err := soroauth.AuthorizeEntry(
		context.Background(), entry, soroauth.NewEd25519Signer(kp),
		uint32(args[1].Int()), args[2].String(), options(args[4].String())...,
	)
	if err != nil {
		return fail(err)
	}
	encoded, err := encodeEntry(signed)
	if err != nil {
		return fail(err)
	}
	return ok(map[string]any{"entryB64": encoded})
}

// topLevelAddress returns the credential address of an address-based entry.
func topLevelAddress(entry xdr.SorobanAuthorizationEntry) (string, error) {
	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		if entry.Credentials.Address == nil {
			return "", fmt.Errorf("soroauth: wasm: entry has no address")
		}
		return soroauth.FormatAddress(entry.Credentials.Address.Address)
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		if entry.Credentials.AddressV2 == nil {
			return "", fmt.Errorf("soroauth: wasm: entry has no v2 address")
		}
		return soroauth.FormatAddress(entry.Credentials.AddressV2.Address)
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		if entry.Credentials.AddressWithDelegates == nil {
			return "", fmt.Errorf("soroauth: wasm: entry has no delegate address")
		}
		return soroauth.FormatAddress(entry.Credentials.AddressWithDelegates.AddressCredentials.Address)
	default:
		return "", fmt.Errorf("soroauth: wasm: unsupported credential type")
	}
}
