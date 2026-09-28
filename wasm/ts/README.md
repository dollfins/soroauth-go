# @soroauth/wasm

A typed TypeScript wrapper around the [soroauth](../) WebAssembly signing core.

Passkey signing happens in the browser. This package lets the browser derive the
bytes it is about to sign — build the Soroban authorization preimage, hash it to
the 32-byte payload, and write the signature back onto the entry — instead of
trusting a server to hand over a payload. It calls through to the same Go code
the native library and CLI use; there is no second implementation to drift.

## Exported Symbol Rationale & Limitations

- `preimage`: Constructs and hashes authorization preimages locally. Throws for source-account entries.
- `payload`: Hashes raw base64 XDR preimages for remote signers.
- `writeSignature`: Applies external signatures (e.g., passkeys) to specific nodes.
- `authorizeWithSeed`: Facilitates local testing and demos with seed-based keypairs.

## Limitations & Production Readiness

This package handles client-side Soroban authorization signing and preimage generation. It does not submit transactions or estimate resource fees directly; callers must perform the two-pass simulation flow and fee computation on their backend or RPC client.

## Install

```sh
npm install @soroauth/wasm
```

## Usage (bundler)

```ts
import { loadSoroauth } from "@soroauth/wasm";
// The Go runtime shim ships in the package; import it for its side effect so
// globalThis.Go exists before loading.
import "@soroauth/wasm/wasm_exec.js";
import wasmUrl from "@soroauth/wasm/soroauth.wasm?url"; // Vite-style asset import

const soroauth = await loadSoroauth({
  wasm: wasmUrl,
  go: globalThis.Go,
});

// 1. Derive the payload locally -- never ask a server what to sign.
const { preimageXdr, payloadHex } = soroauth.preimage(
  entryBase64Xdr,
  validUntilLedger,
  networkPassphrase,
);

// 2. Sign payloadHex with a passkey, producing a signature ScVal (base64 XDR).

// 3. Write that signature back onto the entry.
const signedEntry = soroauth.writeSignature(
  entryBase64Xdr,
  validUntilLedger,
  networkPassphrase,
  forAddress, // "" means the entry's own top-level address
  signatureScvalBase64Xdr,
);
```

The bundler resolves `?url` however it is configured; any loader that yields the
wasm bytes or a URL to them works, including a plain `fetch`.

## Usage (script tag)

`wasm_exec.js` defines `Go` on the global object, and this module registers
`globalThis.Soroauth`:

```html
<script src="https://unpkg.com/@soroauth/wasm/dist/wasm_exec.js"></script>
<script type="module">
  import { loadSoroauth } from "https://unpkg.com/@soroauth/wasm/dist/index.js";
  const soroauth = await loadSoroauth({
    wasm: "https://unpkg.com/@soroauth/wasm/dist/soroauth.wasm",
    go: globalThis.Go,
  });
  globalThis.soroauth = soroauth; // or use globalThis.Soroauth.loadSoroauth
</script>
```

## API

| Method | Returns | Notes |
|---|---|---|
| `preimage(entryB64, validUntilLedger, networkPassphrase)` | `{ preimageXdr, payloadHex }` | Throws for a source-account entry: it has no preimage. |
| `payload(preimageXdrB64)` | hex string | For remote signers that only receive a preimage. |
| `writeSignature(entryB64, validUntilLedger, networkPassphrase, forAddress, signatureScvalB64)` | entry base64 XDR | Writes onto every node whose address matches. |
| `authorizeWithSeed(entryB64, validUntilLedger, networkPassphrase, seedHex, forAddress?)` | entry base64 XDR | Deterministic ed25519 path for tests and demos. |

Every failure is a thrown `SoroauthError` whose message is the module's own — for
example `preimage: soroauth: build preimage: credentials are source-account,
which carry no signature payload`. No numeric error codes.

`loadSoroauth` options:

- `wasm` — bytes, or a URL string to fetch.
- `go` — the `Go` class from the matching `wasm_exec.js`.
- `globalObject` — defaults to `globalThis`; pass an iframe's or Worker's global
  to isolate instances.
- `fetchImpl` — override `fetch`.
- `timeoutMs` — how long to wait for the module to install its bindings.

## About the Go runtime

Any Go wasm module needs the `wasm_exec.js` that matches the toolchain that
built it. The published tarball ships the matching shim as
`@soroauth/wasm/wasm_exec.js`; do not substitute a different version.

## Testing

```sh
npm test        # builds, then runs jsdom wrapper tests and real-wasm integration tests
```

The integration tests load `../dist/soroauth.wasm` and compare against the
repository's golden vectors. Build it first with `wasm/build.sh`; without it the
integration tests skip with a clear message and the wrapper tests still run.

## License

Apache-2.0, the same as the repository.
