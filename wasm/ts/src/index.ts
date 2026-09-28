/**
 * @soroauth/wasm -- a typed wrapper around the soroauth WebAssembly signing
 * core.
 *
 * Exported API Rationale:
 *   - preimage: constructs and hashes authorization preimages locally.
 *   - payload: hashes raw base64 XDR preimages for remote signers.
 *   - writeSignature: applies external signatures (e.g., passkeys) to specific nodes.
 *   - authorizeWithSeed: facilitates local testing with seed-based keypairs.
 *
 * The core builds a Soroban authorization preimage, hashes it to the payload a
 * signer signs, and writes an externally produced signature back onto an entry.
 * That is the whole browser signing path for passkeys: the wallet derives the
 * bytes locally and never trusts a server to tell it what to sign.
 *
 * This module is a wrapper, not a reimplementation. Every function calls through
 * to the Go code compiled to wasm, so there is no TypeScript copy of the signing
 * logic to drift from the library.
 *
 * Loading requires the `Go` class from Go's `wasm_exec.js`, exactly as any Go
 * wasm program does. In a browser, load it with a script tag before this module:
 *
 * ```html
 * <script src="wasm_exec.js"></script>
 * <script type="module">
 *   import { loadSoroauth } from "./index.js";
 *   const soroauth = await loadSoroauth({
 *     wasm: "soroauth.wasm",
 *     go: globalThis.Go,
 *   });
 * </script>
 * ```
 *
 * In a bundler, import the shim's module form (or vendor it) and pass the class.
 */

import { SoroauthError } from "./errors.js";
import type {
  GlobalLike,
  GoConstructor,
  PreimageResult,
  RawBindings,
  RawEnvelope,
} from "./types.js";

export { SoroauthError } from "./errors.js";
export type {
  GlobalLike,
  GoConstructor,
  GoInstance,
  PreimageResult,
} from "./types.js";

/**
 * The ergonomic signing core. Every method throws {@link SoroauthError} on
 * failure; none returns a result envelope to check.
 */
export interface Soroauth {
  /**
   * Build the preimage for an address-credential entry and hash it.
   *
   * Throws for a source-account entry, which has no preimage: the transaction
   * envelope authenticates it. Failing here is deliberate -- returning an empty
   * "success" for an entry with nothing to sign is how a caller ends up signing
   * the wrong bytes.
   */
  preimage(
    entryB64: string,
    validUntilLedger: number,
    networkPassphrase: string,
  ): PreimageResult;

  /** Hash a preimage (base64 XDR) to its 32-byte payload, as hex. */
  payload(preimageXdrB64: string): string;

  /**
   * Write an already-produced signature ScVal (base64 XDR) onto every node
   * whose address matches. Pass an empty `forAddress` to target the entry's own
   * top-level address.
   */
  writeSignature(
    entryB64: string,
    validUntilLedger: number,
    networkPassphrase: string,
    forAddress: string,
    signatureScvalB64: string,
  ): string;

  /**
   * Sign an entry with an in-memory ed25519 key given as a 32-byte raw seed
   * (hex). Intended for deterministic tests and demos; real wallets should
   * build a payload and use {@link writeSignature} with their own signer.
   */
  authorizeWithSeed(
    entryB64: string,
    validUntilLedger: number,
    networkPassphrase: string,
    seedHex: string,
    forAddress?: string,
  ): string;
}

/** Options for {@link loadSoroauth}. */
export interface LoadOptions {
  /** The wasm bytes, or a URL string to fetch them from. */
  wasm: string | ArrayBuffer | Uint8Array<ArrayBuffer>;
  /** The `Go` class from the matching `wasm_exec.js`. */
  go: GoConstructor;
  /**
   * The object the module installs `soroauth` on. Defaults to `globalThis`.
   * Pass an iframe's or Worker's global to isolate instances.
   */
  globalObject?: GlobalLike;
  /** Override `fetch`, e.g. for a custom loader or a test double. */
  fetchImpl?: typeof fetch;
  /** How long to wait for the module to install its bindings. Default 5000ms. */
  timeoutMs?: number;
}

async function resolveWasm(
  source: LoadOptions["wasm"],
  fetchImpl: typeof fetch | undefined,
): Promise<ArrayBuffer | Uint8Array<ArrayBuffer>> {
  if (typeof source !== "string") {
    return source;
  }
  const doFetch = fetchImpl ?? globalThis.fetch;
  if (typeof doFetch !== "function") {
    throw new SoroauthError(
      "no fetch implementation available to load the wasm module from a URL; pass bytes directly or provide fetchImpl",
    );
  }
  let response: Response;
  try {
    response = await doFetch(source);
  } catch (cause) {
    throw new SoroauthError(`fetching the wasm module from ${source} failed`, { cause });
  }
  if (!response.ok) {
    throw new SoroauthError(
      `fetching the wasm module from ${source} failed: HTTP ${response.status}`,
    );
  }
  return new Uint8Array(await response.arrayBuffer());
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForBindings(
  globalObject: GlobalLike,
  timeoutMs: number,
): Promise<RawBindings> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (globalObject.soroauth) {
      return globalObject.soroauth;
    }
    if (Date.now() >= deadline) {
      throw new SoroauthError(
        `timed out after ${timeoutMs}ms waiting for the module to install its bindings`,
      );
    }
    await sleep(10);
  }
}

function unwrap<T extends RawEnvelope>(envelope: T, operation: string): T {
  if (!envelope || envelope.ok !== true) {
    throw new SoroauthError(
      `${operation}: ${envelope?.error ?? "the module returned no result"}`,
    );
  }
  return envelope;
}

function requireField(value: string | undefined, field: string, operation: string): string {
  if (typeof value !== "string") {
    throw new SoroauthError(`${operation}: the module did not return ${field}`);
  }
  return value;
}

function wrap(raw: RawBindings): Soroauth {
  return {
    preimage(entryB64, validUntilLedger, networkPassphrase) {
      const result = unwrap(
        raw.preimage(entryB64, validUntilLedger, networkPassphrase),
        "preimage",
      );
      return {
        preimageXdr: requireField(result.preimageXdr, "preimageXdr", "preimage"),
        payloadHex: requireField(result.payloadHex, "payloadHex", "preimage"),
      };
    },
    payload(preimageXdrB64) {
      const result = unwrap(raw.payload(preimageXdrB64), "payload");
      return requireField(result.payloadHex, "payloadHex", "payload");
    },
    writeSignature(
      entryB64,
      validUntilLedger,
      networkPassphrase,
      forAddress,
      signatureScvalB64,
    ) {
      const result = unwrap(
        raw.writeSignature(
          entryB64,
          validUntilLedger,
          networkPassphrase,
          forAddress,
          signatureScvalB64,
        ),
        "writeSignature",
      );
      return requireField(result.entryB64, "entryB64", "writeSignature");
    },
    authorizeWithSeed(
      entryB64,
      validUntilLedger,
      networkPassphrase,
      seedHex,
      forAddress = "",
    ) {
      const result = unwrap(
        raw.authorizeWithSeed(
          entryB64,
          validUntilLedger,
          networkPassphrase,
          seedHex,
          forAddress,
        ),
        "authorizeWithSeed",
      );
      return requireField(result.entryB64, "entryB64", "authorizeWithSeed");
    },
  };
}

/**
 * Instantiate the signing core and return the typed API.
 *
 * The Go program blocks after installing its bindings, so the underlying `run`
 * promise never settles; that is expected, not a leak.
 */
export async function loadSoroauth(options: LoadOptions): Promise<Soroauth> {
  const globalObject = options.globalObject ?? (globalThis as unknown as GlobalLike);
  const timeoutMs = options.timeoutMs ?? 5000;

  const wasm = await resolveWasm(options.wasm, options.fetchImpl);
  const go = new options.go();

  const instantiated = await WebAssembly.instantiate(wasm, go.importObject);
  // Deliberately not awaited: the module runs until it blocks on select{}.
  void go.run(instantiated.instance);

  const raw = await waitForBindings(globalObject, timeoutMs);
  return wrap(raw);
}

/**
 * The script-tag surface. When this module is loaded with
 * `<script type="module">`, the same functions are also reachable as
 * `globalThis.Soroauth`.
 */
export const SoroauthGlobal = {
  loadSoroauth,
  SoroauthError,
} as const;

declare global {
  // eslint-disable-next-line no-var
  var Soroauth: typeof SoroauthGlobal | undefined;
}

if (typeof globalThis !== "undefined") {
  (globalThis as { Soroauth?: typeof SoroauthGlobal }).Soroauth ??= SoroauthGlobal;
}
