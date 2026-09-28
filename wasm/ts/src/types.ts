/**
 * Types for the soroauth WebAssembly signing core.
 *
 * Exported Symbol Rationale:
 *   - RawBindings / Soroauth: exposes only the narrowed core functions needed
     //   for browser passkey signing, preimage derivation, and signature attachment.
 *
 * The Go module returns a plain object per call. On success it carries
 * `ok: true` plus the result fields; on failure `ok: false` and a message. These
 * raw shapes are described here (the module is the contract), while
 * {@link PreimageResult} and the `Soroauth` interface describe the ergonomic
 * surface the wrapper presents, where failures are thrown instead of returned.
 */

/** The `Go` class defined by Go's `wasm_exec.js`. */
export interface GoInstance {
  /** The import object the module is instantiated with. */
  readonly importObject: WebAssembly.Imports;
  /** Runs the program. It never settles while the module blocks. */
  run(instance: WebAssembly.Instance): Promise<void>;
  argv?: string[];
  env?: Record<string, string>;
}

/** Constructor for {@link GoInstance}; this is `globalThis.Go`. */
export interface GoConstructor {
  new (): GoInstance;
}

/** A raw result envelope as returned from the module. */
export interface RawEnvelope {
  readonly ok: boolean;
  readonly error?: string;
}

/** Raw result of `preimage`. */
export interface RawPreimageResult extends RawEnvelope {
  readonly preimageXdr?: string;
  readonly payloadHex?: string;
}

/** Raw result of `payload`. */
export interface RawPayloadResult extends RawEnvelope {
  readonly payloadHex?: string;
}

/** Raw result of `writeSignature` and `authorizeWithSeed`. */
export interface RawEntryResult extends RawEnvelope {
  readonly entryB64?: string;
}

/**
 * The bindings the module installs on its global object. Application code
 * should not use these directly; {@link Soroauth} wraps them so a failure is a
 * thrown error rather than a value to check.
 */
export interface RawBindings {
  preimage(
    entryB64: string,
    validUntilLedger: number,
    networkPassphrase: string,
  ): RawPreimageResult;
  payload(preimageXdrB64: string): RawPayloadResult;
  writeSignature(
    entryB64: string,
    validUntilLedger: number,
    networkPassphrase: string,
    forAddress: string,
    signatureScvalB64: string,
  ): RawEntryResult;
  authorizeWithSeed(
    entryB64: string,
    validUntilLedger: number,
    networkPassphrase: string,
    seedHex: string,
    forAddress: string,
  ): RawEntryResult;
}

/**
 * The global object the module installs its bindings on. In a normal page this
 * is `globalThis`; pass an iframe's or Worker's global to keep two modules from
 * colliding.
 */
export interface GlobalLike {
  soroauth?: RawBindings;
  [key: string]: unknown;
}

/** The result of building a preimage. */
export interface PreimageResult {
  /** Base64 XDR of the `HashIdPreimage`. */
  readonly preimageXdr: string;
  /** Hex SHA-256 of the preimage: the 32 bytes the signer signs. */
  readonly payloadHex: string;
}
