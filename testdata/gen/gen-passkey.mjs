// Passkey signature-shape golden-vector generator for soroauth-go.
//
// The authorization-entry vectors in gen.mjs are proven against
// @stellar/stellar-sdk. This generator proves a different thing that the SDK
// does not cover: the *passkey* signature ScVal — the
// `{ public_key, signature }` map that a custom Soroban account's
// `__check_auth` decodes — is built byte-for-byte the way a real passkey wallet
// library builds it.
//
// Why a second reference: the passkey shape is not protocol-defined, so unlike
// the entry encoding there is no CAP to cite. The alternative to citing a
// specification is to reproduce a real implementation, which is what this file
// does. Hand-writing the expected bytes would only prove that the Go code
// agrees with itself (issue #27).
//
// THE REFERENCE. smart-account-kit, pinned exactly, is the reference
// implementation. It is the TypeScript SDK for OpenZeppelin smart accounts on
// Stellar with WebAuthn passkeys
// (https://github.com/stellar/smart-account-kit), and its
// `buildAddressSignatureScVal(publicKeyBytes, signatureBytes)` is the function
// that turns a passkey's public key and signature into the signature ScVal.
//
// Because that function is not re-exported from the package root, it is
// imported by file path from the pinned install. The version guard below reads
// the version that was actually loaded, and `npm ci` installs exactly the
// committed lockfile, so the reference cannot drift without this generator
// refusing to run or CI failing on the diff.
//
// WHAT IS COMPARED, AND WHAT IS NOT. The reference wraps the
// `{ public_key, signature }` map in a one-element vector:
//
//     scvVec([ scvMap([ public_key, signature ]) ])
//
// soroauth's Secp256r1SignatureScVal emits the *map itself* — the shape a
// `#[contracttype] struct` signature decodes as, which is what docs/passkeys.md
// targets. Each vector therefore records both:
//
//   - signature_map_xdr: the map element, taken out of the library's own
//     output, which soroauth must reproduce byte-for-byte; and
//   - library_scval_xdr: the library's complete return value, so the test can
//     also assert that it is exactly `scvVec([ soroauth's ScVal ])`.
//
// The vector does not claim that soroauth wraps its map in a vector, or that
// every wallet contract expects this shape: a custom account's signature shape
// is whatever its `__check_auth` declares. It claims the map's bytes and key
// order are the ones a real library produces.
//
// Never edit a file in testdata/vectors by hand. Regenerate with:
//
//     cd testdata/gen && npm ci && node gen.mjs && node gen-passkey.mjs
//
// CI runs exactly that and then `git diff --exit-code testdata/vectors`, so a
// hand-edited or stale vector fails the build.
//
// TEST KEYS. Every P-256 key below is derived deterministically from a label
// that is committed to this repository in plain text. They are therefore PUBLIC
// keys that anyone can derive. Never send real value to them, and never use
// them to authenticate anything.

import { createECDH, createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// Deep import on purpose: smart-account-kit does not re-export the signature
// builder from its package root, and its `exports` map blocks the bare
// specifier. The relative path is pinned with the version below.
import { buildAddressSignatureScVal } from "./node_modules/smart-account-kit/dist/kit/auth-payload.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(HERE, "..", "vectors", "passkey");

// The exact versions this generator is pinned to. A vector from another build
// is not evidence about this one, so the generator refuses to run rather than
// quietly recording something else.
const REQUIRED_LIBRARY = "smart-account-kit";
const REQUIRED_LIBRARY_VERSION = "0.8.0";
const REQUIRED_XDR_SDK_VERSION = "16.3.0";

// SCHEMA_VERSION is stamped into every vector and asserted by
// passkey_golden_test.go, so the two move together or the drift check fails.
const SCHEMA_VERSION = 1;

const readVersion = (path) =>
  JSON.parse(readFileSync(path, "utf8")).version;

// The library's own resolved @stellar/stellar-sdk, which is where its XDR
// types come from. It is nested under the library because the repository's
// direct dependency on 17.1.0 wins at the top level.
const librarySdkPackage = join(
  HERE,
  "node_modules",
  REQUIRED_LIBRARY,
  "node_modules",
  "@stellar",
  "stellar-sdk",
  "package.json",
);
const librarySdkPackagePath = existsSync(librarySdkPackage)
  ? librarySdkPackage
  : join(HERE, "node_modules", "@stellar", "stellar-sdk", "package.json");

const libraryVersion = readVersion(
  join(HERE, "node_modules", REQUIRED_LIBRARY, "package.json"),
);
const xdrSdkVersion = readVersion(librarySdkPackagePath);

if (libraryVersion !== REQUIRED_LIBRARY_VERSION) {
  console.error(
    `refusing to generate passkey vectors: ${REQUIRED_LIBRARY} is ` +
      `${libraryVersion}, this generator is pinned to ` +
      `${REQUIRED_LIBRARY_VERSION}. Run \`npm ci\` in testdata/gen.`,
  );
  process.exit(1);
}

if (xdrSdkVersion !== REQUIRED_XDR_SDK_VERSION) {
  console.error(
    `refusing to generate passkey vectors: ${REQUIRED_LIBRARY} resolved ` +
      `@stellar/stellar-sdk ${xdrSdkVersion}, this generator is pinned to ` +
      `${REQUIRED_XDR_SDK_VERSION}. Run \`npm ci\` in testdata/gen.`,
  );
  process.exit(1);
}

const LIBRARY = `${REQUIRED_LIBRARY}@${libraryVersion}`;
const XDR_SDK = `@stellar/stellar-sdk@${xdrSdkVersion}`;

// ---------------------------------------------------------------------------
// Fixed inputs
// ---------------------------------------------------------------------------

const sha256 = (label) => createHash("sha256").update(label).digest();

// The order of secp256r1's base point, so signature scalars can be reduced into
// the range the host and the Go parser both require (0 < r,s < n).
const P256_ORDER = BigInt(
  "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
);

// A deterministic P-256 public key, as uncompressed SEC1 (0x04 || X || Y). The
// private scalar is a hash of the label, so the point is fixed and genuinely on
// the curve — which matters because soroauth refuses an off-curve key rather
// than recording a shape it would never emit.
const publicKeyFor = (label) => {
  const ecdh = createECDH("prime256v1");
  ecdh.setPrivateKey(sha256(label));
  return ecdh.getPublicKey(); // 65 bytes, uncompressed
};

// The first label of a series whose public key satisfies predicate. Used to
// pin the key-byte edge cases (a leading zero byte, or bytes with the high bit
// set) without hand-editing key material.
const publicKeyMatching = (prefix, predicate) => {
  for (let i = 0; ; i++) {
    const publicKey = publicKeyFor(`${prefix}-${i}`);
    if (predicate(publicKey)) {
      return { label: `${prefix}-${i}`, publicKey };
    }
  }
};

const scalarFromLabel = (label) =>
  BigInt(`0x${sha256(label).toString("hex")}`) % P256_ORDER;

// r || s, each left-padded to 32 bytes, which is the fixed-width form the Go
// parser and the contract both require.
const signatureBytes = (r, s) =>
  Buffer.concat([
    Buffer.from(r.toString(16).padStart(64, "0"), "hex"),
    Buffer.from(s.toString(16).padStart(64, "0"), "hex"),
  ]);

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

// The key-byte edge cases search for their label, so derive them once here and
// fail loudly if the search ever stops finding one.
const highBitKey = publicKeyMatching(
  "soroauth-passkey-vector-key-highbit",
  (publicKey) => (publicKey[1] & 0x80) !== 0 && (publicKey[33] & 0x80) !== 0,
);
const leadingZeroKey = publicKeyMatching(
  "soroauth-passkey-vector-key-leading-zero",
  (publicKey) => publicKey[1] === 0x00,
);

const CASES = [
  // An ordinary key and two in-range scalars.
  {
    name: "passkey_signature_map_typical",
    label: "soroauth-passkey-vector-key-1",
    r: scalarFromLabel("soroauth-passkey-vector-r-1"),
    s: scalarFromLabel("soroauth-passkey-vector-s-1"),
  },
  // The smallest legal scalars, so both halves are 31 zero bytes followed by
  // one byte of value. A fixed-width encoder must left-pad them; a
  // length-prefixed or minimal encoder would emit 1-byte scalars instead.
  {
    name: "passkey_signature_map_min_scalars",
    label: "soroauth-passkey-vector-key-2",
    r: 1n,
    s: 1n,
  },
  // The largest legal scalars, n - 1, so every byte is set to its maximum.
  {
    name: "passkey_signature_map_max_scalars",
    label: "soroauth-passkey-vector-key-3",
    r: P256_ORDER - 1n,
    s: P256_ORDER - 1n,
  },
  // r with a genuinely leading zero byte: the top byte is forced to 0, which no
  // minimal-length encoding would ever produce.
  {
    name: "passkey_signature_map_leading_zero_scalar",
    label: "soroauth-passkey-vector-key-4",
    r:
      (scalarFromLabel("soroauth-passkey-vector-r-4") & ((1n << 248n) - 1n)) || 1n,
    s: scalarFromLabel("soroauth-passkey-vector-s-4"),
  },
  // A public key whose X and Y both have their high bit set.
  {
    name: "passkey_signature_map_high_bit_key",
    label: highBitKey.label,
    r: scalarFromLabel("soroauth-passkey-vector-r-5"),
    s: scalarFromLabel("soroauth-passkey-vector-s-5"),
  },
  // A public key whose X coordinate has a leading zero byte, so the fixed-width
  // 65-byte encoding must left-pad it back to 32 bytes.
  {
    name: "passkey_signature_map_leading_zero_key_byte",
    label: leadingZeroKey.label,
    r: scalarFromLabel("soroauth-passkey-vector-r-6"),
    s: scalarFromLabel("soroauth-passkey-vector-s-6"),
  },
];

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

const generate = (testCase) => {
  const publicKey = publicKeyFor(testCase.label);
  const signature = signatureBytes(testCase.r, testCase.s);

  const libraryScVal = buildAddressSignatureScVal(publicKey, signature);

  // Fail closed if the reference's shape moved: the vector records an element
  // of this vector, so it is only meaningful if the vector has exactly the
  // element the map is expected to be.
  if (libraryScVal.switch().name !== "scvVec") {
    throw new Error(
      `${testCase.name}: ${LIBRARY} returned ${libraryScVal.switch().name}, ` +
        `want a vector`,
    );
  }
  const elements = libraryScVal.vec() ?? [];
  if (elements.length !== 1 || elements[0].switch().name !== "scvMap") {
    throw new Error(
      `${testCase.name}: ${LIBRARY} returned a vector of ${elements.length} ` +
        `elements, want exactly one map`,
    );
  }

  // The library's own inner map, not a hand-built equivalent: this is the
  // element soroauth must reproduce.
  const signatureMap = elements[0];

  return {
    schema_version: SCHEMA_VERSION,
    name: testCase.name,
    library: LIBRARY,
    xdr_sdk: XDR_SDK,
    public_key_hex: publicKey.toString("hex"),
    signature_hex: signature.toString("hex"),
    signature_map_xdr: signatureMap.toXDR("base64"),
    library_scval_xdr: libraryScVal.toXDR("base64"),
  };
};

mkdirSync(OUT_DIR, { recursive: true });

for (const testCase of CASES) {
  const vector = generate(testCase);
  const path = join(OUT_DIR, `${vector.name}.json`);
  writeFileSync(path, `${JSON.stringify(vector, null, 2)}\n`);
  console.log(
    `wrote passkey/${vector.name}.json  key=${vector.public_key_hex.slice(0, 8)}…`,
  );
}

console.log(`\n${CASES.length} passkey vectors generated with ${LIBRARY} (${XDR_SDK})`);
