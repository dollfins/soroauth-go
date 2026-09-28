// A Node check for the browser demo's logic.
//
// Issue #55's page needs a browser, a platform authenticator, and a deployed
// passkey wallet contract on testnet, so CI cannot run it end to end. This
// check runs everything about it that does not: the SDK calls it makes, the
// credential-arm walk, the explorer link, the DER-to-compact conversion, and
// the signature ScVal shape. It is what caught the demo being written against
// @stellar/stellar-sdk 16.x accessor methods (`entry.credentials()`,
// `credentials.switch().name`, `new xdr.ScSymbol(...)`, `new xdr.ScMap(...)`)
// while importing 17.1.0, whose bindings expose properties and a `type`
// discriminant and whose factories take plain values. Nothing in the browser
// would have reported that as anything but a mystery.
//
// Why the import is rewritten: the demo is a static page, so it loads the SDK
// from a CDN URL. Node cannot resolve that. This harness replaces the one
// specifier with a path to the SDK copy pinned in testdata/gen — if the
// specifier moves, the check fails loudly rather than silently testing the
// wrong file.
//
// Run from the repository root, after `cd testdata/gen && npm ci`:
//
//     node examples/browser-passkey/app.test.mjs

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { tmpdir } from "node:os";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..", "..");

const SDK_URL = '"https://esm.sh/@stellar/stellar-sdk@17.1.0"';
const SDK_PATH = join(
  ROOT,
  "testdata",
  "gen",
  "node_modules",
  "@stellar",
  "stellar-sdk",
  "lib",
  "esm",
  "index.js",
);

let failures = 0;
const check = (condition, description) => {
  if (condition) {
    console.log(`ok   - ${description}`);
  } else {
    failures++;
    console.error(`FAIL - ${description}`);
  }
};

const appSource = readFileSync(join(HERE, "app.js"), "utf8");
if (!appSource.includes(SDK_URL)) {
  console.error(
    `FAIL - app.js no longer imports ${SDK_URL}, so this check cannot map it to the pinned SDK`,
  );
  process.exit(1);
}

// The rewritten copy goes to the OS temp directory, never into the repository.
const rewritten = join(tmpdir(), "soroauth-browser-demo-app.mjs");
writeFileSync(
  rewritten,
  appSource.replace(SDK_URL, JSON.stringify(SDK_PATH)),
);

const app = await import(pathToFileURL(rewritten).href);
const sdk = await import(pathToFileURL(SDK_PATH).href);
const {
  Account,
  Address,
  Asset,
  BASE_FEE,
  Keypair,
  Networks,
  TransactionBuilder,
  xdr,
} = sdk;

// --- the SDK calls the submit flow makes -----------------------------------

const contractId = Asset.native().contractId(Networks.TESTNET);
check(
  typeof contractId === "string" && contractId.startsWith("C"),
  `Asset#contractId resolves the native SAC to ${contractId}`,
);
check(
  contractId === "CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC",
  "the testnet native SAC id is the published one",
);

const destination = Keypair.random().publicKey();
const wallet = new Address(Keypair.random().publicKey()).toString();
const operation = app.transferOperation(
  contractId,
  { wallet, destination, amount: "10000000" },
  undefined,
);
check(
  operation && typeof operation.toXdr === "function",
  "transferOperation builds an operation the builder accepts",
);

const payer = new Account(Keypair.random().publicKey(), "0");
const tx = new TransactionBuilder(payer, {
  fee: BASE_FEE,
  networkPassphrase: Networks.TESTNET,
})
  .addOperation(operation)
  .setTimeout(60)
  .build();
check(
  TransactionBuilder.fromXDR(tx.toXdr("base64"), Networks.TESTNET).toXdr(
    "base64",
  ) === tx.toXdr("base64"),
  "a transaction carrying that operation round-trips through XDR",
);

// --- the credential-arm walk ------------------------------------------------

const scAddress = new Address(destination).toScAddress();
const rootInvocation = new xdr.SorobanAuthorizedInvocation({
  function:
    xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: scAddress,
        functionName: "transfer",
        args: [],
      }),
    ),
  subInvocations: [],
});

const v2Entry = new xdr.SorobanAuthorizationEntry({
  rootInvocation,
  credentials: xdr.SorobanCredentials.sorobanCredentialsAddressV2(
    new xdr.SorobanAddressCredentials({
      address: scAddress,
      nonce: 1n,
      signatureExpirationLedger: 0,
      signature: xdr.ScVal.scvVoid(),
    }),
  ),
});
check(
  app.credentialAddress(v2Entry) === destination,
  "credentialAddress reads the V2 arm",
);

const legacyEntry = new xdr.SorobanAuthorizationEntry({
  rootInvocation,
  credentials: xdr.SorobanCredentials.sorobanCredentialsAddress(
    new xdr.SorobanAddressCredentials({
      address: scAddress,
      nonce: 1n,
      signatureExpirationLedger: 0,
      signature: xdr.ScVal.scvVoid(),
    }),
  ),
});
check(
  app.credentialAddress(legacyEntry) === destination,
  "credentialAddress reads the legacy arm",
);

const sourceEntry = new xdr.SorobanAuthorizationEntry({
  rootInvocation,
  credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
});
check(
  app.credentialAddress(sourceEntry) === null,
  "credentialAddress reports no address for the source-account arm",
);

// --- the explorer link ------------------------------------------------------

check(
  app.explorerLink("abc", Networks.TESTNET) ===
    "https://stellar.expert/explorer/testnet/tx/abc",
  "explorerLink builds a testnet link",
);
check(
  app.explorerLink("abc", Networks.PUBLIC) ===
    "https://stellar.expert/explorer/public/tx/abc",
  "explorerLink builds a public link",
);

// --- the assertion conversion -----------------------------------------------

const der = new Uint8Array([
  0x30, 0x08, 0x02, 0x02, 0x00, 0x01, 0x02, 0x02, 0x00, 0x02,
]);
const compact = app.deriveCompactSignature(der);
check(compact.length === 64, "deriveCompactSignature returns 64 bytes");
check(
  compact[31] === 0x01 && compact[63] === 0x02,
  "deriveCompactSignature left-pads r and s to 32 bytes each",
);

// --- the signature ScVal ----------------------------------------------------

const publicKey = app.uncompressedPublicKey({
  x: new Uint8Array(32).fill(7),
  y: new Uint8Array(32).fill(9),
});
check(
  publicKey.length === 65 && publicKey[0] === 0x04,
  "uncompressedPublicKey is 65 bytes with the 0x04 SEC1 prefix",
);

const signatureScVal = app.passkeySignatureScVal(
  publicKey,
  new Uint8Array(64).fill(2),
);
check(
  signatureScVal.type === "scvMap" && signatureScVal.map.length === 2,
  "the passkey signature ScVal is a two-entry map",
);
check(
  signatureScVal.map.map((entry) => entry.key.sym.toString()).join(",") ===
    "public_key,signature",
  "its keys are public_key then signature, the host's sort order",
);
check(
  signatureScVal.map[0].val.bytes.value.length === 65 &&
    signatureScVal.map[1].val.bytes.value.length === 64,
  "it carries the 65-byte public key and the 64-byte signature",
);

// --- the challenge-binding check ---------------------------------------------
//
// The bug this replaced: an earlier revision of the demo (following an earlier
// revision of docs/passkeys.md) compared SHA-256(clientDataJSON) against the
// payload, which can never hold — the hash of the whole client data is not the
// payload. These cases pin the corrected check.

const payload = new Uint8Array(32).fill(0x2a);
const payloadHex = Buffer.from(payload).toString("hex");
const canonicalChallenge = Buffer.from(payload).toString("base64url");
const clientData = (overrides = {}) =>
  new TextEncoder().encode(
    JSON.stringify({
      type: "webauthn.get",
      challenge: canonicalChallenge,
      origin: "http://localhost:8000",
      ...overrides,
    }),
  );

check(
  app.challengeEncodings(payloadHex).includes(canonicalChallenge) &&
    app.challengeEncodings(payloadHex).includes(payloadHex),
  "challengeEncodings offers the base64url and hex spellings of the payload",
);
check(
  app.verifyChallengeBinding(clientData(), payloadHex).type === "webauthn.get",
  "verifyChallengeBinding accepts the payload as the challenge",
);
check(
  app.verifyChallengeBinding(clientData({ challenge: payloadHex }), payloadHex) !==
    null,
  "verifyChallengeBinding accepts a hex-encoded challenge",
);

let rejected = 0;
const rejects = (fn, description) => {
  let threw = false;
  try {
    fn();
  } catch {
    threw = true;
  }
  rejected++;
  check(threw, description);
};

rejects(
  () =>
    app.verifyChallengeBinding(
      clientData({
        challenge: Buffer.from(new Uint8Array(32).fill(0x2b)).toString(
          "base64url",
        ),
      }),
      payloadHex,
    ),
  "verifyChallengeBinding rejects a challenge for a different payload",
);
rejects(
  () =>
    app.verifyChallengeBinding(clientData({ type: "webauthn.create" }), payloadHex),
  "verifyChallengeBinding rejects a non-assertion ceremony",
);
rejects(
  () => app.verifyChallengeBinding(new TextEncoder().encode("not json"), payloadHex),
  "verifyChallengeBinding rejects malformed client data",
);
rejects(
  () => app.verifyChallengeBinding(clientData({ challenge: "" }), payloadHex),
  "verifyChallengeBinding rejects an empty challenge",
);
check(rejected === 4, "all four rejection cases ran");

if (failures > 0) {
  console.error(`\n${failures} check(s) failed`);
  process.exit(1);
}
console.log("\nall browser-demo checks passed");
