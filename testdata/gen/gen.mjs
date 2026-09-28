// Golden-vector generator for soroauth-go.
//
// @stellar/stellar-sdk is the reference implementation this library is proven
// against. Every vector written here is produced by the JS SDK, and
// golden_test.go asserts that the Go code reproduces the preimage, the payload
// hash and the final signed entry byte for byte. If the two ever disagree, the
// Go side is wrong until proven otherwise.
//
// Never edit a file in testdata/vectors by hand. Regenerate with:
//
//     cd testdata/gen && npm ci && node gen.mjs
//
// CI runs exactly that and then `git diff --exit-code testdata/vectors`, so a
// hand-edited or stale vector fails the build.
//
// Every input is fixed so the output is reproducible: ed25519 signatures are
// deterministic (RFC 8032), so identical inputs give identical signature bytes
// in any correct implementation.
//
// TEST KEYS. Every keypair below is derived as
// Keypair.fromRawEd25519Seed(sha256(label)) from a label that is committed to
// this repository in plain text. They are therefore PUBLIC keys that anyone can
// derive and spend from. They exist only to make signatures reproducible.
// Never send real value to them, and never fund them on mainnet.

import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  Address,
  Keypair,
  Networks,
  authorizeEntry,
  buildAuthorizationEntryPreimage,
  buildWithDelegatesEntry,
  hash,
  xdr,
} from "@stellar/stellar-sdk";

const HERE = dirname(fileURLToPath(import.meta.url));
const OUT_DIR = join(HERE, "..", "vectors");

// The exact version this generator is pinned to. Vectors are only meaningful
// if they came from a known reference build.
const REQUIRED_SDK_VERSION = "17.1.0";

// Read the version from the package that was actually loaded, rather than
// trusting a hand-typed constant.
const loadedVersion = JSON.parse(
  readFileSync(
    join(HERE, "node_modules", "@stellar", "stellar-sdk", "package.json"),
    "utf8",
  ),
).version;

if (loadedVersion !== REQUIRED_SDK_VERSION) {
  console.error(
    `refusing to generate vectors: @stellar/stellar-sdk is ${loadedVersion}, ` +
      `this generator is pinned to ${REQUIRED_SDK_VERSION}. ` +
      `Run \`npm ci\` in testdata/gen.`,
  );
  process.exit(1);
}

const SDK = `@stellar/stellar-sdk@${loadedVersion}`;

// SCHEMA_VERSION is the version stamped into every vector. golden_test.go
// asserts it, so the two move together or the drift check fails.
const SCHEMA_VERSION = 1;

// ---------------------------------------------------------------------------
// Fixed inputs
// ---------------------------------------------------------------------------

const sha256 = (label) => createHash("sha256").update(label).digest();

const keypairFor = (label) => Keypair.fromRawEd25519Seed(sha256(label));

const SIGNER_1 = "soroauth-vector-signer-1";
const SIGNER_2 = "soroauth-vector-signer-2";

// One fixed expiration ledger for every vector, so a payload that differs
// differs for a reason the vector names.
const VALID_UNTIL_LEDGER = 1234567;

// Per-case override for validUntilLedger. Used for expiration boundary
// vectors (#116).
const caseValidUntilLedger = (name) => {
  if (name === "v2_expiration_boundary_1") return 1;
  if (name === "v2_expiration_boundary_max") return 4294967295;
  return VALID_UNTIL_LEDGER;
};

// Fixed nonces, chosen to cover the interesting int64 values: an ordinary
// positive one, the maximum, and the minimum (negative). A nonce is a signed
// int64 on the wire, so sign handling is part of what these vectors prove.
const NONCE_ORDINARY = 1234567890123456789n;
const NONCE_MAX = 9223372036854775807n; // 2^63 - 1
const NONCE_MIN = -9223372036854775808n; // -2^63

const scAddress = (label) => new Address(keypairFor(label).publicKey()).toScAddress();

const contractAddress = (label) =>
  new Address(Address.contract(sha256(label)).toString()).toScAddress();

// An invocation carrying a deliberately wide spread of ScVal types, so the
// vectors exercise the encoder rather than just the common i128 transfer.
const invocationWithManyArgTypes = () =>
  new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: contractAddress("soroauth-vector-contract-1"),
        functionName: "transfer",
        args: [
          xdr.ScVal.scvVoid(),
          xdr.ScVal.scvBool(true),
          xdr.ScVal.scvU32(7),
          xdr.ScVal.scvI32(-7),
          xdr.ScVal.scvU64(xdr.Uint64(18446744073709551615n)),
          xdr.ScVal.scvI64(xdr.Int64(-9007199254740993n)),
          xdr.ScVal.scvSymbol("transfer"),
          xdr.ScVal.scvString("a string argument"),
          xdr.ScVal.scvBytes(Buffer.from("soroauth", "utf8")),
          xdr.ScVal.scvAddress(scAddress(SIGNER_2)),
          xdr.ScVal.scvAddress(contractAddress("soroauth-vector-contract-2")),
          xdr.ScVal.scvVec([xdr.ScVal.scvU32(1), xdr.ScVal.scvU32(2)]),
          xdr.ScVal.scvMap([
            new xdr.ScMapEntry({
              key: xdr.ScVal.scvSymbol("amount"),
              val: xdr.ScVal.scvI128(
                new xdr.Int128Parts({ hi: xdr.Int64(-1n), lo: xdr.Uint64(42n) }),
              ),
            }),
          ]),
        ],
      }),
    ),
    subInvocations: [],
  });

// A call tree two levels deep, so the recursive part of the encoding is covered.
const invocationWithSubInvocations = () => {
  const leaf = (name, contractLabel) =>
    new xdr.SorobanAuthorizedInvocation({
      function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
        new xdr.InvokeContractArgs({
          contractAddress: contractAddress(contractLabel),
          functionName: name,
          args: [xdr.ScVal.scvU32(1)],
        }),
      ),
      subInvocations: [],
    });

  const middle = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: contractAddress("soroauth-vector-contract-2"),
        functionName: "approve",
        args: [xdr.ScVal.scvSymbol("inner")],
      }),
    ),
    subInvocations: [
      leaf("deep_one", "soroauth-vector-contract-3"),
      leaf("deep_two", "soroauth-vector-contract-4"),
    ],
  });

  return new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: contractAddress("soroauth-vector-contract-1"),
        functionName: "swap",
        args: [xdr.ScVal.scvAddress(scAddress(SIGNER_1))],
      }),
    ),
    subInvocations: [middle],
  });
};

// A create-contract invocation, which uses a different authorized-function arm
// entirely.
const invocationCreateContract = () =>
  new xdr.SorobanAuthorizedInvocation({
    function:
      xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeCreateContractHostFn(
        new xdr.CreateContractArgs({
          contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
            new xdr.ContractIdPreimageFromAddress({
              address: scAddress(SIGNER_1),
              salt: sha256("soroauth-vector-salt"),
            }),
          ),
          executable: xdr.ContractExecutable.contractExecutableWasm(
            sha256("soroauth-vector-wasm-hash"),
          ),
        }),
      ),
    subInvocations: [],
  });

const DELEGATE_1 = "soroauth-vector-delegate-1";
const DELEGATE_2 = "soroauth-vector-delegate-2";
const DELEGATE_3 = "soroauth-vector-delegate-3";
const DELEGATE_NESTED = "soroauth-vector-delegate-nested-1";

// A delegate descriptor, recorded in the vector exactly as written here — in
// input order, before any sorting. The Go side passes the same unsorted tree to
// WithDelegates, so the recorded unsigned entry proves both implementations
// sort and nest identically, rather than Go merely re-reading JS's output.
const delegate = (label, nested = []) => ({
  label,
  address: keypairFor(label).publicKey(),
  nested,
});

// Converts a recorded descriptor tree into the shape buildWithDelegatesEntry
// expects. Signatures are left out, so each node starts as an scvVoid
// placeholder to be filled by authorizeEntry.
const toSdkDelegates = (delegates) =>
  delegates.map((d) => ({
    address: d.address,
    nestedDelegates: toSdkDelegates(d.nested ?? []),
  }));

// ---------------------------------------------------------------------------
// Entry construction
// ---------------------------------------------------------------------------

const addressCredentials = (label, nonce) =>
  new xdr.SorobanAddressCredentials({
    address: scAddress(label),
    nonce: xdr.Int64(nonce),
    // Both are placeholders that authorizeEntry replaces; they match what
    // simulation hands back.
    signatureExpirationLedger: 0,
    signature: xdr.ScVal.scvVec([]),
  });

// A source-account entry passes through unchanged.
const sourceAccountEntry = (signerLabel) =>
  new xdr.SorobanAuthorizationEntry({
    rootInvocation: invocationWithManyArgTypes(),
    credentials: xdr.SorobanCredentials.sorobanCredentialsSourceAccount(),
  });

// authV2 is always passed explicitly, never left to the default, so a change
// to that default in a future SDK cannot silently change these vectors.
const unsignedEntry = ({ signerLabel, nonce, invocation, authV2 }) => {
  const credentials = addressCredentials(signerLabel, nonce);
  return new xdr.SorobanAuthorizationEntry({
    rootInvocation: invocation,
    credentials: authV2
      ? xdr.SorobanCredentials.sorobanCredentialsAddressV2(credentials)
      : xdr.SorobanCredentials.sorobanCredentialsAddress(credentials),
  });
};

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

const CASES = [
  // §5.9 case 1: legacy arm, single G signer, testnet.
  {
    name: "legacy_single_testnet",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: false,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // §5.9 case 2: legacy arm, public passphrase.
  {
    name: "legacy_single_public",
    networkPassphrase: Networks.PUBLIC,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: false,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // §5.9 case 3: V2 arm, single G signer, testnet.
  {
    name: "v2_single_testnet",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: true,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // §5.9 case 4: V2 arm, sub-invocation tree.
  {
    name: "v2_sub_invocations",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: 42n,
        invocation: invocationWithSubInvocations(),
        authV2: true,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // §5.9 case 5: V2 arm, create-contract invocation.
  {
    name: "v2_create_contract",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_MAX,
        invocation: invocationCreateContract(),
        authV2: true,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // §5.9 case 9: legacy arm, negative nonce.
  {
    name: "legacy_negative_nonce",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_MIN,
        invocation: invocationWithManyArgTypes(),
        authV2: false,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // §5.9 case 6: delegates arm, three unsorted delegates with one nested.
  {
    name: "delegates_unsorted_with_nested",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: true,
      }),
    delegates: [
      delegate(DELEGATE_3),
      delegate(DELEGATE_1, [delegate(DELEGATE_NESTED)]),
      delegate(DELEGATE_2),
    ],
    steps: [
      { signerLabel: DELEGATE_1, forAddress: keypairFor(DELEGATE_1).publicKey() },
      { signerLabel: DELEGATE_2, forAddress: keypairFor(DELEGATE_2).publicKey() },
      { signerLabel: DELEGATE_3, forAddress: keypairFor(DELEGATE_3).publicKey() },
      {
        signerLabel: DELEGATE_NESTED,
        forAddress: keypairFor(DELEGATE_NESTED).publicKey(),
      },
    ],
  },
  // §5.9 case 7: one address at two nesting levels.
  {
    name: "delegates_same_address_two_levels",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: 42n,
        invocation: invocationWithSubInvocations(),
        authV2: true,
      }),
    delegates: [
      delegate(DELEGATE_1),
      delegate(DELEGATE_2, [delegate(DELEGATE_1)]),
    ],
    steps: [
      { signerLabel: DELEGATE_1, forAddress: keypairFor(DELEGATE_1).publicKey() },
    ],
  },
  // §5.9 case 8: legacy entry wrapped into the delegates arm.
  {
    name: "delegates_from_legacy",
    networkPassphrase: Networks.TESTNET,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: false,
      }),
    delegates: [
      delegate(DELEGATE_1),
      delegate(DELEGATE_2, [delegate(DELEGATE_3), delegate(DELEGATE_NESTED)]),
    ],
    steps: [
      { signerLabel: DELEGATE_1, forAddress: keypairFor(DELEGATE_1).publicKey() },
      { signerLabel: DELEGATE_2, forAddress: keypairFor(DELEGATE_2).publicKey() },
      { signerLabel: DELEGATE_3, forAddress: keypairFor(DELEGATE_3).publicKey() },
      {
        signerLabel: DELEGATE_NESTED,
        forAddress: keypairFor(DELEGATE_NESTED).publicKey(),
      },
    ],
  },
  // #115: source-account arm vectors pass through unchanged.
  // The signed_entry_xdr must equal the unsigned_entry_xdr.
  {
    name: "source_account_testnet",
    networkPassphrase: Networks.TESTNET,
    entry: () => sourceAccountEntry(SIGNER_1),
    steps: [],
  },
  {
    name: "source_account_public",
    networkPassphrase: Networks.PUBLIC,
    entry: () => sourceAccountEntry(SIGNER_1),
    steps: [],
  },
  // #116: expiration boundary vectors.
  // Expiration 1 is the minimum valid value (see ExpirationAfter).
  {
    name: "v2_expiration_boundary_1",
    networkPassphrase: Networks.TESTNET,
    validUntilLedger: 1,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: true,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
  // MaxUint32 expiration: near the maximum ledger value.
  {
    name: "v2_expiration_boundary_max",
    networkPassphrase: Networks.TESTNET,
    validUntilLedger: 4294967295,
    entry: () =>
      unsignedEntry({
        signerLabel: SIGNER_1,
        nonce: NONCE_ORDINARY,
        invocation: invocationWithManyArgTypes(),
        authV2: true,
      }),
    steps: [{ signerLabel: SIGNER_1, forAddress: null }],
  },
];

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

const generate = async (testCase) => {
  // Per-case expiration ledger, used for boundary vectors (#116).
  const validUntil = caseValidUntilLedger(testCase.name);

  // A case that declares delegates is built in two stages, and both are
  // recorded: the address entry before wrapping, and the wrapped entry. That
  // lets the Go side reproduce the wrap itself rather than starting from JS's
  // already-wrapped output.
  let preWrapEntry = null;
  let entry;
  if (testCase.delegates) {
    preWrapEntry = testCase.entry();
    entry = buildWithDelegatesEntry({
      entry: preWrapEntry,
      validUntilLedgerSeq: validUntil,
      delegates: toSdkDelegates(testCase.delegates),
      // signature omitted, so the top-level node is scvVoid
    });
  } else {
    entry = testCase.entry();
  }

  const unsignedXdr = entry.toXDR("base64");

  // Source-account entries have no preimage or payload; they pass through
  // unchanged. See Preimage() which returns ErrSourceAccountCredentials.
  const isSourceAccount =
    entry.credentials.type ===
    "sorobanCredentialsSourceAccount";

  let preimageXdr = "";
  let payloadHex = "";

  if (!isSourceAccount) {
    const preimage = buildAuthorizationEntryPreimage(
      entry,
      validUntil,
      testCase.networkPassphrase,
    );
    preimageXdr = preimage.toXDR("base64");
    const payload = hash(preimage.toXDR());
    payloadHex = Buffer.from(payload).toString("hex");
  }

  // Each step signs the entry produced by the step before it, which is how a
  // delegate tree gets filled in one signer at a time.
  let signed = entry;
  for (const step of testCase.steps) {
    signed = await authorizeEntry(
      signed,
      keypairFor(step.signerLabel),
      validUntil,
      testCase.networkPassphrase,
      step.forAddress ?? undefined,
    );
  }

  const signedXdr = signed.toXDR("base64");

  return {
    // The vector schema's version, written by the generator so that a reader
    // can tell which shape it is holding. golden_test.go refuses a vector
    // whose version it does not know, rather than silently reading fields
    // that may have moved. Bump it when a field is renamed, removed, or
    // changes meaning; adding an optional field does not need a bump.
    schema_version: SCHEMA_VERSION,
    name: testCase.name,
    sdk: SDK,
    network_passphrase: testCase.networkPassphrase,
    valid_until_ledger: validUntil,
    pre_wrap_entry_xdr: preWrapEntry ? preWrapEntry.toXDR("base64") : "",
    unsigned_entry_xdr: unsignedXdr,
    delegates: testCase.delegates ?? [],
    steps: testCase.steps.map((step) => ({
      signer_label: step.signerLabel,
      for_address: step.forAddress ?? null,
    })),
    preimage_xdr: preimageXdr,
    payload_hex: payloadHex,
    signed_entry_xdr: signedXdr,
  };
};

mkdirSync(OUT_DIR, { recursive: true });

for (const testCase of CASES) {
  const vector = await generate(testCase);
  const path = join(OUT_DIR, `${vector.name}.json`);
  writeFileSync(path, `${JSON.stringify(vector, null, 2)}\n`);
  console.log(`wrote ${vector.name}.json  payload=${vector.payload_hex}`);
}

console.log(`\n${CASES.length} vectors generated with ${SDK}`);
