/**
 * A runnable browser demo for issue #55: create a passkey, sign a Soroban
 * authorization entry with it, submit the transaction to testnet, and show the
 * resulting transaction hash and an explorer link.
 *
 * The signing path is the point of the demo, so it is deliberately local:
 *
 *   1. the page builds a native-XLM SAC `transfer` whose `from` is the wallet
 *      contract, and simulates it in RECORD mode to obtain the unsigned
 *      authorization entry;
 *   2. the WASM signing core derives the preimage and the 32-byte payload in the
 *      browser — the server never tells the browser what to sign;
 *   3. the payload is used as the WebAuthn challenge, and the authenticator
 *      returns an assertion over authenticatorData || SHA-256(clientDataJSON);
 *   4. the assertion is verified here (challenge binding, UP/UV, ES256) and
 *      turned into the signature ScVal the wallet contract's `__check_auth`
 *      decodes;
 *   5. the WASM core writes that ScVal onto every credential node whose address
 *      is the wallet;
 *   6. the transaction is rebuilt with the signed entry and simulated again in
 *      ENFORCE mode — signing changes what the transaction costs, so a
 *      transaction assembled from the record-mode pass is rejected on resource
 *      fees after the signature is already attached;
 *   7. the fee payer signs (or a relayer does) and the transaction is submitted,
 *      then polled until the network reports a result.
 *
 * Who pays the fee. A contract account (C…) cannot be a transaction source, so
 * the authorization entry exists precisely because the wallet authorizes a
 * transaction somebody else pays for. Two ways to resolve that here:
 *
 *   - a relayer URL: the page POSTs the fully assembled, payer-unsigned
 *     transaction and the relayer adds the fee-payer signature. Use this if you
 *     do not want a secret in the page at all; see README.md for the tiny
 *     request/response contract.
 *   - a testnet fee-payer secret typed into the page: the self-contained path.
 *     It is held in memory only, never persisted, never logged, and never sent
 *     anywhere but the signed transaction. It is a throwaway testnet key.
 *
 * Dependencies are loaded from a CDN so the file you are reading is the whole
 * program:
 *   - @stellar/stellar-sdk for XDR, RPC and strkey;
 *   - @soroauth/wasm from ../../wasm/dist, built by ../../wasm/build.sh.
 *
 * Every SDK call below was checked against the installed
 * @stellar/stellar-sdk@17.1.0 type definitions rather than written from memory:
 * `Operation.invokeContractFunction`, `Asset#contractId`,
 * `Server#simulateTransaction(tx, addlResources, authMode)`,
 * `Server#prepareTransaction`, `rpc.assembleTransaction`,
 * `Server#getLatestLedger`, `Server#sendTransaction`, `Server#getTransaction`.
 */

import * as StellarSdk from "https://esm.sh/@stellar/stellar-sdk@17.1.0";

const {
  Address,
  Asset,
  BASE_FEE,
  Keypair,
  Operation,
  TransactionBuilder,
  nativeToScVal,
  rpc,
  xdr,
} = StellarSdk;

const $ = (id) => document.getElementById(id);
const log = (message) => {
  const line = `${new Date().toISOString().slice(11, 19)}  ${message}`;
  const target = $("log");
  if (target) target.textContent += `${line}\n`;
  console.log(line);
};

const base64urlToBytes = (value) =>
  Uint8Array.from(
    atob(value.replace(/-/g, "+").replace(/_/g, "/")),
    (character) => character.charCodeAt(0),
  );

const bytesToBase64 = (bytes) => btoa(String.fromCharCode(...bytes));

const bytesToBase64url = (bytes) =>
  bytesToBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

/**
 * The encodings a WebAuthn challenge may legitimately be written in, for a given
 * payload hash: base64url with and without padding, standard base64 with and
 * without padding, and hexadecimal.
 *
 * `WebAuthnAssertion.VerifyChallenge` in webauthn.go builds the same candidate
 * list, and for the same reason: matching the received string against known
 * encodings of the expected value has none of the ambiguity that decoding
 * first does. A 64-character hexadecimal string is also valid base64url and
 * would decode to the wrong bytes under a fixed decode order.
 */
export function challengeEncodings(payloadHex) {
  const payload = Uint8Array.from(payloadHex.match(/../g), (byte) =>
    parseInt(byte, 16),
  );
  const base64 = bytesToBase64(payload);
  return [
    bytesToBase64url(payload), // base64url, unpadded (the canonical one)
    base64.replace(/\+/g, "-").replace(/\//g, "_"), // base64url, padded
    base64.replace(/=+$/, ""), // standard base64, unpadded
    base64, // standard base64, padded
    payloadHex, // hexadecimal, lower case
  ];
}

/** A comparison that does not exit on the first differing byte. */
const constantTimeEqual = (a, b) => {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) {
    difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return difference === 0;
};

/**
 * The challenge-binding check (WebAuthn Level 3, §7.2 step 11).
 *
 * The authenticator does not sign the payload: it signs
 * `authenticatorData || SHA-256(clientDataJSON)`, and `clientDataJSON` carries
 * the challenge the browser was given. Comparing `SHA-256(clientDataJSON)`
 * against the payload — which an earlier revision of this demo did, following an
 * earlier revision of docs/passkeys.md — can never hold, because the hash of
 * the whole JSON is not the payload. The check is instead: the challenge the
 * authenticator signed must be an encoding of this payload.
 *
 * Decoding the challenge first would be ambiguous (see `challengeEncodings`), so
 * the received string is matched against the encodings of the expected value,
 * and each candidate compared without early exit.
 */
export function verifyChallengeBinding(clientDataJSON, payloadHex) {
  let clientData;
  try {
    clientData = JSON.parse(new TextDecoder().decode(clientDataJSON));
  } catch {
    throw new Error("clientDataJSON is not valid JSON");
  }
  if (clientData.type !== "webauthn.get") {
    throw new Error(
      `clientDataJSON type is ${JSON.stringify(clientData.type)}, want "webauthn.get"`,
    );
  }
  if (typeof clientData.challenge !== "string" || clientData.challenge === "") {
    throw new Error("clientDataJSON carries no challenge");
  }
  const matches = challengeEncodings(payloadHex).some((candidate) =>
    constantTimeEqual(candidate, clientData.challenge),
  );
  if (!matches) {
    throw new Error(
      "the assertion does not commit to this payload (challenge binding failed)",
    );
  }
  return clientData;
}

/** The explorer link a confirmed transaction hash resolves to. */
export function explorerLink(hash, networkPassphrase) {
  const network =
    networkPassphrase === StellarSdk.Networks.PUBLIC ? "public" : "testnet";
  return `https://stellar.expert/explorer/${network}/tx/${hash}`;
}

/**
 * The signature ScVal this demo's example wallet contract decodes: a map whose
 * keys are symbols in host sort order (`public_key` before `signature`) and
 * whose values are bytes. See docs/passkeys.md.
 */
export function passkeySignatureScVal(publicKeyRaw, signatureRaw) {
  // @stellar/stellar-sdk 17.x factories take plain values: scvSymbol takes a
  // string and scvMap takes ScMapEntry[]. (The 16.x bindings wanted an
  // ScSymbol instance and an ScMap object, which is why this is written
  // against the installed types rather than copied from older code.)
  return xdr.ScVal.scvMap([
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("public_key"),
      val: xdr.ScVal.scvBytes(publicKeyRaw),
    }),
    new xdr.ScMapEntry({
      key: xdr.ScVal.scvSymbol("signature"),
      val: xdr.ScVal.scvBytes(signatureRaw),
    }),
  ]);
}

/**
 * The address a credential node authorizes, whichever arm it is (null for the
 * source-account arm, which has no address).
 *
 * The 17.x XDR bindings expose struct fields and union variants as read-only
 * properties with a `type` discriminant string, not as accessor methods.
 */
function credentialAddress(entry) {
  const credentials = entry.credentials;
  switch (credentials.type) {
    case "sorobanCredentialsAddress":
      return Address.fromScAddress(credentials.address.address).toString();
    case "sorobanCredentialsAddressV2":
      return Address.fromScAddress(credentials.addressV2.address).toString();
    case "sorobanCredentialsAddressWithDelegates":
      return Address.fromScAddress(
        credentials.addressWithDelegates.addressCredentials.address,
      ).toString();
    default:
      return null;
  }
}

function loadCredential() {
  const raw = localStorage.getItem("soroauth.passkey.credential");
  if (!raw) {
    throw new Error(
      "no passkey registered yet: click the button once to register",
    );
  }
  const parsed = JSON.parse(raw);
  return {
    id: parsed.id,
    publicKey: { x: new Uint8Array(parsed.x), y: new Uint8Array(parsed.y) },
  };
}

async function registerPasskey() {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { name: "soroauth demo", id: location.hostname },
      user: {
        id: crypto.getRandomValues(new Uint8Array(16)),
        name: "demo@localhost",
        displayName: "soroauth demo",
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { userVerification: "required" },
    },
  });
  if (!credential) {
    throw new Error("registration was cancelled");
  }
  const response = credential.response;
  const attestation = decodeCBOR(new Uint8Array(response.attestationObject));
  const authData = attestation.authData;
  const credentialData = decodeCBOR(authData);
  const cose = credentialData.publicKey;
  const x = new Uint8Array(cose[-2]);
  const y = new Uint8Array(cose[-3]);

  localStorage.setItem(
    "soroauth.passkey.credential",
    JSON.stringify({
      id: bytesToBase64(new Uint8Array(credential.rawId)),
      x: Array.from(x),
      y: Array.from(y),
    }),
  );
  log(`registered a passkey for ${location.hostname}`);
}

async function signPayloadWithPasskey(payloadHex, publicKey) {
  const payload = Uint8Array.from(payloadHex.match(/../g), (byte) =>
    parseInt(byte, 16),
  );
  const credential = loadCredential();

  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: payload,
      rpId: location.hostname,
      allowCredentials: [
        {
          id: base64urlToBytes(credential.id.replace(/=+$/, "")),
          type: "public-key",
        },
      ],
      userVerification: "required",
      timeout: 60_000,
    },
  });
  if (!assertion) {
    throw new Error("the assertion was cancelled");
  }

  const authenticatorData = new Uint8Array(
    assertion.response.authenticatorData,
  );
  const clientDataJSON = new Uint8Array(assertion.response.clientDataJSON);
  const derSignature = new Uint8Array(assertion.response.signature);

  // The challenge-binding check: the challenge carried in the received client
  // data must be an encoding of the payload this entry commits to.
  verifyChallengeBinding(clientDataJSON, payloadHex);

  // These are the bytes the authenticator actually signed, and the hash here is
  // part of them rather than a challenge check (WebAuthn Level 3, §6.1):
  // authenticatorData || SHA-256(clientDataJSON).
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", clientDataJSON),
  );

  // UP is bit 0, UV is bit 2, in the flags byte at index 32 (WebAuthn §6.1).
  const flags = authenticatorData[32];
  if ((flags & 0x01) === 0 || (flags & 0x04) === 0) {
    throw new Error(
      "the assertion is missing user presence or user verification",
    );
  }

  const signed = new Uint8Array(
    authenticatorData.length + clientDataHash.length,
  );
  signed.set(authenticatorData, 0);
  signed.set(clientDataHash, authenticatorData.length);

  const key = await crypto.subtle.importKey(
    "jwk",
    {
      kty: "EC",
      crv: "P-256",
      x: bytesToBase64(publicKey.x)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, ""),
      y: bytesToBase64(publicKey.y)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, ""),
      ext: true,
    },
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    derSignature,
    signed,
  );
  if (!valid) {
    throw new Error("the assertion signature does not verify");
  }

  const rawSignature = deriveCompactSignature(derSignature);
  return passkeySignatureScVal(uncompressedPublicKey(publicKey), rawSignature);
}

/**
 * The credential public key in the form the signature ScVal carries:
 * uncompressed SEC1, `0x04 || X || Y`, each coordinate left-padded to 32 bytes
 * (65 bytes total).
 *
 * This is the same encoding soroauth.Secp256r1SignatureScVal emits and the same
 * one smart-account-kit's builder takes, which is what the passkey golden
 * vectors in testdata/vectors/passkey prove byte-for-byte. Passing the raw X
 * coordinate instead would produce a shape no vector covers.
 */
export function uncompressedPublicKey({ x, y }) {
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(x, 1 + (32 - x.length));
  out.set(y, 33 + (32 - y.length));
  return out;
}

export function deriveCompactSignature(der) {
  if (der[0] !== 0x30) {
    throw new Error("the assertion signature is not DER-encoded");
  }
  let offset = 2;
  if (der[1] & 0x80) {
    offset = 2 + (der[1] & 0x7f);
  }
  if (der[offset] !== 0x02) {
    throw new Error("the assertion signature has no r value");
  }
  const rLength = der[offset + 1];
  const r = der.slice(offset + 2, offset + 2 + rLength);
  offset += 2 + rLength;
  if (der[offset] !== 0x02) {
    throw new Error("the assertion signature has no s value");
  }
  const sLength = der[offset + 1];
  const s = der.slice(offset + 2, offset + 2 + sLength);
  const out = new Uint8Array(64);
  out.set(r.slice(-32), 32 - Math.min(32, r.length));
  out.set(s.slice(-32), 64 - Math.min(32, s.length));
  return out;
}

function decodeCBOR(bytes) {
  let offset = 0;
  const readLength = (additional) => {
    if (additional < 24) return additional;
    if (additional === 24) return bytes[offset++];
    if (additional === 25) {
      const value = (bytes[offset++] << 8) | bytes[offset++];
      return value;
    }
    if (additional === 26) {
      const value =
        (bytes[offset++] << 24) |
        (bytes[offset++] << 16) |
        (bytes[offset++] << 8) |
        bytes[offset++];
      return value >>> 0;
    }
    throw new Error("unsupported CBOR length");
  };
  const read = () => {
    const initial = bytes[offset++];
    const major = initial >> 5;
    const additional = initial & 0x1f;
    const length = readLength(additional);
    if (major === 0) return length;
    if (major === 1) return -1 - length;
    if (major === 2) {
      const slice = bytes.slice(offset, offset + length);
      offset += length;
      return slice;
    }
    if (major === 3) {
      const slice = bytes.slice(offset, offset + length);
      offset += length;
      return new TextDecoder().decode(slice);
    }
    if (major === 5) {
      const map = {};
      for (let i = 0; i < length; i++) {
        map[read()] = read();
      }
      return map;
    }
    throw new Error(`unsupported CBOR major type ${major}`);
  };
  return read();
}

const readInputs = () => ({
  rpcUrl: ($("rpc") || { value: "" }).value.trim(),
  network: ($("network") || { value: "" }).value.trim(),
  wallet: ($("wallet") || { value: "" }).value.trim(),
  destination: ($("destination") || { value: "" }).value.trim(),
  amount: ($("amount") || { value: "" }).value.trim(),
  payer: ($("payer") || { value: "" }).value.trim(),
  payerSecret: ($("payerSecret") || { value: "" }).value,
  relayerUrl: ($("relayer") || { value: "" }).value.trim(),
  validFor: Number(($("validFor") || { value: "120" }).value),
});

async function loadCore() {
  if (!globalThis.Go) {
    throw new Error(
      "wasm_exec.js did not load: build it with ./wasm/build.sh and reload",
    );
  }
  const go = new globalThis.Go();
  const wasm = await fetch("../../wasm/dist/soroauth.wasm");
  if (!wasm.ok) {
    throw new Error(
      `could not fetch the wasm core (HTTP ${wasm.status}); run ./wasm/build.sh first`,
    );
  }
  const { instance } = await WebAssembly.instantiate(
    await wasm.arrayBuffer(),
    go.importObject,
  );
  void go.run(instance);

  for (let attempts = 0; attempts < 500; attempts++) {
    if (globalThis.soroauth) {
      const raw = globalThis.soroauth;
      return {
        preimage(entry, validUntil, network) {
          const result = raw.preimage(entry, validUntil, network);
          if (!result || result.ok !== true) {
            throw new Error(
              `preimage: ${result?.error ?? "the module returned no result"}`,
            );
          }
          return {
            preimageXdr: result.preimageXdr,
            payloadHex: result.payloadHex,
          };
        },
        writeSignature(entry, validUntil, network, forAddress, signatureXdr) {
          const result = raw.writeSignature(
            entry,
            validUntil,
            network,
            forAddress,
            signatureXdr,
          );
          if (!result || result.ok !== true) {
            throw new Error(
              `writeSignature: ${result?.error ?? "the module returned no result"}`,
            );
          }
          return result.entryB64;
        },
      };
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(
    "the wasm core did not install its bindings within 5 seconds",
  );
}

/** Builds the one operation this demo exercises: a native-XLM SAC transfer. */
function transferOperation(contractId, inputs, auth) {
  return Operation.invokeContractFunction({
    contract: contractId,
    function: "transfer",
    args: [
      new Address(inputs.wallet).toScVal(),
      new Address(inputs.destination).toScVal(),
      nativeToScVal(BigInt(inputs.amount), { type: "i128" }),
    ],
    auth,
  });
}

/** Polls getTransaction until the network reports something other than NOT_FOUND. */
async function waitForResult(server, hash, attempts = 30) {
  for (let i = 0; i < attempts; i++) {
    const result = await server.getTransaction(hash);
    if (result.status !== rpc.Api.GetTransactionStatus.NOT_FOUND) {
      return result;
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(
    `timed out waiting for ${hash}; it may still land — check the explorer`,
  );
}

/**
 * Submits an assembled, payer-unsigned transaction. Either a relayer signs and
 * submits it, or a locally-typed testnet fee-payer secret does.
 *
 * The relayer contract is deliberately tiny — see README.md:
 *   POST { "transaction_xdr": "<base64 envelope>" } → 200 { "hash": "…" }
 */
async function submitAssembled(prepared, inputs) {
  if (inputs.relayerUrl) {
    const response = await fetch(inputs.relayerUrl, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ transaction_xdr: prepared.toXdr("base64") }),
    });
    if (!response.ok) {
      throw new Error(
        `the relayer refused the transaction (HTTP ${response.status})`,
      );
    }
    const body = await response.json();
    if (!body || typeof body.hash !== "string") {
      throw new Error("the relayer did not return a transaction hash");
    }
    return body.hash;
  }

  if (!inputs.payerSecret) {
    throw new Error(
      "no fee payer: set a relayer URL, or paste a throwaway testnet fee-payer secret",
    );
  }
  // Held in memory for this call only: never written to storage, never logged,
  // never sent anywhere but the signed transaction.
  const payer = Keypair.fromSecret(inputs.payerSecret);
  if (payer.publicKey() !== inputs.payer) {
    throw new Error(
      "the fee-payer secret does not match the fee-payer address",
    );
  }
  prepared.sign(payer);
  const sent = await server_send(prepared, inputs.rpcUrl);
  return sent;
}

// Split out so the secret never reaches the RPC through a wider scope than it
// needs to.
async function server_send(prepared, rpcUrl) {
  const server = new rpc.Server(rpcUrl);
  const response = await server.sendTransaction(prepared);
  if (response.status === "ERROR") {
    throw new Error(
      `the network rejected the transaction: ${JSON.stringify(response.errorResult ?? response.status)}`,
    );
  }
  return response.hash;
}

async function runFlow(soroauth, inputs) {
  const server = new rpc.Server(inputs.rpcUrl);

  // Verify the RPC endpoint before relying on it, the way the e2e suite does.
  const health = await server.getHealth();
  log(`rpc ${inputs.rpcUrl} reports ${health.status}`);

  const latest = await server.getLatestLedger();
  const validUntil = latest.sequence + inputs.validFor;
  log(`latest ledger ${latest.sequence}; signing until ${validUntil}`);

  const contractId = Asset.native().contractId(inputs.network);
  log(`native SAC is ${contractId}`);

  // --- pass 1: RECORD mode, to be handed the unsigned authorization entry ---
  const payerAccount = await server.getAccount(inputs.payer);
  const recordTx = new TransactionBuilder(payerAccount, {
    fee: BASE_FEE,
    networkPassphrase: inputs.network,
  })
    .addOperation(transferOperation(contractId, inputs, undefined))
    .setTimeout(60)
    .build();

  const record = await server.simulateTransaction(recordTx, undefined, "record");
  if (rpc.Api.isSimulationError(record)) {
    throw new Error(
      `record simulation failed: ${JSON.stringify(record.error)}`,
    );
  }
  const authEntries = record.result?.auth ?? [];
  if (authEntries.length === 0) {
    throw new Error(
      "the record simulation returned no authorization entries — check that the wallet has a balance and the destination is valid",
    );
  }

  const index = authEntries.findIndex(
    (entry) => credentialAddress(entry) === inputs.wallet,
  );
  if (index < 0) {
    throw new Error(
      `the simulation returned no entry for ${inputs.wallet}; it returned entries for ${authEntries
        .map((entry) => credentialAddress(entry) ?? "source-account")
        .join(", ")}`,
    );
  }

  // --- derive + sign, entirely in the browser ---
  const unsignedEntryXdr = authEntries[index].toXdr("base64");
  const { payloadHex } = soroauth.preimage(
    unsignedEntryXdr,
    validUntil,
    inputs.network,
  );
  log(`derived payload ${payloadHex}`);

  const credential = loadCredential();
  const signature = await signPayloadWithPasskey(
    payloadHex,
    credential.publicKey,
  );
  log("the passkey produced a verified signature ScVal");

  const signedEntryXdr = soroauth.writeSignature(
    unsignedEntryXdr,
    validUntil,
    inputs.network,
    inputs.wallet,
    signature.toXdr("base64"),
  );
  authEntries[index] = xdr.SorobanAuthorizationEntry.fromXdr(
    signedEntryXdr,
    "base64",
  );

  // --- pass 2: ENFORCE mode, now that the entry carries a signature ---
  const enforceTx = new TransactionBuilder(payerAccount, {
    fee: BASE_FEE,
    networkPassphrase: inputs.network,
  })
    .addOperation(transferOperation(contractId, inputs, authEntries))
    .setTimeout(60)
    .build();

  const enforce = await server.simulateTransaction(
    enforceTx,
    undefined,
    "enforce",
  );
  if (rpc.Api.isSimulationError(enforce)) {
    throw new Error(
      `enforce simulation failed: ${JSON.stringify(enforce.error)}`,
    );
  }

  const prepared = rpc.assembleTransaction(enforceTx, enforce).build();
  log("assembled the transaction from the enforce-mode simulation");

  const hash = await submitAssembled(prepared, inputs);
  log(`submitted ${hash}`);

  const result = await waitForResult(server, hash);
  const statusName = Object.keys(rpc.Api.GetTransactionStatus).find(
    (key) => rpc.Api.GetTransactionStatus[key] === result.status,
  );
  log(`ledger result: ${statusName ?? result.status}`);
  log(`explorer: ${explorerLink(hash, inputs.network)}`);
  if (result.status !== rpc.Api.GetTransactionStatus.SUCCESS) {
    throw new Error(
      `the transaction did not succeed: ${statusName ?? result.status}`,
    );
  }
  return hash;
}

async function main() {
  const runBtn = $("run");
  if (!runBtn) return;

  const soroauth = await loadCore();
  log("loaded the soroauth WASM signing core");

  runBtn.addEventListener("click", async () => {
    try {
      const inputs = readInputs();
      for (const [name, value] of Object.entries({
        "RPC URL": inputs.rpcUrl,
        "network passphrase": inputs.network,
        "wallet address": inputs.wallet,
        "destination": inputs.destination,
        "amount": inputs.amount,
        "fee payer": inputs.payer,
      })) {
        if (!value) throw new Error(`set the ${name}`);
      }

      // Register on first run; afterwards the ceremony reuses the stored
      // credential.
      try {
        loadCredential();
      } catch {
        await registerPasskey();
      }

      const hash = await runFlow(soroauth, inputs);
      const link = $("explorer");
      if (link) {
        link.href = explorerLink(hash, inputs.network);
        link.textContent = explorerLink(hash, inputs.network);
      }
    } catch (error) {
      log(`error: ${error.message}`);
      console.error(error);
    }
  });
}

if (typeof document !== "undefined") {
  main().catch((error) => {
    log(`failed to start: ${error.message}`);
    console.error(error);
  });
}

export { credentialAddress, transferOperation };
