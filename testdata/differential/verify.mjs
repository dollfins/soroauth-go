// JS verifier for the differential fuzzing corpus.
//
// cmd/difffuzz generates random, structurally valid Soroban authorization
// entries and records the HashIdPreimage and payload soroauth derived from each.
// This script recomputes both with the reference implementation the golden
// vectors are built from, @stellar/stellar-sdk, and compares. Together with
// testdata/parity-python/parity.py (pointed at the same corpus) that makes the
// comparison three-way: Go, JS and Python must agree on every payload.
//
// It never writes to the corpus. A disagreement is a release blocker, not a
// value to update: see README.md.
//
// Cases the recording side marked as having no preimage -- the source-account
// arms, which the transaction envelope authenticates instead -- are skipped
// loudly, named on stderr and counted, and a run that checked nothing exits
// non-zero so the verifier cannot pass by doing nothing.
//
// The reference is pinned exactly in package.json and package-lock.json. The
// version actually loaded is read back out of node_modules and a different one
// is refused, the same way testdata/gen/gen.mjs refuses to run against a
// non-pinned JS SDK: a parity result is only evidence when the reference that
// produced it is the reference named in the repository.
//
// Run it with:
//
//     cd testdata/differential && npm ci && node verify.mjs
//
// or, equivalently, `make differential` from the repository root.

import { existsSync, readFileSync, readdirSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  buildAuthorizationEntryPreimage,
  hash,
  xdr,
} from "@stellar/stellar-sdk";

const HERE = dirname(fileURLToPath(import.meta.url));

// The exact version this verifier is pinned to. A payload recomputed by any
// other build is not evidence about this one.
const REQUIRED_SDK_VERSION = "17.1.0";

// The version that was actually loaded, read from the installed package rather
// than typed here.
const loadedVersion = JSON.parse(
  readFileSync(
    join(HERE, "node_modules", "@stellar", "stellar-sdk", "package.json"),
    "utf8",
  ),
).version;

if (loadedVersion !== REQUIRED_SDK_VERSION) {
  console.error(
    `refusing to verify: @stellar/stellar-sdk is ${loadedVersion}, this ` +
      `verifier is pinned to ${REQUIRED_SDK_VERSION}. Run \`npm ci\` in ` +
      `testdata/differential.`,
  );
  process.exit(2);
}

// Credential arm names, for readable output. The JS SDK names the union arm
// after the SOROBAN_CREDENTIALS_* value in the protocol; this maps it to the
// short name the rest of the repository uses.
const CREDENTIAL_TYPES = {
  sorobanCredentialsSourceAccount: "source_account",
  sorobanCredentialsAddress: "address",
  sorobanCredentialsAddressV2: "address_v2",
  sorobanCredentialsAddressWithDelegates: "address_with_delegates",
};

const credentialTypeName = (value) =>
  CREDENTIAL_TYPES[value] ?? `unknown(${value})`;

// corpusDirectories returns the directories to check. The generated corpus is
// always checked; the regressions directory holds cases that diverged once and
// were committed as reproducers, and it is checked when it holds anything.
function corpusDirectories(args) {
  if (args.length > 0) {
    return args;
  }
  const directories = [join(HERE, "corpus")];
  const regressions = join(HERE, "regressions");
  if (existsSync(regressions)) {
    directories.push(regressions);
  }
  return directories;
}

// casesIn returns the path of every JSON case in a directory, in name order.
function casesIn(directory) {
  if (!existsSync(directory)) {
    return [];
  }
  return readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .sort()
    .map((name) => join(directory, name));
}

// checkCase recomputes one case's preimage and payload and compares them to the
// record. It returns a result object rather than throwing: a genuine
// disagreement and a skip are both ordinary outcomes to report.
function checkCase(path) {
  const doc = JSON.parse(readFileSync(path, "utf8"));
  const name = doc.name ?? basename(path);

  const entry = xdr.SorobanAuthorizationEntry.fromXDR(
    doc.unsigned_entry_xdr,
    "base64",
  );
  const credentialType = credentialTypeName(entry.credentials.type);

  if (!doc.preimage_xdr) {
    return {
      name,
      status: "skip",
      detail:
        `no recorded preimage: credential_type=${credentialType}; cases with ` +
        `no preimage cannot be recomputed`,
    };
  }

  const preimage = buildAuthorizationEntryPreimage(
    entry,
    doc.valid_until_ledger,
    doc.network_passphrase,
  );
  const gotPreimage = preimage.toXDR("base64");
  const gotPayload = Buffer.from(hash(preimage.toXDR())).toString("hex");

  const problems = [];
  if (gotPreimage !== doc.preimage_xdr) {
    problems.push(
      `preimage differs\n    want ${doc.preimage_xdr}\n     got ${gotPreimage}`,
    );
  }
  if (gotPayload !== (doc.payload_hex ?? "")) {
    problems.push(
      `payload differs\n    want ${doc.payload_hex}\n     got ${gotPayload}`,
    );
  }

  if (problems.length > 0) {
    return { name, status: "mismatch", detail: problems.join("; ") };
  }
  return { name, status: "match", detail: "" };
}

// report prints the results and returns the process exit code.
function report(results) {
  const matched = results.filter((result) => result.status === "match");
  const mismatched = results.filter((result) => result.status === "mismatch");
  const skipped = results.filter((result) => result.status === "skip");

  for (const result of results) {
    if (result.status === "match") {
      console.log(`  ok    ${result.name}`);
    } else if (result.status === "skip") {
      // Skipped cases go to stderr so they cannot be mistaken for "ok" lines.
      console.error(`  skip  ${result.name}: ${result.detail}`);
    }
  }
  for (const result of mismatched) {
    console.error(`  FAIL  ${result.name}: ${result.detail}`);
  }

  console.log(
    `\ndifferential fuzzing (JS @stellar/stellar-sdk ${loadedVersion}): ` +
      `${matched.length} matched, ${skipped.length} skipped, ` +
      `${mismatched.length} mismatched (of ${results.length})`,
  );

  if (mismatched.length > 0) {
    console.error(
      "\nDo not edit a corpus case to make this pass. A disagreement here means " +
        "one implementation is wrong; open an issue with the protocol reference " +
        "(CAP-46-11, CAP-71-01, CAP-71-02) and the case as a reproducer.",
    );
    return 1;
  }
  // A run that checked nothing is not a pass.
  if (matched.length === 0) {
    console.error(
      "differential fuzzing: nothing was actually checked; refusing to report success",
    );
    return 1;
  }
  return 0;
}

const directories = corpusDirectories(process.argv.slice(2));
const paths = directories.flatMap(casesIn);

if (paths.length === 0) {
  console.error(
    `differential fuzzing: no corpus cases found in ${directories.join(", ")}; ` +
      "run `go run ./cmd/difffuzz` to generate them",
  );
  process.exit(2);
}

console.log(`differential fuzzing: JS @stellar/stellar-sdk ${loadedVersion}`);
console.log(`corpus: ${directories.join(", ")}`);

process.exit(report(paths.map(checkCase)));
