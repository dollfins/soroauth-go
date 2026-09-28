package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const verifyUsage = `soroauth verify — check an entry's signatures without submitting it.

usage:
  soroauth verify --entry <base64> --network <name|passphrase> [--valid-until <ledger>] [--allow-unsigned] [--json]

Verification answers one question: do the signatures already on this entry
verify over the payload the entry itself commits to? The payload is rebuilt
from the entry — its credentials arm, nonce, address, invocation tree and the
SignatureExpirationLedger stored on it — so an entry that was tampered with
after signing, or signed over a different expiration than it carries, is caught
here instead of on-chain after fees are paid.

Only classic account signatures can be decided offline: the built-in vector
holding one {public_key, signature} map, checked against the 32-byte payload.
Every other shape — a custom account's signature, a node addressed to a C…
contract — is reported as "cannot_check", never as "verified", because only
the account's own __check_auth defines what it accepts. Whether the key that
signed is actually a signer of the account, and whether enough signers signed
to meet its threshold, are account-state questions this command cannot see and
does not claim to answer.

Each credential node is reported: verified, unsigned, invalid (a well-formed
signature that does not verify), or cannot_check. Under CAP-71-01 a delegates
entry may legitimately leave its top-level node Void, so an unsigned node is
reported rather than treated as a failure; pass --allow-unsigned to accept it.

The exit code is 4 when any node is invalid or cannot_check, when any node is
unsigned and --allow-unsigned was not given, or when --valid-until disagrees
with the expiration the entry carries. It is 0 only when every node verified.

--entry accepts either an authorization entry or a whole transaction envelope;
an envelope is verified entry by entry, each with the operation and entry index
it came from. A fee-bump envelope is read through to its inner transaction.

--valid-until, when given, is an assertion rather than an input: the payload is
always rebuilt from the entry's own stored expiration, and a disagreement is an
error. It exists so a caller can state the expiration it believes the entry
carries and be told when that is wrong.

Results go to stdout; errors go to stderr. With --json the report is a single
object for one entry, or an array of objects with operation_index and
entry_index for an envelope; a usage or decode error is a JSON object with an
"error" field on stdout, as in the other subcommands.

Nothing is signed and no key is involved.
`

// verifyNodeOutput is one credential node's verdict in the JSON report.
type verifyNodeOutput struct {
	Address string `json:"address"`
	Verdict string `json:"verdict"`
	Reason  string `json:"reason,omitempty"`
}

// verifyEntryOutput is one entry's verification report in the JSON output.
type verifyEntryOutput struct {
	OperationIndex   int                `json:"operation_index,omitempty"`
	EntryIndex       int                `json:"entry_index,omitempty"`
	CredentialType   string             `json:"credential_type"`
	AddressBound     bool               `json:"address_bound"`
	Address          string             `json:"address,omitempty"`
	ValidUntilLedger uint32             `json:"valid_until_ledger,omitempty"`
	Verified         bool               `json:"verified"`
	Nodes            []verifyNodeOutput `json:"nodes"`
	Note             string             `json:"note,omitempty"`
}

func newVerifyEntryOutput(report soroauth.VerificationReport) verifyEntryOutput {
	out := verifyEntryOutput{
		CredentialType:   report.CredentialType,
		AddressBound:     report.AddressBound,
		Address:          report.Address,
		ValidUntilLedger: report.ValidUntilLedger,
		Verified:         report.Verified(),
		Note:             report.Note,
		Nodes:            make([]verifyNodeOutput, 0, len(report.Nodes)),
	}
	for _, node := range report.Nodes {
		out.Nodes = append(out.Nodes, verifyNodeOutput{
			Address: node.Address,
			Verdict: string(node.Verdict),
			Reason:  node.Reason,
		})
	}
	return out
}

// verifyFailed reports whether a report has a node that is not a pass.
//
// It is the fail-closed reading of the report: cannot_check is a failure
// because the command cannot say the entry is good, and unsigned is a failure
// unless the operator has said their policy accepts it (--allow-unsigned).
func verifyFailed(report soroauth.VerificationReport, allowUnsigned bool) bool {
	for _, node := range report.Nodes {
		switch node.Verdict {
		case soroauth.VerdictVerified:
		case soroauth.VerdictUnsigned:
			if !allowUnsigned {
				return true
			}
		default:
			return true
		}
	}
	return false
}

func runVerify(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, verifyUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	entryFlag := flags.String("entry", "", "the authorization entry or transaction envelope, as base64 XDR")
	networkFlag := flags.String("network", "", "testnet, futurenet, public, or a literal network passphrase")
	validUntil := flags.Uint("valid-until", 0, "assert the expiration the entry carries (optional)")
	allowUnsigned := flags.Bool("allow-unsigned", false, "accept unsigned nodes (a Void top-level node of a delegates entry is legitimate under CAP-71-01)")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}

	input, err := decodeEntryOrEnvelope(*entryFlag)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	passphrase, err := resolveNetwork(*networkFlag)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}

	// Gather the entries to verify, with their position when they came from
	// an envelope. A source-account entry is kept rather than skipped: its
	// report explains why there is nothing to check, and dropping it would
	// make the output's shape depend on the arm.
	type located struct {
		entry          xdr.SorobanAuthorizationEntry
		operationIndex int
		entryIndex     int
	}

	var locatedEntries []located
	if input.IsEnvelope {
		entries, err := soroauth.EnvelopeEntries(input.Envelope)
		if err != nil {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "%w", err))
		}
		for _, e := range entries {
			locatedEntries = append(locatedEntries, located{entry: e.Entry, operationIndex: e.OperationIndex, entryIndex: e.EntryIndex})
		}
	} else {
		locatedEntries = append(locatedEntries, located{entry: input.Entry})
	}

	outputs := make([]verifyEntryOutput, 0, len(locatedEntries))
	failed := false
	for _, item := range locatedEntries {
		report, err := soroauth.VerifyEntry(item.entry, passphrase)
		if err != nil {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitVerificationFailed, "%w", err))
		}
		if *validUntil != 0 && report.ValidUntilLedger != uint32(*validUntil) {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitVerificationFailed,
				"entry carries expiration %d, but --valid-until says %d", report.ValidUntilLedger, uint32(*validUntil)))
		}

		out := newVerifyEntryOutput(report)
		if input.IsEnvelope {
			out.OperationIndex = item.operationIndex + 1
			out.EntryIndex = item.entryIndex + 1
		}
		outputs = append(outputs, out)
		if verifyFailed(report, *allowUnsigned) {
			failed = true
		}
	}

	if *jsonFlag {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		if input.IsEnvelope {
			if err := enc.Encode(outputs); err != nil {
				return newErrorf(ExitGeneralError, "encoding the report: %w", err)
			}
		} else if err := enc.Encode(outputs[0]); err != nil {
			return newErrorf(ExitGeneralError, "encoding the report: %w", err)
		}
	} else {
		writeVerifyText(stdout, outputs, input.IsEnvelope)
	}

	if failed {
		return newErrorf(ExitVerificationFailed, "one or more credential nodes did not verify")
	}
	return nil
}

// writeVerifyText renders the reports for a human, one line per node.
func writeVerifyText(stdout io.Writer, outputs []verifyEntryOutput, envelope bool) {
	for _, out := range outputs {
		if envelope {
			fmt.Fprintf(stdout, "operation %d entry %d: %s\n", out.OperationIndex, out.EntryIndex, out.CredentialType)
		} else {
			fmt.Fprintf(stdout, "%s\n", out.CredentialType)
		}
		if out.Address != "" {
			fmt.Fprintf(stdout, "  address: %s\n", out.Address)
		}
		if out.ValidUntilLedger != 0 {
			fmt.Fprintf(stdout, "  valid until ledger: %d\n", out.ValidUntilLedger)
		}
		if out.Note != "" {
			fmt.Fprintf(stdout, "  note: %s\n", out.Note)
		}
		for _, node := range out.Nodes {
			if node.Reason != "" {
				fmt.Fprintf(stdout, "  %s: %s (%s)\n", node.Address, node.Verdict, node.Reason)
			} else {
				fmt.Fprintf(stdout, "  %s: %s\n", node.Address, node.Verdict)
			}
		}
		if out.Verified {
			fmt.Fprintln(stdout, "  result: verified")
		} else {
			fmt.Fprintln(stdout, "  result: NOT verified")
		}
	}
}
