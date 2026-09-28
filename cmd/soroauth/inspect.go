package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/soroauth/soroauth-go"
)

const inspectUsage = `soroauth inspect — print an entry's structure as JSON.

usage:
  soroauth inspect --entry <base64>|[-] [--json]

--entry accepts either an authorization entry or a whole transaction envelope,
and the tool works out which it was given. An envelope is reported as an array,
one object per authorization entry, each with the operation_index and
entry_index it came from; a fee-bump envelope is read through to the inner
transaction, so the indices are indices into the inner transaction's
operations. A single entry is reported as one object, as it always has been.

Reports the credential arm, whether the payload is address-bound, the address,
nonce and expiration ledger, which nodes carry signatures, the delegate tree,
and the shape of the invocation tree.

Without --json the report is pretty-printed for reading. With --json it is a
single compact object, so it composes with jq and with the other subcommands.
On error, --json prints a single JSON object with an "error" field to stdout
and exits non-zero; nothing else is written to stdout.

This is structural only. It reports which contract and function are being
called, not what they do or whether the arguments are reasonable, so it is a
check that an entry is the one you meant to submit — the right arm, the right
address, signed in the right places — and not a substitute for understanding
the call.

Nothing is signed and no key is involved.

exit codes:
  0  success
  1  general error
  2  usage error (missing --entry or malformed input)
`

func runInspect(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, inspectUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	entryFlag := flags.String("entry", "", "the authorization entry or transaction envelope, as base64 XDR")
	// inspect's success output is already the JSON report described above;
	// --json exists only so every subcommand accepts the same flag, and here
	// it additionally makes a usage or decode error come back as a JSON
	// object on stdout instead of plain text on stderr, matching every other
	// subcommand's --json contract.
	jsonFlag := flags.Bool("json", false, "accepted for consistency with other subcommands; inspect's output is always JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}

	input, err := decodeEntryOrEnvelope(*entryFlag)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "%w", err))
	}

	// An envelope is reported entry by entry, each with the position it came
	// from, because that is what a caller has to line a signed entry back up
	// with. A lone entry stays a single object, so existing scripts keep
	// working.
	var report any
	if input.IsEnvelope {
		infos, err := soroauth.InspectEnvelope(input.Envelope)
		if err != nil {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "%w", err))
		}
		report = infos
	} else {
		info, err := soroauth.Inspect(input.Entry)
		if err != nil {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "%w", err))
		}
		report = info
	}

	// inspect's success output is already JSON, so --json is a true no-op
	// here: the report is always pretty-printed the same way, with or
	// without the flag, and existing scripts that called inspect before
	// --json existed keep getting byte-identical output.
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "encoding the report: %w", err))
	}
	fmt.Fprintln(stdout, string(encoded))
	return nil
}
