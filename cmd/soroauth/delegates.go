package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/soroauth/soroauth-go"
)

const delegatesUsage = `soroauth delegates — wrap an entry in a delegated-signer credential.

usage:
  soroauth delegates --entry <base64|-> (--valid-until <ledger> | --valid-for <ledgers>) \
                     [--delegate <address> ...] [--nested-json <json>] \
                     [--rpc-url <url>] [--json]

Give exactly one of --valid-until (an absolute ledger) or --valid-for (a
lifetime in ledgers, added to the current ledger). --valid-for needs an RPC
endpoint, taken from --rpc-url or, if that is unset, $SOROAUTH_RPC_URL; it is
refused when neither names one, because guessing a network here would stamp an
expiration bound to the wrong chain.

Subcommands support reading entries from stdin using --entry - so commands compose in pipelines:

  soroauth delegates --entry entry.b64 --valid-until 1234567 --delegate GABC... | \
    soroauth sign --entry - --valid-until 1234567 --network testnet --secret-env SEED --for GABC...

Converts an ADDRESS or ADDRESS_V2 entry into ADDRESS_WITH_DELEGATES (CAP-71-01),
with the delegates sorted into the order the protocol requires. Pass --delegate
once per address; the order they are given in does not matter.

Nested delegate trees are supported via --nested-json (or through the library with WithDelegates).

Nesting limit: up to 10 levels deep.

The delegate signatures are left as placeholders. Fill each one afterwards with:

  soroauth sign --entry <wrapped> --for <delegate address> ...

Note that wrapping a legacy ADDRESS entry makes its payload address-bound, so
any signature already on the entry would stop verifying; such an entry is
rejected rather than silently rewrapped.

Prints the wrapped entry as base64. With --json, prints a JSON object with field
"wrapped_entry". On error, prints a JSON object with field "error" to stdout and
exits non-zero and outputs results-only on failure paths.
`

type delegatesOutput struct {
	WrappedEntry string `json:"wrapped_entry,omitempty"`
	Error        string `json:"error,omitempty"`
}

// addressList collects a flag that may be repeated.
type addressList []string

func (a *addressList) String() string { return fmt.Sprint(*a) }

func (a *addressList) Set(value string) error {
	if value == "" {
		return fmt.Errorf("--delegate needs an address")
	}
	*a = append(*a, value)
	return nil
}

func runDelegates(args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	return runDelegatesWithStdin(args, stdout, stderr, getenv, os.Stdin)
}

// runDelegatesWithStdin is runDelegates with the reader `--entry -` draws from
// injected, so a pipeline can be driven from a test. getenv is here because
// --valid-for falls back to $SOROAUTH_RPC_URL.
func runDelegatesWithStdin(args []string, stdout, stderr io.Writer, getenv func(string) string, stdin io.Reader) error {
	flags := flag.NewFlagSet("delegates", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, delegatesUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	entryFlag := flags.String("entry", "", "the authorization entry, as base64 XDR or -")
	validUntil := flags.Uint("valid-until", 0, "the last ledger at which the signatures are valid")
	validFor := flags.Uint64("valid-for", 0, "the signature lifetime in ledgers, resolved against the current ledger (needs --rpc-url)")
	rpcURL := flags.String("rpc-url", "", "RPC endpoint used to resolve --valid-for (default $SOROAUTH_RPC_URL)")
	var delegates addressList
	flags.Var(&delegates, "delegate", "a delegate address; repeat for several")
	nestedJSONFlag := flags.String("nested-json", "", "JSON string defining nested delegate tree")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}

	resolvedEntry, err := resolveEntryArg(*entryFlag, stdin)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}

	entry, err := decodeEntry(resolvedEntry)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	expiration, err := resolveValidUntil(context.Background(), uint64(*validUntil), *validFor, resolveRPCURL(*rpcURL, getenv), fetchLatestLedger)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}

	var tree []soroauth.Delegate
	if *nestedJSONFlag != "" {
		if err := json.Unmarshal([]byte(*nestedJSONFlag), &tree); err != nil {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "invalid --nested-json: %w", err))
		}
	} else {
		if len(delegates) == 0 {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "at least one --delegate is required"))
		}
		tree = make([]soroauth.Delegate, 0, len(delegates))
		for _, address := range delegates {
			tree = append(tree, soroauth.Delegate{Address: address})
		}
	}

	wrapped, err := soroauth.WithDelegates(entry, expiration, tree, nil)
	if err != nil {
		// Classify the error for exit code
		var exitCode int
		if errors.Is(err, soroauth.ErrUnsupportedCredentials) ||
			errors.Is(err, soroauth.ErrAlreadySigned) ||
			errors.Is(err, soroauth.ErrDuplicateDelegate) {
			exitCode = ExitSigningRefusal
		} else if errors.Is(err, soroauth.ErrInvalidExpiration) {
			exitCode = ExitVerificationFailed
		} else {
			exitCode = ExitGeneralError
		}
		return writeJSONError(stdout, *jsonFlag, newErrorf(exitCode, "%w", err))
	}

	encoded, err := encodeEntry(wrapped)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "%w", err))
	}

	if *jsonFlag {
		out := delegatesOutput{WrappedEntry: encoded}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(out)
	}

	fmt.Fprintln(stdout, encoded)
	return nil
}
