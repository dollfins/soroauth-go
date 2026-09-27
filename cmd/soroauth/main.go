// Command soroauth builds, signs and inspects Soroban authorization entries
// from the shell.
//
// Entries are passed and printed as base64 XDR, so the tool composes with
// anything that can produce or consume that: an RPC client, jq, or another
// invocation of soroauth.
//
// Secrets are never accepted as flag values. The sign subcommand reads a seed
// from a named environment variable instead, which keeps it out of shell
// history, out of the process table, and out of any transcript of the session.
// No subcommand prints a secret, including on the error paths.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/soroauth/soroauth-go"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Exit codes for distinct failure classes.
const (
	ExitOK                 = 0 // success
	ExitGeneralError       = 1 // internal or unclassified error
	ExitUsageError         = 2 // invalid flags, missing required flags, malformed input
	ExitSigningRefusal     = 3 // refused to sign (no matching node, already signed, unsupported credentials, etc.)
	ExitVerificationFailed = 4 // signature verification failed, invalid expiration, etc.
)

// cliError wraps an error with an exit code. It implements the error interface.
type cliError struct {
	err      error
	exitCode int
}

func (e *cliError) Error() string {
	return e.err.Error()
}

func (e *cliError) Unwrap() error {
	return e.err
}

// ExitCode returns the exit code for this error, or ExitOK if err is nil.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var ce *cliError
	if errors.As(err, &ce) {
		return ce.exitCode
	}
	return ExitGeneralError
}

// newErrorf wraps an error with the given exit code.
func newErrorf(exitCode int, format string, args ...any) error {
	return &cliError{err: fmt.Errorf(format, args...), exitCode: exitCode}
}

const usage = `soroauth builds, signs and inspects Soroban authorization entries.

usage:
  soroauth <command> [flags]

commands:
  payload        print the signing preimage and payload hash for an entry
  sign           sign an entry with a seed read from an environment variable
  delegates      wrap an entry in a delegated-signer credential
  inspect        print an entry's structure as JSON
  verify         check an entry's signatures without submitting it
  tree           render an entry's delegate tree as ASCII, DOT, or JSON
  tui            interactive TUI for inspecting and signing an entry
  doctor         check the local environment for common first-run problems
  cross-compile  build soroauth for multiple targets
  completions    emit a shell completion script (bash, zsh, fish)
  wasm-budget    measure the wasm core against a size ceiling

run "soroauth <command> -h" for the flags of a command.

exit codes:
  0  success
  1  general error (internal or unclassified)
  2  usage error (invalid flags, missing required flags, malformed input)
  3  signing refused (no matching node, already signed, unsupported credentials, duplicate delegate)
  4  verification failed (signature mismatch, invalid expiration, too many signatures)
`

func main() {
	err := run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv)
	if err != nil {
		// If the error was already written as JSON to stdout by writeJSONError,
		// don't print to stderr again.
		var jsonHandled *jsonErrorHandled
		if !errors.As(err, &jsonHandled) {
			fmt.Fprintf(os.Stderr, "soroauth: %v\n", err)
		}
		os.Exit(ExitCode(err))
	}
}

// run holds the dispatch so tests can drive it without touching the process.
// getenv is injected for the same reason: sign reads its seed from the
// environment, and a test must be able to supply one without mutating the real
// environment of the test binary.
func run(args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	return runWithStdin(args, stdout, stderr, getenv, os.Stdin)
}

// runWithStdin is run with the standard input it reads `--entry -` from
// injected, so a test can pipe one subcommand's output into the next without
// replacing the process's real os.Stdin. Replacing it is not safe here: the
// test binary runs cases in parallel and os.Stdin is shared, so a swap made by
// one case is visible to every other one.
//
// Only payload, sign and delegates accept `--entry -`; the remaining
// subcommands are dispatched exactly as run would dispatch them.
func runWithStdin(args []string, stdout, stderr io.Writer, getenv func(string) string, stdin io.Reader) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return newErrorf(ExitUsageError, "no command given")
	}

	switch args[0] {
	case "payload":
		return runPayloadWithStdin(args[1:], stdout, stderr, getenv, stdin)
	case "sign":
		return runSignWithStdin(args[1:], stdout, stderr, getenv, stdin)
	case "delegates":
		return runDelegatesWithStdin(args[1:], stdout, stderr, getenv, stdin)
	case "inspect":
		return runInspect(args[1:], stdout, stderr)
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "tree":
		return runTree(args[1:], stdout, stderr)
	case "tui":
		return runTUI(args[1:], stdout, stderr, getenv)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr, getenv)
	case "cross-compile":
		return runCrossCompile(args[1:], stdout, stderr)
	case "completions":
		return runCompletions(args[1:], stdout, stderr)
	case "wasm-budget":
		return runWASMBudget(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		fmt.Fprint(stderr, usage)
		return newErrorf(ExitUsageError, "unknown command %q", args[0])
	}
}

// resolveNetwork turns the --network flag into a passphrase. The two named
// networks are shorthands; anything else is taken as a literal passphrase, so
// futurenet, a standalone network or a quickstart container all work without
// this tool needing to know about them.
func resolveNetwork(value string) (string, error) {
	switch value {
	case "":
		return "", newErrorf(ExitUsageError, "--network is required (testnet, public, or a literal passphrase)")
	case "testnet":
		return network.TestNetworkPassphrase, nil
	case "public":
		return network.PublicNetworkPassphrase, nil
	default:
		return value, nil
	}
}

// readEntryFlag reads the entry value from stdin if value is "-", otherwise
// returns value.
//
// This is the path for the subcommands that do not inject their own reader —
// inspect, verify and tree. It delegates to resolveEntryArg rather than reading
// os.Stdin itself so that there is one definition of what `--entry -` means,
// including the whitespace trimming a pipeline depends on; the two used to
// diverge, and `soroauth delegates … | soroauth inspect --entry -` failed with
// "input not fully consumed" on the trailing newline.
func readEntryFlag(value string) (string, error) {
	resolved, err := resolveEntryArg(value, os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading from stdin: %w", err)
	}
	return resolved, nil
}

// decodeEntry parses a base64 authorization entry from a flag value.
//
// The entry comes from the command line, which means it came from somewhere
// else: a simulation, another tool, a transcript. It is decoded through the
// library's bounded decoder rather than xdr.SafeUnmarshalBase64 directly, so a
// pathological entry is refused at a deliberate limit instead of at the SDK's
// much looser default. Errors that match ErrDecodeLimit get the usage exit
// code, since the input is what is wrong and no retry against the same input
// can succeed.
func decodeEntry(value string) (xdr.SorobanAuthorizationEntry, error) {
	if value == "" {
		return xdr.SorobanAuthorizationEntry{}, newErrorf(ExitUsageError, "--entry is required")
	}
	val, err := readEntryFlag(value)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, newErrorf(ExitUsageError, "%w", err)
	}
	entry, err := soroauth.DecodeAuthorizationEntry(val)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, newErrorf(ExitUsageError, "decoding --entry: %w", err)
	}
	return entry, nil
}

// decodedInput is a base64 blob that was either an authorization entry or a
// transaction envelope, together with which of the two it turned out to be.
type decodedInput struct {
	Entry      xdr.SorobanAuthorizationEntry
	Envelope   xdr.TransactionEnvelope
	IsEnvelope bool
}

// decodeEntryOrEnvelope parses the --entry flag, which accepts either an
// authorization entry or a whole transaction envelope.
//
// Both are base64 XDR unions whose first byte is a small discriminant, so a
// blob has to be tried against both shapes and judged on what it decodes to:
// EnvelopeType values 0, 2 and 5 overlap the credential discriminants 0 to 3.
// An envelope only wins when it decodes AND carries an invokeHostFunction
// operation, which an authorization entry does not look like by any reading;
// when that test fails the blob is read as an entry. If neither reading works,
// the entry error is reported, since --entry has always meant an entry and a
// caller who passed an envelope with nothing to authorize should hear why.
func decodeEntryOrEnvelope(value string) (decodedInput, error) {
	if value == "" {
		return decodedInput{}, newErrorf(ExitUsageError, "--entry is required")
	}
	val, err := readEntryFlag(value)
	if err != nil {
		return decodedInput{}, newErrorf(ExitUsageError, "%w", err)
	}

	var envelope xdr.TransactionEnvelope
	envelopeErr := xdr.SafeUnmarshalBase64(val, &envelope)

	var entry xdr.SorobanAuthorizationEntry
	entryErr := xdr.SafeUnmarshalBase64(val, &entry)

	// An envelope only wins when it decodes and carries an invokeHostFunction
	// operation. A blob that decodes as an envelope but has nothing to
	// authorize, and does not decode as an entry either, is reported as the
	// envelope problem it is; anything else that fails both readings gets the
	// entry error, since --entry has always meant an entry.
	if envelopeErr == nil {
		if _, entriesErr := soroauth.EnvelopeEntries(envelope); entriesErr == nil {
			return decodedInput{Envelope: envelope, IsEnvelope: true}, nil
		} else if entryErr != nil {
			return decodedInput{}, newErrorf(ExitUsageError, "decoding --entry as an envelope: %w", entriesErr)
		}
	}

	if entryErr != nil {
		return decodedInput{}, newErrorf(ExitUsageError, "decoding --entry: %w", entryErr)
	}
	return decodedInput{Entry: entry}, nil
}

// encodeEntry renders an entry as base64 for printing.
func encodeEntry(entry xdr.SorobanAuthorizationEntry) (string, error) {
	encoded, err := xdr.MarshalBase64(entry)
	if err != nil {
		return "", fmt.Errorf("encoding the entry: %w", err)
	}
	return encoded, nil
}

// jsonErrorHandled is a sentinel error returned by writeJSONError when it has
// already written the error as JSON to stdout. main() checks for this and
// skips printing to stderr.
type jsonErrorHandled struct{ error }

func (e *jsonErrorHandled) Unwrap() error { return e.error }

// writeJSONError writes a JSON error object to stdout if jsonFlag is true,
// otherwise returns the error for the caller to print to stderr.
// When jsonFlag is true, it returns a jsonErrorHandled sentinel so that
// main() knows not to print to stderr again.
func writeJSONError(stdout io.Writer, jsonFlag bool, err error) error {
	if jsonFlag {
		type jsonError struct {
			Error string `json:"error"`
		}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(jsonError{Error: err.Error()})
		return &jsonErrorHandled{err}
	}
	return err
}

// runTUI runs the interactive TUI command.
func runTUI(args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	// Parse flags manually since we don't use flag package for subcommands
	var entryB64 string
	var validUntilLedger uint32
	var networkPassphrase string
	var secretEnvVar string
	var forAddress string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--entry":
			if i+1 < len(args) {
				entryB64 = args[i+1]
				i++
			}
		case "--valid-until":
			if i+1 < len(args) {
				// A malformed value leaves validUntilLedger at zero, which the
				// required-flag check below refuses. The TUI parses its own
				// flags rather than using the flag package, so there is no
				// parse error to surface here.
				_, _ = fmt.Sscanf(args[i+1], "%d", &validUntilLedger)
				i++
			}
		case "--network":
			if i+1 < len(args) {
				networkPassphrase = args[i+1]
				i++
			}
		case "--secret-env":
			if i+1 < len(args) {
				secretEnvVar = args[i+1]
				i++
			}
		case "--for":
			if i+1 < len(args) {
				forAddress = args[i+1]
				i++
			}
		case "--help", "-h":
			fmt.Fprint(stdout, tuiUsage)
			return nil
		}
	}

	if entryB64 == "" || validUntilLedger == 0 || networkPassphrase == "" || secretEnvVar == "" {
		fmt.Fprint(stderr, tuiUsage)
		return newErrorf(ExitUsageError, "missing required flags")
	}

	// Resolve network passphrase
	passphrase, err := resolveNetwork(networkPassphrase)
	if err != nil {
		return err
	}

	return soroauth.TUI(context.Background(), entryB64, validUntilLedger, passphrase, secretEnvVar, forAddress)
}

const tuiUsage = `usage: soroauth tui --entry <base64> --valid-until <ledger> --network <passphrase> --secret-env <var> [--for <addr>]

Interactive TUI for inspecting and signing an authorization entry.

flags:
  --entry        base64-encoded authorization entry (required)
  --valid-until  signature expiration ledger (required)
  --network      network passphrase: testnet, public, or literal (required)
  --secret-env   name of environment variable holding the secret seed (required)
  --for          target address to sign for (optional, defaults to signer's address)

The seed is read from the named environment variable and is never prompted for
or echoed. If stdin is not a TTY, the command degrades to non-interactive output
(equivalent to running inspect and sign).
`
