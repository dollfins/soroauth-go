package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

const signUsage = `soroauth sign — sign an authorization entry.

usage:
  soroauth sign --entry <base64|-> (--valid-until <ledger> | --valid-for <ledgers>) \
                --network <name|passphrase> \
                (--secret-env <VAR> | --assertion <file|->) \
                [--rpc-url <url>] [--for <address>] [--json]

Give exactly one of --valid-until (an absolute ledger) or --valid-for (a
lifetime in ledgers, added to the current ledger). --valid-for needs an RPC
endpoint, taken from --rpc-url or, if that is unset, $SOROAUTH_RPC_URL; it is
refused when neither names one, because guessing a network here would sign an
expiration bound to the wrong chain.

Give exactly one of --secret-env (the name of an environment variable holding an
S… seed) or --assertion (a WebAuthn assertion, from a file or - for stdin).

Subcommands support reading entries from stdin using --entry - so commands compose in pipelines:

  soroauth delegates --entry entry.b64 --valid-until 1234567 --delegate GABC... | \
    soroauth sign --entry - --valid-until 1234567 --network testnet --secret-env SEED --for GABC...

--entry accepts either an authorization entry or a whole transaction envelope,
and the tool works out which it was given. Given an envelope it signs every
authorization entry the envelope carries and prints the envelope back; a
fee-bump envelope is read through to its inner transaction, which is where the
entries live.

A wallet that has just signed entries must run a second simulation in enforce
mode before submitting: signing changes what the transaction costs to run, and
a transaction assembled from the record-mode simulation will be rejected on
resource fees. This command signs entries only — it does not simulate, and it
does not sign the envelope itself, which is the source account's (or the
fee-bump fee source's) signature, not an authorization entry.

The signing seed is read from the environment variable named by --secret-env,
or a WebAuthn assertion JSON is read from a file or stdin via --assertion.
There is deliberately no flag that takes a seed or private key as a literal value:
flag values end up in shell history, in the process table, and in any transcript
of the session.

The signature is written only onto credential nodes whose address matches the
signer's own address, or the address given by --for. If no node matches, the
command fails rather than signing something else. --for applies to a single
entry and is refused for an envelope, where it would have to mean something
different per entry.

Prints the signed entry as base64, or the signed envelope as base64 when given
an envelope. With --json, prints a JSON object with field "signed_entry", or
"signed_envelope". On error, prints a JSON object with field "error" to stdout
and exits non-zero.
`

type signOutput struct {
	SignedEntry    string `json:"signed_entry,omitempty"`
	SignedEnvelope string `json:"signed_envelope,omitempty"`
	Error          string `json:"error,omitempty"`
}

func runSign(args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	return runSignWithStdin(args, stdout, stderr, getenv, os.Stdin)
}

func runSignWithStdin(args []string, stdout, stderr io.Writer, getenv func(string) string, stdin io.Reader) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, signUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	entryFlag := flags.String("entry", "", "the authorization entry or transaction envelope, as base64 XDR or -")
	validUntil := flags.Uint("valid-until", 0, "the last ledger at which the signature is valid")
	validFor := flags.Uint64("valid-for", 0, "the signature lifetime in ledgers, resolved against the current ledger (needs --rpc-url)")
	rpcURL := flags.String("rpc-url", "", "RPC endpoint used to resolve --valid-for (default $SOROAUTH_RPC_URL)")
	networkFlag := flags.String("network", "", "testnet, futurenet, public, or a literal network passphrase")
	secretEnv := flags.String("secret-env", "", "name of the environment variable holding the signing seed (S…)")
	assertionFlag := flags.String("assertion", "", "path to a WebAuthn assertion JSON file, or - for stdin")
	forAddress := flags.String("for", "", "credential node to sign, when it is not the signer's own address")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}

	resolvedEntry, err := resolveEntryArg(*entryFlag, stdin)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}

	input, err := decodeEntryOrEnvelope(resolvedEntry)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	passphrase, err := resolveNetwork(*networkFlag)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	expiration, err := resolveValidUntil(context.Background(), uint64(*validUntil), *validFor, resolveRPCURL(*rpcURL, getenv), fetchLatestLedger)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, err)
	}
	if (*secretEnv == "" && *assertionFlag == "") || (*secretEnv != "" && *assertionFlag != "") {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "--secret-env is required unless --assertion is given: exactly one of --secret-env or --assertion must be provided"))
	}

	var signer soroauth.Signer
	if *secretEnv != "" {
		seed := getenv(*secretEnv)
		if seed == "" {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "environment variable %s is empty or unset", *secretEnv))
		}

		parsed, err := keypair.Parse(seed)
		if err != nil {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "the value of %s is not a valid Stellar key", *secretEnv))
		}
		full, ok := parsed.(*keypair.Full)
		if !ok {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "the value of %s is a public key; a secret seed (S…) is required", *secretEnv))
		}
		signer = soroauth.NewEd25519Signer(full)
	} else {
		// Passkey support not implemented in current library version.
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError, "passkey authentication is not yet supported"))
	}

	// An envelope carries entries for whatever addresses simulation recorded,
	// so a single target address would be ambiguous: it would have to apply to
	// one of them and not the others. Refusing is the fail-closed reading.
	if input.IsEnvelope && *forAddress != "" {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitUsageError,
			"--for applies to a single entry; given an envelope, sign the entries one at a time or drop --for"))
	}

	if input.IsEnvelope {
		signed, err := soroauth.AuthorizeEnvelope(context.Background(), input.Envelope,
			[]soroauth.Signer{signer}, expiration, passphrase)
		if err != nil {
			return writeJSONError(stdout, *jsonFlag, newErrorf(exitCodeForSigningError(err), "%w", err))
		}

		encoded, err := xdr.MarshalBase64(signed)
		if err != nil {
			return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "encoding the signed envelope: %w", err))
		}
		if *jsonFlag {
			enc := json.NewEncoder(stdout)
			enc.SetEscapeHTML(false)
			return enc.Encode(signOutput{SignedEnvelope: encoded})
		}
		fmt.Fprintln(stdout, encoded)
		return nil
	}

	var opts []soroauth.AuthorizeOption
	if *forAddress != "" {
		opts = append(opts, soroauth.ForAddress(*forAddress))
	}

	signed, err := soroauth.AuthorizeEntry(context.Background(), input.Entry,
		signer, expiration, passphrase, opts...)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(exitCodeForSigningError(err), "%w", err))
	}

	encoded, err := encodeEntry(signed)
	if err != nil {
		return writeJSONError(stdout, *jsonFlag, newErrorf(ExitGeneralError, "%w", err))
	}

	if *jsonFlag {
		out := signOutput{SignedEntry: encoded}
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(out)
	}

	fmt.Fprintln(stdout, encoded)
	return nil
}

// exitCodeForSigningError maps a refusal or a verification failure onto the
// exit code that classifies it, so both the entry and the envelope paths report
// the same way.
func exitCodeForSigningError(err error) int {
	switch {
	case errors.Is(err, soroauth.ErrNoMatchingCredentialNode),
		errors.Is(err, soroauth.ErrAlreadySigned),
		errors.Is(err, soroauth.ErrSourceAccountCredentials),
		errors.Is(err, soroauth.ErrUnsupportedCredentials),
		errors.Is(err, soroauth.ErrDuplicateDelegate),
		errors.Is(err, soroauth.ErrMissingSigner),
		errors.Is(err, soroauth.ErrNoInvokeOperation),
		errors.Is(err, soroauth.ErrUnsupportedEnvelope):
		return ExitSigningRefusal
	case errors.Is(err, soroauth.ErrSignatureMismatch),
		errors.Is(err, soroauth.ErrInvalidExpiration),
		errors.Is(err, soroauth.ErrTooManySignatures):
		return ExitVerificationFailed
	default:
		return ExitGeneralError
	}
}
