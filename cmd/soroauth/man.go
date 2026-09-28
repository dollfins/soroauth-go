// Man page generation for the CLI.
//
// The page is generated rather than written by hand so it cannot describe a
// CLI that does not exist: the command and flag lists come from commandSpecs,
// the same table the shell completions are generated from and which
// TestSpecsMatchTheRealFlagSets pins to the flag sets the dispatcher actually
// parses. A subcommand added without updating that table fails the test suite,
// and a man page generated from a stale table would be the same class of bug
// with a longer feedback loop.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

const manUsage = `soroauth man — emit a roff man page for this CLI.

usage:
  soroauth man [--out <path>] [--json]

Prints soroauth(1) on stdout, or writes it to the file named by --out.
Packaging (Homebrew, apt, an RPM) installs that file as the tool's man page.

Every subcommand and flag the CLI parses is documented, including the global
--version and --help. Nothing is hand-written per subcommand: the page is
generated from the same command/flag table the completion scripts use, so it
cannot describe a flag the binary does not accept.

The page carries no build timestamp, so two builds of the same source emit
byte-identical pages. A packager that wants a date in .TH stamps it, rather
than having the generated file change on every build.

With --json, prints a JSON object with fields "format" and "page"; on error, a
JSON object with field "error" and exits non-zero. --json and --out are
mutually exclusive.

exit codes:
  0  success
  2  usage error (unknown flag, or --json together with --out)
`

// manOutput is the shape of the --json success object.
type manOutput struct {
	Format string `json:"format"`
	Page   string `json:"page"`
}

func runMan(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("man", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, manUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	outFlag := flags.String("out", "", "write the page to this path instead of stdout")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}
	// Refused rather than resolved by precedence: a caller that asked for the
	// page on stdout and in a file does not get to be surprised about which
	// one happened.
	if *outFlag != "" && *jsonFlag {
		return writeJSONError(stdout, *jsonFlag,
			newErrorf(ExitUsageError, "--out and --json are mutually exclusive"))
	}

	page := manPage()

	if *outFlag != "" {
		if err := os.WriteFile(*outFlag, []byte(page), 0o644); err != nil {
			return newErrorf(ExitGeneralError, "writing %s: %w", *outFlag, err)
		}
		return nil
	}

	if *jsonFlag {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(manOutput{Format: "man", Page: page})
	}

	if _, err := io.WriteString(stdout, page); err != nil {
		return newErrorf(ExitGeneralError, "writing the man page: %w", err)
	}
	return nil
}

// manPage renders the roff source of soroauth(1).
func manPage() string {
	var b strings.Builder

	b.WriteString(`.TH SOROAUTH 1 "" "soroauth ` + roffField(version) + `" "User Commands"` + "\n")
	b.WriteString(".SH NAME\n")
	b.WriteString("soroauth \\- build, sign and inspect Soroban authorization entries\n")

	b.WriteString(".SH SYNOPSIS\n")
	b.WriteString(".B soroauth\n")
	b.WriteString(".I command\n")
	b.WriteString(".RI [ flags ]\n")

	b.WriteString(".SH DESCRIPTION\n")
	b.WriteString(".B soroauth\n")
	b.WriteString("builds, signs and inspects Soroban authorization entries: the values a\n")
	b.WriteString("Soroban contract's require_auth call needs when the authorizing address is\n")
	b.WriteString("not the transaction's source account.\n")
	b.WriteString(".PP\n")
	b.WriteString("Entries are passed and printed as base64 XDR, so the tool composes with\n")
	b.WriteString("anything that produces or consumes that: an RPC client, jq, or another\n")
	b.WriteString("invocation of soroauth.\n")
	b.WriteString(".PP\n")
	b.WriteString("Secrets are never accepted as flag values. The sign subcommand reads a seed\n")
	b.WriteString("from a named environment variable instead, which keeps it out of shell\n")
	b.WriteString("history, out of the process table, and out of any transcript of the session.\n")
	b.WriteString("No subcommand prints a secret, including on the error paths.\n")
	b.WriteString(".PP\n")
	b.WriteString("Run\n")
	b.WriteString(".B soroauth\n")
	b.WriteString(".I command\n")
	b.WriteString(".B \\-h\n")
	b.WriteString("for a command's own flags. With --json, a command prints a single JSON\n")
	b.WriteString("object on stdout and, on failure, a JSON object with an \"error\" field.\n")

	b.WriteString(".SH COMMANDS\n")
	for _, cmd := range commandSpecs {
		b.WriteString(".TP\n")
		b.WriteString(".B " + roffText(cmd.Name) + "\n")
		b.WriteString(roffText(cmd.Description) + "\n")
		if len(cmd.Flags) > 0 {
			b.WriteString(".RS\n")
			for _, f := range cmd.Flags {
				b.WriteString(".TP\n")
				b.WriteString(".B " + roffFlag(f.Name) + "\n")
				b.WriteString(roffText(f.Description) + "\n")
			}
			b.WriteString(".RE\n")
		}
	}

	b.WriteString(".SH GLOBAL FLAGS\n")
	b.WriteString(".TP\n")
	b.WriteString(".B \\-\\-version\n")
	b.WriteString("print the build version, commit and Go toolchain version, then exit\n")
	b.WriteString(".TP\n")
	b.WriteString(".B \\-h, \\-\\-help\n")
	b.WriteString("print the usage text\n")

	b.WriteString(".SH EXIT CODES\n")
	b.WriteString(".TP\n")
	b.WriteString(".B 0\n")
	b.WriteString("success\n")
	b.WriteString(".TP\n")
	b.WriteString(".B 1\n")
	b.WriteString("general error (internal or unclassified)\n")
	b.WriteString(".TP\n")
	b.WriteString(".B 2\n")
	b.WriteString("usage error (invalid flags, missing required flags, malformed input)\n")
	b.WriteString(".TP\n")
	b.WriteString(".B 3\n")
	b.WriteString("signing refused (no matching node, already signed, unsupported credentials)\n")
	b.WriteString(".TP\n")
	b.WriteString(".B 4\n")
	b.WriteString("verification failed (signature mismatch, invalid expiration)\n")

	b.WriteString(".SH ENVIRONMENT\n")
	b.WriteString(".TP\n")
	b.WriteString(".B SOROAUTH_RPC_URL\n")
	b.WriteString("default RPC endpoint for --rpc-url, used by --valid-for\n")

	b.WriteString(".SH SEE ALSO\n")
	b.WriteString("The project README and the guides under docs/ in the source repository.\n")

	b.WriteString(".SH LICENSE\n")
	b.WriteString("Apache License 2.0. This software is unaudited; see SECURITY.md.\n")

	return b.String()
}

// roffText renders s as an argument or body text on a roff line.
//
// A backslash is roff's escape character, and a line whose first character is
// '.' or '\” would be read as a request rather than as text, so both are
// neutralised. Everything this page renders is either a fixed string from this
// file or a description from commandSpecs, but a page that can be broken by one
// apostrophe in a description is a page a packager cannot trust.
func roffText(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	if strings.HasPrefix(s, ".") || strings.HasPrefix(s, "'") {
		return `\&` + s
	}
	return s
}

// roffFlag renders a long flag name (without its leading dashes) for a .B
// line. The dashes are escaped because a macro argument beginning with '-' is
// read as an option to the macro rather than as text, and the '\(em' roff
// would otherwise print is not the flag a caller types.
func roffFlag(name string) string {
	return `\-\-` + strings.ReplaceAll(name, `\`, `\\`)
}

// roffField renders s for use inside a double-quoted roff argument, as in
// .TH's heading lines, where a double quote would end the argument and a
// newline would end the line. The value is build metadata (the version), which
// comes from a git tag rather than from a user, but escaping it here is cheaper
// than reasoning about which characters a tag may contain.
func roffField(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n', '\r':
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
