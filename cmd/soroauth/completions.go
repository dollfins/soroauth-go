package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"
)

const completionsUsage = `soroauth completions — emit a shell completion script.

usage:
  soroauth completions --shell bash|zsh|fish [--json]

Prints a completion script for the named shell on stdout. Source it or write it
to your shell's completion directory; README.md ("Shell completions") carries
the installation line for each shell:

  bash:  source <(soroauth completions --shell bash)          # interactive shells only
  bash:  soroauth completions --shell bash > /etc/bash_completion.d/soroauth
  zsh:   soroauth completions --shell zsh > "${fpath[1]}/_soroauth"
  fish:  soroauth completions --shell fish > ~/.config/fish/completions/soroauth.fish

bash and zsh complete subcommands and flags; fish completes subcommands, flags
and their descriptions. --secret-env is completed by name only: the shells
never see or complete a variable's value.

With --json, prints a JSON object with fields "shell" and "script"; on error, a
JSON object with field "error" and exits non-zero.

exit codes:
  0  success
  2  usage error (missing or unknown --shell)
`

// flagSpec describes one flag of one subcommand, so the completion generators
// and the flag definitions in this package cannot drift apart silently. The
// per-command flag lists below are hand-maintained: TestSpecsMatchTheRealFlags
// in completions_test.go drives each subcommand's real flag parsing (through
// the same dispatcher main uses) and fails if the two lists disagree.
type flagSpec struct {
	Name        string // long name, without the leading dashes
	Description string // what the flag is for, shown by fish and zsh
	TakesValue  bool   // false for boolean flags
}

// commandSpec describes one subcommand the completion scripts offer.
type commandSpec struct {
	Name        string
	Description string
	Flags       []flagSpec
}

// commandSpecs is the completion source of truth. Order is the order the
// shells print, which is the order of the usage text.
//
// The descriptions deliberately never embed a flag *value*: --secret-env
// names an environment variable holding a seed, and completions must suggest
// variable names, never values. No spec below carries anything secret, and
// the test suite asserts the generated scripts contain no seed- or
// address-shaped string.
var commandSpecs = []commandSpec{
	{
		Name:        "payload",
		Description: "print the signing preimage and payload hash for an entry",
		Flags: []flagSpec{
			{Name: "entry", Description: "authorization entry or transaction envelope, as base64 XDR", TakesValue: true},
			{Name: "valid-until", Description: "the last ledger at which the signature is valid", TakesValue: true},
			{Name: "valid-for", Description: "the signature lifetime in ledgers, resolved against the current ledger (needs --rpc-url)", TakesValue: true},
			{Name: "rpc-url", Description: "RPC endpoint used to resolve --valid-for (default $SOROAUTH_RPC_URL)", TakesValue: true},
			{Name: "network", Description: "testnet, futurenet, public, or a literal network passphrase", TakesValue: true},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "sign",
		Description: "sign an entry with a seed read from an environment variable",
		Flags: []flagSpec{
			{Name: "entry", Description: "authorization entry or transaction envelope, as base64 XDR", TakesValue: true},
			{Name: "valid-until", Description: "the last ledger at which the signature is valid", TakesValue: true},
			{Name: "valid-for", Description: "the signature lifetime in ledgers, resolved against the current ledger (needs --rpc-url)", TakesValue: true},
			{Name: "rpc-url", Description: "RPC endpoint used to resolve --valid-for (default $SOROAUTH_RPC_URL)", TakesValue: true},
			{Name: "network", Description: "testnet, futurenet, public, or a literal network passphrase", TakesValue: true},
			{Name: "secret-env", Description: "name of the environment variable holding the seed", TakesValue: true},
			{Name: "assertion", Description: "path to a WebAuthn assertion JSON file, or - for stdin", TakesValue: true},
			{Name: "for", Description: "credential node to sign, when it is not the signer's own address", TakesValue: true},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "delegates",
		Description: "wrap an entry in a delegated-signer credential",
		Flags: []flagSpec{
			{Name: "entry", Description: "the authorization entry, as base64 XDR", TakesValue: true},
			{Name: "valid-until", Description: "the last ledger at which the signatures are valid", TakesValue: true},
			{Name: "valid-for", Description: "the signature lifetime in ledgers, resolved against the current ledger (needs --rpc-url)", TakesValue: true},
			{Name: "rpc-url", Description: "RPC endpoint used to resolve --valid-for (default $SOROAUTH_RPC_URL)", TakesValue: true},
			{Name: "delegate", Description: "a delegate address; repeat for several", TakesValue: true},
			{Name: "nested-json", Description: "JSON string defining nested delegate tree", TakesValue: true},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "inspect",
		Description: "print an entry's structure as JSON",
		Flags: []flagSpec{
			{Name: "entry", Description: "the authorization entry or transaction envelope, as base64 XDR", TakesValue: true},
			{Name: "json", Description: "accepted for consistency; inspect's output is always JSON", TakesValue: false},
		},
	},
	{
		Name:        "tree",
		Description: "render an entry's delegate tree as ASCII, DOT, or JSON",
		Flags: []flagSpec{
			{Name: "entry", Description: "the authorization entry or transaction envelope, as base64 XDR", TakesValue: true},
			{Name: "format", Description: "tree rendering: ascii or dot", TakesValue: true},
			{Name: "json", Description: "output structured JSON instead of a rendering", TakesValue: false},
		},
	},
	{
		Name:        "tui",
		Description: "interactive TUI for inspecting and signing an entry",
		Flags: []flagSpec{
			{Name: "entry", Description: "base64-encoded authorization entry (required)", TakesValue: true},
			{Name: "valid-until", Description: "signature expiration ledger (required)", TakesValue: true},
			{Name: "network", Description: "testnet, futurenet, public, or a literal passphrase (required)", TakesValue: true},
			{Name: "secret-env", Description: "name of environment variable holding the secret seed (required)", TakesValue: true},
			{Name: "for", Description: "target address to sign for (optional)", TakesValue: true},
		},
	},
	{
		Name:        "doctor",
		Description: "check the local environment for common first-run problems",
		Flags: []flagSpec{
			{Name: "rpc-url", Description: "URL to check network reachability against", TakesValue: true},
			{Name: "secret-env", Description: "name of an environment variable whose presence to check", TakesValue: true},
			{Name: "timeout", Description: "timeout for the network check", TakesValue: true},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "cross-compile",
		Description: "build soroauth for multiple targets",
		Flags: []flagSpec{
			{Name: "json", Description: "emit results as JSON (one object per line)", TakesValue: false},
			{Name: "targets", Description: "comma-separated GOOS/GOARCH pairs (default: all)", TakesValue: true},
			{Name: "output-dir", Description: "directory to write binaries (default: stdout only)", TakesValue: true},
		},
	},
	{
		Name:        "verify",
		Description: "check an entry's signatures without submitting it",
		Flags: []flagSpec{
			{Name: "entry", Description: "the authorization entry or transaction envelope, as base64 XDR", TakesValue: true},
			{Name: "network", Description: "testnet, futurenet, public, or a literal network passphrase", TakesValue: true},
			{Name: "valid-until", Description: "assert the expiration the entry carries (optional)", TakesValue: true},
			{Name: "allow-unsigned", Description: "accept unsigned nodes (a Void top-level node of a delegates entry is legitimate under CAP-71-01)", TakesValue: false},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "completions",
		Description: "emit a shell completion script",
		Flags: []flagSpec{
			{Name: "shell", Description: "which shell: bash, zsh, or fish", TakesValue: true},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "man",
		Description: "emit a roff man page",
		Flags: []flagSpec{
			{Name: "out", Description: "write the page to this path instead of stdout", TakesValue: true},
			{Name: "json", Description: "output as JSON", TakesValue: false},
		},
	},
	{
		Name:        "wasm-budget",
		Description: "measure the wasm core against a size ceiling",
		Flags: []flagSpec{
			{Name: "out", Description: "path to the wasm artifact to measure", TakesValue: true},
			{Name: "budget", Description: "maximum allowed size in bytes", TakesValue: true},
			{Name: "prev-size", Description: "previous release's size, for a delta", TakesValue: true},
			{Name: "build-cmd", Description: "command to build the artifact before measuring", TakesValue: true},
			{Name: "json", Description: "output the result as JSON", TakesValue: false},
		},
	},
}

// completionsOutput is the shape of the --json success object.
type completionsOutput struct {
	Shell  string `json:"shell"`
	Script string `json:"script"`
}

func runCompletions(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("completions", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, completionsUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	shellFlag := flags.String("shell", "", "which shell to generate completions for: bash, zsh, or fish")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}
	if *shellFlag == "" {
		return writeJSONError(stdout, *jsonFlag,
			newErrorf(ExitUsageError, "--shell is required: one of bash, zsh, or fish"))
	}

	var script string
	switch *shellFlag {
	case "bash":
		script = bashCompletionScript()
	case "zsh":
		script = zshCompletionScript()
	case "fish":
		script = fishCompletionScript()
	default:
		return writeJSONError(stdout, *jsonFlag,
			newErrorf(ExitUsageError, "unknown shell %q: expected bash, zsh, or fish", *shellFlag))
	}

	if *jsonFlag {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		return enc.Encode(completionsOutput{Shell: *shellFlag, Script: script})
	}

	fmt.Fprint(stdout, script)
	return nil
}

// bashCompletionScript renders the bash completion. It is a plain function,
// not a template: the completed words come from commandSpecs at generation
// time, so the emitted script never needs to know the command list itself.
//
// The three enumerable flag values (--shell, --format, --network) complete
// their values from any position, since bash's $prev check is global; the
// per-subcommand case arms complete each subcommand's flags. -h/--help are
// offered everywhere, matching what the binary actually accepts.
func bashCompletionScript() string {
	var b strings.Builder
	b.WriteString("# bash completion for soroauth\n")
	b.WriteString("# generated by: soroauth completions --shell bash\n")
	b.WriteString("# sourcing this file defines the completion function; see README.md for installation\n\n")
	b.WriteString("_soroauth_completions()\n{\n")
	b.WriteString("\tlocal cur prev cmd\n")
	b.WriteString("\tcur=\"${COMP_WORDS[COMP_CWORD]}\"\n")
	b.WriteString("\tprev=\"${COMP_WORDS[COMP_CWORD-1]}\"\n")
	b.WriteString("\n\t# complete an enumerable flag's value, whatever the position\n")
	b.WriteString("\tcase \"$prev\" in\n")
	b.WriteString("\t\t--shell)\n")
	b.WriteString("\t\t\tCOMPREPLY=( $(compgen -W \"bash zsh fish\" -- \"$cur\") )\n")
	b.WriteString("\t\t\treturn 0\n\t\t\t;;\n")
	b.WriteString("\t\t--format)\n")
	b.WriteString("\t\t\tCOMPREPLY=( $(compgen -W \"ascii dot\" -- \"$cur\") )\n")
	b.WriteString("\t\t\treturn 0\n\t\t\t;;\n")
	b.WriteString("\t\t--network)\n")
	b.WriteString("\t\t\tCOMPREPLY=( $(compgen -W \"testnet futurenet public\" -- \"$cur\") )\n")
	b.WriteString("\t\t\treturn 0\n\t\t\t;;\n")
	b.WriteString("\tesac\n")
	b.WriteString("\n\t# after a subcommand, complete that subcommand's flags\n")
	b.WriteString("\tif (( COMP_CWORD > 1 )); then\n")
	b.WriteString("\t\tcmd=\"${COMP_WORDS[1]}\"\n")
	b.WriteString("\t\tcase \"$cmd\" in\n")
	for _, cmd := range commandSpecs {
		words := make([]string, 0, len(cmd.Flags)+2)
		words = append(words, "-h", "--help")
		for _, f := range cmd.Flags {
			words = append(words, "--"+f.Name)
		}
		b.WriteString(fmt.Sprintf("\t\t\t%s)\n", cmd.Name))
		b.WriteString(fmt.Sprintf("\t\t\t\tCOMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(words, " ")))
		b.WriteString("\t\t\t\treturn 0\n\t\t\t\t;;\n")
	}
	b.WriteString("\t\tesac\n")
	b.WriteString("\tfi\n\n")
	b.WriteString("\t# first word: the subcommands\n")
	b.WriteString(fmt.Sprintf("\tCOMPREPLY=( $(compgen -W %q -- \"$cur\") )\n", strings.Join(commandNames(), " ")))
	b.WriteString("}\n\n")
	b.WriteString("complete -F _soroauth_completions soroauth\n")
	return b.String()
}

// zshCompletionScript renders the zsh completion with the shell's native
// _arguments machinery, so value-taking flags complete with descriptions and
// boolean flags complete bare. Every user-visible string goes through
// zshQuote as a whole unit, because an apostrophe in a description (signer's,
// inspect's) ends a single-quoted zsh string unless escaped.
func zshCompletionScript() string {
	var b strings.Builder
	b.WriteString("#compdef soroauth\n")
	b.WriteString("# generated by: soroauth completions --shell zsh\n")
	b.WriteString("# install to a directory in $fpath as _soroauth; see README.md\n\n")
	b.WriteString("_soroauth()\n{\n")
	b.WriteString("\tlocal -a cmds\n")
	b.WriteString("\tcmds=(\n")
	for _, cmd := range commandSpecs {
		b.WriteString("\t\t" + zshQuote(cmd.Name+":"+cmd.Description) + "\n")
	}
	b.WriteString("\t)\n")
	b.WriteString("\tif (( CURRENT == 2 )); then\n")
	b.WriteString("\t\t_describe 'command' cmds\n")
	b.WriteString("\telse\n")
	b.WriteString("\t\tlocal cmd=\"${words[2]}\"\n")
	b.WriteString("\t\tcase \"$cmd\" in\n")
	for _, cmd := range commandSpecs {
		b.WriteString(fmt.Sprintf("\t\t\t(%s)\n", cmd.Name))
		b.WriteString("\t\t\t_arguments \\\n")
		parts := make([]string, 0, len(cmd.Flags)+1)
		// The closing quote of the help spec is part of this string: the join
		// separator (" \\") lands outside every part's quotes, and an unclosed
		// quote here shifts every quote after it to end of file.
		parts = append(parts, `'(-h --help)'{-h,--help}'[show this help]'`)
		for _, f := range cmd.Flags {
			if f.TakesValue {
				parts = append(parts, zshQuote(fmt.Sprintf("--%s=[%s]", f.Name, f.Description)))
			} else {
				parts = append(parts, zshQuote(fmt.Sprintf("--%s[%s]", f.Name, f.Description)))
			}
		}
		b.WriteString("\t\t\t\t" + strings.Join(parts, " \\\n\t\t\t\t") + "\n")
		b.WriteString("\t\t\t\t;;\n")
	}
	b.WriteString("\t\tesac\n")
	b.WriteString("\tfi\n")
	b.WriteString("}\n\n")
	b.WriteString("compdef _soroauth soroauth\n")
	return b.String()
}

// fishCompletionScript renders the fish completion. Fish reads its
// completions eagerly, one `complete` line per word, and is the one shell
// whose completions carry descriptions natively, so the specs' descriptions
// appear in the user's tab menu. Each description goes through fishQuote as
// a whole unit for the same apostrophe reason as zsh.
func fishCompletionScript() string {
	var b strings.Builder
	b.WriteString("# fish completion for soroauth\n")
	b.WriteString("# generated by: soroauth completions --shell fish\n")
	b.WriteString("# install to ~/.config/fish/completions/soroauth.fish; see README.md\n\n")
	for _, cmd := range commandSpecs {
		b.WriteString(fmt.Sprintf("complete -c soroauth -n '__fish_use_subcommand' -a %s -d %s\n",
			fishQuote(cmd.Name), fishQuote(cmd.Description)))
	}
	b.WriteString("\n")
	for _, cmd := range commandSpecs {
		for _, f := range cmd.Flags {
			b.WriteString(fmt.Sprintf("complete -c soroauth -n '__fish_seen_subcommand_from %s' -l %s -d %s\n",
				cmd.Name, f.Name, fishQuote(f.Description)))
		}
		// A subcommand's own -h/--help, offered alongside its flags.
		b.WriteString(fmt.Sprintf("complete -c soroauth -n '__fish_seen_subcommand_from %s' -s h -l help -d %s\n",
			cmd.Name, fishQuote("show this help")))
	}
	return b.String()
}

// commandNames returns the subcommand names in spec order, plus "help", which
// the dispatcher accepts but the spec table does not carry (it has no flags
// of its own).
func commandNames() []string {
	names := make([]string, 0, len(commandSpecs)+1)
	for _, cmd := range commandSpecs {
		names = append(names, cmd.Name)
	}
	return append(names, "help")
}

// zshQuote renders s as a single-quoted zsh string, escaping any embedded
// apostrophe with the close-escape-reopen convention, which zsh shares with
// POSIX shell.
func zshQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// fishQuote renders s as a single-quoted fish string. Fish — unlike the
// POSIX shells — treats a backslash before an apostrophe INSIDE single quotes
// as an escape, so '...' quoting with \' is the one correct form; the POSIX
// close-escape-reopen trick ( '\” ) reads as an unbalanced quote in fish and
// aborts the load of the whole completion file at that line.
func fishQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}
