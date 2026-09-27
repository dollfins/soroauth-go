package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// runCompletionsCLI drives runCompletions directly and captures both streams,
// the way the other subcommand tests drive their run functions.
func runCompletionsCLI(t *testing.T, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut strings.Builder
	err = runCompletions(args, &out, &errOut)
	return out.String(), errOut.String(), err
}

// TestCompletionsGenerateForEveryShell asserts each supported shell produces a
// non-empty script naming every subcommand and every flag.
func TestCompletionsGenerateForEveryShell(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			stdout, stderr, err := runCompletionsCLI(t, "--shell", shell)
			if err != nil {
				t.Fatalf("--shell %s failed: %v (stderr: %s)", shell, err, stderr)
			}
			if stderr != "" {
				t.Errorf("--shell %s wrote to stderr: %q", shell, stderr)
			}
			if stdout == "" {
				t.Fatal("empty completion script")
			}
			for _, cmd := range commandSpecs {
				if !strings.Contains(stdout, cmd.Name) {
					t.Errorf("script does not mention subcommand %q", cmd.Name)
				}
				for _, f := range cmd.Flags {
					if !strings.Contains(stdout, f.Name) {
						t.Errorf("script does not mention flag %q", f.Name)
					}
				}
			}
		})
	}
}

// TestCompletionsAreDeterministic asserts the same shell generates
// byte-identical output across calls, so a committed or cached script cannot
// differ from what the binary would emit.
func TestCompletionsAreDeterministic(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		first, _, err := runCompletionsCLI(t, "--shell", shell)
		if err != nil {
			t.Fatalf("--shell %s: %v", shell, err)
		}
		second, _, err := runCompletionsCLI(t, "--shell", shell)
		if err != nil {
			t.Fatalf("--shell %s second call: %v", shell, err)
		}
		if first != second {
			t.Errorf("--shell %s produced different output across calls", shell)
		}
	}
}

// TestCompletionsJSONMode asserts --json wraps the exact script the plain mode
// prints, so a script captured either way is the same bytes.
func TestCompletionsJSONMode(t *testing.T) {
	plain, _, err := runCompletionsCLI(t, "--shell", "fish")
	if err != nil {
		t.Fatalf("plain mode: %v", err)
	}
	out, _, err := runCompletionsCLI(t, "--shell", "fish", "--json")
	if err != nil {
		t.Fatalf("json mode: %v", err)
	}
	var decoded completionsOutput
	if err := json.Unmarshal([]byte(out), &decoded); err != nil {
		t.Fatalf("decoding --json output: %v\noutput: %s", err, out)
	}
	if decoded.Shell != "fish" {
		t.Errorf("shell field = %q, want %q", decoded.Shell, "fish")
	}
	if decoded.Script != plain {
		t.Errorf("--json script differs from the plain-mode output")
	}
}

// TestCompletionsUsageErrors asserts the failure contract: missing --shell and
// unknown --shell are usage errors on exit code 2, in plain and JSON mode
// alike, with nothing on stdout in plain mode.
func TestCompletionsUsageErrors(t *testing.T) {
	t.Run("missing shell", func(t *testing.T) {
		stdout, _, err := runCompletionsCLI(t)
		if got := ExitCode(err); got != ExitUsageError {
			t.Errorf("exit code = %d, want %d", got, ExitUsageError)
		}
		if err != nil && !strings.Contains(err.Error(), "--shell is required") {
			t.Errorf("error %q does not say --shell is required", err)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty", stdout)
		}
	})
	t.Run("missing shell json", func(t *testing.T) {
		stdout, _, err := runCompletionsCLI(t, "--json")
		if got := ExitCode(err); got != ExitUsageError {
			t.Errorf("exit code = %d, want %d", got, ExitUsageError)
		}
		var decoded struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
			t.Fatalf("stdout is not a JSON error object: %v\noutput: %s", err, stdout)
		}
		if decoded.Error == "" {
			t.Error("JSON error object carries an empty error field")
		}
	})
	t.Run("unknown shell", func(t *testing.T) {
		stdout, _, err := runCompletionsCLI(t, "--shell", "powershell")
		if got := ExitCode(err); got != ExitUsageError {
			t.Errorf("exit code = %d, want %d", got, ExitUsageError)
		}
		if stdout != "" {
			t.Errorf("stdout = %q, want empty", stdout)
		}
	})
	t.Run("unknown shell json", func(t *testing.T) {
		stdout, _, err := runCompletionsCLI(t, "--shell", "powershell", "--json")
		if got := ExitCode(err); got != ExitUsageError {
			t.Errorf("exit code = %d, want %d", got, ExitUsageError)
		}
		var decoded struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal([]byte(stdout), &decoded); err != nil {
			t.Fatalf("stdout is not a JSON error object: %v\noutput: %s", err, stdout)
		}
	})
}

// parsePrintDefaults extracts a FlagSet's registered flags from the output of
// flag.PrintDefaults: a map from flag name to whether the flag line names a
// type (string, uint, duration, value) — which for this CLI is exactly
// "takes a value", since every boolean flag prints bare.
func parsePrintDefaults(out string) map[string]bool {
	flags := map[string]bool{}
	for _, line := range strings.Split(out, "\n") {
		// Flag lines start with exactly two spaces and a dash; the usage
		// lines beneath them are indented deeper and carry a tab.
		if !strings.HasPrefix(line, "  -") || strings.HasPrefix(line, "    ") {
			continue
		}
		fields := strings.Fields(line)
		name := strings.TrimPrefix(fields[0], "-")
		flags[name] = len(fields) > 1
	}
	return flags
}

// TestSpecsMatchTheRealFlagSets is the drift guard: for every subcommand built
// on the flag package, it drives the real flag parsing (via the same run
// function the dispatcher calls, asking for -h) and compares the flags that
// were actually registered against the spec table the completion generators
// use — in both directions, names and takes-a-value. A flag added to a
// subcommand without updating commandSpecs, or a spec entry for a flag that
// no longer exists, fails here.
//
// tui parses its arguments by hand and has no FlagSet; its spec is checked
// against its usage text instead, in TestTUISpecMatchesItsUsage.
func TestSpecsMatchTheRealFlagSets(t *testing.T) {
	for _, spec := range commandSpecs {
		t.Run(spec.Name, func(t *testing.T) {
			if spec.Name == "tui" {
				t.Skip("tui parses args by hand; covered by TestTUISpecMatchesItsUsage")
			}
			_, stderr, err := runCLI(t, spec.Name, "-h")
			// -h prints usage and returns a usage error through the flag
			// package's ErrHelp path; anything naming the command unknown is
			// the dispatcher rejecting it, which is a different failure.
			if err != nil && strings.Contains(err.Error(), "unknown command") {
				t.Fatalf("dispatcher does not know subcommand %q", spec.Name)
			}

			real := parsePrintDefaults(stderr)
			if len(real) == 0 {
				t.Fatalf("no registered flags found in usage output for %q:\n%s", spec.Name, stderr)
			}

			want := map[string]bool{}
			for _, f := range spec.Flags {
				want[f.Name] = f.TakesValue
				if got, ok := real[f.Name]; !ok {
					t.Errorf("spec lists flag --%s, which %q does not register", f.Name, spec.Name)
				} else if got != f.TakesValue {
					t.Errorf("flag --%s: spec says takesValue=%v, real FlagSet says %v", f.Name, f.TakesValue, got)
				}
			}
			var extra []string
			for name := range real {
				if _, ok := want[name]; !ok {
					extra = append(extra, name)
				}
			}
			if len(extra) > 0 {
				sort.Strings(extra)
				t.Errorf("%q registers flags missing from the spec table: %v — "+
					"add them to commandSpecs so the completion scripts offer them", spec.Name, extra)
			}
		})
	}
}

// TestTUISpecMatchesItsUsage covers the one subcommand without a FlagSet: its
// usage text is the machine-readable contract, so every spec flag must appear
// in it.
func TestTUISpecMatchesItsUsage(t *testing.T) {
	stdout, _, err := runCLI(t, "tui", "-h")
	if err != nil {
		t.Fatalf("tui -h failed: %v", err)
	}
	// Looked up by name, not by index. This was commandSpecs[5], which silently
	// started checking a different subcommand's flags against tui's usage text
	// the moment a spec was inserted above it.
	var tui *commandSpec
	for i := range commandSpecs {
		if commandSpecs[i].Name == "tui" {
			tui = &commandSpecs[i]
			break
		}
	}
	if tui == nil {
		t.Fatal("no tui entry in commandSpecs")
	}
	for _, f := range tui.Flags {
		if !strings.Contains(stdout, "--"+f.Name) {
			t.Errorf("tui usage text does not mention --%s", f.Name)
		}
	}
}

// TestSpecsCoverTheUsageText asserts the spec table and the top-level usage
// text name the same subcommands, so the completion menu and the help text
// cannot disagree about what the CLI offers. "help" is dispatcher-only and
// intentionally absent from both the usage list and the spec table.
func TestSpecsCoverTheUsageText(t *testing.T) {
	_, stderr, err := runCLI(t, "--help")
	if err != nil {
		t.Fatalf("--help failed: %v", err)
	}

	inCommands := false
	usageNames := map[string]bool{}
	for _, line := range strings.Split(stderr+usage, "\n") {
		switch {
		case strings.HasPrefix(line, "commands:"):
			inCommands = true
		case strings.HasPrefix(line, "run \"soroauth"):
			inCommands = false
		case inCommands && strings.HasPrefix(line, "  "):
			name := strings.Fields(line)[0]
			usageNames[name] = true
		}
	}

	specNames := map[string]bool{}
	for _, cmd := range commandSpecs {
		specNames[cmd.Name] = true
		if !usageNames[cmd.Name] {
			t.Errorf("spec table offers %q, but the usage text does not list it", cmd.Name)
		}
	}
	for name := range usageNames {
		if !specNames[name] {
			t.Errorf("usage text lists %q, but the spec table does not — the completion scripts would not offer it", name)
		}
	}
}

// TestGeneratedScriptsNameNoSecretShape asserts none of the generated scripts
// carries anything seed- or address-shaped: completions suggest flag and
// variable names, never values, and the specs' descriptions must never grow
// an example that looks like a real key.
func TestGeneratedScriptsNameNoSecretShape(t *testing.T) {
	seedPattern := regexp.MustCompile(`[SG][A-Z2-7]{55}`)
	for _, shell := range []string{"bash", "zsh", "fish"} {
		script, _, err := runCompletionsCLI(t, "--shell", shell)
		if err != nil {
			t.Fatalf("--shell %s: %v", shell, err)
		}
		if seedPattern.MatchString(script) {
			t.Errorf("--shell %s script contains a seed- or address-shaped string", shell)
		}
		if strings.Contains(script, "SABC") {
			t.Errorf("--shell %s script contains a literal seed example", shell)
		}
	}
}

// TestApostrophesSurviveQuoting exercises the one quoting hazard in the spec
// descriptions (signer's, inspect's): the escaped form must round-trip to the
// original through both quote helpers.
func TestApostrophesSurviveQuoting(t *testing.T) {
	const withApostrophe = "the signer's own address"
	// Each output must round-trip through a decoder implementing its shell's
	// real single-quote tokenization, which is where the two helpers differ:
	// POSIX (zsh) treats a backslash as an escape only OUTSIDE quotes, so an
	// apostrophe inside a quoted segment must be spelled close-escape-reopen
	// ('\''), while fish treats a backslash inside quotes as escaping the next
	// apostrophe or backslash (\'). A form that merely balances quotes but
	// decodes to the wrong text — or never terminates — fails here.
	decode := func(s string, fish bool) string {
		var b strings.Builder
		inQuote := false
		for i := 0; i < len(s); i++ {
			switch c := s[i]; c {
			case '\'':
				inQuote = !inQuote
			case '\\':
				escapes := !inQuote || (fish && i+1 < len(s) && (s[i+1] == '\'' || s[i+1] == '\\'))
				if escapes && i+1 < len(s) {
					b.WriteByte(s[i+1])
					i++
				} else {
					b.WriteByte(c)
				}
			default:
				b.WriteByte(c)
			}
		}
		return b.String()
	}
	for _, q := range []struct {
		name   string
		quoted string
		fish   bool
	}{
		{"zsh", zshQuote(withApostrophe), false},
		{"fish", fishQuote(withApostrophe), true},
	} {
		if got := decode(q.quoted, q.fish); got != withApostrophe {
			t.Errorf("%s: %q decodes to %q, want %q", q.name, q.quoted, got, withApostrophe)
		}
	}
	// The unquoted spec descriptions feed every generator; a generator that
	// stops quoting would embed a bare apostrophe, so assert the raw hazard
	// exists in the table this test protects.
	found := false
	for _, cmd := range commandSpecs {
		for _, f := range cmd.Flags {
			if strings.Contains(f.Description, "'") {
				found = true
			}
		}
	}
	if !found {
		t.Error("no apostrophe in any spec description; this test no longer covers the quoting hazard")
	}
}

// writeCompletionScript writes the generated script for shell to a temp file
// and returns its path.
func writeCompletionScript(t *testing.T, shell string) string {
	t.Helper()
	script, _, err := runCompletionsCLI(t, "--shell", shell)
	if err != nil {
		t.Fatalf("--shell %s: %v", shell, err)
	}
	path := filepath.Join(t.TempDir(), map[string]string{
		"bash": "soroauth.bash", "zsh": "_soroauth", "fish": "soroauth.fish",
	}[shell])
	if err := os.WriteFile(path, []byte(script), 0o644); err != nil {
		t.Fatalf("writing script: %v", err)
	}
	return path
}

// TestBashScriptLoadsAndCompletes proves the bash script is not merely
// well-formed but functional: sourced by real bash, it registers the
// completion and produces the expected candidates for a subcommand prefix and
// for --shell's value.
func TestBashScriptLoadsAndCompletes(t *testing.T) {
	bashPath, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("no bash on PATH")
	}
	path := writeCompletionScript(t, "bash")

	harness := `source "$1"
COMP_WORDS=(soroauth "pa"); COMP_CWORD=1; _soroauth_completions; echo "sub:${COMPREPLY[*]}"
COMP_WORDS=(soroauth completions --shell ""); COMP_CWORD=3; _soroauth_completions; echo "val:${COMPREPLY[*]}"
`
	out, err := exec.Command(bashPath, "-c", harness, "soroauth-test", path).CombinedOutput()
	if err != nil {
		t.Fatalf("bash harness failed: %v\noutput:\n%s", err, out)
	}
	assertLineHas(t, "bash", string(out), "sub:", "payload")
	assertLineHas(t, "bash", string(out), "val:", "bash zsh fish")
}

// TestFishScriptCompletes proves the fish script functionally: fish parses
// and executes the generated file, and the resulting complete rules list the
// subcommands and a subcommand's flags. The script is sourced explicitly
// rather than relied on fish's lazy load of the completions directory, which
// does not fire for a non-interactive `fish -c` process; installation into
// that directory is exactly what the script's install line does, and the
// file's loadability is what this test proves.
func TestFishScriptCompletes(t *testing.T) {
	fishPath, err := exec.LookPath("fish")
	if err != nil {
		t.Skip("no fish on PATH")
	}
	script := writeCompletionScript(t, "fish")

	run := func(commandLine string) string {
		harness := "source " + quoteFish(script) + "; complete -C " + quoteFish(commandLine)
		out, err := exec.Command(fishPath, "-c", harness).CombinedOutput()
		if err != nil {
			t.Fatalf("fish %q failed: %v\noutput:\n%s", commandLine, err, out)
		}
		return string(out)
	}

	subs := run("soroauth ")
	assertLineHas(t, "fish", subs, "", "payload")
	assertLineHas(t, "fish", subs, "", "cross-compile")
	flags := run("soroauth sign --")
	assertLineHas(t, "fish", flags, "", "--entry")
	assertLineHas(t, "fish", flags, "", "--secret-env")
}

// quoteFish renders s as a single-quoted fish argument for the test harness.
func quoteFish(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `\'`) + "'"
}

// assertLineHas asserts some output line starts with prefix (when non-empty)
// and contains want.
func assertLineHas(t *testing.T, shell, out, prefix, want string) {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, prefix) && strings.Contains(line, want) {
			return
		}
	}
	t.Errorf("%s: no output line with prefix %q contains %q\noutput:\n%s", shell, prefix, want, out)
}

// TestZshScriptParsesAndRegisters syntax-checks the zsh script with zsh -n and
// then sources it under a real compinit to confirm compdef accepts the
// registration. Interactive completion itself needs a TTY, which CI has
// none of, so this is a parse-and-register proof, not a tab-behavior proof;
// bash and fish carry the functional checks for all three generators' shared
// spec table.
func TestZshScriptParsesAndRegisters(t *testing.T) {
	zshPath, err := exec.LookPath("zsh")
	if err != nil {
		t.Skip("no zsh on PATH")
	}
	path := writeCompletionScript(t, "zsh")

	if out, err := exec.Command(zshPath, "-n", path).CombinedOutput(); err != nil {
		t.Fatalf("zsh -n rejected the script: %v\noutput:\n%s", err, out)
	}

	harness := `fpath=(` + filepath.Dir(path) + ` $fpath)
autoload -Uz compinit
compinit -u
whence -w _soroauth
`
	home := t.TempDir()
	cmd := exec.Command(zshPath, "-c", harness)
	cmd.Env = append(os.Environ(), "HOME="+home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("zsh harness failed: %v\noutput:\n%s", err, out)
	}
	if !strings.Contains(string(out), "_soroauth: function") {
		t.Errorf("compinit did not register _soroauth as a function\noutput:\n%s", out)
	}
}

// TestCompletionsThroughTheDispatcher asserts the subcommand is reachable the
// way a user reaches it, through run().
func TestCompletionsThroughTheDispatcher(t *testing.T) {
	stdout, stderr, err := runCLI(t, "completions", "--shell", "zsh")
	if err != nil {
		t.Fatalf("dispatcher rejected completions: %v (stderr: %s)", err, stderr)
	}
	if !strings.Contains(stdout, "#compdef soroauth") {
		t.Errorf("dispatcher output is not the zsh completion script:\n%.100s", stdout)
	}
}
