package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const doctorUsage = `soroauth doctor — check the local environment for common first-run problems.

usage:
  soroauth doctor [--rpc-url <url>] [--secret-env <VAR>] [--timeout <duration>] [--json]

Most first-run failures are environmental rather than something wrong with an
entry or a key, and the error from "sign" or "payload" does not say so. This
runs a small set of checks and reports each as pass or fail:

  go toolchain    the "go" binary on PATH is at least the version this module
                  requires (see go.mod), needed to build or update soroauth
                  from source
  network         an HTTP request to --rpc-url succeeds within --timeout
                  (default: https://soroban-testnet.stellar.org). Any HTTP
                  response counts as reachable; only a transport-level
                  failure (DNS, connection refused, timeout) does not
  secret env var  only checked when --secret-env is given: whether the named
                  environment variable is set to a non-empty value

Nothing here ever inspects or prints a secret's value, only whether it is set.

With --json, prints one JSON object: "checks" (one entry per check, each with
"name", "pass" and an optional "detail") and an overall "ok" field. Nothing
else is written to stdout in JSON mode.

exit codes:
  0  every check passed
  1  at least one check failed
  2  usage error (invalid flags)
`

// goVersionFloor is the minimum toolchain version this module's go.mod
// declares. Doctor checks the "go" binary on PATH against it, not the
// version soroauth itself happened to be built with, because a stale local
// Go toolchain is what breaks "go install" and "go test", the failures this
// command exists to explain.
const goVersionFloor = "go1.25.0"

// doctorCheck is the pass/fail result of one environment check.
type doctorCheck struct {
	Name   string `json:"name"`
	Pass   bool   `json:"pass"`
	Detail string `json:"detail,omitempty"`
}

// doctorReport is the full result of a doctor run, and the shape of its JSON
// output.
type doctorReport struct {
	Checks []doctorCheck `json:"checks"`
	OK     bool          `json:"ok"`
}

func runDoctor(args []string, stdout, stderr io.Writer, getenv func(string) string) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprint(stderr, doctorUsage)
		fmt.Fprintln(stderr, "\nflags:")
		flags.PrintDefaults()
	}

	rpcURL := flags.String("rpc-url", "https://soroban-testnet.stellar.org", "URL to check network reachability against")
	secretEnv := flags.String("secret-env", "", "name of an environment variable whose presence (not value) to check")
	timeout := flags.Duration("timeout", 5*time.Second, "timeout for the network check")
	jsonFlag := flags.Bool("json", false, "output as JSON")

	if err := flags.Parse(args); err != nil {
		return newErrorf(ExitUsageError, "%w", err)
	}

	checks := []doctorCheck{
		checkGoToolchain(),
		checkNetwork(*rpcURL, *timeout),
	}
	if *secretEnv != "" {
		checks = append(checks, checkSecretEnv(*secretEnv, getenv))
	}

	ok := true
	for _, c := range checks {
		if !c.Pass {
			ok = false
		}
	}
	report := doctorReport{Checks: checks, OK: ok}

	if *jsonFlag {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(report); err != nil {
			return newErrorf(ExitGeneralError, "encoding the report: %w", err)
		}
		if !ok {
			// Wrapped as already-handled so main() does not also print a
			// generic message to stderr: the JSON report on stdout is the
			// complete, results-only account of what failed.
			return &jsonErrorHandled{newErrorf(ExitGeneralError, "one or more doctor checks failed")}
		}
		return nil
	}

	for _, c := range checks {
		status := "FAIL"
		if c.Pass {
			status = "PASS"
		}
		if c.Detail != "" {
			fmt.Fprintf(stdout, "%-4s %-16s %s\n", status, c.Name, c.Detail)
		} else {
			fmt.Fprintf(stdout, "%-4s %-16s\n", status, c.Name)
		}
	}
	if ok {
		fmt.Fprintln(stdout, "all checks passed")
		return nil
	}
	fmt.Fprintln(stdout, "one or more checks failed")
	return newErrorf(ExitGeneralError, "one or more doctor checks failed")
}

// checkGoToolchain reports whether the "go" binary on PATH meets
// goVersionFloor. Missing entirely counts as a failure: soroauth's own
// go.mod requires it to build the CLI from source or run "go install".
func checkGoToolchain() doctorCheck {
	const name = "go toolchain"

	path, err := exec.LookPath("go")
	if err != nil {
		return doctorCheck{Name: name, Pass: false,
			Detail: fmt.Sprintf("no \"go\" binary on PATH (this module requires %s or later): %v", goVersionFloor, err)}
	}

	out, err := exec.Command(path, "version").Output()
	if err != nil {
		return doctorCheck{Name: name, Pass: false, Detail: fmt.Sprintf("running %q: %v", path+" version", err)}
	}

	version, ok := parseGoVersion(string(out))
	if !ok {
		return doctorCheck{Name: name, Pass: false,
			Detail: fmt.Sprintf("could not parse a go version from %q", strings.TrimSpace(string(out)))}
	}
	if !goVersionAtLeast(version, goVersionFloor) {
		return doctorCheck{Name: name, Pass: false,
			Detail: fmt.Sprintf("%s found, but this module requires %s or later", version, goVersionFloor)}
	}
	return doctorCheck{Name: name, Pass: true, Detail: version}
}

var goVersionPattern = regexp.MustCompile(`go\d+\.\d+(?:\.\d+)?`)

// parseGoVersion extracts a "goX.Y" or "goX.Y.Z" token from the output of
// "go version", such as "go version go1.25.4 linux/amd64".
func parseGoVersion(output string) (string, bool) {
	m := goVersionPattern.FindString(output)
	return m, m != ""
}

// goVersionAtLeast reports whether version is the same as, or newer than,
// floor, comparing major, minor and patch numerically rather than as
// strings (so "go1.9.0" correctly compares below "go1.10.0").
func goVersionAtLeast(version, floor string) bool {
	v, f := goVersionParts(version), goVersionParts(floor)
	for i := range v {
		if v[i] != f[i] {
			return v[i] > f[i]
		}
	}
	return true
}

func goVersionParts(version string) [3]int {
	var parts [3]int
	fields := strings.SplitN(strings.TrimPrefix(version, "go"), ".", 3)
	for i := 0; i < len(fields) && i < 3; i++ {
		n, _ := strconv.Atoi(fields[i])
		parts[i] = n
	}
	return parts
}

// checkNetwork reports whether url is reachable within timeout. Any HTTP
// response, including a non-2xx status, counts as reachable: it proves DNS
// resolution, the TCP handshake and (for https) TLS all succeeded, which is
// what "no network" actually breaks. Only a transport-level error fails the
// check.
func checkNetwork(url string, timeout time.Duration) doctorCheck {
	const name = "network"

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return doctorCheck{Name: name, Pass: false, Detail: fmt.Sprintf("building a request for %s: %v", url, err)}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return doctorCheck{Name: name, Pass: false, Detail: fmt.Sprintf("%s: %v", url, err)}
	}
	// The response body is only drained for the connection's sake; its close
	// error cannot change the reachability verdict.
	defer func() { _ = resp.Body.Close() }()

	return doctorCheck{Name: name, Pass: true, Detail: fmt.Sprintf("%s reachable (HTTP %d)", url, resp.StatusCode)}
}

// checkSecretEnv reports whether the named environment variable is set to a
// non-empty value. It never reads the value into the report beyond that
// boolean: the CLI never prints a secret, not even on a failure path.
func checkSecretEnv(name string, getenv func(string) string) doctorCheck {
	checkName := "secret env: " + name
	if getenv(name) == "" {
		return doctorCheck{Name: checkName, Pass: false, Detail: fmt.Sprintf("%s is empty or unset", name)}
	}
	return doctorCheck{Name: checkName, Pass: true, Detail: fmt.Sprintf("%s is set", name)}
}
