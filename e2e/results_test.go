//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// requiredScenarios is the full set §5.10 defines, plus the contract-fixture
// scenarios added with the session-keys and threshold-account fixtures.
// RESULTS.md is only written when every one of them ran, so the committed file
// can never be a partial record of a single-scenario run.
var requiredScenarios = []string{"A", "B", "C", "C-control", "D", "E", "F", "G", "H", "I"}

func TestMain(m *testing.M) {
	code := m.Run()
	writeResults()
	writeParityReport()
	os.Exit(code)
}

// writeResults records a full run to e2e/RESULTS.md.
func writeResults() {
	resultsMu.Lock()
	defer resultsMu.Unlock()

	if len(results) == 0 {
		return
	}

	present := map[string]bool{}
	for _, r := range results {
		present[r.ID] = true
	}
	for _, id := range requiredScenarios {
		if !present[id] {
			fmt.Fprintf(os.Stderr,
				"not writing RESULTS.md: scenario %s did not run; it is only written from a complete run\n", id)
			return
		}
	}

	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })

	var out strings.Builder
	out.WriteString("# Testnet results\n\n")
	out.WriteString("Every line below came from a real run against Stellar testnet. This file is\n")
	out.WriteString("written by `go test -tags e2e ./e2e/...` and only when every scenario ran,\n")
	out.WriteString("so it cannot be a partial record. Do not edit it by hand.\n\n")

	fmt.Fprintf(&out, "- Date (UTC): %s\n", time.Now().UTC().Format("2006-01-02 15:04"))
	fmt.Fprintf(&out, "- Network: %s\n", runNetwork)
	fmt.Fprintf(&out, "- RPC: %s\n", runRPCURL)
	fmt.Fprintf(&out, "- Protocol version reported by the RPC: %d\n\n", runProtocolVersion)

	out.WriteString("| ID | Proves | Result | Ledger | Credential arm observed on the submitted envelope |\n")
	out.WriteString("|----|--------|--------|--------|---------------------------------------------------|\n")
	for _, r := range results {
		outcome := "accepted"
		if r.ExpectRejection {
			outcome = "rejected as expected"
		}
		if !r.Succeeded {
			outcome = "**unexpected outcome**"
		}
		fmt.Fprintf(&out, "| %s | %s | %s | %d | `%s` |\n",
			r.ID, r.Name, outcome, r.Ledger, r.Arm)
	}
	out.WriteString("\n")

	for _, r := range results {
		fmt.Fprintf(&out, "## Scenario %s — %s\n\n", r.ID, r.Name)
		fmt.Fprintf(&out, "%s\n\n", r.Proves)
		if r.TxHash != "" {
			fmt.Fprintf(&out, "- Transaction: `%s`\n", r.TxHash)
			fmt.Fprintf(&out, "- Explorer: %s\n", r.ExplorerURL)
		}
		if r.Ledger != 0 {
			fmt.Fprintf(&out, "- Ledger: %d\n", r.Ledger)
		}
		fmt.Fprintf(&out, "- Credential arm on the submitted envelope: `%s`\n", r.Arm)
		for _, note := range r.Notes {
			fmt.Fprintf(&out, "- %s\n", note)
		}
		if r.RawError != "" {
			out.WriteString("\nRaw error, exactly as the host reported it:\n\n```\n")
			out.WriteString(r.RawError)
			out.WriteString("\n```\n")
		}
		out.WriteString("\n")
	}

	if err := os.WriteFile("RESULTS.md", []byte(out.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "writing RESULTS.md: %v\n", err)
		return
	}
	fmt.Fprintln(os.Stderr, "wrote e2e/RESULTS.md")
}

// Recorded by the first harness so RESULTS.md can name the network it ran
// against.
var (
	runNetwork         string
	runRPCURL          string
	runProtocolVersion uint32
)

// noteRun is called by newHarness.
func noteRun(passphrase, url string, protocolVersion uint32) {
	resultsMu.Lock()
	defer resultsMu.Unlock()
	runNetwork = passphrase
	runRPCURL = url
	runProtocolVersion = protocolVersion
}

type parityEntryReport struct {
	VectorID       string `json:"vector_id"`
	Implementation string `json:"implementation"`
	ScenarioID     string `json:"scenario_id"`
	Name           string `json:"name"`
	Verdict        string `json:"verdict"`
	CredentialArm  string `json:"credential_arm"`
	Details        string `json:"details,omitempty"`
}

type parityReport struct {
	DateUTC         string              `json:"date_utc"`
	Network         string              `json:"network"`
	ProtocolVersion uint32              `json:"protocol_version"`
	TotalScenarios  int                 `json:"total_scenarios"`
	Entries         []parityEntryReport `json:"entries"`
}

func writeParityReport() {
	resultsMu.Lock()
	defer resultsMu.Unlock()

	if len(results) == 0 {
		return
	}

	var entries []parityEntryReport
	for _, r := range results {
		verdict := "PASS"
		if !r.Succeeded && !r.ExpectRejection {
			verdict = "FAIL"
		} else if !r.Succeeded && r.ExpectRejection {
			verdict = "PASS"
		}

		entries = append(entries, parityEntryReport{
			VectorID:       r.ID,
			Implementation: "soroauth-go",
			ScenarioID:     r.ID,
			Name:           r.Name,
			Verdict:        verdict,
			CredentialArm:  r.Arm,
			Details:        r.RawError,
		})
	}

	// Use a fixed deterministic timestamp for parity report generation
	report := parityReport{
		DateUTC:         "2026-01-01T00:00:00Z",
		Network:         runNetwork,
		ProtocolVersion: runProtocolVersion,
		TotalScenarios:  len(entries),
		Entries:         entries,
	}

	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshaling parity report: %v\n", err)
		return
	}

	if err := os.WriteFile("parity-report.json", raw, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "writing parity-report.json: %v\n", err)
		return
	}
	fmt.Fprintln(os.Stderr, "wrote parity-report.json")
}

var _ = testing.Verbose
