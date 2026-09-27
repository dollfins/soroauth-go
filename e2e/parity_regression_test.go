//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestParityReportRegression(t *testing.T) {
	// Look for parity-report.json either in root or e2e/ directory depending on where test is run
	reportPath := "parity-report.json"
	if _, err := os.Stat(reportPath); os.IsNotExist(err) {
		reportPath = filepath.Join("..", "parity-report.json")
	}

	raw, err := os.ReadFile(reportPath)
	if err != nil {
		// If generated report doesn't exist yet (e.g. running standalone before e2e suite), fall back to checking the regression fixture
		fixturePath := filepath.Join("testdata", "parity_regression.json")
		if _, fErr := os.Stat(fixturePath); os.IsNotExist(fErr) {
			fixturePath = filepath.Join("e2e", "testdata", "parity_regression.json")
		}
		raw, err = os.ReadFile(fixturePath)
		if err != nil {
			t.Fatalf("failed to read parity report or regression fixture: %v", err)
		}
	}

	var report parityReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatalf("failed to unmarshal parity report: %v", err)
	}

	if report.TotalScenarios == 0 {
		t.Fatal("parity report contains zero scenarios")
	}

	for _, entry := range report.Entries {
		if entry.VectorID == "" || entry.Verdict == "" {
			t.Fatalf("invalid parity entry: %+v", entry)
		}
	}
}
