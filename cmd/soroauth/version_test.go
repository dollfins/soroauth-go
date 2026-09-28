package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestVersionFlagReportsBuildMetadata drives --version through the dispatcher
// the way a user does, and asserts each field the flag promises. The values
// themselves come from the build, so this asserts shape and presence rather
// than a pinned version: a test that hard-coded v0.3.0 would fail on every
// release.
func TestVersionFlagReportsBuildMetadata(t *testing.T) {
	for _, arg := range []string{"--version", "-version"} {
		t.Run(arg, func(t *testing.T) {
			stdout, stderr, err := runCLI(t, arg)
			if err != nil {
				t.Fatalf("%s failed: %v (stderr: %s)", arg, err, stderr)
			}
			if stderr != "" {
				t.Errorf("%s wrote to stderr: %q", arg, stderr)
			}

			lines := strings.Split(strings.TrimSuffix(stdout, "\n"), "\n")
			if len(lines) != 4 {
				t.Fatalf("%s printed %d lines, want 4:\n%s", arg, len(lines), stdout)
			}
			if !strings.HasPrefix(lines[0], "soroauth ") {
				t.Errorf("first line %q does not name the program", lines[0])
			}
			if !strings.HasPrefix(lines[1], "commit: ") || strings.TrimSpace(strings.TrimPrefix(lines[1], "commit: ")) == "" {
				t.Errorf("second line %q does not report a commit", lines[1])
			}
			if !strings.HasPrefix(lines[2], "built: ") || strings.TrimSpace(strings.TrimPrefix(lines[2], "built: ")) == "" {
				t.Errorf("third line %q does not report a build time", lines[2])
			}
			if want := "go: " + runtime.Version(); lines[3] != want {
				t.Errorf("fourth line = %q, want %q", lines[3], want)
			}
		})
	}
}

// TestVersionTextRendersInjectedMetadata proves the ldflags-injected values are
// the ones that reach the output. The release workflow writes main.version,
// main.commit and main.date; this is the Go side of that contract.
func TestVersionTextRendersInjectedMetadata(t *testing.T) {
	originalVersion, originalCommit, originalDate := version, commit, date
	defer func() { version, commit, date = originalVersion, originalCommit, originalDate }()

	version, commit, date = "v9.9.9", "abc1234", "2026-09-28T00:00:00Z"

	got := versionText()
	for _, want := range []string{"soroauth v9.9.9", "commit: abc1234", "built: 2026-09-28T00:00:00Z", "go: " + runtime.Version()} {
		if !strings.Contains(got, want) {
			t.Errorf("versionText() = %q, which does not contain %q", got, want)
		}
	}
}

// TestVersionDefaultsAreSelfDescribing pins the no-ldflags defaults. An empty
// string would read as a parsing bug in a bug report; "dev" and "unknown" say
// what actually happened, which is that the binary was not built by the release
// workflow.
func TestVersionDefaultsAreSelfDescribing(t *testing.T) {
	if version != "dev" {
		t.Errorf("default version = %q, want %q", version, "dev")
	}
	if commit != "unknown" {
		t.Errorf("default commit = %q, want %q", commit, "unknown")
	}
	if date != "unknown" {
		t.Errorf("default date = %q, want %q", date, "unknown")
	}
}

// TestReleaseWorkflowSetsBuildMetadata is the drift guard for the acceptance
// criterion "release workflow sets them": the fields --version reports are only
// populated if the workflow passes them to -ldflags, and a workflow edit that
// drops one would otherwise be invisible until a user asked for a version.
func TestReleaseWorkflowSetsBuildMetadata(t *testing.T) {
	path := filepath.Join("..", "..", ".github", "workflows", "release.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	workflow := string(raw)
	for _, field := range []string{"-X main.version=", "-X main.commit=", "-X main.date="} {
		if !strings.Contains(workflow, field) {
			t.Errorf("%s does not pass %q to the linker, so --version would report the default", path, field)
		}
	}
}
