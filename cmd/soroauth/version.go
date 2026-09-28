package main

import (
	"fmt"
	"io"
	"runtime"
)

// Build metadata, injected at build time with
//
//	go build -ldflags "-X main.version=… -X main.commit=… -X main.date=…"
//
// The defaults describe a binary built by hand — `go build`, a `go install`
// from a checkout, a contributor's local build — where there is no release to
// name. They are deliberately non-empty and self-describing: an empty version
// string reads as a parsing bug in a bug report, whereas "dev" says plainly
// that this binary came from a source tree. The release workflow overrides all
// three (see .github/workflows/release.yml), and
// TestReleaseWorkflowSetsBuildMetadata fails if it stops doing so.
var (
	// version is the release tag this binary was built from, e.g. v0.2.0.
	version = "dev"
	// commit is the git commit this binary was built from.
	commit = "unknown"
	// date is the build timestamp, RFC 3339 in UTC.
	date = "unknown"
)

// versionText renders the build metadata that --version reports.
//
// The Go toolchain version comes from runtime.Version() rather than from an
// ldflags value: it is the one field the binary can read from its own runtime,
// so it cannot be stale or mis-stamped, and it is exactly what a bug report
// needs when a build fails on someone else's machine.
func versionText() string {
	return fmt.Sprintf("soroauth %s\ncommit: %s\nbuilt: %s\ngo: %s\n",
		version, commit, date, runtime.Version())
}

// runVersion writes the build metadata to stdout.
//
// It parses no flags. `soroauth --version` answers one question and exits, so
// anything after it is ignored rather than treated as a usage error — a caller
// who typed the flag wanted the version, not a lecture about extra arguments,
// and there is nothing here that could consume a following argument by
// mistake.
func runVersion(stdout io.Writer) error {
	if _, err := io.WriteString(stdout, versionText()); err != nil {
		return newErrorf(ExitGeneralError, "writing the version: %w", err)
	}
	return nil
}
