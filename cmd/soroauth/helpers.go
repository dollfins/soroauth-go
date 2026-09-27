package main

import (
	"io"
	"os"
	"strings"
)

func readAssertionInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

// resolveEntryArg turns an --entry value of "-" into whatever is on r,
// leaving any other value alone.
//
// The result is trimmed of surrounding whitespace, which is what makes a
// pipeline work at all: every subcommand prints its base64 with a trailing
// newline, so the next one in the pipe reads that newline too and the XDR
// decoder rejects the blob with "input not fully consumed". Trimming is safe
// because base64 XDR never contains whitespace.
func resolveEntryArg(val string, r io.Reader) (string, error) {
	if val == "-" {
		if r == nil {
			r = os.Stdin
		}
		data, err := io.ReadAll(r)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(data)), nil
	}
	return val, nil
}
