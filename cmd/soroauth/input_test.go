package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/soroauth/soroauth-go"
)

// notBase64 is not valid standard base64: '-' is not in the alphabet.
const notBase64 = "not-base64"

// wrongXDR is valid base64 — it decodes to four 0xff bytes — but its first four
// bytes are a credentials discriminant of 0xffffffff, which is not one of the
// four defined SorobanCredentialsType values, so it cannot be an authorization
// entry.
const wrongXDR = "/////w=="

// TestDecodeEntryDistinguishesBase64FromXDR is the acceptance criterion: "this
// is not base64" and "this is base64 but is not an entry" are different
// messages, because they call for different fixes.
func TestDecodeEntryDistinguishesBase64FromXDR(t *testing.T) {
	t.Run("not base64", func(t *testing.T) {
		_, err := decodeEntry(notBase64)
		if err == nil {
			t.Fatal("decodeEntry accepted a non-base64 value")
		}
		if !strings.Contains(err.Error(), "not valid base64") {
			t.Errorf("error %q does not say the input is not base64", err)
		}
		if strings.Contains(err.Error(), "but is not a Soroban authorization entry") {
			t.Errorf("error %q misclassifies a non-base64 value as a wrong XDR type", err)
		}
	})

	t.Run("wrong XDR type", func(t *testing.T) {
		_, err := decodeEntry(wrongXDR)
		if err == nil {
			t.Fatal("decodeEntry accepted non-entry XDR")
		}
		if !strings.Contains(err.Error(), "valid base64 but is not a Soroban authorization entry") {
			t.Errorf("error %q does not say the input decoded but is the wrong type", err)
		}
		if strings.Contains(err.Error(), "not valid base64") {
			t.Errorf("error %q misclassifies valid base64 as malformed", err)
		}
	})
}

// TestEntryErrorsDoNotEchoTheInput proves the second half of the criterion:
// neither classification repeats the blob it was handed. An --entry value may
// be a signed entry, and the error is printed to a terminal, a CI log or a
// shell session.
func TestEntryErrorsDoNotEchoTheInput(t *testing.T) {
	for _, value := range []string{notBase64, wrongXDR} {
		_, err := decodeEntry(value)
		if err == nil {
			t.Fatalf("decodeEntry(%q) succeeded", value)
		}
		if strings.Contains(err.Error(), value) {
			t.Errorf("the error for %q echoes the input: %q", value, err)
		}
	}
}

// TestEntryDecodeMessagesThroughTheCLI drives both classifications through a
// real subcommand, since classifyInput is only useful if its text is what the
// user actually sees.
func TestEntryDecodeMessagesThroughTheCLI(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantMsg string
	}{
		{name: "not base64", value: notBase64, wantMsg: "not valid base64"},
		{name: "wrong XDR type", value: wrongXDR, wantMsg: "valid base64 but is not a Soroban authorization entry"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stdout, _, err := runCLI(t, "inspect", "--entry", tt.value)
			if err == nil {
				t.Fatalf("inspect accepted %q, printing %q", tt.value, stdout)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}

			// The same message reaches a --json caller, in the error field.
			jsonOut, _, jsonErr := runCLI(t, "inspect", "--entry", tt.value, "--json")
			if jsonErr == nil {
				t.Fatal("inspect --json accepted the value")
			}
			var decoded struct {
				Error string `json:"error"`
			}
			if err := json.Unmarshal([]byte(jsonOut), &decoded); err != nil {
				t.Fatalf("stdout is not a JSON error object: %v\noutput: %q", err, jsonOut)
			}
			if !strings.Contains(decoded.Error, tt.wantMsg) {
				t.Errorf("JSON error field %q does not mention %q", decoded.Error, tt.wantMsg)
			}
		})
	}
}

// TestDecodeEntryOrEnvelopeDistinguishesAndNamesBothShapes covers the
// subcommands that accept an envelope as well as an entry. They make the same
// base64-versus-XDR distinction, and their wrong-type message names both
// accepted shapes, so a caller who handed over neither hears what would have
// been accepted.
func TestDecodeEntryOrEnvelopeDistinguishesAndNamesBothShapes(t *testing.T) {
	tests := []struct {
		name      string
		value     string
		wantMsg   string
		absentMsg string
	}{
		{
			name:      "not base64",
			value:     notBase64,
			wantMsg:   "not valid base64",
			absentMsg: "but is not a Soroban authorization entry or a transaction envelope",
		},
		{
			name:    "wrong XDR type",
			value:   wrongXDR,
			wantMsg: "valid base64 but is not a Soroban authorization entry or a transaction envelope with an invokeHostFunction operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := decodeEntryOrEnvelope(tt.value)
			if err == nil {
				t.Fatalf("decodeEntryOrEnvelope(%q) succeeded", tt.value)
			}
			if !strings.Contains(err.Error(), tt.wantMsg) {
				t.Errorf("error %q does not mention %q", err, tt.wantMsg)
			}
			if tt.absentMsg != "" && strings.Contains(err.Error(), tt.absentMsg) {
				t.Errorf("error %q misclassifies the input", err)
			}
			if strings.Contains(err.Error(), tt.value) {
				t.Errorf("the error for %q echoes the input: %q", tt.value, err)
			}
		})
	}
}

// TestClassifyInputPassesDecodeLimitsThrough asserts a refusal at one of the
// library's limits is reported as itself. The input reached the limit, so it
// was well-formed enough to decode that far; calling it "not base64" would
// send the caller to fix the wrong thing.
func TestClassifyInputPassesDecodeLimitsThrough(t *testing.T) {
	limitErr := fmt.Errorf("refused: %w", soroauth.ErrDecodeLimit)
	got := classifyInput(notBase64, "a Soroban authorization entry", limitErr)
	if !strings.Contains(got.Error(), "decode limit") {
		t.Errorf("classifyInput rewrote a decode-limit refusal into %q", got)
	}
	if strings.Contains(got.Error(), "base64") {
		t.Errorf("classifyInput describes a decode-limit refusal as a base64 problem: %q", got)
	}
}
