package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func runCLIStdin(t *testing.T, env map[string]string, stdinContent string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }()
	r, w, errPipe := os.Pipe()
	if errPipe != nil {
		t.Fatalf("creating pipe: %v", errPipe)
	}
	os.Stdin = r
	go func() {
		_, _ = w.Write([]byte(stdinContent))
		_ = w.Close()
	}()
	err = run(args, &out, &errOut, func(key string) string { return env[key] })
	return out.String(), errOut.String(), err
}

func TestStdinEntryPipingAcrossSubcommands(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signer := vectorKeypair(t, "soroauth-vector-signer-1")

	t.Run("payload via stdin", func(t *testing.T) {
		stdout, _, err := runCLIStdin(t, nil, v.UnsignedEntryXDR,
			"payload", "--entry", "-", "--valid-until", "1234567", "--network", "testnet", "--json")
		if err != nil {
			t.Fatalf("payload via stdin failed: %v", err)
		}
		var out struct {
			Preimage string `json:"preimage"`
		}
		if err := json.Unmarshal([]byte(stdout), &out); err != nil {
			t.Fatalf("output not valid JSON: %v\nstdout: %s", err, stdout)
		}
		if out.Preimage != v.PreimageXDR {
			t.Errorf("preimage mismatch: got %s, want %s", out.Preimage, v.PreimageXDR)
		}
	})

	t.Run("sign via stdin", func(t *testing.T) {
		stdout, _, err := runCLIStdin(t, map[string]string{"SEED": signer.Seed()},
			v.UnsignedEntryXDR,
			"sign", "--entry", "-", "--valid-until", "1234567", "--network", "testnet", "--secret-env", "SEED", "--json")
		if err != nil {
			t.Fatalf("sign via stdin failed: %v", err)
		}
		var signRes struct {
			SignedEntry string `json:"signed_entry"`
		}
		if err := json.Unmarshal([]byte(stdout), &signRes); err != nil {
			t.Fatalf("sign via stdin json unmarshal failed: %v\nstdout: %s", err, stdout)
		}
		if signRes.SignedEntry == "" {
			t.Error("signed_entry field empty")
		}
	})

	_ = v
	_ = signer
}

func TestStdinEntryPipelinesReal(t *testing.T) {
	v := loadVector(t, "v2_single_testnet")
	signer := vectorKeypair(t, "soroauth-vector-signer-1")

	stdout, _, err := runCLIStdin(t, nil, v.UnsignedEntryXDR,
		"payload", "--entry", "-", "--valid-until", "1234567", "--network", "testnet")
	if err != nil {
		t.Fatalf("payload stdin failed: %v", err)
	}
	if !strings.Contains(stdout, v.PreimageXDR) {
		t.Errorf("payload stdin output missing preimage: %s", stdout)
	}

	stdoutSign, _, err := runCLIStdin(t, map[string]string{"SEED": signer.Seed()},
		v.UnsignedEntryXDR,
		"sign", "--entry", "-", "--valid-until", "1234567", "--network", "testnet", "--secret-env", "SEED", "--json")
	if err != nil {
		t.Fatalf("sign stdin failed: %v", err)
	}
	var signRes struct {
		SignedEntry string `json:"signed_entry"`
	}
	if err := json.Unmarshal([]byte(stdoutSign), &signRes); err != nil {
		t.Fatalf("sign stdin json unmarshal failed: %v\nstdout: %s", err, stdoutSign)
	}

	vecDel := loadVector(t, "delegates_from_legacy")
	if vecDel.PreWrapEntryXDR != "" {
		stdoutDel, _, err := runCLIStdin(t, nil, vecDel.PreWrapEntryXDR,
			"delegates", "--entry", "-", "--valid-until", "1234567", "--delegate", vecDel.Delegates[0].Address, "--json")
		if err != nil {
			t.Fatalf("delegates stdin failed: %v", err)
		}
		var delRes struct {
			WrappedEntry string `json:"wrapped_entry"`
		}
		if err := json.Unmarshal([]byte(stdoutDel), &delRes); err != nil {
			t.Fatalf("delegates stdin json unmarshal failed: %v\nstdout: %s", err, stdoutDel)
		}
		if delRes.WrappedEntry == "" {
			t.Errorf("delegates read the entry from stdin but printed no wrapped_entry: %s", stdoutDel)
		}
	}

	stdoutFail, _, err := runCLIStdin(t, nil, "not-base64-data",
		"inspect", "--entry", "-", "--json")
	if err == nil {
		t.Fatal("expected failure for malformed stdin entry")
	}
	var failRes struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdoutFail), &failRes); err != nil {
		t.Fatalf("expected JSON error on stdout for stdin failure, got: %s", stdoutFail)
	}
	if failRes.Error == "" {
		t.Error("error field empty in JSON error output")
	}
}
