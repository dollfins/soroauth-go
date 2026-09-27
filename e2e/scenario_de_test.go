//go:build e2e

package e2e

import (
	"testing"

	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// prepareDelegates returns the entry-preparation hook for the CAP-71-01
// delegate flow. runScenario owns record, enforce, assemble and submit; this
// hook owns only the difference: wrapping the contract account's entry with
// WithDelegates and signing each attached delegate by address.
//
// delegatesToAttach is what goes into the entry. The unified runner then signs
// those nodes through scenarioSpec.signers. Scenario E attaches an address that
// is missing from the account's registered set, which is the whole point of
// that scenario.
func prepareDelegates(contract string, delegatesToAttach []string) prepareFunc {
	return func(t *testing.T, entries []xdr.SorobanAuthorizationEntry, validUntil uint32) []xdr.SorobanAuthorizationEntry {
		t.Helper()

		delegates := make([]soroauth.Delegate, 0, len(delegatesToAttach))
		for _, address := range delegatesToAttach {
			delegates = append(delegates, soroauth.Delegate{Address: address})
		}

		prepared := make([]xdr.SorobanAuthorizationEntry, 0, len(entries))
		for i, entry := range entries {
			info, err := soroauth.Inspect(entry)
			if err != nil {
				t.Fatalf("inspecting recorded entry %d: %v", i, err)
			}
			if info.CredentialType == soroauth.CredentialTypeSourceAccount || info.Address != contract {
				prepared = append(prepared, entry)
				continue
			}

			wrapped, err := soroauth.WithDelegates(entry, validUntil, delegates, nil)
			if err != nil {
				t.Fatalf("WithDelegates on entry %d: %v", i, err)
			}
			prepared = append(prepared, wrapped)
		}
		return prepared
	}
}

// TestScenarioD proves the delegated-signer arm is accepted by a live host: a
// contract account holding XLM transfers it, authorized only by two G-account
// delegates that soroauth signed.
func TestScenarioD(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	d1 := h.newAccount(t, "delegate D1")
	d2 := h.newAccount(t, "delegate D2")
	to := h.newAccount(t, "recipient B")

	deployed := h.deployModularAccount(t, payer, []string{d1.Address(), d2.Address()})
	h.fundContract(t, payer, deployed.ContractAddress, transferAmount*5)

	op := h.transferOp(t, scAddressOf(t, deployed.ContractAddress), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())
	result := runScenario(t, h, scenarioSpec{
		payer:        payer,
		op:           op,
		upgradedAuth: true,
		signers: []soroauth.Signer{
			soroauth.NewEd25519Signer(d1),
			soroauth.NewEd25519Signer(d2),
		},
		prepare: prepareDelegates(deployed.ContractAddress,
			[]string{d1.Address(), d2.Address()}),
	})

	t.Logf("contract:  %s", deployed.ContractAddress)
	t.Logf("deploy tx: %s", deployed.CreateTxHash)
	t.Logf("tx hash:   %s", result.Hash)
	t.Logf("ledger:    %d", result.Ledger)
	t.Logf("arm:       %s", result.Arm)
	t.Logf("link:      %s%s", explorerBaseURL, result.Hash)

	record(scenarioResult{
		ID:        "D",
		Name:      "CAP-71 delegated signers accepted live",
		Proves:    "A SOROBAN_CREDENTIALS_ADDRESS_WITH_DELEGATES entry, with a Void top-level signature and two G-account delegates signed by soroauth, is accepted by the host.",
		TxHash:    result.Hash,
		Ledger:    result.Ledger,
		Arm:       result.Arm,
		Succeeded: result.Status == rpc.TransactionStatusSuccess,
		RawError:  result.RawError,
		Notes: []string{
			"modular-account contract: " + deployed.ContractAddress,
			"wasm upload tx: " + deployed.UploadTxHash,
			"contract deploy tx: " + deployed.CreateTxHash,
			"wasm hash: " + deployed.WasmHash,
			"Registered signers: " + d1.Address() + ", " + d2.Address(),
			"The account itself never signs: its top-level signature is ScvVoid, which CAP-71-01 permits when delegates carry the authentication.",
		},
	})

	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("scenario D failed on-chain (status %s):\n%s", result.Status, result.RawError)
	}
	if result.Arm != "SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates" {
		t.Errorf("submitted envelope carried arm %q, want the delegates arm", result.Arm)
	}
}

// TestScenarioE proves the host rejects what it should: the same flow as D, but
// with a delegate the account has not registered. The contract's __check_auth
// returns UnknownDelegate, and this test reports the raw error verbatim.
func TestScenarioE(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	d1 := h.newAccount(t, "delegate D1")
	d2 := h.newAccount(t, "delegate D2")
	d3 := h.newAccount(t, "stranger D3")
	to := h.newAccount(t, "recipient B")

	// D3 is deliberately left out of the registered set.
	deployed := h.deployModularAccount(t, payer, []string{d1.Address(), d2.Address()})
	h.fundContract(t, payer, deployed.ContractAddress, transferAmount*5)

	op := h.transferOp(t, scAddressOf(t, deployed.ContractAddress), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())
	result := runScenario(t, h, scenarioSpec{
		payer:         payer,
		op:            op,
		upgradedAuth:  true,
		expectFailure: true,
		signers:       []soroauth.Signer{soroauth.NewEd25519Signer(d3)},
		prepare:       prepareDelegates(deployed.ContractAddress, []string{d3.Address()}),
	})

	t.Logf("contract:  %s", deployed.ContractAddress)
	t.Logf("deploy tx: %s", deployed.CreateTxHash)
	t.Logf("tx hash:   %s", result.Hash)
	t.Logf("status:    %s", result.Status)
	t.Logf("arm:       %s", result.Arm)
	t.Logf("RAW ERROR:\n%s", result.RawError)

	record(scenarioResult{
		ID:              "E",
		Name:            "the host rejects an unregistered delegate",
		Proves:          "A delegates entry naming an address the account has not registered is refused by the contract's __check_auth with its UnknownDelegate error.",
		TxHash:          result.Hash,
		Ledger:          result.Ledger,
		Arm:             result.Arm,
		Succeeded:       result.Status != rpc.TransactionStatusSuccess,
		ExpectRejection: true,
		RawError:        result.RawError,
		Notes: []string{
			"modular-account contract: " + deployed.ContractAddress,
			"contract deploy tx: " + deployed.CreateTxHash,
			"Registered signers: " + d1.Address() + ", " + d2.Address(),
			"Attached delegate (not registered): " + d3.Address(),
			"AccountError::UnknownDelegate is contract error #1 in e2e/contracts/modular-account/src/lib.rs.",
		},
	})

	if result.Status == rpc.TransactionStatusSuccess {
		t.Fatal("the host accepted an unregistered delegate; scenario E proves nothing if this succeeds")
	}
	if result.RawError == "" {
		t.Error("no raw error was captured, so there is nothing to report")
	}

	// The transaction must have been refused by the account contract with
	// UnknownDelegate (#1), not for some unrelated reason such as running out
	// of instructions before __check_auth was ever reached.
	const unknownDelegate = 1
	codes := contractErrorCodes(t, result.Diagnostics)
	found := false
	for _, code := range codes {
		if code == unknownDelegate {
			found = true
		}
	}
	if !found {
		t.Errorf("the host reported contract error codes %v, want %d (AccountError::UnknownDelegate); "+
			"the transaction failed, but not for the reason this scenario is about", codes, unknownDelegate)
	} else {
		t.Logf("contract error code %d (AccountError::UnknownDelegate) confirmed in the host diagnostics", unknownDelegate)
	}
}

// TestScenarioPolicyWithinLimit proves the policy account authorizes a transfer
// that is within its spending limit through soroauth and CAP-71 delegates.
func TestScenarioPolicyWithinLimit(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	d1 := h.newAccount(t, "delegate D1")
	to := h.newAccount(t, "recipient B")

	// Deploy policy account with limit 1000 and period 100
	deployed := h.deployPolicyAccount(t, payer, []string{d1.Address()}, 1000, 100)
	h.fundContract(t, payer, deployed.ContractAddress, transferAmount*5)

	op := h.transferOp(t, scAddressOf(t, deployed.ContractAddress), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())
	result := runScenario(t, h, scenarioSpec{
		payer:        payer,
		op:           op,
		upgradedAuth: true,
		signers: []soroauth.Signer{
			soroauth.NewEd25519Signer(d1),
		},
		prepare: prepareDelegates(deployed.ContractAddress, []string{d1.Address()}),
	})

	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("policy within-limit scenario failed on-chain (status %s):\n%s", result.Status, result.RawError)
	}
}

// TestScenarioPolicyOverLimit proves the policy account refuses a transfer
// exceeding its spending limit with PolicyAccountError::SpendingLimitExceeded.
func TestScenarioPolicyOverLimit(t *testing.T) {
	h := newHarness(t)

	payer := h.newAccount(t, "payer P")
	d1 := h.newAccount(t, "delegate D1")
	to := h.newAccount(t, "recipient B")

	// Deploy policy account with a low limit of 1
	deployed := h.deployPolicyAccount(t, payer, []string{d1.Address()}, 1, 100)
	h.fundContract(t, payer, deployed.ContractAddress, transferAmount*5)

	op := h.transferOp(t, scAddressOf(t, deployed.ContractAddress), scAddressOf(t, to.Address()),
		transferAmount, payer.Address())
	result := runScenario(t, h, scenarioSpec{
		payer:         payer,
		op:            op,
		upgradedAuth:  true,
		expectFailure: true,
		signers: []soroauth.Signer{
			soroauth.NewEd25519Signer(d1),
		},
		prepare: prepareDelegates(deployed.ContractAddress, []string{d1.Address()}),
	})

	if result.Status == rpc.TransactionStatusSuccess {
		t.Fatal("the host accepted an over-limit transfer; scenario policy over-limit proves nothing if this succeeds")
	}

	const spendingLimitExceeded = 3
	codes := contractErrorCodes(t, result.Diagnostics)
	found := false
	for _, code := range codes {
		if code == spendingLimitExceeded {
			found = true
		}
	}
	if !found {
		t.Errorf("the host reported contract error codes %v, want %d (PolicyAccountError::SpendingLimitExceeded)", codes, spendingLimitExceeded)
	}
}
