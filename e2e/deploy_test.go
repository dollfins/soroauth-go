//go:build e2e

package e2e

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// wasmPath is where `stellar contract build` puts a workspace member's wasm.
// Cargo writes a crate's dashes as underscores in the file name, so the
// "session-keys" crate builds to "session_keys.wasm".
func wasmPath(wasmName string) string {
	return filepath.Join("contracts", "target", "wasm32v1-none", "release", wasmName+".wasm")
}

// deployment records what a deploy produced, so RESULTS.md can name it.
type deployment struct {
	ContractAddress string
	UploadTxHash    string
	CreateTxHash    string
	WasmHash        string
}

// deployFixture uploads a fixture's wasm and instantiates it with the given
// constructor arguments.
func (h *harness) deployFixture(
	t *testing.T,
	deployer *keypair.Full,
	wasmName string,
	ctorArgs []xdr.ScVal,
) deployment {
	t.Helper()

	path := wasmPath(wasmName)
	wasm, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v\nBuild it first: cd e2e/contracts && stellar contract build", path, err)
	}
	t.Logf("wasm: %s (%d bytes)", filepath.Base(path), len(wasm))

	// 1. upload the wasm
	uploadOp := txnbuild.InvokeHostFunction{
		HostFunction: xdr.HostFunction{
			Type: xdr.HostFunctionTypeHostFunctionTypeUploadContractWasm,
			Wasm: &wasm,
		},
		SourceAccount: deployer.Address(),
	}
	uploadResult, uploadReturn := h.submitHostFunction(t, deployer, uploadOp)
	if uploadResult.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("uploading the wasm failed (status %s):\n%s", uploadResult.Status, uploadResult.RawError)
	}

	var wasmHash xdr.Hash
	if uploadReturn.Type == xdr.ScValTypeScvBytes && uploadReturn.Bytes != nil {
		copy(wasmHash[:], *uploadReturn.Bytes)
	} else {
		t.Fatalf("upload returned %v, want the wasm hash as bytes", uploadReturn.Type)
	}
	t.Logf("wasm hash: %x", wasmHash)

	// 2. instantiate it, passing the signer set to __constructor
	var salt xdr.Uint256
	if _, err := rand.Read(salt[:]); err != nil {
		t.Fatalf("generating a deploy salt: %v", err)
	}

	deployerID, err := xdr.AddressToAccountId(deployer.Address())
	if err != nil {
		t.Fatalf("decoding the deployer address: %v", err)
	}

	createOp := txnbuild.InvokeHostFunction{
		HostFunction: xdr.HostFunction{
			Type: xdr.HostFunctionTypeHostFunctionTypeCreateContractV2,
			CreateContractV2: &xdr.CreateContractArgsV2{
				ContractIdPreimage: xdr.ContractIdPreimage{
					Type: xdr.ContractIdPreimageTypeContractIdPreimageFromAddress,
					FromAddress: &xdr.ContractIdPreimageFromAddress{
						Address: xdr.ScAddress{
							Type:      xdr.ScAddressTypeScAddressTypeAccount,
							AccountId: &deployerID,
						},
						Salt: salt,
					},
				},
				Executable: xdr.ContractExecutable{
					Type:     xdr.ContractExecutableTypeContractExecutableWasm,
					WasmHash: &wasmHash,
				},
				ConstructorArgs: ctorArgs,
			},
		},
		SourceAccount: deployer.Address(),
	}

	createResult, createReturn := h.submitHostFunction(t, deployer, createOp)
	if createResult.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("creating the contract failed (status %s):\n%s", createResult.Status, createResult.RawError)
	}

	if createReturn.Type != xdr.ScValTypeScvAddress || createReturn.Address == nil {
		t.Fatalf("create returned %v, want a contract address", createReturn.Type)
	}
	if createReturn.Address.ContractId == nil {
		t.Fatal("create returned an address with no contract id")
	}
	contractAddress, err := strkey.Encode(strkey.VersionByteContract, createReturn.Address.ContractId[:])
	if err != nil {
		t.Fatalf("encoding the contract address: %v", err)
	}

	t.Logf("contract: %s", contractAddress)

	return deployment{
		ContractAddress: contractAddress,
		UploadTxHash:    uploadResult.Hash,
		CreateTxHash:    createResult.Hash,
		WasmHash:        hexOf(wasmHash[:]),
	}
}

// deployModularAccount uploads the modular-account fixture and instantiates it
// with the given delegate signer set.
func (h *harness) deployModularAccount(t *testing.T, deployer *keypair.Full, signers []string) deployment {
	t.Helper()
	return h.deployFixture(t, deployer, "modular_account", []xdr.ScVal{scAddressVecVal(t, signers)})
}

// sessionKey is one entry of the SessionKey vector the session-keys fixture
// takes in its constructor: an address and the ledger window it is valid in,
// both bounds inclusive.
type sessionKey struct {
	Address    string
	ValidFrom  uint32
	ValidUntil uint32
}

// deploySessionKeys uploads the session-keys fixture and instantiates it with
// the given session keys.
func (h *harness) deploySessionKeys(t *testing.T, deployer *keypair.Full, keys []sessionKey) deployment {
	t.Helper()
	values := make([]xdr.ScVal, 0, len(keys))
	for _, key := range keys {
		values = append(values, sessionKeyVal(t, key))
	}
	return h.deployFixture(t, deployer, "session_keys", []xdr.ScVal{scVecVal(values)})
}

// deployThresholdAccount uploads the threshold-account fixture and
// instantiates it with the given signer set and threshold.
func (h *harness) deployThresholdAccount(
	t *testing.T,
	deployer *keypair.Full,
	signers []string,
	threshold uint32,
) deployment {
	t.Helper()
	return h.deployFixture(t, deployer, "threshold_account", []xdr.ScVal{scAddressVecVal(t, signers), scU32Val(threshold)})
}

// deployPolicyAccount uploads the policy-account fixture and instantiates it
// with the given delegate signer set, per-period spending limit, and period
// length in ledgers.
//
// The constructor's argument order is (signers, limit, period_ledgers), and the
// limit is an i128 because that is the type the SAC transfer amount it is
// compared against uses.
func (h *harness) deployPolicyAccount(
	t *testing.T,
	deployer *keypair.Full,
	signers []string,
	limit int64,
	periodLedgers uint32,
) deployment {
	t.Helper()
	return h.deployFixture(t, deployer, "policy_account", []xdr.ScVal{
		scAddressVecVal(t, signers),
		i128(limit),
		scU32Val(periodLedgers),
	})
}

// scSymbolVal wraps a symbol as an ScVal, the type an ScMap's keys must use.
func scSymbolVal(symbol string) xdr.ScVal {
	value := xdr.ScSymbol(symbol)
	return xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &value}
}

// scU32Val wraps a u32 as an ScVal argument.
func scU32Val(value uint32) xdr.ScVal {
	u32 := xdr.Uint32(value)
	return xdr.ScVal{Type: xdr.ScValTypeScvU32, U32: &u32}
}

// scVecVal wraps ScVals as an ScVal vector argument.
func scVecVal(values []xdr.ScVal) xdr.ScVal {
	vec := xdr.ScVec(values)
	ptr := &vec
	return xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &ptr}
}

// scAddressVecVal wraps G… or C… addresses as an ScVal vector argument.
func scAddressVecVal(t *testing.T, addresses []string) xdr.ScVal {
	t.Helper()
	values := make([]xdr.ScVal, 0, len(addresses))
	for _, address := range addresses {
		values = append(values, scAddressVal(scAddressOf(t, address)))
	}
	return scVecVal(values)
}

// sessionKeyVal encodes one SessionKey for the constructor.
//
// A #[contracttype] struct is an ScMap keyed by its field names as symbols, and
// an ScMap must be sorted by key, so the entries are written in that order:
// "key", then "valid_from_ledger", then "valid_until_ledger". The field names
// are the ones in e2e/contracts/session-keys/src/lib.rs.
func sessionKeyVal(t *testing.T, key sessionKey) xdr.ScVal {
	t.Helper()

	address := scAddressOf(t, key.Address)
	from := xdr.Uint32(key.ValidFrom)
	until := xdr.Uint32(key.ValidUntil)

	entries := xdr.ScMap{
		{Key: scSymbolVal("key"), Val: xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &address}},
		{Key: scSymbolVal("valid_from_ledger"), Val: xdr.ScVal{Type: xdr.ScValTypeScvU32, U32: &from}},
		{Key: scSymbolVal("valid_until_ledger"), Val: xdr.ScVal{Type: xdr.ScValTypeScvU32, U32: &until}},
	}
	ptr := &entries
	return xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &ptr}
}

func hexOf(b []byte) string {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&0x0f])
	}
	return string(out)
}

// submitHostFunction runs a host function that needs no soroauth signatures —
// an upload, a deploy, or a transfer the source account authorizes itself —
// and returns its result plus its return value.
func (h *harness) submitHostFunction(t *testing.T, source *keypair.Full, op txnbuild.InvokeHostFunction) (submission, xdr.ScVal) {
	t.Helper()

	// Record mode, not enforce: a CreateContractV2 from an address needs that
	// address's authorization, and an enforcing pass over a transaction with
	// no auth entries fails with "Unauthorized function call for address".
	// Recording produces the source-account entry, which needs no signature of
	// its own because the envelope signature covers it.
	tx := h.build(t, h.account(t, source.Address()), op)
	sim := h.simulate(t, tx, rpc.AuthModeRecord, false)

	if len(sim.Results) == 1 && sim.Results[0].AuthXDR != nil {
		entries := make([]xdr.SorobanAuthorizationEntry, 0, len(*sim.Results[0].AuthXDR))
		for i, encoded := range *sim.Results[0].AuthXDR {
			var entry xdr.SorobanAuthorizationEntry
			if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
				t.Fatalf("decoding auth entry %d: %v", i, err)
			}
			entries = append(entries, entry)
		}
		op.Auth = entries
	}

	// Now the resources can be measured against the real auth.
	enforceTx := h.build(t, h.account(t, source.Address()), op)
	sim = h.simulate(t, enforceTx, rpc.AuthModeEnforce, false)

	finalTx := h.assemble(t, h.account(t, source.Address()), op, sim)
	finalTx, err := finalTx.Sign(h.passphrase, source)
	if err != nil {
		t.Fatalf("signing: %v", err)
	}

	result := h.send(t, finalTx)

	var returnValue xdr.ScVal
	if len(sim.Results) == 1 && sim.Results[0].ReturnValueXDR != nil {
		if err := xdr.SafeUnmarshalBase64(*sim.Results[0].ReturnValueXDR, &returnValue); err != nil {
			t.Fatalf("decoding the simulated return value: %v", err)
		}
	}
	return result, returnValue
}

// fundContract moves XLM from a funded G account into a contract address, so
// the contract has a balance to transfer in scenario D.
func (h *harness) fundContract(t *testing.T, from *keypair.Full, contract string, amount int64) {
	t.Helper()

	op := h.transferOp(t, scAddressOf(t, from.Address()), scAddressOf(t, contract), amount, from.Address())
	result, _ := h.submitHostFunction(t, from, op)
	if result.Status != rpc.TransactionStatusSuccess {
		t.Fatalf("funding the contract failed (status %s):\n%s", result.Status, result.RawError)
	}
	t.Logf("contract funded with %d stroops (tx %s)", amount, result.Hash)
}
