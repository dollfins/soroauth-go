//go:build e2e

package e2e

import (
	"context"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	rpc "github.com/stellar/go-stellar-sdk/protocols/rpc"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// rejectionHeadroom multiplies the instruction budget and the resource fee of
// a submission that exists to be rejected on-chain.
//
// The scenarios that expect a refusal cannot size their resources from an
// enforcing simulation — that pass fails locally for the very reason under
// test, which would prove only that simulation agrees with the host. Their
// resources come from the recording pass instead, which never executed the
// account's __check_auth and therefore under-counts. Submitting those numbers
// unchanged produces a transaction that runs out of instructions before it
// reaches the check the scenario is about, and "passes" for a reason that has
// nothing to do with what it claims to prove: scenario E once did exactly
// that (see e2e/README.md, "What each scenario proves").
//
// The value is insurance, not the control. It was measured, not assumed: for
// the classic-account threshold check (scenario C-control), headroom 1 was
// already sufficient — reverting it still produced "signature weight is lower
// than threshold", because verifying a classic account signature is far
// cheaper than executing a custom account contract's __check_auth, which is
// what exhausted the budget in scenario E. What makes both rejection scenarios
// valid is that they assert the host's specific error, not that they carry
// headroom.
const rejectionHeadroom = 6

// prepareFunc rewrites the recorded authorization entries between the
// recording pass and signing. It receives the validUntilLedger that will be
// signed over, so a prepare step that changes what gets signed (such as
// wrapping an entry with WithDelegates, which fixes the expiration) can use
// the same value the signer will.
//
// It returns the entries to sign; returning the input unchanged is legal.
type prepareFunc func(t *testing.T, entries []xdr.SorobanAuthorizationEntry, validUntil uint32) []xdr.SorobanAuthorizationEntry

// scenarioSpec holds the differences between the scenarios. runScenario holds
// the shape they all share.
//
// Before this existed, runTransfer, runTransferExpectingFailure and
// delegatesFlow each carried a full copy of the record/sign/enforce/submit
// flow, and a fix applied to one had to be mirrored by hand into the others —
// the instruction-headroom fix that scenario E needed is an example where that
// mirroring mattered, and the three copies had already drifted in their error
// handling and logging. Keeping the differences as data is what stops that
// class of drift: there is now one place that decides how a scenario runs.
type scenarioSpec struct {
	// payer signs and pays for the transaction envelope. It is never the
	// account under test: an address credential only proves something when
	// the authorized account is someone other than the payer, so the
	// transfer cannot fall back to source-account auth.
	payer *keypair.Full

	// op is the operation to submit, before authorization entries are
	// attached. runScenario sets op.Auth itself; callers never set it.
	op txnbuild.InvokeHostFunction

	// signers are handed to AuthorizeAll, which applies each signer to every
	// credential node whose address matches, at any depth of a delegate
	// tree, and fails the whole run rather than skipping an entry nobody
	// can sign.
	signers []soroauth.Signer

	// upgradedAuth asks the recording pass for upgraded (CAP-71) auth
	// entries via UseUpgradedAuth. That flag is best-effort — read in
	// go-stellar-sdk protocols/rpc/simulate_transaction.go — so no scenario
	// trusts it: every scenario verifies the credential arm on the
	// submitted envelope instead (harness.send decodes it back).
	//
	// Scenario A records without it, because the legacy arm is what it is
	// about. Every other scenario records with it.
	upgradedAuth bool

	// prepare runs between recording and signing and may rewrite the
	// recorded entries: scenario B upgrades legacy entries to V2, scenarios
	// D and E wrap the contract's entry with WithDelegates. nil means no
	// rewrite.
	prepare prepareFunc

	// expectFailure marks a run whose point is an on-chain refusal. The
	// enforcing simulation is skipped — it would fail locally for the very
	// reason under test — and the submission is sized from the recording
	// pass with rejectionHeadroom, so the transaction reaches the real host
	// and is refused there, after fees.
	expectFailure bool

	// headroom overrides the multiplier applied to the recording pass's
	// instruction budget and resource fee. Zero means the default from
	// submissionHeadroom.
	//
	// It exists for a refusal whose cost is not the one the default was
	// measured against. rejectionHeadroom is sized for a contract that
	// returns an error, where the work the recording pass missed is one
	// __check_auth call. Scenario K's refusal happens inside the host's own
	// secp256r1 verification, and paying for that verification is itself
	// most of the cost: at the default multiplier the submission exhausted
	// its instruction budget while the host was escalating the trap, and the
	// host reported the budget failure rather than the P-256 one. The value
	// is measured, not guessed; see e2e/README.md.
	headroom uint32
}

// runScenario is the one runner every scenario uses: record, sign with
// soroauth, enforce, assemble, sign the envelope as the payer, submit, and
// poll. The five steps and why they exist are described in e2e/README.md,
// "How a scenario works"; the differences between scenarios live in
// scenarioSpec, not here.
func runScenario(t *testing.T, h *harness, spec scenarioSpec) submission {
	t.Helper()

	// 1. record: the host reports which addresses must authorize the call
	// and hands back unsigned authorization entries.
	recordTx := h.build(t, h.account(t, spec.payer.Address()), spec.op)
	recorded := h.simulate(t, recordTx, rpc.AuthModeRecord, spec.upgradedAuth)
	entries := recordedAuthEntries(t, recorded)

	// 2. sign: one expiration for the whole run, computed once so the value
	// signed over and the value stored can never disagree.
	validUntil, err := soroauth.ExpirationAfter(h.latestLedger(t), 1000)
	if err != nil {
		t.Fatalf("computing the expiration ledger: %v", err)
	}
	if spec.prepare != nil {
		entries = spec.prepare(t, entries, validUntil)
	}
	signedEntries, err := soroauth.AuthorizeAll(context.Background(), entries, spec.signers, validUntil, h.passphrase)
	if err != nil {
		t.Fatalf("AuthorizeAll: %v", err)
	}
	logSignedEntries(t, signedEntries)

	spec.op.Auth = signedEntries

	// 3. enforce: re-simulate carrying the signed entries, so the resource
	// fee accounts for the signatures that are actually going out — unless
	// the run exists to be refused, in which case that pass would fail here
	// for the reason under test and prove nothing about the host.
	sim := recorded
	if !spec.expectFailure {
		enforceTx := h.build(t, h.account(t, spec.payer.Address()), spec.op)
		sim = h.simulate(t, enforceTx, rpc.AuthModeEnforce, false)
	}
	headroom := spec.headroom
	if headroom == 0 {
		headroom = submissionHeadroom(spec.expectFailure)
	}

	// 4. assemble with that pass's resources — the Go SDK has no
	// assembleTransaction, so harness.assembleWithHeadroom attaches the
	// simulated SorobanTransactionData explicitly — and 5. sign the
	// envelope as the payer.
	finalTx := h.assembleWithHeadroom(t, h.account(t, spec.payer.Address()), spec.op, sim, headroom)
	finalTx, err = finalTx.Sign(h.passphrase, spec.payer)
	if err != nil {
		t.Fatalf("signing the envelope as the payer: %v", err)
	}

	// 6. submit and poll until it resolves. h.send does not fail the test
	// on an on-chain rejection: the rejection scenarios expect one and
	// report the raw error; the calling test decides what to assert.
	return h.send(t, finalTx)
}

// submissionHeadroom selects the resource multiplier for a scenario. It is a
// small pure helper so the regression that motivated rejectionHeadroom remains
// directly testable without a live RPC.
func submissionHeadroom(expectFailure bool) uint32 {
	if expectFailure {
		return rejectionHeadroom
	}
	return 1
}

// recordedAuthEntries decodes the authorization entries a recording pass
// returned.
//
// Exactly one result carrying non-empty auth is the only shape these
// scenarios know how to sign. Anything else means the RPC or the operation
// changed, and failing here is the useful outcome: proceeding would submit a
// transaction that is accepted, charged for, and then fails during
// application because its entries were never signed.
func recordedAuthEntries(t *testing.T, sim rpc.SimulateTransactionResponse) []xdr.SorobanAuthorizationEntry {
	t.Helper()

	if len(sim.Results) != 1 {
		t.Fatalf("simulation returned %d results, want 1", len(sim.Results))
	}
	if sim.Results[0].AuthXDR == nil {
		t.Fatal("simulation recorded no authorization entries; the transfer would not need soroauth at all")
	}
	entries := make([]xdr.SorobanAuthorizationEntry, 0, len(*sim.Results[0].AuthXDR))
	for i, encoded := range *sim.Results[0].AuthXDR {
		var entry xdr.SorobanAuthorizationEntry
		if err := xdr.SafeUnmarshalBase64(encoded, &entry); err != nil {
			t.Fatalf("decoding recorded auth entry %d: %v", i, err)
		}
		entries = append(entries, entry)
	}
	if len(entries) == 0 {
		t.Fatal("simulation recorded no authorization entries")
	}
	return entries
}

// logSignedEntries reports what Inspect sees in each signed entry, so a
// failing run's log shows which arm went out and which delegate nodes carry
// signatures without anyone decoding XDR by hand.
func logSignedEntries(t *testing.T, entries []xdr.SorobanAuthorizationEntry) {
	t.Helper()

	for i, entry := range entries {
		info, err := soroauth.Inspect(entry)
		if err != nil {
			t.Fatalf("inspecting signed entry %d: %v", i, err)
		}
		t.Logf("entry %d: %s address=%s signed=%v delegates=%d",
			i, info.CredentialType, info.Address, info.TopLevelSigned, len(info.Delegates))
		for _, node := range info.Delegates {
			t.Logf("           delegate %s signed=%v", node.Address, node.Signed)
		}
	}
}
