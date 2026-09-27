package soroauth

import (
	"bytes"
	"context"
	"fmt"
	"sync"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// signersForEntry returns the signers whose address appears somewhere in the
// entry, in the order they were supplied, together with whether the top-level
// node is among the addresses matched.
func signersForEntry(entry xdr.SorobanAuthorizationEntry, signers []Signer) (matched []Signer, topLevelMatched bool, err error) {
	local := entry
	nodes, err := credentialNodes(&local)
	if err != nil {
		return nil, false, err
	}
	if len(nodes) == 0 {
		return nil, false, fmt.Errorf("entry has no credential nodes")
	}
	// credentialNodes always puts the top-level node first.
	topLevel := nodes[0].encoded

	for _, signer := range signers {
		if signer == nil {
			continue
		}
		address, parseErr := ParseAddress(signer.Address())
		if parseErr != nil {
			// A signer this batch cannot address simply matches nothing; if
			// that leaves an entry unsigned, the caller hears about it below.
			continue
		}
		encoded, encodeErr := addressBytes(address)
		if encodeErr != nil {
			return nil, false, encodeErr
		}

		for _, node := range nodes {
			if bytes.Equal(node.encoded, encoded) {
				matched = append(matched, signer)
				if bytes.Equal(encoded, topLevel) {
					topLevelMatched = true
				}
				break
			}
		}
	}

	return matched, topLevelMatched, nil
}

// DelegatePlan describes how WithDelegatePlans should wrap one entry in the
// delegates arm before AuthorizeAll signs it.
//
// Without a plan for its address, an entry is signed exactly as it arrived —
// legacy, V2, or already the delegates arm. A plan only applies to an entry
// whose top-level address matches the plan's key, and only when that entry
// is the legacy or V2 arm; WithDelegates itself refuses to wrap an entry
// that is already the delegates arm or has already been signed, and
// AuthorizeAll surfaces that refusal as this batch's error rather than
// signing around it.
type DelegatePlan struct {
	// Delegates is the tree WithDelegates wraps the entry in.
	Delegates []Delegate

	// TopSignature is the account's own signature, passed through to
	// WithDelegates unchanged. Nil stores ScvVoid, which CAP-71-01 permits
	// for an account that authenticates purely through its delegates.
	TopSignature *xdr.ScVal
}

// authorizeAllConfig holds the optional behaviour of AuthorizeAll.
type authorizeAllConfig struct {
	requireAllSigned bool
	delegatePlans    map[string]DelegatePlan
}

// AuthorizeAllOption adjusts how AuthorizeAll behaves.
type AuthorizeAllOption func(*authorizeAllConfig)

// RequireAllSigned makes AuthorizeAll fail if any credential node in the
// resulting batch — the top-level node of a legacy or V2 entry, the
// top-level node of a delegates entry, or any delegate at any depth — is
// left without a signature. It checks every node literally, including the
// top-level node of a delegates entry that CAP-71-01 otherwise permits to
// stay Void.
//
// AuthorizeAll's default behaviour (documented above) accepts a batch once
// each address entry has at least one matching signer, because it cannot
// know an account's own signing policy: a 2-of-3 delegate tree with one
// branch left unsigned is not necessarily wrong, and neither is an account
// that authenticates purely through its delegates and never signs its own
// top-level node. RequireAllSigned is the opt-in for a caller who does know
// their policy requires every node signed — including the top-level node,
// if their account also requires its own key — and would rather fail
// locally than submit a transaction that fails during application because
// an account's __check_auth called delegate_account_auth for a node with an
// empty signature.
//
// Because the check is literal, a caller whose delegates-only account
// deliberately leaves the top-level node Void must not use
// RequireAllSigned for that entry — it will report the Void top-level node
// as unsigned, correctly, since this option cannot tell "intentionally
// Void" from "forgotten". This cannot detect a policy that intentionally
// leaves some nodes unsigned; it only proves the stronger claim "everything
// is signed", which is a property of the batch's structure, not of the
// account's rules. A single legacy or V2 entry that is already fully
// signed is unaffected: it has one node, and AuthorizeAll never returns
// such an entry with that node unsigned, so RequireAllSigned is a no-op
// there.
func RequireAllSigned() AuthorizeAllOption {
	return func(c *authorizeAllConfig) {
		c.requireAllSigned = true
	}
}

// WithDelegatePlans wraps each named address's entry in the delegates arm,
// via WithDelegates, before AuthorizeAll signs the batch.
//
// Without this option, using the delegates arm through AuthorizeAll meant
// unpacking the batch, calling WithDelegates on the one entry that needed
// it, and repacking — this does that step for every plan entry, keyed by
// the strkey address WithDelegates would have wrapped.
//
// An address in plans that matches no entry's top-level address is an
// error (ErrDelegatePlanUnmatched), never a silent no-op: a plan that never
// applied usually means the caller expected an entry that is not in this
// batch, and signing the batch anyway would produce a transaction missing
// the delegation the caller intended.
func WithDelegatePlans(plans map[string]DelegatePlan) AuthorizeAllOption {
	return func(c *authorizeAllConfig) {
		c.delegatePlans = plans
	}
}

// AuthorizeAll signs every entry in a batch, or none of them.
//
// Source-account entries pass through unchanged, so a caller can hand over
// exactly what simulation returned without sorting the entries by arm first.
//
// Every other entry must be signed by someone. An entry that goes out unsigned
// produces a transaction that is accepted, charged for, and then fails during
// application, so an entry with no applicable signer fails the whole call with
// ErrMissingSigner naming its address. Nothing is ever skipped quietly.
//
// On any error the returned slice is nil. There is no partial result: a caller
// cannot accidentally submit a batch that is half signed.
//
// For the legacy and V2 arms, which have exactly one node, that means a signer
// whose Address() equals the entry's address. For the delegates arm, every
// signer whose address appears anywhere in the tree is applied, each targeted
// with ForAddress, and one matching signer anywhere in the tree is enough.
//
// What that means in practice, and it matters before submission: a delegate
// node with no matching signer is left unsigned. AuthorizeAll does not fail for
// it, because it cannot know whether that delegate's signature was required —
// a 2-of-3 delegate policy is legitimate, and so is a tree where only one
// branch needs to sign.
//
// When an unsigned node does fail is a protocol question, not a guess. Under
// CAP-71-01 ("Semantics", the delegate_account_auth function), a delegate node
// is only exercised if the account's own __check_auth calls
// delegate_account_auth for that address; the host then calls that delegate's
// __check_auth with the signature stored on the node. An unsigned node that is
// never delegated to costs nothing, while an unsigned node that is delegated to
// hands the delegate an empty signature — which a G-account delegate cannot
// authenticate with.
//
// In practice that second case is the one to expect. The CAP's own guidance on
// get_delegated_signers_for_current_auth_check says the account contract must
// check that the signers belong to it "and perform authentication for every one
// of them via delegate_account_auth", which is what soroban-sdk's delegate_auth
// documentation describes and what the modular-account fixture in e2e/ does.
//
// So unless you know your account's policy, treat an unsigned node as one that
// will fail: check the per-node Signed flags that Inspect reports before
// submitting, rather than reading a nil error here as "fully signed".
//
// That last rule is a deliberate reading of an ambiguity in the specification,
// which asks both that every address entry have a signer for its top-level
// address and that the delegates arm be signed through the tree. Requiring a
// top-level signature would make the delegates arm unusable in the exact case
// it was designed for: CAP-71-01 permits a Void top-level signature when the
// account authenticates purely through its delegates, and an entry built that
// way is complete without the account signing anything. soroauth cannot know
// an account's delegation policy — how many delegates it requires, or whether
// it requires its own key as well — so it enforces what it can check, that the
// entry is not going out with nothing signed at all, and leaves the policy to
// the caller who supplies the signers.
//
// ctx is checked before the first entry, including an empty batch, so a
// cancelled context fails closed even when no Signer would run. The same ctx
// is passed unchanged to AuthorizeEntry and from there to Signer.Sign.
func AuthorizeAll(
	ctx context.Context,
	entries []xdr.SorobanAuthorizationEntry,
	signers []Signer,
	validUntilLedger uint32,
	networkPassphrase string,
	opts ...AuthorizeAllOption,
) ([]xdr.SorobanAuthorizationEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("soroauth: authorize all: %w", err)
	}

	var config authorizeAllConfig
	for _, opt := range opts {
		if opt != nil {
			opt(&config)
		}
	}

	usedPlans := make(map[string]bool, len(config.delegatePlans))
	out := make([]xdr.SorobanAuthorizationEntry, 0, len(entries))

	for i, entry := range entries {
		if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
			copied, err := xdrcopy.Copy(entry)
			if err != nil {
				return nil, fmt.Errorf("soroauth: authorize all: entry %d: %w", i, err)
			}
			out = append(out, copied)
			continue
		}

		credentials, err := addressCredentials(entry.Credentials)
		if err != nil {
			return nil, fmt.Errorf("soroauth: authorize all: entry %d: %w", i, err)
		}
		address, err := FormatAddress(credentials.Address)
		if err != nil {
			return nil, fmt.Errorf("soroauth: authorize all: entry %d: %w", i, err)
		}

		if plan, ok := config.delegatePlans[address]; ok {
			wrapped, err := WithDelegates(entry, validUntilLedger, plan.Delegates, plan.TopSignature)
			if err != nil {
				return nil, fmt.Errorf("soroauth: authorize all: entry %d (%s): delegate plan: %w", i, address, err)
			}
			entry = wrapped
			usedPlans[address] = true
		}

		matched, _, err := signersForEntry(entry, signers)
		if err != nil {
			return nil, fmt.Errorf("soroauth: authorize all: entry %d (%s): %w", i, address, err)
		}
		if len(matched) == 0 {
			return nil, fmt.Errorf("soroauth: authorize all: entry %d (%s): %w", i, address,
				&MissingSignerError{Address: address})
		}

		signed := entry
		for _, signer := range matched {
			signed, err = AuthorizeEntry(ctx, signed, signer, validUntilLedger, networkPassphrase,
				ForAddress(signer.Address()))
			if err != nil {
				return nil, fmt.Errorf("soroauth: authorize all: entry %d (%s): signer %s: %w",
					i, address, signer.Address(), err)
			}
		}

		out = append(out, signed)
	}

	for address := range config.delegatePlans {
		if !usedPlans[address] {
			return nil, fmt.Errorf("soroauth: authorize all: %s: %w", address, &DelegatePlanUnmatchedError{Address: address})
		}
	}

	if config.requireAllSigned {
		for i := range out {
			if out[i].Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
				continue
			}
			nodes, err := credentialNodes(&out[i])
			if err != nil {
				return nil, fmt.Errorf("soroauth: authorize all: entry %d: %w", i, err)
			}
			for _, node := range nodes {
				if !isSigned(*node.signature) {
					address, formatErr := formatAddressBytes(node.encoded)
					if formatErr != nil {
						address = "<unformattable address>"
					}
					return nil, fmt.Errorf("soroauth: authorize all: entry %d: %s: %w", i, address,
						&UnsignedCredentialNodeError{Address: address})
				}
			}
		}
	}

	return out, nil
}

// VerifyResult holds the outcome of verifying a single Soroban authorization entry in a batch.
type VerifyResult struct {
	// Index is the position of the entry in the input slice.
	Index int
	// Address is the address extracted from the entry's credentials, if parseable.
	Address string
	// Error is nil if the entry verification succeeded, or the error encountered.
	Error error
}

// verifyConfig holds configuration options for batch verification.
type verifyConfig struct {
	concurrency int
}

// VerifyOption configures batch verification behavior.
type VerifyOption func(*verifyConfig)

// WithConcurrency sets the maximum number of concurrent goroutines used during batch verification.
// If n <= 0, concurrency is unbounded (or defaults to runtime limits as appropriate).
func WithConcurrency(n int) VerifyOption {
	return func(c *verifyConfig) {
		c.concurrency = n
	}
}

// VerifyAll verifies a slice of Soroban authorization entries in one call, reporting per-entry verdicts.
//
// Unlike AuthorizeAll, a failure in one entry does not abort the rest: every entry is checked,
// and each result contains its own index, address, and error status.
// Concurrency is bounded and configurable via VerifyOption parameters (e.g. WithConcurrency).
func VerifyAll(
	ctx context.Context,
	entries []xdr.SorobanAuthorizationEntry,
	networkPassphrase string,
	opts ...VerifyOption,
) ([]VerifyResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("soroauth: verify all: %w", err)
	}

	cfg := verifyConfig{concurrency: 0}
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	if len(entries) == 0 {
		return []VerifyResult{}, nil
	}

	workerLimit := cfg.concurrency
	if workerLimit <= 0 {
		workerLimit = len(entries)
	}
	if workerLimit > len(entries) {
		workerLimit = len(entries)
	}

	type job struct {
		index int
		entry xdr.SorobanAuthorizationEntry
	}

	jobs := make(chan job, len(entries))
	for i, entry := range entries {
		jobs <- job{index: i, entry: entry}
	}
	close(jobs)

	results := make([]VerifyResult, len(entries))
	var wg sync.WaitGroup
	var mu sync.Mutex
	for w := 0; w < workerLimit; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				res := VerifyResult{Index: j.index}
				local := j.entry
				if local.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
					mu.Lock()
					results[j.index] = res
					mu.Unlock()
					continue
				}

				credentials, err := addressCredentials(local.Credentials)
				if err != nil {
					res.Error = err
					mu.Lock()
					results[j.index] = res
					mu.Unlock()
					continue
				}
				addrStr, err := FormatAddress(credentials.Address)
				if err == nil {
					res.Address = addrStr
				}

				rep, err := VerifyEntry(local, networkPassphrase)
				if err == nil && !rep.Verified() {
					for _, n := range rep.Nodes {
						if n.Verdict != VerdictVerified && n.Verdict != VerdictUnsigned {
							err = fmt.Errorf("node %s verdict %s: %s", n.Address, n.Verdict, n.Reason)
							break
						}
					}
				}
				res.Error = err
				mu.Lock()
				results[j.index] = res
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return results, nil
}
