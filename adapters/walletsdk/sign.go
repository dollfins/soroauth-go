package walletsdk

import (
	"context"
	"errors"
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go"
)

// ErrEnforcePassMissing is returned by Signed.Envelope when the enforce
// simulation pass has not been recorded.
var ErrEnforcePassMissing = errors.New("the enforce simulation pass has not been recorded")

// Signed is what Sign returns: the signed authorization entries, and the
// envelope they were written into.
//
// It will not hand out a submittable envelope until the caller records that the
// enforce simulation pass has run, because signing entries changes what the
// transaction costs to run. See Signed.Envelope and Signed.MarkEnforced.
type Signed struct {
	envelope xdr.TransactionEnvelope
	entries  []soroauth.EnvelopeEntry
	enforced bool
}

// Entries returns the signed authorization entries, in operation order, each
// with the operation index and entry index it came from.
//
// These are what the caller puts into the enforce simulation, which is why they
// are available before MarkEnforced: the pass cannot run without them. Entries
// sharing an OperationIndex belong to the same operation's auth vector, in
// ascending EntryIndex order, which is the shape the request needs.
//
// The entries alias the envelope this Signed holds. They are for reading and
// for building the enforce request, not for editing.
func (s *Signed) Entries() []soroauth.EnvelopeEntry { return s.entries }

// Enforced reports whether the enforce pass has been recorded.
func (s *Signed) Enforced() bool { return s.enforced }

// MarkEnforced records that the enforce simulation pass has run with the signed
// entries, and that the transaction about to be submitted was assembled from
// what that pass reported.
//
// This is deliberately a statement the caller has to make rather than something
// this package can check. The enforce pass runs in the caller's RPC client, and
// how its result is turned back into a transaction is that client's business;
// what this package can do is refuse to look like it did the work.
func (s *Signed) MarkEnforced() { s.enforced = true }

// Envelope returns the transaction envelope with the signed entries written
// into it.
//
// It refuses with ErrEnforcePassMissing until MarkEnforced has been called, and
// that refusal is the point of this type. A wallet that submits what the
// record-mode simulation produced gets a fee error on-chain, after fees are
// paid, because the resource fee it carries does not cover the signatures that
// are now attached. Turning that into a local error with a name is cheaper than
// debugging it on-chain.
//
// The returned envelope is this Signed's copy, not the caller's input.
func (s *Signed) Envelope() (xdr.TransactionEnvelope, error) {
	if !s.enforced {
		return xdr.TransactionEnvelope{}, fmt.Errorf("walletsdk: envelope: %w", ErrEnforcePassMissing)
	}
	return s.envelope, nil
}

// Sign signs every authorization entry in env that this wallet's key is
// responsible for, and returns them with the envelope they went into.
//
// It is soroauth.AuthorizeEnvelope over a wallet SDK keypair, and it inherits
// that function's all-or-nothing rule: every entry that is not on the
// source-account arm must be signed by this key, or the call fails with
// soroauth.ErrMissingSigner naming the entry. An envelope that also needs
// somebody else's signature is not returned half-signed; the caller hears about
// it, because entries belonging to other addresses are not this wallet's to
// fill in.
//
// The caller's envelope is not modified. AuthorizeEnvelope deep-copies before
// writing, so env is byte-identical afterwards.
//
// What comes back still has to go through the enforce simulation pass before it
// can be submitted; see Signed.
func Sign(
	ctx context.Context,
	env xdr.TransactionEnvelope,
	kp Keypair,
	validUntilLedger uint32,
	networkPassphrase string,
) (*Signed, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("walletsdk: sign: %w", err)
	}
	signer, err := NewSigner(kp)
	if err != nil {
		return nil, fmt.Errorf("walletsdk: sign: %w", err)
	}

	signed, err := soroauth.AuthorizeEnvelope(ctx, env,
		[]soroauth.Signer{signer}, validUntilLedger, networkPassphrase)
	if err != nil {
		return nil, fmt.Errorf("walletsdk: sign: %w", err)
	}

	entries, err := soroauth.EnvelopeEntries(signed)
	if err != nil {
		return nil, fmt.Errorf("walletsdk: sign: %w", err)
	}

	return &Signed{envelope: signed, entries: entries}, nil
}
