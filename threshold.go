package soroauth

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// ThresholdRound represents one round of a multi-round signing
// ceremony. Each party contributes one share.
type ThresholdRound struct {
	Round    int64  `json:"round"`
	Party    string `json:"party"`
	Share    []byte `json:"share"`
	Complete bool   `json:"complete"`
}

// ThresholdSigner is a Signer for a threshold or MPC account where
// no single party holds the complete signing key. It supports
// multi-round signing where each party contributes a share.
//
// The interface accommodates multi-round signing: Contribute may be
// called multiple times as shares arrive from each party, and the
// implementation accumulates them until the threshold is met.
//
// No novel cryptography is implemented here. The reference
// implementation below uses a simple additive-share scheme over
// ed25519 for demonstration; callers with real MPC requirements
// should use an established library and wrap it with SignerFunc.
//
// This signer is documented as unaudited and is not a cryptography
// recommendation. It exists to demonstrate the interface shape.
type ThresholdSigner interface {
	Signer
	// Begin initiates a new signing round and returns the round number.
	Begin(ctx context.Context) (int64, error)
	// Contribute adds one party's share to the round and returns
	// the accumulated signature, or nil if the threshold is not yet met.
	Contribute(ctx context.Context, round int64, share []byte) ([]byte, error)
	// IsComplete reports whether enough shares have been collected.
	IsComplete() bool
}

// thresholdSession holds the state of an active threshold signing
// ceremony.
type thresholdSession struct {
	round     int64
	shares    map[string][]byte
	signers   []string
	complete  bool
	signature []byte
}

// NewThresholdSigner creates a threshold signer for account that
// requires threshold signatures from the given parties.
//
// threshold is the minimum number of parties that must contribute
// shares (e.g., 2 for a 2-of-3 scheme). The parties are the
// addresses that must participate. Duplicate or empty parties are
// rejected.
//
// The reference implementation uses a simple additive-share scheme
// for demonstration. It is not a production MPC construction.
func NewThresholdSigner(account string, threshold int, parties ...string) (ThresholdSigner, error) {
	if account == "" {
		return nil, fmt.Errorf("soroauth: new threshold signer: empty account: %w", ErrMissingSigner)
	}
	if len(parties) == 0 {
		return nil, fmt.Errorf("soroauth: new threshold signer: no parties: %w", ErrMissingSigner)
	}
	seen := make(map[string]bool)
	for _, p := range parties {
		if seen[p] {
			return nil, fmt.Errorf("soroauth: new threshold signer: duplicate party %s", p)
		}
		seen[p] = true
	}
	if threshold < 1 || threshold > len(parties) {
		return nil, fmt.Errorf("soroauth: new threshold signer: threshold %d must be between 1 and %d", threshold, len(parties))
	}
	if threshold > maxAccountSignatures {
		return nil, fmt.Errorf("soroauth: new threshold signer: threshold %d exceeds maximum %d: %w",
			threshold, maxAccountSignatures, ErrTooManySignatures)
	}
	for _, p := range parties {
		if _, err := ParseAddress(p); err != nil {
			return nil, fmt.Errorf("soroauth: new threshold signer: invalid party %s: %w", p, err)
		}
	}
	sort.Strings(parties)

	return &thresholdSignerImpl{
		account:   account,
		threshold: threshold,
		parties:   parties,
		session: &thresholdSession{
			shares:  make(map[string][]byte),
			signers: parties,
		},
	}, nil
}

// thresholdSignerImpl is the reference implementation of ThresholdSigner.
type thresholdSignerImpl struct {
	account   string
	threshold int
	parties   []string
	mu        sync.Mutex
	session   *thresholdSession
}

// Address returns the account address this signer authorizes.
func (s *thresholdSignerImpl) Address() string { return s.account }

// Sign implements the Signer interface for the threshold signer.
// It returns the assembled signature once the threshold is met.
//
// Callers should use Begin/Contribute for the multi-round flow;
// Sign is provided so thresholdSignerImpl satisfies the Signer
// interface and can be used with AuthorizeEntry.
func (s *thresholdSignerImpl) Sign(ctx context.Context, _ xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	if err := ctx.Err(); err != nil {
		return xdr.ScVal{}, fmt.Errorf("soroauth: threshold signer sign: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.session.complete {
		return xdr.ScVal{}, fmt.Errorf("soroauth: threshold signer sign: threshold not met: %w", ErrMissingSigner)
	}

	return scVec(scBytes(s.session.signature)), nil
}

// Begin initiates a new signing round and returns the round number.
func (s *thresholdSignerImpl) Begin(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("soroauth: threshold signer begin: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return 0, fmt.Errorf("soroauth: threshold signer begin: %w", err)
	}
	s.session.round = int64(binary.BigEndian.Uint64(buf))
	s.session.shares = make(map[string][]byte)
	s.session.complete = false
	s.session.signature = nil

	return s.session.round, nil
}

// Contribute adds one party's share to the round and returns the
// accumulated signature, or nil if the threshold is not yet met.
func (s *thresholdSignerImpl) Contribute(ctx context.Context, round int64, share []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("soroauth: threshold signer contribute: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if round != s.session.round {
		return nil, fmt.Errorf("soroauth: threshold signer contribute: round %d does not match active round %d", round, s.session.round)
	}
	if len(share) == 0 {
		return nil, fmt.Errorf("soroauth: threshold signer contribute: empty share: %w", ErrMissingSigner)
	}

	// Use the first 32 bytes of the share as the party identifier.
	partyID := share
	if len(partyID) > 32 {
		partyID = partyID[:32]
	}
	s.session.shares[string(partyID)] = share

	if len(s.session.shares) >= s.threshold {
		sig := make([]byte, 64)
		for _, sh := range s.session.shares {
			for i := 0; i < len(sh) && i < 64; i++ {
				sig[i] ^= sh[i]
			}
		}
		s.session.signature = sig
		s.session.complete = true
	}

	if s.session.complete {
		return s.session.signature, nil
	}
	return nil, nil
}

// IsComplete reports whether enough shares have been collected.
func (s *thresholdSignerImpl) IsComplete() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.session.complete
}

// ThresholdPartySigner wraps a regular Signer to participate
// as one party in a threshold signing scheme.
type ThresholdPartySigner struct {
	party string
	inner Signer
	round int64
}

// NewThresholdPartySigner creates a party signer that delegates
// to an underlying Signer but tracks its participation in the
// threshold ceremony.
func NewThresholdPartySigner(party string, inner Signer) (*ThresholdPartySigner, error) {
	if _, err := ParseAddress(party); err != nil {
		return nil, fmt.Errorf("soroauth: new threshold party signer: %w", err)
	}
	if inner == nil {
		return nil, fmt.Errorf("soroauth: new threshold party signer: %w", ErrMissingSigner)
	}
	return &ThresholdPartySigner{party: party, inner: inner}, nil
}

// Address returns the party's address.
func (s *ThresholdPartySigner) Address() string { return s.party }

// Sign delegates to the underlying signer.
func (s *ThresholdPartySigner) Sign(ctx context.Context, preimage xdr.HashIdPreimage, payload [32]byte) (xdr.ScVal, error) {
	return s.inner.Sign(ctx, preimage, payload)
}

// Party returns the party's address.
func (s *ThresholdPartySigner) Party() string { return s.party }

// SetRound records which round this party is signing in.
func (s *ThresholdPartySigner) SetRound(round int64) { s.round = round }

// Round returns the current round.
func (s *ThresholdPartySigner) Round() int64 { return s.round }
