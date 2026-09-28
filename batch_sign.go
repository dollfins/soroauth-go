package soroauth

import (
	"context"
	"fmt"
	"sync"

	"github.com/stellar/go-stellar-sdk/xdr"

	"github.com/soroauth/soroauth-go/internal/xdrcopy"
)

// AuthorizeBatchOption adjusts how AuthorizeBatch behaves.
type AuthorizeBatchOption func(*batchConfig)

// WithMaxWorkers limits how many sign requests run concurrently. The
// default is the number of available CPUs, which is what a backend raising
// a few hundred entries per second is usually after. Nothing in the batch
// is dropped or reordered to accommodate it: entries keep their position
// in the output, and the batch fails as a whole if any one of them fails.
func WithMaxWorkers(n int) AuthorizeBatchOption {
	return func(c *batchConfig) {
		if n < 1 {
			n = 1
		}
		c.maxWorkers = n
	}
}

// batchConfig holds the optional behaviour of AuthorizeBatch. It is an
// unexported struct behind AuthorizeBatchOption, the same shape
// AuthorizeAll uses for its options.
type batchConfig struct {
	maxWorkers int
}

// AuthorizeBatch signs every entry in a batch, or none of them.
//
// It is AuthorizeAll with a bounded worker pool, stable output ordering and
// an all-or-nothing contract. Output ordering is the input ordering:
// entry i comes back in position i of the result slice, so a caller that
// put its delegation entries first and its classic accounts after sees
// exactly that order back. Entries are never dropped to balance workers,
// and there is no partial result: on any error the returned slice is nil.
//
// The signature flow for one entry is the same as AuthorizeEntry's:
// Preimage -> Payload (SHA-256 of the marshaled HashIdPreimage) -> Signer.Sign
// over the matching credential node(s) -> expiration written into the
// credentials. The batch shares that flow, so the two rows soroauth is
// known for stay the same, and the difference is only in how many rows it
// signs at once.
//
// ctx is checked before the first entry, including an empty batch, so a
// cancelled context fails closed even when no Signer would run. The same
// ctx is passed unchanged to AuthorizeEntry and from there to Signer.Sign.
func AuthorizeBatch(
	ctx context.Context,
	entries []xdr.SorobanAuthorizationEntry,
	signers []Signer,
	validUntilLedger uint32,
	networkPassphrase string,
	opts ...AuthorizeBatchOption,
) ([]xdr.SorobanAuthorizationEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("soroauth: authorize batch: %w", err)
	}

	var config batchConfig
	for _, opt := range opts {
		opt(&config)
	}

	workers := config.maxWorkers
	if workers < 1 {
		workers = 1
	}

	// results and errs hold one slot per input entry, in the same order. A
	// worker writes only into its own slots, so a failure in one entry cannot
	// clobber a neighbour's output, and no lock is needed.
	//
	// The error is kept, not just the fact that there was one. Inferring
	// failure from a zero-valued result would throw the sentinel away, and
	// the batch's callers match on those: ErrMissingSigner tells a caller
	// which address it forgot to supply a signer for, which "1 of 2 entries
	// failed" does not.
	results := make([]xdr.SorobanAuthorizationEntry, len(entries))
	errs := make([]error, len(entries))

	var wg sync.WaitGroup
	sem := make(chan struct{}, workers)
	for i := range entries {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			signed, err := authorizeOne(ctx, entries[i], signers, validUntilLedger, networkPassphrase)
			if err != nil {
				errs[i] = err
				return
			}
			results[i] = signed
		}(i)
	}

	wg.Wait()

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("soroauth: authorize batch: %w", err)
	}

	// The first failure by input position, not by whichever goroutine lost
	// its race: the same batch must report the same error every time it is
	// run, or a caller cannot write a test against it. The count comes with
	// it, so a caller fixing one entry knows whether more are waiting.
	failed := 0
	firstFailure := -1
	for i := range errs {
		if errs[i] != nil {
			failed++
			if firstFailure < 0 {
				firstFailure = i
			}
		}
	}
	if failed > 0 {
		return nil, fmt.Errorf("soroauth: authorize batch: %d of %d entries failed, first at entry %d: %w",
			failed, len(entries), firstFailure, errs[firstFailure])
	}

	out := make([]xdr.SorobanAuthorizationEntry, 0, len(entries))
	for i := range results {
		out = append(out, results[i])
	}
	return out, nil
}

// authorizeOne signs one entry and returns the signed copy, or the zero
// entry on error so the caller can tell a failed slot from a successful
// one without reading the error. The returned entry shares no memory with
// the input.
func authorizeOne(
	ctx context.Context,
	entry xdr.SorobanAuthorizationEntry,
	signers []Signer,
	validUntilLedger uint32,
	networkPassphrase string,
) (xdr.SorobanAuthorizationEntry, error) {
	if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
		return xdrcopy.Copy(entry)
	}

	credentials, err := addressCredentials(entry.Credentials)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize batch: %w", err)
	}
	address, err := FormatAddress(credentials.Address)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize batch: %w", err)
	}

	matched, _, err := signersForEntry(entry, signers)
	if err != nil {
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize batch: %w", err)
	}
	if len(matched) == 0 {
		// MissingSignerError.Error() is deliberately just the sentinel's text;
		// the address is the call site's to format in, as AuthorizeAll does,
		// and is also on the error for errors.As.
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize batch: %s: %w",
			address, &MissingSignerError{Address: address})
	}

	signed := entry
	for _, signer := range matched {
		signed, err = AuthorizeEntry(ctx, signed, signer, validUntilLedger, networkPassphrase, ForAddress(signer.Address()))
		if err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("soroauth: authorize batch: signer %s: %w", signer.Address(), err)
		}
	}
	return signed, nil
}
