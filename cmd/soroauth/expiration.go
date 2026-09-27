package main

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/stellar/go-stellar-sdk/clients/rpcclient"

	"github.com/soroauth/soroauth-go"
)

// validForTimeout bounds the getLatestLedger call that --valid-for makes. It is
// short on purpose: the call resolves a ledger number a caller could otherwise
// look up, so waiting on an unreachable endpoint helps no one.
const validForTimeout = 10 * time.Second

// ledgerFetcher fetches the current ledger sequence from an RPC endpoint. It is
// a function type so the resolve path can be exercised without a network.
type ledgerFetcher func(ctx context.Context, rpcURL string) (uint32, error)

// fetchLatestLedger asks an RPC endpoint for the current ledger sequence.
//
// The endpoint is whatever the caller passed to --rpc-url or set in
// SOROAUTH_RPC_URL; this command does not invent one. The current ledger is
// read-only, so no credential is involved and nothing here signs.
func fetchLatestLedger(ctx context.Context, rpcURL string) (uint32, error) {
	client := rpcclient.NewClient(rpcURL, nil)
	defer func() { _ = client.Close() }()

	ledger, err := client.GetLatestLedger(ctx)
	if err != nil {
		return 0, fmt.Errorf("soroauth: rpc %s: getLatestLedger: %w", rpcURL, err)
	}
	return ledger.Sequence, nil
}

// resolveRPCURL returns the RPC endpoint a command should use: --rpc-url when
// given, otherwise $SOROAUTH_RPC_URL, otherwise empty. It is deliberately empty
// rather than defaulted to public testnet: --valid-for resolves an expiration
// that authorizes value to move, so the network it is resolved against should
// be the caller's explicit choice, not this tool's guess.
func resolveRPCURL(flagValue string, getenv func(string) string) string {
	if flagValue != "" {
		return flagValue
	}
	return getenv("SOROAUTH_RPC_URL")
}

// resolveValidUntil turns the --valid-until/--valid-for pair into the absolute
// expiration ledger a command needs. Exactly one of the two must be given.
//
// --valid-until is absolute: it is used as written. --valid-for is relative: it
// is added to the current ledger, read from the RPC endpoint (fetch), so that a
// caller can ask for "about an hour" without first querying the ledger and
// adding by hand. The two are mutually exclusive because accepting both would
// leave which one wins to a guess.
//
// Every refusal is fail-closed and names what to do: both flags given, neither
// given, --valid-for without an endpoint, a non-positive --valid-for, or an
// endpoint that cannot be reached.
func resolveValidUntil(
	ctx context.Context,
	validUntil, validFor uint64,
	rpcURL string,
	fetch ledgerFetcher,
) (uint32, error) {
	switch {
	case validUntil != 0 && validFor != 0:
		return 0, newErrorf(ExitUsageError,
			"--valid-until and --valid-for are mutually exclusive: give one or the other")

	case validUntil != 0:
		if validUntil > math.MaxUint32 {
			return 0, newErrorf(ExitUsageError,
				"--valid-until %d is out of range for a ledger sequence (maximum %d)", validUntil, uint32(math.MaxUint32))
		}
		return uint32(validUntil), nil

	case validFor != 0:
		if validFor > math.MaxUint32 {
			return 0, newErrorf(ExitUsageError,
				"--valid-for %d is out of range for a ledger count (maximum %d)", validFor, uint32(math.MaxUint32))
		}
		if rpcURL == "" {
			return 0, newErrorf(ExitUsageError,
				"--valid-for resolves against the current ledger and needs an RPC endpoint: "+
					"pass --rpc-url <url> or set SOROAUTH_RPC_URL")
		}
		callCtx, cancel := context.WithTimeout(ctx, validForTimeout)
		defer cancel()
		latest, err := fetch(callCtx, rpcURL)
		if err != nil {
			return 0, newErrorf(ExitGeneralError,
				"--valid-for could not read the current ledger from %s: %w", rpcURL, err)
		}
		expiration, err := soroauth.ExpirationAfter(latest, uint32(validFor))
		if err != nil {
			return 0, newErrorf(ExitVerificationFailed,
				"--valid-for %d from ledger %d: %w", validFor, latest, err)
		}
		return expiration, nil

	default:
		// Kept in this shape so existing callers and tests that name
		// --valid-until still match; --valid-for is the alternative.
		return 0, newErrorf(ExitUsageError,
			"--valid-until is required and must be greater than zero, or give --valid-for <ledgers>")
	}
}
