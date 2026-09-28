package soroauth

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// testKeypair derives a deterministic public test keypair from a label. These
// keys are public by construction and must never be funded on mainnet.
func testKeypair(t testing.TB, label string) *keypair.Full {
	t.Helper()
	kp, err := keypair.FromRawSeed(sha256.Sum256([]byte(label)))
	if err != nil {
		t.Fatalf("deriving keypair for %q: %v", label, err)
	}
	return kp
}

// testContractAddress derives a deterministic C… address from a label.
func testContractAddress(t testing.TB, label string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(label))
	address, err := strkey.Encode(strkey.VersionByteContract, sum[:])
	if err != nil {
		t.Fatalf("encoding contract address for %q: %v", label, err)
	}
	return address
}

func TestParseAddressFormatAddressRoundTrip(t *testing.T) {
	accountAddress := testKeypair(t, "soroauth-address-account").Address()
	contractAddress := testContractAddress(t, "soroauth-address-contract")

	tests := []struct {
		name     string
		address  string
		wantType xdr.ScAddressType
	}{
		{
			name:     "account address",
			address:  accountAddress,
			wantType: xdr.ScAddressTypeScAddressTypeAccount,
		},
		{
			name:     "contract address",
			address:  contractAddress,
			wantType: xdr.ScAddressTypeScAddressTypeContract,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseAddress(tt.address)
			if err != nil {
				t.Fatalf("ParseAddress(%q) returned an unexpected error: %v", tt.address, err)
			}
			if parsed.Type != tt.wantType {
				t.Errorf("ParseAddress(%q) produced type %v, want %v", tt.address, parsed.Type, tt.wantType)
			}

			// The parsed value must be a legal XDR value, since it is about
			// to be signed over.
			if _, err := parsed.MarshalBinary(); err != nil {
				t.Errorf("parsed address does not marshal: %v", err)
			}

			formatted, err := FormatAddress(parsed)
			if err != nil {
				t.Fatalf("FormatAddress returned an unexpected error: %v", err)
			}
			if formatted != tt.address {
				t.Errorf("round trip changed the address\n want %s\n  got %s", tt.address, formatted)
			}

			// And the other direction: format then parse is the identity on
			// the XDR value, not just on the string.
			reparsed, err := ParseAddress(formatted)
			if err != nil {
				t.Fatalf("ParseAddress on the formatted address failed: %v", err)
			}
			wantBytes, err := parsed.MarshalBinary()
			if err != nil {
				t.Fatalf("marshalling parsed address: %v", err)
			}
			gotBytes, err := reparsed.MarshalBinary()
			if err != nil {
				t.Fatalf("marshalling reparsed address: %v", err)
			}
			if !bytes.Equal(wantBytes, gotBytes) {
				t.Errorf("round trip changed the XDR\n want %x\n  got %x", wantBytes, gotBytes)
			}
		})
	}
}

// TestParseAddressCarriesTheRightKeyBytes proves the payload lands in the right
// field, which a type-only assertion would miss.
func TestParseAddressCarriesTheRightKeyBytes(t *testing.T) {
	kp := testKeypair(t, "soroauth-address-account")

	parsed, err := ParseAddress(kp.Address())
	if err != nil {
		t.Fatalf("ParseAddress returned an unexpected error: %v", err)
	}

	raw, err := strkey.Decode(strkey.VersionByteAccountID, kp.Address())
	if err != nil {
		t.Fatalf("decoding the test address: %v", err)
	}
	if parsed.AccountId == nil || parsed.AccountId.Ed25519 == nil {
		t.Fatal("parsed account address has no ed25519 key")
	}
	if !bytes.Equal(parsed.AccountId.Ed25519[:], raw) {
		t.Errorf("key bytes differ\n want %x\n  got %x", raw, parsed.AccountId.Ed25519[:])
	}
}

func TestParseAddressRejects(t *testing.T) {
	muxed, err := xdr.MuxedAccountFromAccountId(testKeypair(t, "soroauth-address-account").Address(), 1234)
	if err != nil {
		t.Fatalf("building a muxed account: %v", err)
	}
	muxedAddress, err := muxed.GetAddress()
	if err != nil {
		t.Fatalf("rendering the muxed address: %v", err)
	}

	payload32 := sha256.Sum256([]byte("soroauth-address-reject"))
	liquidityPool, err := strkey.Encode(strkey.VersionByteLiquidityPool, payload32[:])
	if err != nil {
		t.Fatalf("encoding a liquidity pool strkey: %v", err)
	}
	claimableBalance, err := strkey.Encode(strkey.VersionByteClaimableBalance, append([]byte{0}, payload32[:]...))
	if err != nil {
		t.Fatalf("encoding a claimable balance strkey: %v", err)
	}

	valid := testKeypair(t, "soroauth-address-account").Address()

	tests := []struct {
		name        string
		address     string
		wantMessage string
	}{
		{
			name:        "muxed account",
			address:     muxedAddress,
			wantMessage: "muxed",
		},
		{
			name:        "secret seed",
			address:     testKeypair(t, "soroauth-address-account").Seed(),
			wantMessage: "not an account",
		},
		{
			name:        "liquidity pool",
			address:     liquidityPool,
			wantMessage: "not an account",
		},
		{
			name:        "claimable balance",
			address:     claimableBalance,
			wantMessage: "not an account",
		},
		{
			name:        "empty string",
			address:     "",
			wantMessage: "parse address",
		},
		{
			name:        "not base32",
			address:     "not-an-address",
			wantMessage: "parse address",
		},
		{
			name:        "corrupted checksum",
			address:     valid[:len(valid)-1] + string(flipLast(valid)),
			wantMessage: "parse address",
		},
		{
			name:        "truncated",
			address:     valid[:len(valid)-2],
			wantMessage: "parse address",
		},
		{
			// Canonicality is pinned in full by
			// TestParseAddressRejectsNonCanonicalEncodings; these four only
			// keep the plain rejection path covered here too.
			name:        "lowercased",
			address:     strings.ToLower(valid),
			wantMessage: "parse address",
		},
		{
			name:        "leading whitespace",
			address:     " " + valid,
			wantMessage: "parse address",
		},
		{
			name:        "base32 padding",
			address:     valid + "=",
			wantMessage: "parse address",
		},
		{
			name:        "extra trailing character",
			address:     valid + "A",
			wantMessage: "parse address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAddress(tt.address)
			if err == nil {
				t.Fatalf("ParseAddress(%q) succeeded, returning %+v", tt.address, got)
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Errorf("error %q does not mention %q", err, tt.wantMessage)
			}
			if got != (xdr.ScAddress{}) {
				t.Errorf("ParseAddress returned %+v alongside an error, want the zero value", got)
			}
		})
	}
}

// TestParseAddressRejectsNonCanonicalEncodings pins the canonicality rule
// documented on ParseAddress: only the canonical SEP-23 base32 spelling of an
// address is accepted, even when a laxer decoder could recover the same version
// byte and payload from a non-canonical one.
//
// Every rejection is asserted together with the canonical spelling of the same
// address being accepted, so the test proves the refusal is about the encoding
// rather than about the key. The expected reason is part of each case, because
// a rejection test that only asserts "it failed" passes for the wrong reason.
func TestParseAddressRejectsNonCanonicalEncodings(t *testing.T) {
	account := testKeypair(t, "soroauth-address-account").Address()
	contract := testContractAddress(t, "soroauth-address-canonical-contract")

	// The canonical spellings this table mutates must parse, or the rest of the
	// test would be pinning the wrong thing.
	for _, address := range []string{account, contract} {
		if _, err := ParseAddress(address); err != nil {
			t.Fatalf("ParseAddress(%q) rejected the canonical address: %v", address, err)
		}
	}

	tests := []struct {
		name       string
		address    string
		wantReason string
	}{
		{
			name:       "lower-cased account address",
			address:    strings.ToLower(account),
			wantReason: "base32 decode failed",
		},
		{
			name:       "lower-cased contract address",
			address:    strings.ToLower(contract),
			wantReason: "base32 decode failed",
		},
		{
			name:       "mixed-case account address",
			address:    strings.ToUpper(account[:1]) + strings.ToLower(account[1:]),
			wantReason: "base32 decode failed",
		},
		{
			name:       "leading whitespace",
			address:    " " + account,
			wantReason: "non-canonical",
		},
		{
			name:       "trailing whitespace",
			address:    account + " ",
			wantReason: "non-canonical",
		},
		{
			name:       "trailing newline",
			address:    account + "\n",
			wantReason: "non-canonical",
		},
		{
			name:       "base32 padding",
			address:    account + "=",
			wantReason: "non-canonical",
		},
		{
			name:       "extra trailing character",
			address:    account + "A",
			wantReason: "non-canonical",
		},
		{
			// A 55-character body leaves three unused bits in its final
			// character. 'B' has value 1, so those bits are non-zero and the
			// decoder refuses on canonicality before it ever reaches the
			// checksum.
			name:       "non-zero unused trailing bits",
			address:    account[:len(account)-2] + "B",
			wantReason: "non-canonical",
		},
		{
			name:       "0 is not in the base32 alphabet",
			address:    account[:len(account)-1] + "0",
			wantReason: "base32 decode failed",
		},
		{
			name:       "1 is not in the base32 alphabet",
			address:    account[:len(account)-1] + "1",
			wantReason: "base32 decode failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAddress(tt.address)
			if err == nil {
				t.Fatalf("ParseAddress(%q) accepted a non-canonical address, returning %+v", tt.address, got)
			}
			if got != (xdr.ScAddress{}) {
				t.Errorf("ParseAddress returned %+v alongside an error, want the zero value", got)
			}
			if !strings.Contains(err.Error(), tt.wantReason) {
				t.Errorf("error %q does not carry the decoder reason %q", err, tt.wantReason)
			}
		})
	}
}

// flipLast changes the final base32 character so the checksum no longer matches.
func flipLast(s string) byte {
	last := s[len(s)-1]
	if last == 'A' {
		return 'B'
	}
	return 'A'
}

func TestFormatAddressRejects(t *testing.T) {
	muxedKey := xdr.Uint256(sha256.Sum256([]byte("soroauth-address-muxed")))

	tests := []struct {
		name        string
		address     xdr.ScAddress
		wantMessage string
	}{
		{
			name: "muxed account",
			address: xdr.ScAddress{
				Type: xdr.ScAddressTypeScAddressTypeMuxedAccount,
				MuxedAccount: &xdr.MuxedEd25519Account{
					Id:      1,
					Ed25519: muxedKey,
				},
			},
			wantMessage: "muxed",
		},
		{
			name:        "unknown address type",
			address:     xdr.ScAddress{Type: xdr.ScAddressType(99)},
			wantMessage: "unsupported address type",
		},
		{
			name:        "account arm without an account id",
			address:     xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeAccount},
			wantMessage: "no account id",
		},
		{
			name:        "contract arm without a contract id",
			address:     xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract},
			wantMessage: "no contract id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FormatAddress(tt.address)
			if err == nil {
				t.Fatalf("FormatAddress succeeded, returning %q", got)
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Errorf("error %q does not mention %q", err, tt.wantMessage)
			}
			if got != "" {
				t.Errorf("FormatAddress returned %q alongside an error, want an empty string", got)
			}
		})
	}
}
