package soroauth

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// scAddressPayloadLen is the raw payload length, in bytes, of both an ed25519
// account address and a contract address. strkey.DecodeAny already enforces the
// SEP-23 payload length for the version bytes accepted here; the length is
// re-checked at the copy so that a future version byte sharing one of these
// arms can never be silently truncated into a valid-looking address.
const scAddressPayloadLen = 32

// ParseAddress converts a G… account strkey or a C… contract strkey into the
// xdr.ScAddress that names it.
//
// Only those two forms are accepted. An M… muxed address is rejected rather
// than unwrapped to the account it wraps: a Soroban address credential names
// the identity whose require_auth() is being satisfied (CAP-46-11), and
// unwrapping would mean signing on behalf of an identity the caller did not
// write down. Every other strkey form (seeds, signed payloads, liquidity pools,
// claimable balances) names something that cannot appear in an address
// credential at all.
//
// Only the canonical SEP-23 base32 spelling of an address is accepted: upper
// case A-Z and 2-7, no padding, no surrounding whitespace, no extra characters,
// and any unused trailing bits set to zero. A strkey that decodes to the right
// version byte and payload but is not that canonical spelling — lower-cased,
// padded, wrapped in whitespace, or carrying non-zero unused bits — is refused,
// so a caller can never be handed a string that means the same bytes here but
// re-encodes differently elsewhere. The rejection is a strkey decoder refusal
// (SEP-23; go-stellar-sdk strkey.decodeString) rather than a check made here.
//
// The returned error wraps strkey's own error for malformed input, so a bad
// checksum is distinguishable from a well-formed address of the wrong kind.
func ParseAddress(s string) (xdr.ScAddress, error) {
	// DecodeAny validates the base32, the CRC-16 checksum, that the version
	// byte is a defined one, and that the payload length matches it.
	version, payload, err := strkey.DecodeAny(s)
	if err != nil {
		return xdr.ScAddress{}, fmt.Errorf("soroauth: parse address: %w", err)
	}

	switch version {
	case strkey.VersionByteAccountID:
		if len(payload) != scAddressPayloadLen {
			return xdr.ScAddress{}, fmt.Errorf(
				"soroauth: parse address: account address has a %d-byte payload, want %d",
				len(payload), scAddressPayloadLen)
		}
		var ed25519 xdr.Uint256
		copy(ed25519[:], payload)
		accountID := xdr.AccountId{
			Type:    xdr.PublicKeyTypePublicKeyTypeEd25519,
			Ed25519: &ed25519,
		}
		return xdr.ScAddress{
			Type:      xdr.ScAddressTypeScAddressTypeAccount,
			AccountId: &accountID,
		}, nil

	case strkey.VersionByteContract:
		if len(payload) != scAddressPayloadLen {
			return xdr.ScAddress{}, fmt.Errorf(
				"soroauth: parse address: contract address has a %d-byte payload, want %d",
				len(payload), scAddressPayloadLen)
		}
		var contractID xdr.ContractId
		copy(contractID[:], payload)
		return xdr.ScAddress{
			Type:       xdr.ScAddressTypeScAddressTypeContract,
			ContractId: &contractID,
		}, nil

	case strkey.VersionByteMuxedAccount:
		return xdr.ScAddress{}, fmt.Errorf(
			"soroauth: parse address: %q is a muxed (M…) address; an address credential must name the "+
				"account itself, so pass the underlying G… address", s)

	default:
		return xdr.ScAddress{}, fmt.Errorf(
			"soroauth: parse address: %q is not an account (G…) or contract (C…) address", s)
	}
}

// FormatAddress is the inverse of ParseAddress: it renders an xdr.ScAddress as
// the strkey that names it.
//
// It accepts exactly what ParseAddress produces, so ParseAddress and
// FormatAddress round-trip. Arms that ParseAddress refuses to build — muxed
// accounts, claimable balances, liquidity pools — are refused here too rather
// than rendered, so a caller can never be shown an address that this library
// would decline to sign for.
func FormatAddress(a xdr.ScAddress) (string, error) {
	switch a.Type {
	case xdr.ScAddressTypeScAddressTypeAccount:
		if a.AccountId == nil {
			return "", fmt.Errorf("soroauth: format address: account arm has no account id")
		}
		address, err := a.AccountId.GetAddress()
		if err != nil {
			return "", fmt.Errorf("soroauth: format address: %w", err)
		}
		return address, nil

	case xdr.ScAddressTypeScAddressTypeContract:
		if a.ContractId == nil {
			return "", fmt.Errorf("soroauth: format address: contract arm has no contract id")
		}
		address, err := strkey.Encode(strkey.VersionByteContract, a.ContractId[:])
		if err != nil {
			return "", fmt.Errorf("soroauth: format address: %w", err)
		}
		return address, nil

	case xdr.ScAddressTypeScAddressTypeMuxedAccount:
		return "", fmt.Errorf(
			"soroauth: format address: muxed (M…) addresses are not valid in an address credential")

	default:
		return "", fmt.Errorf(
			"soroauth: format address: unsupported address type %d", a.Type)
	}
}
