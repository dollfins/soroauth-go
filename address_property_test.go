package soroauth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// TestParseAddressFormatAddressProperty runs property-based tests for address
// round-trips using generated G... and C... addresses.
func TestParseAddressFormatAddressProperty(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 1000
	parameters.MaxSize = 100

	properties := gopter.NewProperties(parameters)

	// Property: ParseAddress then FormatAddress round-trips for valid account addresses
	properties.Property("account address round-trip", propAccountAddressRoundTrip())

	// Property: ParseAddress then FormatAddress round-trips for valid contract addresses
	properties.Property("contract address round-trip", propContractAddressRoundTrip())

	// Property: XDR encoding is stable across ParseAddress -> FormatAddress -> ParseAddress
	properties.Property("account XDR stable across round-trip", propAccountXDRStable())
	properties.Property("contract XDR stable across round-trip", propContractXDRStable())

	// Property: Invalid inputs are rejected
	properties.Property("muxed address rejected", propMuxedRejected())
	properties.Property("secret seed rejected", propSecretSeedRejected())
	properties.Property("liquidity pool rejected", propLiquidityPoolRejected())
	properties.Property("claimable balance rejected", propClaimableBalanceRejected())
	properties.Property("malformed base32 rejected", propMalformedRejected())
	properties.Property("corrupted checksum rejected", propCorruptedChecksumRejected())
	properties.Property("truncated address rejected", propTruncatedRejected())
	properties.Property("empty string rejected", propEmptyStringRejected())
	properties.Property("case-altered address rejected", propCaseAlteredRejected())

	properties.TestingRun(t, gopter.ConsoleReporter(true))
}

// genAccountAddressGen generates a valid G... account address.
func genAccountAddressGen() gopter.Gen {
	return gen.SliceOfN(32, gen.UInt8Range(0, 255)).MapResult(func(result *gopter.GenResult) *gopter.GenResult {
		payload := result.Result.([]uint8)
		address, err := strkey.Encode(strkey.VersionByteAccountID, payload)
		if err != nil {
			panic(err)
		}
		return gopter.NewGenResult(address, result.Shrinker)
	})
}

// genContractAddressGen generates a valid C... contract address.
func genContractAddressGen() gopter.Gen {
	return gen.SliceOfN(32, gen.UInt8Range(0, 255)).MapResult(func(result *gopter.GenResult) *gopter.GenResult {
		payload := result.Result.([]uint8)
		address, err := strkey.Encode(strkey.VersionByteContract, payload)
		if err != nil {
			panic(err)
		}
		return gopter.NewGenResult(address, result.Shrinker)
	})
}

// propAccountAddressRoundTrip tests that ParseAddress -> FormatAddress
// returns the original account address string.
func propAccountAddressRoundTrip() gopter.Prop {
	return prop.ForAll(func(address string) bool {
		parsed, err := ParseAddress(address)
		if err != nil {
			return false
		}
		formatted, err := FormatAddress(parsed)
		if err != nil {
			return false
		}
		return formatted == address
	}, genAccountAddressGen())
}

// propContractAddressRoundTrip tests that ParseAddress -> FormatAddress
// returns the original contract address string.
func propContractAddressRoundTrip() gopter.Prop {
	return prop.ForAll(func(address string) bool {
		parsed, err := ParseAddress(address)
		if err != nil {
			return false
		}
		formatted, err := FormatAddress(parsed)
		if err != nil {
			return false
		}
		return formatted == address
	}, genContractAddressGen())
}

// propAccountXDRStable tests that the XDR encoding is stable across
// ParseAddress -> FormatAddress -> ParseAddress for account addresses.
func propAccountXDRStable() gopter.Prop {
	return prop.ForAll(func(address string) bool {
		parsed, err := ParseAddress(address)
		if err != nil {
			return false
		}
		wantBytes, err := parsed.MarshalBinary()
		if err != nil {
			return false
		}

		formatted, err := FormatAddress(parsed)
		if err != nil {
			return false
		}

		reparsed, err := ParseAddress(formatted)
		if err != nil {
			return false
		}

		gotBytes, err := reparsed.MarshalBinary()
		if err != nil {
			return false
		}

		return bytes.Equal(wantBytes, gotBytes)
	}, genAccountAddressGen())
}

// propContractXDRStable tests that the XDR encoding is stable across
// ParseAddress -> FormatAddress -> ParseAddress for contract addresses.
func propContractXDRStable() gopter.Prop {
	return prop.ForAll(func(address string) bool {
		parsed, err := ParseAddress(address)
		if err != nil {
			return false
		}
		wantBytes, err := parsed.MarshalBinary()
		if err != nil {
			return false
		}

		formatted, err := FormatAddress(parsed)
		if err != nil {
			return false
		}

		reparsed, err := ParseAddress(formatted)
		if err != nil {
			return false
		}

		gotBytes, err := reparsed.MarshalBinary()
		if err != nil {
			return false
		}

		return bytes.Equal(wantBytes, gotBytes)
	}, genContractAddressGen())
}

// genMuxedAddress generates a valid M... muxed address.
func genMuxedAddress() gopter.Gen {
	return genAccountAddressGen().FlatMap(
		func(baseAddr interface{}) gopter.Gen {
			var addr string
			switch val := baseAddr.(type) {
			case *gopter.GenResult:
				addr = val.Result.(string)
			case string:
				addr = val
			default:
				return gen.Const("")
			}
			return gen.UInt64Range(1, math.MaxUint32).MapResult(func(result *gopter.GenResult) *gopter.GenResult {
				uid := result.Result.(uint64)

				// Decode the base account address
				_, payload, err := strkey.DecodeAny(addr)
				if err != nil {
					panic(err)
				}

				var ed25519 xdr.Uint256
				copy(ed25519[:], payload)

				muxed := xdr.MuxedAccount{
					Type: xdr.CryptoKeyTypeKeyTypeMuxedEd25519,
					Med25519: &xdr.MuxedAccountMed25519{
						Id:      xdr.Uint64(uid),
						Ed25519: ed25519,
					},
				}

				muxedAddr, err := muxed.GetAddress()
				if err != nil {
					panic(err)
				}
				return gopter.NewGenResult(muxedAddr, result.Shrinker)
			})
		},
		reflect.TypeOf(""),
	)
}

func propMuxedRejected() gopter.Prop {
	return prop.ForAll(func(address string) bool {
		_, err := ParseAddress(address)
		return err != nil
	}, genMuxedAddress())
}

func genAccountSeedGen() gopter.Gen {
	return gen.SliceOfN(32, gen.UInt8Range(0, 255)).MapResult(func(result *gopter.GenResult) *gopter.GenResult {
		payload := result.Result.([]uint8)
		seed, err := strkey.Encode(strkey.VersionByteSeed, payload)
		if err != nil {
			panic(err)
		}
		return gopter.NewGenResult(seed, result.Shrinker)
	})
}

func propSecretSeedRejected() gopter.Prop {
	return prop.ForAll(func(seed string) bool {
		_, err := ParseAddress(seed)
		return err != nil
	}, genAccountSeedGen())
}

func genLiquidityPoolAddressGen() gopter.Gen {
	return gen.SliceOfN(32, gen.UInt8Range(0, 255)).MapResult(func(result *gopter.GenResult) *gopter.GenResult {
		payload := result.Result.([]uint8)
		address, err := strkey.Encode(strkey.VersionByteLiquidityPool, payload)
		if err != nil {
			panic(err)
		}
		return gopter.NewGenResult(address, result.Shrinker)
	})
}

func propLiquidityPoolRejected() gopter.Prop {
	return prop.ForAll(func(address string) bool {
		_, err := ParseAddress(address)
		return err != nil
	}, genLiquidityPoolAddressGen())
}

func genClaimableBalanceAddressGen() gopter.Gen {
	return gen.SliceOfN(32, gen.UInt8Range(0, 255)).MapResult(func(result *gopter.GenResult) *gopter.GenResult {
		payload := result.Result.([]uint8)
		// Claimable balance uses version byte 0x0D (13) with 33-byte payload
		fullPayload := append([]byte{0}, payload...)
		address, err := strkey.Encode(strkey.VersionByteClaimableBalance, fullPayload)
		if err != nil {
			panic(err)
		}
		return gopter.NewGenResult(address, result.Shrinker)
	})
}

func propClaimableBalanceRejected() gopter.Prop {
	return prop.ForAll(func(address string) bool {
		_, err := ParseAddress(address)
		return err != nil
	}, genClaimableBalanceAddressGen())
}

func genMalformedBase32() gopter.Gen {
	return gen.OneGenOf(
		gen.Const("not-an-address"),
		gen.Const("G!!!INVALID"),
		gen.Const("C!!!INVALID"),
		gen.RegexMatch(`[!@#$%^&*]{1,100}`),
	)
}

func propMalformedRejected() gopter.Prop {
	return prop.ForAll(func(address string) bool {
		_, err := ParseAddress(address)
		return err != nil
	}, genMalformedBase32())
}

func propCorruptedChecksumRejected() gopter.Prop {
	return prop.ForAll(func(_ struct{}) bool {
		// Generate a valid address and corrupt its checksum
		addrGen := gen.OneGenOf(genAccountAddressGen(), genContractAddressGen())
		params := gopter.DefaultGenParameters()
		result := addrGen(params)
		if result == nil {
			return false
		}
		address := result.Result.(string)
		if len(address) == 0 {
			return false
		}
		// Flip the last character to corrupt the checksum
		last := address[len(address)-1]
		var replacement byte
		if last == 'A' {
			replacement = 'B'
		} else {
			replacement = 'A'
		}
		corrupted := address[:len(address)-1] + string(replacement)
		_, err := ParseAddress(corrupted)
		return err != nil
	}, gen.Const(struct{}{}))
}

func propTruncatedRejected() gopter.Prop {
	return prop.ForAll(func(_ struct{}) bool {
		// Generate a valid address and truncate it
		addrGen := gen.OneGenOf(genAccountAddressGen(), genContractAddressGen())
		params := gopter.DefaultGenParameters()
		result := addrGen(params)
		if result == nil {
			return false
		}
		address := result.Result.(string)
		if len(address) < 3 {
			return false
		}
		// Truncate by 1-2 characters
		cut := 1
		if len(address) > 3 {
			cut = 2
		}
		truncated := address[:len(address)-cut]
		_, err := ParseAddress(truncated)
		return err != nil
	}, gen.Const(struct{}{}))
}

func propEmptyStringRejected() gopter.Prop {
	return prop.ForAll(func(_ struct{}) bool {
		_, err := ParseAddress("")
		return err != nil
	}, gen.Const(struct{}{}))
}

// propCaseAlteredRejected pins the canonicality rule from the other side: a
// valid address whose case is changed is no longer canonical base32, so
// ParseAddress must refuse it rather than recover the same key.
func propCaseAlteredRejected() gopter.Prop {
	return prop.ForAll(func(address string) bool {
		lowered := strings.ToLower(address)
		if lowered == address {
			// Nothing to alter; not a case this property speaks about.
			return true
		}
		_, err := ParseAddress(lowered)
		return err != nil
	}, gen.OneGenOf(genAccountAddressGen(), genContractAddressGen()))
}

// TestParseAddressFormatAddressDeterministic runs a deterministic subset of
// property tests using fixed seeds for CI reproducibility.
func TestParseAddressFormatAddressDeterministic(t *testing.T) {
	// Fixed seed for deterministic test runs
	seed := int64(0xDEADBEEF)

	parameters := gopter.DefaultTestParametersWithSeed(seed)
	parameters.MinSuccessfulTests = 100
	parameters.MaxSize = 50

	properties := gopter.NewProperties(parameters)

	properties.Property("account address round-trip (deterministic)", propAccountAddressRoundTrip())
	properties.Property("contract address round-trip (deterministic)", propContractAddressRoundTrip())
	properties.Property("account XDR stable (deterministic)", propAccountXDRStable())
	properties.Property("contract XDR stable (deterministic)", propContractXDRStable())
	properties.Property("muxed address rejected (deterministic)", propMuxedRejected())
	properties.Property("secret seed rejected (deterministic)", propSecretSeedRejected())
	properties.Property("liquidity pool rejected (deterministic)", propLiquidityPoolRejected())
	properties.Property("claimable balance rejected (deterministic)", propClaimableBalanceRejected())
	properties.Property("malformed base32 rejected (deterministic)", propMalformedRejected())
	properties.Property("corrupted checksum rejected (deterministic)", propCorruptedChecksumRejected())
	properties.Property("truncated address rejected (deterministic)", propTruncatedRejected())
	properties.Property("empty string rejected (deterministic)", propEmptyStringRejected())
	properties.Property("case-altered address rejected (deterministic)", propCaseAlteredRejected())

	properties.TestingRun(t, gopter.ConsoleReporter(true))
}

// TestParseAddressWithRandomXDR tests that randomly generated valid XDR
// ScAddress values round-trip through FormatAddress -> ParseAddress.
func TestParseAddressWithRandomXDR(t *testing.T) {
	for i := 0; i < 1000; i++ {
		// Randomly choose account or contract
		if randomBytes(1)[0]%2 == 0 {
			// Account
			var ed25519 xdr.Uint256
			copy(ed25519[:], randomBytes(32))
			accountID := xdr.AccountId{
				Type:    xdr.PublicKeyTypePublicKeyTypeEd25519,
				Ed25519: &ed25519,
			}
			addr := xdr.ScAddress{
				Type:      xdr.ScAddressTypeScAddressTypeAccount,
				AccountId: &accountID,
			}

			formatted, err := FormatAddress(addr)
			if err != nil {
				t.Fatalf("FormatAddress failed: %v", err)
			}

			reparsed, err := ParseAddress(formatted)
			if err != nil {
				t.Fatalf("ParseAddress failed: %v", err)
			}

			wantBytes, _ := addr.MarshalBinary()
			gotBytes, _ := reparsed.MarshalBinary()
			if !bytes.Equal(wantBytes, gotBytes) {
				t.Errorf("iteration %d: XDR mismatch\nwant %x\ngot  %x", i, wantBytes, gotBytes)
			}
		} else {
			// Contract
			var contractID xdr.ContractId
			copy(contractID[:], randomBytes(32))
			addr := xdr.ScAddress{
				Type:       xdr.ScAddressTypeScAddressTypeContract,
				ContractId: &contractID,
			}

			formatted, err := FormatAddress(addr)
			if err != nil {
				t.Fatalf("FormatAddress failed: %v", err)
			}

			reparsed, err := ParseAddress(formatted)
			if err != nil {
				t.Fatalf("ParseAddress failed: %v", err)
			}

			wantBytes, _ := addr.MarshalBinary()
			gotBytes, _ := reparsed.MarshalBinary()
			if !bytes.Equal(wantBytes, gotBytes) {
				t.Errorf("iteration %d: XDR mismatch\nwant %x\ngot  %x", i, wantBytes, gotBytes)
			}
		}
	}
}

// TestFormatAddressRejectsInvalidXDR tests that FormatAddress rejects
// ScAddress values that ParseAddress would not produce.
func TestFormatAddressRejectsInvalidXDR(t *testing.T) {
	// Muxed account
	muxedKey := xdr.Uint256(sha256.Sum256([]byte("test-muxed")))
	_, err := FormatAddress(xdr.ScAddress{
		Type: xdr.ScAddressTypeScAddressTypeMuxedAccount,
		MuxedAccount: &xdr.MuxedEd25519Account{
			Id:      1,
			Ed25519: muxedKey,
		},
	})
	if err == nil {
		t.Error("FormatAddress accepted muxed account")
	}

	// Unknown type
	_, err = FormatAddress(xdr.ScAddress{Type: xdr.ScAddressType(99)})
	if err == nil {
		t.Error("FormatAddress accepted unknown type")
	}

	// Account without ID
	_, err = FormatAddress(xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeAccount})
	if err == nil {
		t.Error("FormatAddress accepted account without ID")
	}

	// Contract without ID
	_, err = FormatAddress(xdr.ScAddress{Type: xdr.ScAddressTypeScAddressTypeContract})
	if err == nil {
		t.Error("FormatAddress accepted contract without ID")
	}
}

// Helper to generate random bytes for testing
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}
