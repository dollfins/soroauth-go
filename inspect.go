package soroauth

import (
	"fmt"

	"github.com/stellar/go-stellar-sdk/xdr"
)

// Credential type names reported by Inspect. They are stable strings, safe for
// a CLI to print or a caller to switch on.
const (
	CredentialTypeSourceAccount        = "source_account"
	CredentialTypeAddress              = "address"
	CredentialTypeAddressV2            = "address_v2"
	CredentialTypeAddressWithDelegates = "address_with_delegates"
)

// SignatureShapeType identifies the category of a signature's structure best-effort.
type SignatureShapeType string

const (
	// SignatureShapePasskey represents a passkey signature shape.
	SignatureShapePasskey SignatureShapeType = "passkey"

	// SignatureShapeMap represents a map structure signature shape.
	SignatureShapeMap SignatureShapeType = "map"

	// SignatureShapeUnknown represents an unknown or uncheckable signature shape.
	SignatureShapeUnknown SignatureShapeType = "unknown"
)

// SignatureShape describes the structural shape of a signature best-effort without
// performing verification or upgrading the description into a verification verdict.
type SignatureShape struct {
	Type        SignatureShapeType `json:"type"`
	Description string             `json:"description"`
}

// DescribeSignature inspects an ScVal signature and returns its best-effort shape description.
func DescribeSignature(sig xdr.ScVal) SignatureShape {
	switch sig.Type {
	case xdr.ScValTypeScvVoid:
		return SignatureShape{
			Type:        SignatureShapeUnknown,
			Description: "void (unsigned placeholder)",
		}
	case xdr.ScValTypeScvBytes:
		if sig.Bytes != nil && *sig.Bytes != nil && len(*sig.Bytes) == 64 {
			return SignatureShape{
				Type:        SignatureShapePasskey,
				Description: "64-byte binary passkey signature",
			}
		}
		var length int
		if sig.Bytes != nil && *sig.Bytes != nil {
			length = len(*sig.Bytes)
		}
		return SignatureShape{
			Type:        SignatureShapeUnknown,
			Description: fmt.Sprintf("binary signature of length %d", length),
		}
	case xdr.ScValTypeScvMap:
		return SignatureShape{
			Type:        SignatureShapeMap,
			Description: "map structure signature",
		}
	case xdr.ScValTypeScvVec:
		return SignatureShape{
			Type:        SignatureShapeUnknown,
			Description: "vector structure signature",
		}
	default:
		return SignatureShape{
			Type:        SignatureShapeUnknown,
			Description: fmt.Sprintf("unknown scval type %v", sig.Type),
		}
	}
}

// NodeInfo describes one delegate node and everything beneath it.
type NodeInfo struct {
	Address string          `json:"address"`
	Signed  bool            `json:"signed"` // false for Void or an empty ScvVec
	Shape   *SignatureShape `json:"shape,omitempty"`
	Nested  []NodeInfo      `json:"nested,omitempty"`
}

// EntryInfo is a structural summary of an authorization entry.
type EntryInfo struct {
	CredentialType   string     `json:"credential_type"`
	AddressBound     bool       `json:"address_bound"`
	Address          string     `json:"address,omitempty"`
	Nonce            int64      `json:"nonce,omitempty"`
	ValidUntilLedger uint32     `json:"valid_until_ledger,omitempty"`
	TopLevelSigned   bool       `json:"top_level_signed"`
	Delegates        []NodeInfo `json:"delegates,omitempty"`
	RootContract     string     `json:"root_contract,omitempty"` // C… for contract-fn invocations
	RootFunction     string     `json:"root_function,omitempty"`
	SubInvocations   int        `json:"sub_invocations"` // total, recursive
}

// countSubInvocations totals every invocation beneath these nodes, at any
// depth. The root itself is not counted. depth is the current level, with the
// root's direct children at 1.
//
// The walk is bounded by MaxDecodeDepth: Inspect is pointed at entries from
// elsewhere by design, and a caller may have decoded the entry with an SDK
// default rather than DecodeAuthorizationEntry, so this recursion refuses a
// pathological tree instead of following it.
func countSubInvocations(invocations []xdr.SorobanAuthorizedInvocation, depth int) (int, error) {
	if err := checkTraversalDepth(depth); err != nil {
		return 0, err
	}
	total := 0
	for i := range invocations {
		nested, err := countSubInvocations(invocations[i].SubInvocations, depth+1)
		if err != nil {
			return 0, err
		}
		total += 1 + nested
	}
	return total, nil
}

// inspectDelegates summarises one delegates level and recurses. depth is the
// current level, with the top-level delegates at 1, and is bounded the same way
// countSubInvocations is.
func inspectDelegates(nodes []xdr.SorobanDelegateSignature, depth int) ([]NodeInfo, error) {
	if err := checkTraversalDepth(depth); err != nil {
		return nil, err
	}
	if len(nodes) == 0 {
		return nil, nil
	}
	out := make([]NodeInfo, 0, len(nodes))
	for i := range nodes {
		address, err := FormatAddress(nodes[i].Address)
		if err != nil {
			return nil, err
		}
		nested, err := inspectDelegates(nodes[i].NestedDelegates, depth+1)
		if err != nil {
			return nil, err
		}
		shape := DescribeSignature(nodes[i].Signature)
		out = append(out, NodeInfo{
			Address: address,
			Signed:  isSigned(nodes[i].Signature),
			Shape:   &shape,
			Nested:  nested,
		})
	}
	return out, nil
}

// Inspect reports the structure of an authorization entry: which credential
// arm it uses, whether its payload is address-bound, which addresses appear in
// it, which nodes are already signed, and the shape of the invocation tree.
//
// This is deliberately structural only. It reports that a call is
// transfer on some contract, not what transferring means or whether the
// arguments are reasonable. Presenting an entry to a human as "what am I
// signing" needs argument decoding, contract metadata and a threat model, and
// nothing here should be mistaken for that. What it is good for is checking
// before submission that an entry is the arm you expected, bound to the
// address you expected, and signed where you expected.
//
// Delegates are reported in stored order, which for a valid entry is ascending
// address order (CAP-71-01). Inspect does not enforce that;
// ValidateDelegateOrder does, and reporting the real order is what makes a
// mis-ordered entry visible here.
//
// Nonce and ValidUntilLedger are omitted from JSON when zero, per the field
// tags in §5.8. A zero nonce is legal, so a caller that must distinguish it
// should read the struct rather than the JSON.
//
// The delegate tree and the invocation tree are walked with MaxDecodeDepth as
// the ceiling. Inspect is pointed at entries produced elsewhere, so an entry
// nested beyond that ceiling is refused with ErrDecodeLimit rather than
// followed. To decode such an entry from base64 with the same bound, use
// DecodeAuthorizationEntry.
func Inspect(entry xdr.SorobanAuthorizationEntry) (EntryInfo, error) {
	var info EntryInfo

	switch entry.Credentials.Type {
	case xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount:
		info.CredentialType = CredentialTypeSourceAccount
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddress:
		info.CredentialType = CredentialTypeAddress
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2:
		info.CredentialType = CredentialTypeAddressV2
		info.AddressBound = true
	case xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates:
		info.CredentialType = CredentialTypeAddressWithDelegates
		info.AddressBound = true
	default:
		return EntryInfo{}, fmt.Errorf("soroauth: inspect: %w", ErrUnsupportedCredentials)
	}

	if entry.Credentials.Type != xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount {
		credentials, err := addressCredentials(entry.Credentials)
		if err != nil {
			return EntryInfo{}, fmt.Errorf("soroauth: inspect: %w", err)
		}

		address, err := FormatAddress(credentials.Address)
		if err != nil {
			return EntryInfo{}, fmt.Errorf("soroauth: inspect: %w", err)
		}
		info.Address = address
		info.Nonce = int64(credentials.Nonce)
		info.ValidUntilLedger = uint32(credentials.SignatureExpirationLedger)
		info.TopLevelSigned = isSigned(credentials.Signature)

		if entry.Credentials.Type == xdr.SorobanCredentialsTypeSorobanCredentialsAddressWithDelegates {
			delegates, err := inspectDelegates(entry.Credentials.AddressWithDelegates.Delegates, 1)
			if err != nil {
				return EntryInfo{}, fmt.Errorf("soroauth: inspect: %w", err)
			}
			info.Delegates = delegates
		}
	}

	// The root function. Only the contract-call arm names a contract and a
	// function; the create-contract arms are reported by their absence rather
	// than by inventing a name for them.
	if entry.RootInvocation.Function.Type == xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn {
		contractFn := entry.RootInvocation.Function.ContractFn
		if contractFn == nil {
			return EntryInfo{}, fmt.Errorf("soroauth: inspect: contract_fn invocation arm is empty")
		}
		contract, err := FormatAddress(contractFn.ContractAddress)
		if err != nil {
			return EntryInfo{}, fmt.Errorf("soroauth: inspect: %w", err)
		}
		info.RootContract = contract
		info.RootFunction = string(contractFn.FunctionName)
	}

	subInvocations, err := countSubInvocations(entry.RootInvocation.SubInvocations, 1)
	if err != nil {
		return EntryInfo{}, fmt.Errorf("soroauth: inspect: %w", err)
	}
	info.SubInvocations = subInvocations

	return info, nil
}
