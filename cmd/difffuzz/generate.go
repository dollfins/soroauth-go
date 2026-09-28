package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/xdr"

	soroauth "github.com/soroauth/soroauth-go"
)

// credentialArms is the set of credentials arms a case can be built on, in the
// order the generator cycles through them. Cycling rather than sampling is
// deliberate: every corpus is required to contain every arm, so a change that
// breaks one arm cannot hide behind a lucky distribution.
var credentialArms = []string{
	"source_account",
	"address",
	"address_v2",
	"address_with_delegates",
}

// passphrases is the set of network passphrases a case is bound to. Both real
// networks plus one that exists only here, because a payload that is correct
// for the two well-known passphrases could still be wrong for a passphrase
// whose bytes start or end unusually.
var passphrases = []string{
	network.TestNetworkPassphrase,
	network.PublicNetworkPassphrase,
	"soroauth differential fuzzing network",
}

// Bounds on the generated structures. Depth is capped because the point is
// coverage of the shapes the protocol defines, not of pathological nesting;
// MaxDecodeDepth in the library already refuses the latter.
const (
	maxInvocationDepth = 3
	maxScValDepth      = 3
	maxDelegateDepth   = 3
)

// functionNames are the contract function names attached to generated calls.
// They are plain identifiers so a contract-fn invocation reads like a real one.
var functionNames = []string{
	"transfer",
	"approve",
	"swap",
	"mint",
	"burn",
	"deposit",
	"withdraw",
	"set_admin",
}

// corpusCase is one generated entry and what this library derives from it. The
// field names are the ones testdata/parity-python/parity.py and
// testdata/differential/verify.mjs read, so the two verifiers need no adapter.
type corpusCase struct {
	SchemaVersion     int    `json:"schema_version"`
	Name              string `json:"name"`
	Generator         string `json:"generator"`
	Seed              uint64 `json:"seed"`
	Index             int    `json:"index"`
	CredentialArm     string `json:"credential_arm"`
	NetworkPassphrase string `json:"network_passphrase"`
	ValidUntilLedger  uint32 `json:"valid_until_ledger"`
	UnsignedEntryXDR  string `json:"unsigned_entry_xdr"`
	PreimageXDR       string `json:"preimage_xdr"`
	PayloadHex        string `json:"payload_hex"`
}

// generateCorpus writes cases entries into outDir and returns how many were
// written.
//
// The directory is removed and recreated first. A stale case lying next to the
// fresh ones is not harmless: it would be checked against a library it no
// longer describes, and the drift check could not tell the difference.
func generateCorpus(outDir string, cases int, seed uint64) (int, error) {
	if err := os.RemoveAll(outDir); err != nil {
		return 0, fmt.Errorf("clearing %s: %w", outDir, err)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return 0, fmt.Errorf("creating %s: %w", outDir, err)
	}

	rng := newPRNG(seed)
	written := 0
	for index := 0; index < cases; index++ {
		arm := credentialArms[index%len(credentialArms)]
		doc, err := buildCase(rng, seed, index, arm)
		if err != nil {
			return written, fmt.Errorf("case %d (%s): %w", index, arm, err)
		}

		encoded, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return written, fmt.Errorf("encoding case %d: %w", index, err)
		}
		encoded = append(encoded, '\n')

		path := filepath.Join(outDir, doc.Name+".json")
		if err := os.WriteFile(path, encoded, 0o644); err != nil {
			return written, fmt.Errorf("writing %s: %w", path, err)
		}
		written++
	}

	if written == 0 {
		return 0, errNoCases
	}
	return written, nil
}

// buildCase generates one entry and records the preimage and payload this
// library derives from it.
func buildCase(r *prng, seed uint64, index int, arm string) (corpusCase, error) {
	validUntil := randomValidUntil(r)
	passphrase := passphrases[r.intn(len(passphrases))]
	invocation := randomInvocation(r, 0)
	address := randomAccount(r)
	nonce := randomNonce(r)

	entry, err := buildEntry(r, arm, address, nonce, invocation, validUntil)
	if err != nil {
		return corpusCase{}, err
	}

	unsigned, err := entry.MarshalBinary()
	if err != nil {
		return corpusCase{}, fmt.Errorf("encoding the unsigned entry: %w", err)
	}

	preimageXDR, payloadHex, err := recordDerived(entry, validUntil, passphrase)
	if err != nil {
		return corpusCase{}, err
	}

	return corpusCase{
		SchemaVersion:     1,
		Name:              fmt.Sprintf("diff_%03d_%s", index, arm),
		Generator:         generatorName,
		Seed:              seed,
		Index:             index,
		CredentialArm:     arm,
		NetworkPassphrase: passphrase,
		ValidUntilLedger:  validUntil,
		UnsignedEntryXDR:  base64.StdEncoding.EncodeToString(unsigned),
		PreimageXDR:       preimageXDR,
		PayloadHex:        payloadHex,
	}, nil
}

// generatorName is stamped into every case this command writes. A frozen
// regression records the flag it was written with, so a reader can tell the two
// apart.
const generatorName = "cmd/difffuzz"

// recordDerived computes the preimage and payload this library derives from an
// entry and returns them in the encodings the corpus records: the preimage as
// base64, the payload as lowercase hex.
//
// A source-account entry has no preimage -- the transaction envelope
// authenticates it instead (CAP-46-11) -- so both values come back empty. That
// is recorded rather than skipped: the arm is still a credentials arm, and the
// verifiers must show they agree there is nothing to recompute.
func recordDerived(entry xdr.SorobanAuthorizationEntry, validUntil uint32, passphrase string) (preimageXDR, payloadHex string, err error) {
	preimage, err := soroauth.Preimage(entry, validUntil, passphrase)
	switch {
	case err == nil:
		preimageBytes, err := preimage.MarshalBinary()
		if err != nil {
			return "", "", fmt.Errorf("encoding the preimage: %w", err)
		}
		payload, err := soroauth.Payload(preimage)
		if err != nil {
			return "", "", fmt.Errorf("hashing the preimage: %w", err)
		}
		return base64.StdEncoding.EncodeToString(preimageBytes), hex.EncodeToString(payload[:]), nil
	case errors.Is(err, soroauth.ErrSourceAccountCredentials):
		return "", "", nil
	default:
		return "", "", fmt.Errorf("building the preimage: %w", err)
	}
}

// freezeCase re-records one case against this library and writes it into
// intoDir, returning the path it wrote.
//
// This is how a divergence becomes a regression vector. A fuzzing run that
// finds one hands the verifier a case file -- the entry, the parameters, and
// the payload the recording side computed -- and the case is committed under
// testdata/differential/regressions/, which the verifiers check alongside the
// swept corpus. Freezing re-derives the recorded values from the entry rather
// than trusting what the file held, so the reproducer always describes the
// entry it carries; and it pins the case against a later change of --seed,
// which would otherwise sweep it away.
//
// The name is prefixed so a frozen case is obvious among generated ones.
func freezeCase(casePath, intoDir string) (string, error) {
	raw, err := os.ReadFile(casePath)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", casePath, err)
	}

	var doc corpusCase
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&doc); err != nil {
		return "", fmt.Errorf("decoding %s: %w", casePath, err)
	}
	if doc.UnsignedEntryXDR == "" {
		return "", fmt.Errorf("%s carries no unsigned_entry_xdr to freeze", casePath)
	}

	var entry xdr.SorobanAuthorizationEntry
	if err := xdr.SafeUnmarshalBase64(doc.UnsignedEntryXDR, &entry); err != nil {
		return "", fmt.Errorf("%s: decoding the unsigned entry: %w", casePath, err)
	}

	preimageXDR, payloadHex, err := recordDerived(entry, doc.ValidUntilLedger, doc.NetworkPassphrase)
	if err != nil {
		return "", fmt.Errorf("%s: %w", casePath, err)
	}

	doc.PreimageXDR = preimageXDR
	doc.PayloadHex = payloadHex
	doc.Name = "regression_" + strings.TrimPrefix(doc.Name, "regression_")
	doc.Generator = generatorName + " --freeze"

	if err := os.MkdirAll(intoDir, 0o755); err != nil {
		return "", fmt.Errorf("creating %s: %w", intoDir, err)
	}
	encoded, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encoding the regression: %w", err)
	}
	encoded = append(encoded, '\n')

	path := filepath.Join(intoDir, doc.Name+".json")
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// buildEntry assembles an entry on the requested arm.
//
// The delegates arm is built by wrapping a legacy or V2 entry with
// soroauth.WithDelegates rather than by hand, so the corpus exercises the
// library's own wrapper: its sorting, its duplicate rejection and its
// ScvVoid top-level placeholder (CAP-71-01). Which of the two wrappable arms is
// wrapped is chosen at random, because wrapping a legacy entry changes its
// payload from ENVELOPE_TYPE_SOROBAN_AUTHORIZATION to the address-bound
// variant, and that conversion is exactly the kind of thing a differential test
// should be watching.
func buildEntry(
	r *prng,
	arm string,
	address xdr.ScAddress,
	nonce int64,
	invocation xdr.SorobanAuthorizedInvocation,
	validUntil uint32,
) (xdr.SorobanAuthorizationEntry, error) {
	entry := xdr.SorobanAuthorizationEntry{RootInvocation: invocation}
	credentials := xdr.SorobanAddressCredentials{
		Address:                   address,
		Nonce:                     xdr.Int64(nonce),
		SignatureExpirationLedger: 0,
		Signature:                 emptyVec(),
	}

	switch arm {
	case "source_account":
		entry.Credentials = xdr.SorobanCredentials{
			Type: xdr.SorobanCredentialsTypeSorobanCredentialsSourceAccount,
		}
		return entry, nil

	case "address":
		entry.Credentials = xdr.SorobanCredentials{
			Type:    xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
			Address: &credentials,
		}
		return entry, nil

	case "address_v2":
		entry.Credentials = xdr.SorobanCredentials{
			Type:      xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
			AddressV2: &credentials,
		}
		return entry, nil

	case "address_with_delegates":
		if r.intn(2) == 0 {
			entry.Credentials = xdr.SorobanCredentials{
				Type:    xdr.SorobanCredentialsTypeSorobanCredentialsAddress,
				Address: &credentials,
			}
		} else {
			entry.Credentials = xdr.SorobanCredentials{
				Type:      xdr.SorobanCredentialsTypeSorobanCredentialsAddressV2,
				AddressV2: &credentials,
			}
		}
		delegates, err := randomDelegates(r)
		if err != nil {
			return xdr.SorobanAuthorizationEntry{}, err
		}
		wrapped, err := soroauth.WithDelegates(entry, validUntil, delegates, nil)
		if err != nil {
			return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("wrapping with delegates: %w", err)
		}
		return wrapped, nil

	default:
		return xdr.SorobanAuthorizationEntry{}, fmt.Errorf("unknown credentials arm %q", arm)
	}
}

// randomDelegates builds a delegate tree of random depth and width. Each level
// is sorted and de-duplicated before it reaches WithDelegates, because the
// generator's job is to produce structurally valid entries, and a duplicate at
// one level is not valid (CAP-71-01).
func randomDelegates(r *prng) ([]soroauth.Delegate, error) {
	depth := 1 + r.intn(maxDelegateDepth)
	return randomDelegateLevel(r, depth)
}

func randomDelegateLevel(r *prng, remaining int) ([]soroauth.Delegate, error) {
	count := 1 + r.intn(3)
	delegates := make([]soroauth.Delegate, 0, count)

	// The raw 32 bytes are drawn first and used both to build the address and
	// to detect a repeat, so a level never carries the same address twice.
	// Collisions are astronomically unlikely; the loop is bounded anyway so a
	// pathological seed cannot spin here.
	seen := make(map[string]bool, count)
	for attempt := 0; attempt < count*8 && len(delegates) < count; attempt++ {
		raw := r.bytes(32)
		key := string(raw)
		if seen[key] {
			continue
		}
		seen[key] = true

		address := accountFromRaw(raw)
		// A delegate may itself be a contract; which one is drawn from the
		// generator so both address forms appear.
		if r.intn(4) == 0 {
			address = contractFromRaw(raw)
		}
		strkey, err := soroauth.FormatAddress(address)
		if err != nil {
			return nil, fmt.Errorf("formatting a generated delegate address: %w", err)
		}

		delegate := soroauth.Delegate{Address: strkey}
		if remaining > 1 && r.intn(2) == 0 {
			nested, err := randomDelegateLevel(r, remaining-1)
			if err != nil {
				return nil, err
			}
			delegate.Nested = nested
		}
		delegates = append(delegates, delegate)
	}

	return delegates, nil
}

// randomInvocation builds a call tree. One in four is a create-contract
// invocation, the other authorized-function arm; the rest are contract calls
// carrying generated arguments. Sub-invocations are added up to
// maxInvocationDepth, so the recursive part of the encoding is covered rather
// than a bare leaf.
func randomInvocation(r *prng, depth int) xdr.SorobanAuthorizedInvocation {
	if r.intn(4) == 0 {
		hash := randomHash(r)
		return xdr.SorobanAuthorizedInvocation{
			Function: xdr.SorobanAuthorizedFunction{
				Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeCreateContractHostFn,
				CreateContractHostFn: &xdr.CreateContractArgs{
					ContractIdPreimage: xdr.ContractIdPreimage{
						Type: xdr.ContractIdPreimageTypeContractIdPreimageFromAddress,
						FromAddress: &xdr.ContractIdPreimageFromAddress{
							Address: randomAccount(r),
							Salt:    randomUint256(r),
						},
					},
					Executable: xdr.ContractExecutable{
						Type:     xdr.ContractExecutableTypeContractExecutableWasm,
						WasmHash: &hash,
					},
				},
			},
		}
	}

	invocation := xdr.SorobanAuthorizedInvocation{
		Function: xdr.SorobanAuthorizedFunction{
			Type: xdr.SorobanAuthorizedFunctionTypeSorobanAuthorizedFunctionTypeContractFn,
			ContractFn: &xdr.InvokeContractArgs{
				ContractAddress: randomContract(r),
				FunctionName:    xdr.ScSymbol(functionNames[r.intn(len(functionNames))]),
				Args:            randomArgs(r),
			},
		},
	}

	if depth+1 < maxInvocationDepth {
		for i := 0; i < r.intn(3); i++ {
			invocation.SubInvocations = append(invocation.SubInvocations, randomInvocation(r, depth+1))
		}
	}
	return invocation
}

// randomArgs builds between zero and four argument values.
func randomArgs(r *prng) []xdr.ScVal {
	count := r.intn(5)
	args := make([]xdr.ScVal, 0, count)
	for i := 0; i < count; i++ {
		args = append(args, randomScVal(r, 0))
	}
	return args
}

// randomScVal builds a value from the ScVal arms the reference implementations
// all agree on. The list stops short of the internal arms (contract instances,
// ledger keys, executable tags): those never appear in a real invocation, and
// generating them would test decoders rather than the signing payload.
func randomScVal(r *prng, depth int) xdr.ScVal {
	if depth >= maxScValDepth {
		return randomLeafScVal(r)
	}
	switch r.intn(14) {
	case 12:
		count := r.intn(4)
		values := make([]xdr.ScVal, 0, count)
		for i := 0; i < count; i++ {
			values = append(values, randomScVal(r, depth+1))
		}
		return vecVal(values)
	case 13:
		count := r.intn(4)
		entries := make(xdr.ScMap, 0, count)
		for i := 0; i < count; i++ {
			// Symbol keys "k0", "k1", … are already in ascending order, so the
			// map is a valid one (a host rejects an unsorted ScMap).
			entries = append(entries, xdr.ScMapEntry{
				Key: symbolVal(fmt.Sprintf("k%d", i)),
				Val: randomScVal(r, depth+1),
			})
		}
		return mapVal(entries)
	default:
		return randomLeafScVal(r)
	}
}

func randomLeafScVal(r *prng) xdr.ScVal {
	switch r.intn(12) {
	case 0:
		return xdr.ScVal{Type: xdr.ScValTypeScvVoid}
	case 1:
		value := r.intn(2) == 1
		return xdr.ScVal{Type: xdr.ScValTypeScvBool, B: &value}
	case 2:
		value := xdr.Uint32(r.next() >> 32)
		return xdr.ScVal{Type: xdr.ScValTypeScvU32, U32: &value}
	case 3:
		value := xdr.Int32(int32(r.next() >> 32))
		return xdr.ScVal{Type: xdr.ScValTypeScvI32, I32: &value}
	case 4:
		value := xdr.Uint64(r.next())
		return xdr.ScVal{Type: xdr.ScValTypeScvU64, U64: &value}
	case 5:
		value := xdr.Int64(r.next())
		return xdr.ScVal{Type: xdr.ScValTypeScvI64, I64: &value}
	case 6:
		value := xdr.UInt128Parts{Hi: xdr.Uint64(r.next()), Lo: xdr.Uint64(r.next())}
		return xdr.ScVal{Type: xdr.ScValTypeScvU128, U128: &value}
	case 7:
		value := xdr.Int128Parts{Hi: xdr.Int64(r.next()), Lo: xdr.Uint64(r.next())}
		return xdr.ScVal{Type: xdr.ScValTypeScvI128, I128: &value}
	case 8:
		return symbolVal(functionNames[r.intn(len(functionNames))])
	case 9:
		value := xdr.ScString("soroauth differential argument")
		return xdr.ScVal{Type: xdr.ScValTypeScvString, Str: &value}
	case 10:
		value := xdr.ScBytes(r.bytes(1 + r.intn(20)))
		return xdr.ScVal{Type: xdr.ScValTypeScvBytes, Bytes: &value}
	default:
		address := randomAccount(r)
		return xdr.ScVal{Type: xdr.ScValTypeScvAddress, Address: &address}
	}
}

// randomNonce covers the interesting int64 values as well as the general case:
// both edges, zero, minus one, and an arbitrary draw. The nonce is signed on
// the wire, so sign handling is part of what the corpus checks.
func randomNonce(r *prng) int64 {
	switch r.intn(6) {
	case 0:
		return math.MaxInt64
	case 1:
		return math.MinInt64
	case 2:
		return 0
	case 3:
		return -1
	default:
		return int64(r.next())
	}
}

// randomValidUntil returns a non-zero expiration ledger. Zero is refused by
// WithDelegates and by AuthorizeEntry, and the host treats an entry whose
// expiration has passed as already expired, so it is never a valid corpus
// value. The two edges are included.
func randomValidUntil(r *prng) uint32 {
	switch r.intn(8) {
	case 0:
		return 1
	case 1:
		return math.MaxUint32
	default:
		value := uint32(r.next() >> 32)
		if value == 0 {
			value = 1
		}
		return value
	}
}

func randomAccount(r *prng) xdr.ScAddress {
	return accountFromRaw(r.bytes(32))
}

func randomContract(r *prng) xdr.ScAddress {
	return contractFromRaw(r.bytes(32))
}

func accountFromRaw(raw []byte) xdr.ScAddress {
	var id xdr.Uint256
	copy(id[:], raw)
	return xdr.ScAddress{
		Type:      xdr.ScAddressTypeScAddressTypeAccount,
		AccountId: &xdr.AccountId{Type: xdr.PublicKeyTypePublicKeyTypeEd25519, Ed25519: &id},
	}
}

func contractFromRaw(raw []byte) xdr.ScAddress {
	var id xdr.ContractId
	copy(id[:], raw)
	return xdr.ScAddress{
		Type:       xdr.ScAddressTypeScAddressTypeContract,
		ContractId: &id,
	}
}

func randomHash(r *prng) xdr.Hash {
	var hash xdr.Hash
	copy(hash[:], r.bytes(32))
	return hash
}

// randomUint256 is the salt of a from-address contract id preimage, which is a
// plain 32-byte value rather than an xdr.Hash.
func randomUint256(r *prng) xdr.Uint256 {
	var value xdr.Uint256
	copy(value[:], r.bytes(32))
	return value
}

func symbolVal(symbol string) xdr.ScVal {
	value := xdr.ScSymbol(symbol)
	return xdr.ScVal{Type: xdr.ScValTypeScvSymbol, Sym: &value}
}

func vecVal(values []xdr.ScVal) xdr.ScVal {
	vec := xdr.ScVec(values)
	pointer := &vec
	return xdr.ScVal{Type: xdr.ScValTypeScvVec, Vec: &pointer}
}

func mapVal(entries xdr.ScMap) xdr.ScVal {
	pointer := &entries
	return xdr.ScVal{Type: xdr.ScValTypeScvMap, Map: &pointer}
}

// emptyVec is the "to be filled in" placeholder simulation and the JS reference
// both use for an unsigned credential node.
func emptyVec() xdr.ScVal {
	return vecVal(nil)
}

// prng is a splitmix64 generator: the algorithm is fixed and documented
// (Sebastiano Vigna, "Further scramblings of Marsaglia's xorshift generators"),
// so the corpus it produces is reproducible by construction rather than by a
// promise about a standard library's sequence. It is emphatically not a
// cryptographic generator and must never be used as one.
type prng struct {
	state uint64
}

func newPRNG(seed uint64) *prng {
	return &prng{state: seed}
}

func (p *prng) next() uint64 {
	p.state += 0x9E3779B97F4A7C15
	z := p.state
	z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9
	z = (z ^ (z >> 27)) * 0x94D049BB133111EB
	return z ^ (z >> 31)
}

// intn returns a value in [0, n). n is always a small positive constant here.
func (p *prng) intn(n int) int {
	if n <= 0 {
		return 0
	}
	return int(p.next() % uint64(n))
}

// bytes returns n bytes drawn from the generator.
func (p *prng) bytes(n int) []byte {
	out := make([]byte, n)
	for i := 0; i < n; i += 8 {
		value := p.next()
		for j := 0; j < 8 && i+j < n; j++ {
			out[i+j] = byte(value >> (8 * j))
		}
	}
	return out
}
