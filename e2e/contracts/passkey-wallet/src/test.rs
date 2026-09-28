//! Unit tests for the passkey wallet fixture.
//!
//! These cover what can be settled without a network: that the constructor
//! stores its credential key, that the signature ScVal encodes to the exact
//! sorted symbol-keyed map soroauth's `Secp256r1SignatureScVal` builds, that a
//! key the wallet never registered is refused, and that the P-256 verification
//! both accepts a real ES256 signature and refuses a corrupted one.
//!
//! The happy path here drives `__check_auth` through the host with a real key,
//! which means recomputing the payload the host will hand the contract — the
//! SHA-256 of the `HashIdPreimage::SorobanAuthorization` for this entry, with
//! the test environment's network id (`soroban-sdk` 27.0.6,
//! `src/testutils.rs`, `EnvTestConfig::default`). Scenario J in the live suite
//! covers the same path against a real host, where the network id is the real
//! one and nothing is recomputed by hand.

extern crate std;

use std::boxed::Box;
use std::string::{String, ToString};
use std::vec::Vec as StdVec;

use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use soroban_sdk::{
    contract, contractimpl,
    xdr::{
        self, HashIdPreimage, HashIdPreimageSorobanAuthorization, InvokeContractArgs, Limits,
        ScAddress, ScSymbol, ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry,
        SorobanAuthorizedFunction, SorobanAuthorizedInvocation, SorobanCredentials, StringM, VecM,
        WriteXdr,
    },
    Address, Bytes, BytesN, Env, IntoVal, TryFromVal, Val,
};

use crate::{PasskeySignature, PasskeyWallet, PasskeyWalletArgs, PasskeyWalletClient};

/// The nonce every entry in these tests carries. Fixed so the recomputed
/// payload is reproducible.
const NONCE: i64 = 42;

/// A fixed secret key, so a failure is reproducible. It is a test key; nothing
/// derived from it is ever funded.
const SECRET: [u8; 32] = [
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x0f,
    0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
    0x0a, 0x1b,
];

/// A contract whose operation requires the wallet's authorization, so
/// `__check_auth` is reached the way it is on-chain.
#[contract]
pub struct Protected;

#[contractimpl]
impl Protected {
    pub fn protected(_env: Env, account: Address) {
        account.require_auth();
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_slice(&SECRET).expect("the test secret is a valid P-256 scalar")
}

/// The uncompressed SEC1 encoding of a verifying key: 65 bytes, `0x04` first.
fn sec1_public_key(key: &SigningKey) -> [u8; 65] {
    let encoded = key.verifying_key().to_encoded_point(false);
    let mut bytes = [0u8; 65];
    bytes.copy_from_slice(encoded.as_bytes());
    bytes
}

fn register(env: &Env, public_key: &[u8; 65]) -> Address {
    env.register(
        PasskeyWallet,
        PasskeyWalletArgs::__constructor(&BytesN::from_array(env, public_key)),
    )
}

/// The invocation both the entry and the recomputed preimage use.
fn root_invocation(wallet: &Address, protected: &Address) -> SorobanAuthorizedInvocation {
    let protected_sc: ScAddress = protected.try_into().unwrap();
    let wallet_arg: ScVal = wallet.try_into().unwrap();
    SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
            contract_address: protected_sc,
            function_name: ScSymbol(StringM::try_from("protected").unwrap()),
            args: VecM::try_from(std::vec![wallet_arg]).unwrap(),
        }),
        sub_invocations: VecM::default(),
    }
}

/// Builds a legacy-arm entry for `wallet.protected(...)` carrying `signature`.
fn entry(
    wallet: &Address,
    protected: &Address,
    signature: ScVal,
    expiration: u32,
) -> SorobanAuthorizationEntry {
    let wallet_sc: ScAddress = wallet.try_into().unwrap();
    SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(SorobanAddressCredentials {
            address: wallet_sc,
            nonce: NONCE,
            signature_expiration_ledger: expiration,
            signature,
        }),
        root_invocation: root_invocation(wallet, protected),
    }
}

/// Recomputes the 32-byte payload the host will hand `__check_auth` for this
/// entry: SHA-256 of the legacy `HashIdPreimage::SorobanAuthorization`, using
/// the test environment's network id.
fn payload_for(env: &Env, root: &SorobanAuthorizedInvocation, expiration: u32) -> [u8; 32] {
    let preimage = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: xdr::Hash(env.ledger().network_id().to_array()),
        nonce: NONCE,
        signature_expiration_ledger: expiration,
        invocation: root.clone(),
    });
    let bytes = preimage.to_xdr(Limits::none()).unwrap();
    env.crypto()
        .sha256(&Bytes::from_slice(env, &bytes))
        .to_array()
}

/// Encodes the signature the way `soroauth.Secp256r1SignatureScVal` does.
fn signature_scval(env: &Env, public_key: &[u8; 65], signature: &[u8; 64]) -> ScVal {
    let value = PasskeySignature {
        public_key: BytesN::from_array(env, public_key),
        signature: BytesN::from_array(env, signature),
    };
    let raw: Val = value.into_val(env);
    ScVal::try_from_val(env, &raw).unwrap()
}

#[test]
fn constructor_stores_the_registered_key() {
    let env = Env::default();
    let public_key = sec1_public_key(&signing_key());

    let wallet = register(&env, &public_key);
    let client = PasskeyWalletClient::new(&env, &wallet);

    assert_eq!(client.public_key(), BytesN::from_array(&env, &public_key));
}

/// Pins the wire shape, independently of the contract's decoder.
///
/// `soroauth.Secp256r1SignatureScVal` builds this map by hand in Go. If the two
/// ever drift, the host would reject scenario J's entry with an opaque
/// `Error(Object, InvalidInput)`, so the shape is asserted here rather than
/// discovered on-chain.
#[test]
fn the_signature_encodes_to_the_sorted_symbol_map_soroauth_builds() {
    let env = Env::default();
    let public_key = sec1_public_key(&signing_key());

    let value = signature_scval(&env, &public_key, &[7u8; 64]);

    let entries = match value {
        ScVal::Map(Some(map)) => map,
        other => panic!("the signature encoded to {:?}, want an ScMap", other),
    };
    assert_eq!(entries.len(), 2, "the signature map must carry exactly two entries");

    let keys: StdVec<String> = entries
        .iter()
        .map(|pair| match &pair.key {
            ScVal::Symbol(symbol) => symbol.to_string(),
            other => panic!("signature map key {:?} is not a symbol", other),
        })
        .collect();
    // Sorted ascending, which is what the host requires of an ScMap: an
    // unsorted map fails on-chain as `Error(Object, InvalidInput)`.
    assert_eq!(keys, std::vec!["public_key".to_string(), "signature".to_string()]);

    // The public key is bytes, not a scalar: this is the SEC-1 form the host's
    // `secp256r1_verify` decodes.
    match &entries.get(0).unwrap().val {
        ScVal::Bytes(bytes) => assert_eq!(bytes.len(), 65),
        other => panic!("public_key encoded as {:?}, want 65 bytes", other),
    }
    match &entries.get(1).unwrap().val {
        ScVal::Bytes(bytes) => assert_eq!(bytes.len(), 64),
        other => panic!("signature encoded as {:?}, want 64 bytes", other),
    }
}

#[test]
fn check_auth_refuses_a_key_the_wallet_never_registered() {
    let env = Env::default();

    let registered = sec1_public_key(&signing_key());
    let wallet = register(&env, &registered);
    let protected = env.register(Protected, ());
    let expiration = env.ledger().sequence() + 1000;

    // A different, well-formed key. The wallet compares the key before it
    // verifies anything, so this is refused without any cryptography running.
    let mut stranger = registered;
    stranger[64] ^= 0x01;
    let signature = signature_scval(&env, &stranger, &[0u8; 64]);
    env.set_auths(&[entry(&wallet, &protected, signature, expiration)]);

    let client = ProtectedClient::new(&env, &protected);
    let result = client.try_protected(&wallet);

    // A failing __check_auth surfaces to the caller as (Context, InvalidAction);
    // the account's own error code is not visible from here. That the code is
    // WalletError::UnknownKey is asserted in src/lib.rs's doc and covered
    // end-to-end on the live host by the rejection scenario's error reporting;
    // what matters here is that the refusal happens before verification and is
    // reported as an account-auth failure rather than a panic.
    match result {
        Err(Ok(error)) => {
            let expected = soroban_sdk::Error::from_type_and_code(
                soroban_sdk::xdr::ScErrorType::Context,
                soroban_sdk::xdr::ScErrorCode::InvalidAction,
            );
            assert_eq!(error, expected, "an unregistered key must be refused");
        }
        other => panic!("an unregistered key was not refused as expected: {:?}", other),
    }
}

#[test]
fn check_auth_accepts_a_valid_p256_signature() {
    let env = Env::default();

    let key = signing_key();
    let public_key = sec1_public_key(&key);
    let wallet = register(&env, &public_key);
    let protected = env.register(Protected, ());
    let expiration = env.ledger().sequence() + 1000;

    let root = root_invocation(&wallet, &protected);
    let payload = payload_for(&env, &root, expiration);
    let signature: Signature = key
        .sign_prehash(&payload)
        .expect("signing a 32-byte prehash cannot fail");
    let mut raw_bytes = [0u8; 64];
    raw_bytes.copy_from_slice(&signature.to_bytes()[..]);

    env.set_auths(&[entry(
        &wallet,
        &protected,
        signature_scval(&env, &public_key, &raw_bytes),
        expiration,
    )]);

    let client = ProtectedClient::new(&env, &protected);
    client.protected(&wallet);
}

#[test]
fn check_auth_refuses_a_corrupted_p256_signature() {
    let env = Env::default();

    let key = signing_key();
    let public_key = sec1_public_key(&key);
    let wallet = register(&env, &public_key);
    let protected = env.register(Protected, ());
    let expiration = env.ledger().sequence() + 1000;

    let root = root_invocation(&wallet, &protected);
    let payload = payload_for(&env, &root, expiration);
    let signature: Signature = key.sign_prehash(&payload).unwrap();
    let mut raw_bytes = [0u8; 64];
    raw_bytes.copy_from_slice(&signature.to_bytes()[..]);

    // Flip the low bit of `s`. The scalars stay in range and the low-S form is
    // preserved (s is below n/2, so s+1 or s-1 is too), so the host parses the
    // signature and then fails to verify it — which is the case under test.
    raw_bytes[63] ^= 0x01;

    env.set_auths(&[entry(
        &wallet,
        &protected,
        signature_scval(&env, &public_key, &raw_bytes),
        expiration,
    )]);

    // A failed host verification traps the VM and propagates the host's own
    // error rather than returning to the contract, so what surfaces here is a
    // panic carrying the host's message. The live assertion on the exact
    // Crypto/InvalidInput error is scenario K in the e2e suite; this test pins
    // that the refusal happens inside secp256r1 verification and not somewhere
    // else.
    let client = ProtectedClient::new(&env, &protected);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        client.protected(&wallet);
    }));

    let payload = outcome.expect_err("a corrupted signature must not authenticate");
    let message = panic_message(&payload);
    assert!(
        message.contains("secp256r1"),
        "the refusal came from {:?}, want the host's secp256r1 verification",
        message
    );
}

/// Renders a caught panic payload as a string.
fn panic_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        return (*text).to_string();
    }
    if let Some(text) = payload.downcast_ref::<String>() {
        return text.clone();
    }
    std::format!("{:?}", payload)
}
