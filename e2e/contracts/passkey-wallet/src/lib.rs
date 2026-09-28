//! A passkey wallet fixture: a custom account that authenticates a P-256
//! (secp256r1 / ES256) signature over the authorization payload.
//!
//! This is TEST FIXTURE CODE. It exists so that soroauth's passkey signing path
//! can be proven against a real host on testnet (scenarios J and K), and for
//! nothing else. It is deliberately not a product: there is no policy engine,
//! no admin function, no upgradability, and no way to change the credential key
//! after construction. Do not deploy it to mainnet or treat it as a
//! smart-account starting point.
//!
//! # What this contract verifies, and what it deliberately does not
//!
//! It verifies an ES256 signature over the 32-byte `signature_payload` the host
//! hands `__check_auth` — that is, over the SHA-256 of the authorization
//! preimage, which is the digest soroauth's `SignSecp256r1` signs. The
//! signature value it decodes is the one
//! `soroauth.Secp256r1SignatureScVal` builds: a sorted symbol-keyed ScMap with
//! `public_key` (uncompressed SEC1, 65 bytes) before `signature` (raw low-S
//! `r || s`, 64 bytes).
//!
//! It does NOT implement WebAuthn assertion verification. A real passkey wallet
//! also has to bind the ceremony to the transaction — the authenticator signs
//! `authenticatorData || SHA-256(clientDataJSON)`, and `clientDataJSON` carries
//! the challenge — which needs bytes this ScMap shape does not carry. See
//! `docs/passkeys.md`, "Gaps", for what remains open there. Scenario J proves
//! that a P-256 signature soroauth produced is accepted by the live host; it
//! does not claim more than that.
#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    BytesN, Env, Vec,
};

/// How long to keep the instance alive, in ledgers. Roughly 30 days at 5
/// seconds per ledger, which comfortably outlives a test run.
const INSTANCE_TTL_THRESHOLD: u32 = 518_400;
const INSTANCE_TTL_EXTEND_TO: u32 = 518_400;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum WalletError {
    /// The public key carried in the entry is not the one this wallet
    /// registered. Contract error #1.
    UnknownKey = 1,
}

#[contracttype]
pub enum DataKey {
    PublicKey,
}

/// The signature ScVal this wallet's `__check_auth` decodes.
///
/// A `#[contracttype]` struct is an ScMap keyed by its field names in sorted
/// order, which is exactly the shape `soroauth.Secp256r1SignatureScVal` emits:
/// `public_key` before `signature`. The host refuses an unsorted ScMap with
/// `Error(Object, InvalidInput)`, so a hand-built shape fails on-chain rather
/// than here.
///
/// The public key travels in the signature rather than being assumed, which is
/// how a caller proves which credential it used; `__check_auth` compares it
/// against the registered key before verifying anything, so a caller cannot
/// substitute a key of its own.
#[contracttype]
pub struct PasskeySignature {
    pub public_key: BytesN<65>,
    pub signature: BytesN<64>,
}

#[contract]
pub struct PasskeyWallet;

#[contractimpl]
impl PasskeyWallet {
    /// Registers the P-256 credential public key this wallet authenticates.
    ///
    /// The key is fixed at construction. This is a test fixture, so there is
    /// deliberately no way to rotate it afterwards.
    pub fn __constructor(env: Env, public_key: BytesN<65>) {
        env.storage().instance().set(&DataKey::PublicKey, &public_key);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    }

    /// Returns the registered public key, so a test can confirm what was
    /// stored.
    pub fn public_key(env: Env) -> BytesN<65> {
        env.storage()
            .instance()
            .get(&DataKey::PublicKey)
            .unwrap()
    }
}

#[contractimpl]
impl CustomAccountInterface for PasskeyWallet {
    type Signature = PasskeySignature;
    type Error = WalletError;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: PasskeySignature,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), WalletError> {
        let registered = Self::public_key(env.clone());

        // Fail closed. The signature carries its own public key, so without
        // this check anyone could attach a key they control, sign with it, and
        // spend this wallet's balance. An unknown key is reported as this
        // contract's own error, before any cryptography runs.
        if signature.public_key != registered {
            return Err(WalletError::UnknownKey);
        }

        // ES256 over the payload. A signature that does not verify is not
        // returned as a contract error: the host's P-256 verification fails
        // with `Crypto` / `InvalidInput` ("failed secp256r1 verification"),
        // which traps the VM and propagates that error to the transaction's
        // caller rather than returning to this contract
        // (soroban-sdk 27.0.6, `src/env.rs`, the `reject_err` comments; the
        // host's implementation is
        // soroban-env-host 27.0.1, `src/crypto/mod.rs`,
        // `secp256r1_verify_signature`). Scenario K asserts that exact error.
        env.crypto()
            .secp256r1_verify(&registered, &signature_payload, &signature.signature);

        Ok(())
    }
}

#[cfg(test)]
mod test;
