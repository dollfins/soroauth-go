//! A custom account whose guardians can rotate its signing key after a
//! timelock.
//!
//! This is TEST FIXTURE CODE. It exists so that key rotation and the timelock
//! rejection can be proven against a real host on testnet, and for nothing
//! else. It is deliberately not a product: no policies, no admin functions, no
//! upgradability, and no way to change the guardian set after construction. Do
//! not deploy it to mainnet or treat it as a smart-account starting point.
//!
//! ## How it authenticates
//!
//! The account carries no signature of its own. Its `__check_auth` reads the
//! delegated signers attached to the authorization entry, refuses any that is
//! not the account's current signer, and otherwise forwards authentication to
//! it with `delegate_auth` — the CAP-71-01 flow, the same shape
//! `modular-account` and `threshold-account` use.
//!
//! That is what makes rotation observable: after `execute_recovery` swaps the
//! stored signer, an entry delegating to the *old* signer stops authenticating
//! and one delegating to the new signer starts.
//!
//! ## Recovery
//!
//! Any registered guardian may start a recovery, naming the signer to move to.
//! The change only applies once `RECOVERY_TIMELOCK_LEDGERS` have passed, which
//! is the window in which the current key holder could intervene. There is
//! deliberately no cancel function; this is a fixture, and the timelock
//! rejection is the behaviour under test.
#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    Address, Env, Vec,
};

/// Ledgers that must pass between starting and executing a recovery. Short,
/// because the e2e test has to wait it out.
const RECOVERY_TIMELOCK_LEDGERS: u32 = 10;

const INSTANCE_TTL_THRESHOLD: u32 = 518_400;
const INSTANCE_TTL_EXTEND_TO: u32 = 518_400;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum RecoveryError {
    /// A delegate was attached that is not this account's current signer.
    UnknownSigner = 1,
    /// No delegates were attached at all.
    NoDelegates = 2,
    /// Recovery was started by an address that is not a registered guardian.
    NotAGuardian = 3,
    /// execute_recovery was called with no recovery in progress.
    NoPendingRecovery = 4,
    /// execute_recovery was called before the timelock elapsed.
    TimelockNotExpired = 5,
}

#[contracttype]
pub enum DataKey {
    Signer,
    Guardians,
    PendingSigner,
    RecoveryLedger,
}

#[contract]
pub struct SocialRecoveryAccount;

#[contractimpl]
impl SocialRecoveryAccount {
    /// Registers the initial signer and the guardian set. Both are fixed at
    /// construction apart from the signer, which recovery can rotate.
    pub fn __constructor(env: Env, signer: Address, guardians: Vec<Address>) {
        env.storage().instance().set(&DataKey::Signer, &signer);
        env.storage().instance().set(&DataKey::Guardians, &guardians);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    }

    /// The signer that currently authenticates for this account.
    pub fn signer(env: Env) -> Address {
        env.storage().instance().get(&DataKey::Signer).unwrap()
    }

    /// The registered guardians.
    pub fn guardians(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Guardians)
            .unwrap_or_else(|| Vec::new(&env))
    }

    /// The pending signer and the ledger at which it may be applied, if a
    /// recovery is in progress.
    pub fn pending_recovery(env: Env) -> Option<(Address, u32)> {
        let pending: Option<Address> = env.storage().instance().get(&DataKey::PendingSigner);
        let at: Option<u32> = env.storage().instance().get(&DataKey::RecoveryLedger);
        match (pending, at) {
            (Some(p), Some(a)) => Some((p, a)),
            _ => None,
        }
    }

    /// Starts a recovery. Only a registered guardian may call this, and the
    /// guardian must authorize the call itself.
    pub fn initiate_recovery(
        env: Env,
        guardian: Address,
        new_signer: Address,
    ) -> Result<(), RecoveryError> {
        guardian.require_auth();

        if !Self::guardians(env.clone()).contains(&guardian) {
            return Err(RecoveryError::NotAGuardian);
        }

        let apply_at = env.ledger().sequence() + RECOVERY_TIMELOCK_LEDGERS;
        env.storage()
            .instance()
            .set(&DataKey::PendingSigner, &new_signer);
        env.storage()
            .instance()
            .set(&DataKey::RecoveryLedger, &apply_at);
        Ok(())
    }

    /// Applies a pending recovery once its timelock has elapsed. Deliberately
    /// callable by anyone: the guardian authorization happened at
    /// initiate_recovery, and the timelock is what protects the window.
    pub fn execute_recovery(env: Env) -> Result<(), RecoveryError> {
        let (pending, apply_at) = match Self::pending_recovery(env.clone()) {
            Some(v) => v,
            None => return Err(RecoveryError::NoPendingRecovery),
        };

        if env.ledger().sequence() < apply_at {
            return Err(RecoveryError::TimelockNotExpired);
        }

        env.storage().instance().set(&DataKey::Signer, &pending);
        env.storage().instance().remove(&DataKey::PendingSigner);
        env.storage().instance().remove(&DataKey::RecoveryLedger);
        Ok(())
    }
}

#[contractimpl]
impl CustomAccountInterface for SocialRecoveryAccount {
    /// The account verifies no signature of its own. Authentication comes
    /// entirely from the delegate it forwards to.
    type Signature = ();
    type Error = RecoveryError;

    fn __check_auth(
        env: Env,
        _signature_payload: Hash<32>,
        _signature: (),
        _auth_contexts: Vec<Context>,
    ) -> Result<(), RecoveryError> {
        let delegates = env.custom_account().get_delegated_signers();

        // Fail closed. With no delegates nothing is authenticating this
        // account, and returning Ok would authorize on the strength of nobody.
        if delegates.is_empty() {
            return Err(RecoveryError::NoDelegates);
        }

        let signer = Self::signer(env.clone());

        // Validate every delegate before forwarding any authorization, so an
        // unrecognised one is always reported as UnknownSigner rather than
        // reached after a partial delegation.
        for delegate in delegates.iter() {
            if delegate != signer {
                return Err(RecoveryError::UnknownSigner);
            }
        }

        for delegate in delegates.iter() {
            env.custom_account().delegate_auth(&delegate);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test;
