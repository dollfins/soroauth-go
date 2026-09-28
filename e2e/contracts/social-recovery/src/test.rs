//! Unit tests for the social-recovery fixture.
//!
//! These cover constructor storage, the guardian check, the timelock rejection
//! in both directions, and that a rotation actually moves the stored signer.
//!
//! What they deliberately do not cover is `__check_auth` itself. Reaching it
//! needs a real delegates-arm authorization entry, because
//! `get_delegated_signers` panics outside an auth-check frame; that path is
//! exercised against the live host by the e2e scenarios, the same way
//! modular-account's is. The signer stored here is a contract account that
//! approves anything, which keeps these tests free of real signatures.

extern crate std;

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contractimpl,
    testutils::{Address as _, Ledger as _},
    vec, Address, Env, Vec,
};

use crate::{
    RecoveryError, SocialRecoveryAccount, SocialRecoveryAccountArgs, SocialRecoveryAccountClient,
    RECOVERY_TIMELOCK_LEDGERS,
};

/// A delegate that approves everything, so the tests can drive delegation
/// without producing real signatures.
#[contract]
pub struct AlwaysApproves;

#[contractimpl]
impl CustomAccountInterface for AlwaysApproves {
    type Signature = ();
    type Error = RecoveryError;

    fn __check_auth(
        _env: Env,
        _signature_payload: soroban_sdk::crypto::Hash<32>,
        _signature: (),
        _auth_contexts: Vec<Context>,
    ) -> Result<(), RecoveryError> {
        Ok(())
    }
}

fn setup(env: &Env) -> (Address, Address, Address, Address) {
    let signer = env.register(AlwaysApproves, ());
    let g1 = Address::generate(env);
    let g2 = Address::generate(env);
    let account = env.register(
        SocialRecoveryAccount,
        SocialRecoveryAccountArgs::__constructor(&signer, &vec![env, g1.clone(), g2.clone()]),
    );
    (account, signer, g1, g2)
}

#[test]
fn constructor_stores_signer_and_guardians() {
    let env = Env::default();
    let (account, signer, g1, g2) = setup(&env);
    let client = SocialRecoveryAccountClient::new(&env, &account);

    assert_eq!(client.signer(), signer);
    let guardians = client.guardians();
    assert_eq!(guardians.len(), 2);
    assert!(guardians.contains(&g1));
    assert!(guardians.contains(&g2));
    assert_eq!(client.pending_recovery(), None);
}

#[test]
fn a_guardian_can_start_a_recovery() {
    let env = Env::default();
    env.mock_all_auths();
    let (account, _signer, g1, _g2) = setup(&env);
    let client = SocialRecoveryAccountClient::new(&env, &account);

    let new_signer = Address::generate(&env);
    client.initiate_recovery(&g1, &new_signer);

    let (pending, apply_at) = client.pending_recovery().expect("recovery should be pending");
    assert_eq!(pending, new_signer);
    assert_eq!(apply_at, env.ledger().sequence() + RECOVERY_TIMELOCK_LEDGERS);
}

#[test]
fn a_non_guardian_cannot_start_a_recovery() {
    let env = Env::default();
    env.mock_all_auths();
    let (account, _signer, _g1, _g2) = setup(&env);
    let client = SocialRecoveryAccountClient::new(&env, &account);

    let stranger = Address::generate(&env);
    let new_signer = Address::generate(&env);

    let result = client.try_initiate_recovery(&stranger, &new_signer);
    assert_eq!(result, Err(Ok(RecoveryError::NotAGuardian)));
    assert_eq!(client.pending_recovery(), None);
}

#[test]
fn recovery_before_the_timelock_is_refused() {
    let env = Env::default();
    env.mock_all_auths();
    let (account, signer, g1, _g2) = setup(&env);
    let client = SocialRecoveryAccountClient::new(&env, &account);

    let new_signer = Address::generate(&env);
    client.initiate_recovery(&g1, &new_signer);

    let result = client.try_execute_recovery();
    assert_eq!(result, Err(Ok(RecoveryError::TimelockNotExpired)));

    // The signer must not have moved.
    assert_eq!(client.signer(), signer);
}

#[test]
fn recovery_after_the_timelock_rotates_the_signer() {
    let env = Env::default();
    env.mock_all_auths();
    let (account, signer, g1, _g2) = setup(&env);
    let client = SocialRecoveryAccountClient::new(&env, &account);

    let new_signer = Address::generate(&env);
    client.initiate_recovery(&g1, &new_signer);

    env.ledger()
        .set_sequence_number(env.ledger().sequence() + RECOVERY_TIMELOCK_LEDGERS + 1);
    client.execute_recovery();

    assert_eq!(client.signer(), new_signer);
    assert_ne!(client.signer(), signer);
    assert_eq!(client.pending_recovery(), None);
}

#[test]
fn execute_recovery_with_nothing_pending_is_refused() {
    let env = Env::default();
    env.mock_all_auths();
    let (account, _signer, _g1, _g2) = setup(&env);
    let client = SocialRecoveryAccountClient::new(&env, &account);

    assert_eq!(
        client.try_execute_recovery(),
        Err(Ok(RecoveryError::NoPendingRecovery))
    );
}
