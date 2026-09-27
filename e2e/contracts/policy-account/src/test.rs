//! Unit tests for the policy account fixture.
//!
//! These cover constructor storage and the two decisions the fixture makes on
//! its own: which period a ledger falls in, and whether a requested amount
//! fits the period's remaining budget.
//!
//! What they deliberately do not cover is `__check_auth` itself. Reaching it
//! needs a real delegates-arm authorization entry, because
//! `get_delegated_signers` panics outside an auth-check frame; that path is
//! exercised against the live host by the e2e scenarios, the same way
//! modular-account's is. That is why the two decisions above are pure
//! functions: a failure inside `__check_auth` reaches a test harness as the
//! host's `(Context, InvalidAction)` wrapper, which is identical for every
//! arm, so the only way to prove *which* refusal happened is to test the
//! decision itself.

extern crate std;

use soroban_sdk::{testutils::Address as _, vec, Address, Env, Vec};

use crate::{period_index, require_within_limit, PolicyAccount, PolicyAccountClient,
            PolicyAccountError};

fn register_account(env: &Env, signers: Vec<Address>, limit: i128, period: u32) -> Address {
    env.register(PolicyAccount, (&signers, &limit, &period))
}

#[test]
fn constructor_stores_policy_settings() {
    let env = Env::default();
    let signer = Address::generate(&env);
    let account = register_account(&env, vec![&env, signer.clone()], 500, 200);
    let client = PolicyAccountClient::new(&env, &account);

    assert_eq!(client.limit(), 500);
    assert_eq!(client.period(), 200);
    assert_eq!(client.signers(), vec![&env, signer]);
}

#[test]
fn nothing_is_spent_before_the_first_authorization() {
    let env = Env::default();
    let signer = Address::generate(&env);
    let account = register_account(&env, vec![&env, signer], 100, 100);
    let client = PolicyAccountClient::new(&env, &account);

    assert_eq!(client.spent_in_period(&0), 0);
}

#[test]
#[should_panic(expected = "period must be at least 1 ledger")]
fn a_zero_period_is_refused() {
    let env = Env::default();
    let signer = Address::generate(&env);
    register_account(&env, vec![&env, signer], 100, 0);
}

#[test]
#[should_panic(expected = "limit must not be negative")]
fn a_negative_limit_is_refused() {
    let env = Env::default();
    let signer = Address::generate(&env);
    register_account(&env, vec![&env, signer], -1, 100);
}

#[test]
fn a_ledger_falls_in_the_period_that_contains_it() {
    assert_eq!(period_index(0, 100), 0);
    assert_eq!(period_index(99, 100), 0);
    assert_eq!(period_index(100, 100), 1);
    assert_eq!(period_index(250, 100), 2);
    // The constructor refuses a zero period, so this is only reachable by
    // calling the helper directly; it must not divide by zero.
    assert_eq!(period_index(500, 0), 0);
}

#[test]
fn a_spend_within_the_remaining_budget_is_allowed() {
    assert_eq!(require_within_limit(0, 100, 100), Ok(100));
    assert_eq!(require_within_limit(40, 60, 100), Ok(100));
    assert_eq!(require_within_limit(40, 1, 100), Ok(41));
}

#[test]
fn a_spend_over_the_remaining_budget_is_refused() {
    assert_eq!(
        require_within_limit(0, 101, 100),
        Err(PolicyAccountError::SpendingLimitExceeded)
    );
    assert_eq!(
        require_within_limit(100, 1, 100),
        Err(PolicyAccountError::SpendingLimitExceeded)
    );
}

#[test]
fn an_amount_that_would_overflow_the_tally_is_refused() {
    // Without checked_add this wraps negative and reads as under the limit.
    assert_eq!(
        require_within_limit(i128::MAX, 1, i128::MAX),
        Err(PolicyAccountError::SpendingLimitExceeded)
    );
}
