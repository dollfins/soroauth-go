//! A custom account contract enforcing per-period spending limits with CAP-71 delegates.
//!
//! This is TEST FIXTURE CODE. It exists to exercise inspectable invocation arguments
//! inside __check_auth, verifying that spending limits can be enforced per rolling period.
#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    Address, Env, Symbol, TryFromVal, Vec,
};

const INSTANCE_TTL_THRESHOLD: u32 = 518_400;
const INSTANCE_TTL_EXTEND_TO: u32 = 518_400;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum PolicyAccountError {
    UnknownDelegate = 1,
    NoDelegates = 2,
    SpendingLimitExceeded = 3,
}

#[contracttype]
pub enum DataKey {
    Signers,
    Limit,
    Period,
    Spent(u64),
}

/// Which spending period a ledger falls in.
///
/// Split out of `__check_auth` so it can be unit tested: reaching
/// `__check_auth` needs a real delegates-arm authorization entry, because
/// `get_delegated_signers` panics outside an auth-check frame.
pub(crate) fn period_index(ledger: u32, period_ledgers: u32) -> u64 {
    if period_ledgers == 0 {
        // The constructor refuses a zero period, so this is unreachable
        // through the contract. Treating the whole chain as one period is
        // still the fail-closed answer: every spend counts against one
        // budget rather than dividing by zero.
        return 0;
    }
    (ledger as u64) / (period_ledgers as u64)
}

/// Decides whether `requested` more may be spent, returning the new total.
///
/// Split out for the same reason as `period_index`. The end-to-end scenario
/// that drives this decision against a live host is in e2e/.
pub(crate) fn require_within_limit(
    spent: i128,
    requested: i128,
    limit: i128,
) -> Result<i128, PolicyAccountError> {
    // checked_add rather than spent + requested: i128 addition of two
    // attacker-supplied amounts can overflow, and an overflow that wrapped
    // negative would read as comfortably under the limit.
    let total = match spent.checked_add(requested) {
        Some(total) => total,
        None => return Err(PolicyAccountError::SpendingLimitExceeded),
    };
    if total > limit {
        return Err(PolicyAccountError::SpendingLimitExceeded);
    }
    Ok(total)
}

#[contract]
pub struct PolicyAccount;

#[contractimpl]
impl PolicyAccount {
    /// Registers the signer set, the per-period limit and the period length.
    ///
    /// Panics on a period of zero, rather than deploying an account whose
    /// period arithmetic would divide by zero, and on a negative limit, which
    /// would refuse every spend including a zero one.
    pub fn __constructor(env: Env, signers: Vec<Address>, limit: i128, period_ledgers: u32) {
        assert!(period_ledgers >= 1, "period must be at least 1 ledger");
        assert!(limit >= 0, "limit must not be negative");
        env.storage().instance().set(&DataKey::Signers, &signers);
        env.storage().instance().set(&DataKey::Limit, &limit);
        env.storage().instance().set(&DataKey::Period, &period_ledgers);
        env.storage()
            .instance()
            .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    }

    pub fn signers(env: Env) -> Vec<Address> {
        env.storage()
            .instance()
            .get(&DataKey::Signers)
            .unwrap_or_else(|| Vec::new(&env))
    }

    pub fn limit(env: Env) -> i128 {
        env.storage().instance().get(&DataKey::Limit).unwrap_or(0)
    }

    pub fn period(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::Period).unwrap_or(100)
    }

    pub fn spent_in_period(env: Env, period_index: u64) -> i128 {
        env.storage()
            .instance()
            .get(&DataKey::Spent(period_index))
            .unwrap_or(0)
    }
}

#[contractimpl]
impl CustomAccountInterface for PolicyAccount {
    type Signature = ();
    type Error = PolicyAccountError;

    fn __check_auth(
        env: Env,
        _signature_payload: Hash<32>,
        _signature: (),
        auth_contexts: Vec<Context>,
    ) -> Result<(), PolicyAccountError> {
        let delegates = env.custom_account().get_delegated_signers();
        if delegates.is_empty() {
            return Err(PolicyAccountError::NoDelegates);
        }

        let registered = Self::signers(env.clone());
        for delegate in delegates.iter() {
            if !registered.contains(&delegate) {
                return Err(PolicyAccountError::UnknownDelegate);
            }
        }

        // What this entry is asking to move. The amount is read out of the
        // invocation arguments rather than from a signature, which is the
        // point of the fixture: the account decides on what is being
        // authorized, not only on who signed.
        let limit = Self::limit(env.clone());
        let period_ledgers = Self::period(env.clone());
        let period_index = period_index(env.ledger().sequence(), period_ledgers);

        let transfer = Symbol::new(&env, "transfer");
        let mut requested_amount: i128 = 0;
        for ctx in auth_contexts.iter() {
            if let Context::Contract(c) = ctx {
                // ContractContext names the function fn_name, not function
                // (soroban-sdk 27.0.6, src/auth.rs). The available fields are
                // contract, fn_name and args.
                if c.fn_name == transfer {
                    // transfer(from, to, amount): the amount is the third
                    // argument. A call shaped otherwise is not a transfer this
                    // fixture knows how to price, so it is not counted.
                    if c.args.len() >= 3 {
                        if let Ok(amount) = i128::try_from_val(&env, &c.args.get_unchecked(2)) {
                            requested_amount += amount;
                        }
                    }
                }
            }
        }

        let spent = Self::spent_in_period(env.clone(), period_index);
        if requested_amount > 0 {
            let allowed = require_within_limit(spent, requested_amount, limit)?;
            env.storage()
                .instance()
                .set(&DataKey::Spent(period_index), &allowed);
        }

        for delegate in delegates.iter() {
            env.custom_account().delegate_auth(&delegate);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test;
