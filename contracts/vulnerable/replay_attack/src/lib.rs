//! # Replay Attack Example
//!
//! ## Vulnerability: Reusable Signed Transaction Logic (No Nonce / No Expiry)
//!
//! FLAW: The contract accepts a `(sender, amount, signature_nonce)` payload and
//! processes it without recording which nonces have already been used.
//! An attacker who observes a valid submission can replay it any number of times.
//!
//! ## Attack Vector
//! 1. Alice submits a valid signed transfer of 100 tokens (nonce = 42).
//! 2. Attacker captures the call parameters.
//! 3. Attacker resubmits the exact same call — contract accepts it again.
//! 4. Repeat indefinitely to drain Alice's balance.
//!
//! ## Fix (see contracts/patched/replay_attack)
//! Store every used nonce in persistent storage. On each call, assert the nonce
//! has not been seen before, then record it.

#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

const PREFIX: Symbol = Symbol::short("BAL");

#[contract]
pub struct ReplayAttack;

#[contractimpl]
impl ReplayAttack {
    pub fn fund(env: Env, user: Address, amount: u64) {
        user.require_auth();
        let key = (PREFIX, user.clone());
        let bal: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(bal + amount));
    }

    /// ❌ VULNERABILITY: `nonce` is accepted but never stored or validated.
    /// The same (sender, amount, nonce) triple can be submitted repeatedly.
    pub fn transfer(env: Env, sender: Address, amount: u64, _nonce: u64) {
        sender.require_auth();

        // BUG: nonce is ignored — no replay protection
        let key = (PREFIX, sender.clone());
        let bal: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        // BUG: no underflow check either
        env.storage().persistent().set(&key, &(bal - amount));
    }

    pub fn balance(env: Env, user: Address) -> u64 {
        let key = (PREFIX, user);
        env.storage().persistent().get(&key).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    #[test]
    fn exploit_replay() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, ReplayAttack);
        let client = ReplayAttackClient::new(&env, &id);

        let alice = Address::generate(&env);
        client.fund(&alice, &300);
        assert_eq!(client.balance(&alice), 300);

        // First legitimate transfer
        client.transfer(&alice, &100, &1);
        assert_eq!(client.balance(&alice), 200);

        // Replay the same nonce — should be rejected but isn't
        client.transfer(&alice, &100, &1);
        assert_eq!(client.balance(&alice), 100); // replayed successfully

        // Replay again
        client.transfer(&alice, &100, &1);
        assert_eq!(client.balance(&alice), 0); // fully drained via replay
    }
}
