//! # Broken Access Control
//!
//! ## Vulnerability: Missing Admin Validation / Improper Ownership Checks
//!
//! FLAW: Admin-only functions (`set_admin`, `drain_funds`) do not verify the caller
//! is the current admin. Any address can call them freely.
//!
//! ## Attack Vector
//! 1. Contract is initialized with `admin = alice`.
//! 2. Attacker calls `set_admin(attacker_address)` — no auth check, succeeds.
//! 3. Attacker is now admin and can call `drain_funds`.
//!
//! ## Fix (see contracts/patched/broken_access)
//! Read the stored admin address and call `admin.require_auth()` at the top of
//! every privileged function before performing any state changes.

#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

const ADMIN: Symbol = Symbol::short("ADMIN");
const FUNDS: Symbol = Symbol::short("FUNDS");

#[contract]
pub struct BrokenAccess;

#[contractimpl]
impl BrokenAccess {
    pub fn initialize(env: Env, admin: Address) {
        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&FUNDS, &0u64);
    }

    pub fn add_funds(env: Env, amount: u64) {
        let bal: u64 = env.storage().persistent().get(&FUNDS).unwrap_or(0);
        env.storage().persistent().set(&FUNDS, &(bal + amount));
    }

    /// ❌ VULNERABILITY: no check that caller == current admin.
    pub fn set_admin(env: Env, new_admin: Address) {
        // BUG: should call current_admin.require_auth() first
        env.storage().persistent().set(&ADMIN, &new_admin);
    }

    /// ❌ VULNERABILITY: no check that caller is admin before draining.
    pub fn drain_funds(env: Env) -> u64 {
        // BUG: should call admin.require_auth() first
        let bal: u64 = env.storage().persistent().get(&FUNDS).unwrap_or(0);
        env.storage().persistent().set(&FUNDS, &0u64);
        bal
    }

    pub fn get_admin(env: Env) -> Address {
        env.storage().persistent().get(&ADMIN).unwrap()
    }

    pub fn get_funds(env: Env) -> u64 {
        env.storage().persistent().get(&FUNDS).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    #[test]
    fn exploit_takeover_and_drain() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, BrokenAccess);
        let client = BrokenAccessClient::new(&env, &id);

        let alice = Address::generate(&env);
        let attacker = Address::generate(&env);

        client.initialize(&alice);
        client.add_funds(&5000);

        // Attacker hijacks admin — no auth required
        client.set_admin(&attacker);
        assert_eq!(client.get_admin(), attacker);

        // Attacker drains all funds
        let drained = client.drain_funds();
        assert_eq!(drained, 5000);
        assert_eq!(client.get_funds(), 0);
    }
}
