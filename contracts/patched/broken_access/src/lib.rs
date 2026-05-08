//! # Patched Broken Access Control
//!
//! ## Fix Applied: Admin Auth on Every Privileged Function
//!
//! The stored admin address is loaded and `admin.require_auth()` is called
//! before any privileged state change. Soroban's auth framework then verifies
//! the transaction was signed by that address.

#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

const ADMIN: Symbol = Symbol::short("ADMIN");
const FUNDS: Symbol = Symbol::short("FUNDS");

#[contract]
pub struct PatchedBrokenAccess;

#[contractimpl]
impl PatchedBrokenAccess {
    pub fn initialize(env: Env, admin: Address) {
        admin.require_auth();
        env.storage().persistent().set(&ADMIN, &admin);
        env.storage().persistent().set(&FUNDS, &0u64);
    }

    pub fn add_funds(env: Env, amount: u64) {
        let bal: u64 = env.storage().persistent().get(&FUNDS).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&FUNDS, &bal.checked_add(amount).expect("overflow"));
    }

    /// ✅ FIX: current admin must sign this transaction.
    pub fn set_admin(env: Env, new_admin: Address) {
        let admin: Address = env.storage().persistent().get(&ADMIN).unwrap();
        admin.require_auth();
        env.storage().persistent().set(&ADMIN, &new_admin);
    }

    /// ✅ FIX: only admin can drain funds.
    pub fn drain_funds(env: Env) -> u64 {
        let admin: Address = env.storage().persistent().get(&ADMIN).unwrap();
        admin.require_auth();
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
    fn admin_can_drain() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, PatchedBrokenAccess);
        let client = PatchedBrokenAccessClient::new(&env, &id);

        let alice = Address::generate(&env);
        client.initialize(&alice);
        client.add_funds(&5000);
        let drained = client.drain_funds();
        assert_eq!(drained, 5000);
    }

    /// Patch validation: attacker cannot call set_admin without current admin's auth.
    #[test]
    #[should_panic]
    fn attacker_cannot_set_admin() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, PatchedBrokenAccess);
        let client = PatchedBrokenAccessClient::new(&env, &id);

        let alice = Address::generate(&env);
        let attacker = Address::generate(&env);
        client.initialize(&alice);

        // Clear all mocked auths — no one is authorized now.
        // set_admin requires alice's auth, so this must fail.
        env.mock_auths(&[]);
        client.set_admin(&attacker); // panics: alice's auth not satisfied
    }
}
