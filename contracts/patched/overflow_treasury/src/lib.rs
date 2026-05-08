//! # Patched Overflow Treasury
//!
//! ## Fix Applied: Checked Arithmetic
//!
//! All addition and subtraction uses `checked_add` / `checked_sub`.
//! On overflow or underflow the contract panics with a descriptive message
//! rather than silently wrapping.

#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Symbol};

const TOTAL: Symbol = Symbol::short("TOTAL");

#[contract]
pub struct PatchedOverflowTreasury;

#[contractimpl]
impl PatchedOverflowTreasury {
    pub fn initialize(env: Env) {
        env.storage().persistent().set(&TOTAL, &0u64);
    }

    /// ✅ FIX: checked_add panics on overflow instead of wrapping.
    pub fn deposit(env: Env, amount: u64) {
        let bal: u64 = env.storage().persistent().get(&TOTAL).unwrap_or(0);
        let new = bal.checked_add(amount).expect("deposit overflow");
        env.storage().persistent().set(&TOTAL, &new);
    }

    /// ✅ FIX: checked_sub panics on underflow instead of wrapping.
    pub fn withdraw(env: Env, amount: u64) {
        let bal: u64 = env.storage().persistent().get(&TOTAL).unwrap_or(0);
        let new = bal.checked_sub(amount).expect("insufficient funds");
        env.storage().persistent().set(&TOTAL, &new);
    }

    pub fn balance(env: Env) -> u64 {
        env.storage().persistent().get(&TOTAL).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn normal_operations() {
        let env = Env::default();
        let id = env.register_contract(None, PatchedOverflowTreasury);
        let client = PatchedOverflowTreasuryClient::new(&env, &id);
        client.initialize();
        client.deposit(&1000);
        client.withdraw(&300);
        assert_eq!(client.balance(), 700);
    }

    #[test]
    #[should_panic(expected = "insufficient funds")]
    fn underflow_is_rejected() {
        let env = Env::default();
        let id = env.register_contract(None, PatchedOverflowTreasury);
        let client = PatchedOverflowTreasuryClient::new(&env, &id);
        client.initialize();
        client.deposit(&100);
        client.withdraw(&200); // should panic
    }

    #[test]
    #[should_panic(expected = "deposit overflow")]
    fn overflow_is_rejected() {
        let env = Env::default();
        let id = env.register_contract(None, PatchedOverflowTreasury);
        let client = PatchedOverflowTreasuryClient::new(&env, &id);
        client.initialize();
        client.deposit(&u64::MAX);
        client.deposit(&1); // now overflows: MAX + 1 wraps
    }
}
