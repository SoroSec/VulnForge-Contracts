//! # Vulnerable Overflow Treasury
//!
//! ## Vulnerability: Integer Overflow / Underflow (Unsafe Arithmetic)
//!
//! FLAW: All arithmetic uses plain `+` and `-` operators with no overflow checks.
//! In Rust release builds, integer overflow wraps silently (two's complement).
//! An attacker can deposit `u64::MAX` to wrap the treasury balance to 0,
//! or withdraw more than the balance to underflow to a huge number.
//!
//! ## Attack Vector
//! 1. Treasury has balance = 100.
//! 2. Attacker calls `deposit(u64::MAX)` → balance wraps to 99 (overflow).
//! 3. Or: attacker calls `withdraw(200)` when balance = 100 → underflows to u64::MAX - 99.
//!
//! ## Fix (see contracts/patched/overflow_treasury)
//! Replace `+` / `-` with `checked_add` / `checked_sub` and panic/error on None.

#![no_std]
use soroban_sdk::{contract, contractimpl, Env, Symbol};

const TOTAL: Symbol = Symbol::short("TOTAL");

#[contract]
pub struct OverflowTreasury;

#[contractimpl]
impl OverflowTreasury {
    pub fn initialize(env: Env) {
        env.storage().persistent().set(&TOTAL, &0u64);
    }

    /// ❌ VULNERABILITY: unchecked addition — wraps on overflow in release builds.
    pub fn deposit(env: Env, amount: u64) {
        let bal: u64 = env.storage().persistent().get(&TOTAL).unwrap_or(0);
        // BUG: plain `+` with no overflow guard
        env.storage().persistent().set(&TOTAL, &(bal + amount));
    }

    /// ❌ VULNERABILITY: unchecked subtraction — wraps on underflow in release builds.
    pub fn withdraw(env: Env, amount: u64) {
        let bal: u64 = env.storage().persistent().get(&TOTAL).unwrap_or(0);
        // BUG: plain `-` with no underflow guard
        env.storage().persistent().set(&TOTAL, &(bal - amount));
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
    fn test_normal_deposit_withdraw() {
        let env = Env::default();
        let id = env.register_contract(None, OverflowTreasury);
        let client = OverflowTreasuryClient::new(&env, &id);
        client.initialize();
        client.deposit(&500);
        client.withdraw(&200);
        assert_eq!(client.balance(), 300);
    }

    /// Exploit: underflow — withdraw more than the balance.
    /// In a release build this wraps to u64::MAX - delta instead of panicking.
    #[test]
    #[should_panic] // panics in debug; wraps silently in --release
    fn exploit_underflow() {
        let env = Env::default();
        let id = env.register_contract(None, OverflowTreasury);
        let client = OverflowTreasuryClient::new(&env, &id);
        client.initialize();
        client.deposit(&100);
        // Withdraw more than deposited — underflow
        client.withdraw(&200);
    }
}
