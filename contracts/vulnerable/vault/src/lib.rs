//! # Vulnerable Vault
//!
//! ## Vulnerability: Authorization Flaw + Insecure Withdrawal Logic
//!
//! FLAW: The `withdraw` function does NOT check who is calling it.
//! Any address can call `withdraw(depositor)` and drain that depositor's balance.
//!
//! ## Attack Vector
//! 1. Alice deposits 1000 tokens — her balance is stored under her address.
//! 2. Attacker calls `withdraw(alice_address)` from their own account.
//! 3. The contract pays out to the *caller* (attacker) without verifying identity.
//!
//! ## Fix (see contracts/patched/vault)
//! Require `env.current_contract_address()` caller == depositor, or use
//! `depositor.require_auth()` so Soroban's auth framework enforces the check.

#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

const BALANCE: Symbol = Symbol::short("BALANCE");

#[contract]
pub struct VulnerableVault;

#[contractimpl]
impl VulnerableVault {
    /// Store tokens for `depositor`. In a real contract a token transfer would
    /// happen here; for simplicity we just record the amount.
    pub fn deposit(env: Env, depositor: Address, amount: u64) {
        // ✅ Auth is required on deposit so only the owner can deposit for themselves.
        depositor.require_auth();

        let key = (BALANCE, depositor.clone());
        let current: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage().persistent().set(&key, &(current + amount));
    }

    /// ❌ VULNERABILITY: No auth check — anyone can withdraw on behalf of any depositor.
    /// The payout goes to `env.invoker()` (the actual caller), not the depositor.
    pub fn withdraw(env: Env, depositor: Address, amount: u64) {
        // BUG: depositor.require_auth() is intentionally MISSING here.

        let key = (BALANCE, depositor.clone());
        let current: u64 = env.storage().persistent().get(&key).unwrap_or(0);

        // BUG: No check that current >= amount — underflow possible in debug builds.
        let new_balance = current - amount;
        env.storage().persistent().set(&key, &new_balance);

        // In a real contract: transfer `amount` tokens to env.invoker() here.
        // The attacker receives the funds, not the depositor.
    }

    /// Read the stored balance for any address.
    pub fn balance(env: Env, depositor: Address) -> u64 {
        let key = (BALANCE, depositor);
        env.storage().persistent().get(&key).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::Env;

    #[test]
    fn test_deposit_and_balance() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, VulnerableVault);
        let client = VulnerableVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        client.deposit(&alice, &500);
        assert_eq!(client.balance(&alice), 500);
    }

    /// Exploit test: attacker drains Alice's balance without her authorization.
    #[test]
    fn exploit_unauthorized_withdrawal() {
        let env = Env::default();
        env.mock_all_auths();
        let contract_id = env.register_contract(None, VulnerableVault);
        let client = VulnerableVaultClient::new(&env, &contract_id);

        let alice = Address::generate(&env);
        let _attacker = Address::generate(&env);

        client.deposit(&alice, &1000);
        assert_eq!(client.balance(&alice), 1000);

        // Attacker calls withdraw specifying Alice as the depositor — succeeds!
        client.withdraw(&alice, &1000);
        assert_eq!(client.balance(&alice), 0); // Alice's funds are gone.
    }
}
