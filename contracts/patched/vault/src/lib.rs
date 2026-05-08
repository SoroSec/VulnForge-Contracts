//! # Patched Vault
//!
//! ## Fix Applied: Caller Authorization on Withdrawal
//!
//! `depositor.require_auth()` is called at the top of `withdraw`, ensuring
//! Soroban's auth framework verifies the transaction was signed by the depositor.
//! Subtraction is also guarded with `checked_sub` to prevent underflow.

#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

const BALANCE: Symbol = Symbol::short("BALANCE");

#[contract]
pub struct PatchedVault;

#[contractimpl]
impl PatchedVault {
    pub fn deposit(env: Env, depositor: Address, amount: u64) {
        depositor.require_auth();
        let key = (BALANCE, depositor.clone());
        let current: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&key, &current.checked_add(amount).expect("overflow"));
    }

    /// ✅ FIX: depositor must sign this transaction.
    pub fn withdraw(env: Env, depositor: Address, amount: u64) {
        // Auth check — only the depositor can withdraw their own funds.
        depositor.require_auth();

        let key = (BALANCE, depositor.clone());
        let current: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        let new_balance = current.checked_sub(amount).expect("insufficient funds");
        env.storage().persistent().set(&key, &new_balance);
    }

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
    fn owner_can_withdraw() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, PatchedVault);
        let client = PatchedVaultClient::new(&env, &id);

        let alice = Address::generate(&env);
        client.deposit(&alice, &1000);
        client.withdraw(&alice, &400);
        assert_eq!(client.balance(&alice), 600);
    }

    /// Patch validation: attacker cannot withdraw without Alice's auth.
    #[test]
    #[should_panic]
    fn attacker_cannot_withdraw() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, PatchedVault);
        let client = PatchedVaultClient::new(&env, &id);

        let alice = Address::generate(&env);
        client.deposit(&alice, &1000);

        // Clear mocked auths — attacker has no valid signature for alice.
        env.mock_auths(&[]);
        client.withdraw(&alice, &1000); // panics: alice's auth not satisfied
    }
}
