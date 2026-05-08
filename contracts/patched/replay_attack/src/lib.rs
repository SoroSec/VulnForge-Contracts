//! # Patched Replay Attack
//!
//! ## Fix Applied: Nonce Tracking in Persistent Storage
//!
//! Every nonce submitted via `transfer` is stored. If the same nonce is seen
//! again the contract panics, making replay attacks impossible.

#![no_std]
use soroban_sdk::{contract, contractimpl, Address, Env, Symbol};

const PREFIX: Symbol = Symbol::short("BAL");
const NONCE_PFX: Symbol = Symbol::short("NONCE");

#[contract]
pub struct PatchedReplayAttack;

#[contractimpl]
impl PatchedReplayAttack {
    pub fn fund(env: Env, user: Address, amount: u64) {
        user.require_auth();
        let key = (PREFIX, user.clone());
        let bal: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&key, &bal.checked_add(amount).expect("overflow"));
    }

    /// ✅ FIX: nonce is checked against storage and recorded after first use.
    pub fn transfer(env: Env, sender: Address, amount: u64, nonce: u64) {
        sender.require_auth();

        // Replay protection: reject if nonce already used.
        let nonce_key = (NONCE_PFX, sender.clone(), nonce);
        if env.storage().persistent().has(&nonce_key) {
            panic!("nonce already used");
        }
        env.storage().persistent().set(&nonce_key, &true);

        let key = (PREFIX, sender.clone());
        let bal: u64 = env.storage().persistent().get(&key).unwrap_or(0);
        env.storage()
            .persistent()
            .set(&key, &bal.checked_sub(amount).expect("insufficient funds"));
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
    fn unique_nonces_work() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, PatchedReplayAttack);
        let client = PatchedReplayAttackClient::new(&env, &id);

        let alice = Address::generate(&env);
        client.fund(&alice, &300);
        client.transfer(&alice, &100, &1);
        client.transfer(&alice, &100, &2); // different nonce — ok
        assert_eq!(client.balance(&alice), 100);
    }

    /// Patch validation: replaying nonce 1 is rejected.
    #[test]
    #[should_panic(expected = "nonce already used")]
    fn replay_is_rejected() {
        let env = Env::default();
        env.mock_all_auths();
        let id = env.register_contract(None, PatchedReplayAttack);
        let client = PatchedReplayAttackClient::new(&env, &id);

        let alice = Address::generate(&env);
        client.fund(&alice, &300);
        client.transfer(&alice, &100, &1);
        client.transfer(&alice, &100, &1); // replay — should panic
    }
}
