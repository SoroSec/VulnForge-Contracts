//! Shared test helpers for VulnForge exploit and patch validation tests.

#![no_std]

// This crate only provides test utilities; all public items live under #[cfg(test)].
#[cfg(test)]
pub mod test_helpers {
    use soroban_sdk::testutils::Address as _;
    use soroban_sdk::{Address, Env, Vec};

    /// Generate `n` distinct test addresses.
    pub fn make_addresses(env: &Env, n: usize) -> Vec<Address> {
        let mut v = Vec::new(env);
        for _ in 0..n {
            v.push_back(Address::generate(env));
        }
        v
    }
}
