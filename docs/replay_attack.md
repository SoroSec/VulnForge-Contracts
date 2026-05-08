# Replay Attack — Write-up

## Vulnerability Class
Missing Replay Protection (No Nonce / No Expiry)

## Description
The `transfer` function accepts a `nonce` parameter intended to make each
invocation unique, but the contract never stores or validates it. An observer
can capture any valid call and resubmit it indefinitely.

## Affected Code
`contracts/vulnerable/replay_attack/src/lib.rs` — `transfer` function.

## Exploit Steps
1. Alice submits `transfer(alice, 100, nonce=1)` — balance drops from 300 → 200.
2. Attacker replays the same call: `transfer(alice, 100, nonce=1)` — 200 → 100.
3. Attacker replays again — 100 → 0. Alice is fully drained.

Note: `mock_all_auths` is used in tests; in a real scenario the attacker would
need Alice's signature, but the nonce flaw means one valid signature is enough
to drain the account.

## Root Cause
The nonce parameter is accepted but never written to storage, so there is no
record of which nonces have been consumed.

## Fix
Before processing, check that the nonce has not been used:
```rust
let nonce_key = (NONCE_PFX, sender.clone(), nonce);
if env.storage().persistent().has(&nonce_key) {
    panic!("nonce already used");
}
env.storage().persistent().set(&nonce_key, &true);
```
See `contracts/patched/replay_attack/src/lib.rs`.

## Severity
High — any signed transaction can be replayed to drain the sender's balance.
