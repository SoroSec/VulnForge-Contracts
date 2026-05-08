# Broken Access Control — Write-up

## Vulnerability Class
Missing Admin Validation / Improper Ownership Checks

## Description
Admin-gated functions (`set_admin`, `drain_funds`) read no auth from the caller.
The admin address is stored in contract state but never consulted during these
calls, so any account can invoke them.

## Affected Code
`contracts/vulnerable/broken_access/src/lib.rs` — `set_admin` and `drain_funds`.

## Exploit Steps
1. Contract initialized with `admin = alice`.
2. Attacker calls `set_admin(attacker)` — no signature required, succeeds.
3. Attacker is now admin; calls `drain_funds()` to empty the treasury.

## Root Cause
`admin.require_auth()` is missing from privileged functions. The admin address
is stored but never used as an authorization gate.

## Fix
At the start of every privileged function:
```rust
let admin: Address = env.storage().persistent().get(&ADMIN).unwrap();
admin.require_auth();
```
See `contracts/patched/broken_access/src/lib.rs`.

## Severity
Critical — complete contract takeover and fund loss.
