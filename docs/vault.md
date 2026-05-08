# Vulnerable Vault — Write-up

## Vulnerability Class
Authorization Flaw / Missing Caller Verification

## Description
The `withdraw` function accepts a `depositor` address as a parameter but never
verifies that the transaction signer is that depositor. Because Soroban passes
the caller's identity separately from function arguments, an attacker can supply
any victim address as `depositor` and the contract will deduct from that balance
and pay out to the attacker.

## Affected Code
`contracts/vulnerable/vault/src/lib.rs` — `withdraw` function.

## Exploit Steps
1. Alice calls `deposit(alice, 1000)`.
2. Attacker calls `withdraw(alice, 1000)` from their own account.
3. Alice's balance drops to 0; attacker receives the funds.

## Root Cause
`depositor.require_auth()` is absent. Soroban's auth framework is opt-in —
forgetting the call means anyone can act on behalf of any address.

## Fix
Add `depositor.require_auth();` as the first line of `withdraw`.
See `contracts/patched/vault/src/lib.rs`.

## Severity
Critical — complete fund loss for any depositor.
