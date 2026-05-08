# Overflow Treasury — Write-up

## Vulnerability Class
Integer Overflow / Underflow (Unsafe Arithmetic)

## Description
Rust's primitive integer types wrap on overflow in `--release` builds unless
`overflow-checks = true` is set in the profile. Even with that flag, the
contract's logic is semantically wrong: it never validates that a withdrawal
amount is ≤ the current balance, so the intent is broken regardless of
compile-time checks.

## Affected Code
`contracts/vulnerable/overflow_treasury/src/lib.rs` — `deposit` and `withdraw`.

## Exploit Steps
**Underflow:** Call `withdraw(200)` when balance is 100.
- Debug build: panics (overflow-checks catches it).
- Release build without `overflow-checks`: balance wraps to `u64::MAX - 99`.

**Overflow:** Call `deposit(u64::MAX)` when balance > 0.
- Balance wraps to a small number, erasing the treasury.

## Root Cause
Plain `+` / `-` operators with no bounds validation.

## Fix
Replace with `checked_add` / `checked_sub` and `expect(...)` or return an error.
See `contracts/patched/overflow_treasury/src/lib.rs`.

## Severity
High — treasury balance can be manipulated to arbitrary values.
