# VulnForge Contracts

> **⚠️ Educational Use Only** — These contracts are **intentionally vulnerable**. Do not deploy to mainnet or use in production.

A smart contract security playground by [SoroSec](https://github.com/SoroSec) built on [Soroban](https://soroban.stellar.org/). Each contract demonstrates a real-world vulnerability alongside a patched version, so you can learn to identify, exploit, and fix common smart contract security flaws.

---

## Project Status — 30% Complete

This project is open for contributors on [Drips Network](https://drips.network). The foundation is built and all tests pass. Contributors are needed to take it to completion.

**Built (30%)**
- ✅ All 4 vulnerable contracts with intentional bugs and inline explanations
- ✅ All 4 patched contracts with fixes applied
- ✅ 15 passing tests — exploit demos, patch validation, and unit tests
- ✅ Vulnerability write-ups in `docs/`
- ✅ Shared `utils/` crate scaffold

**Open for Contributors (70%)**
- 🔲 Standalone `exploits/` scripts per vulnerability
- 🔲 Additional contracts — reentrancy, oracle manipulation, flash loan attacks
- 🔲 Cross-crate integration test harness in `tests/`
- 🔲 Richer `utils/` helpers — mock tokens, event assertions
- 🔲 Deployment guide and Soroban testnet walkthrough
- 🔲 GitHub Actions CI workflow
- 🔲 `CONTRIBUTING.md` — guide for adding new vulnerable/patched contract pairs

See [CONTRIBUTING.md](./CONTRIBUTING.md) to get started.

---

## Contracts

| Contract | Vulnerability | Status |
|---|---|---|
| Vulnerable Vault | Authorization flaw, insecure withdrawal logic | ✅ |
| Overflow Treasury | Integer overflow/underflow, unsafe arithmetic | ✅ |
| Broken Access Control | Missing admin validation, improper ownership checks | ✅ |
| Replay Attack Example | Reusable signed transaction logic | ✅ |

---

## Project Structure

```
VulnForge-Contracts/
├── contracts/
│   ├── vulnerable/          # Intentionally flawed contracts
│   │   ├── vault/
│   │   ├── overflow_treasury/
│   │   ├── broken_access/
│   │   └── replay_attack/
│   └── patched/             # Secure fixed versions
│       ├── vault/
│       ├── overflow_treasury/
│       ├── broken_access/
│       └── replay_attack/
├── exploits/                # 🔲 Exploit demonstration scripts (open for contributors)
├── tests/                   # 🔲 Cross-crate integration tests (open for contributors)
├── docs/                    # Per-vulnerability write-ups
└── utils/                   # Shared helper utilities
```

---

## Vulnerabilities Covered

### 1. Vulnerable Vault
**Flaw:** No caller authorization on `withdraw` — any address can drain the vault.  
**Attack:** Call `withdraw` from an unauthorized account.  
**Fix:** Validate `env.invoker()` against the depositor before allowing withdrawal.

### 2. Overflow Treasury
**Flaw:** Unchecked arithmetic on deposit/withdrawal amounts causes integer overflow/underflow.  
**Attack:** Deposit a value near `u64::MAX` to wrap the balance counter.  
**Fix:** Use Rust's `checked_add` / `checked_sub` and return an error on overflow.

### 3. Broken Access Control
**Flaw:** Admin functions lack ownership checks — any caller can invoke privileged operations.  
**Attack:** Call `set_admin` or `drain_funds` without being the contract owner.  
**Fix:** Store an admin address at initialization and assert it on every privileged call.

### 4. Replay Attack Example
**Flaw:** Signed transaction payloads can be resubmitted indefinitely — no nonce or expiry.  
**Attack:** Capture a valid signed message and replay it multiple times.  
**Fix:** Track used nonces in contract storage and reject duplicate submissions.

---

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (stable)
- [Soroban CLI](https://soroban.stellar.org/docs/getting-started/setup)

```bash
cargo install --locked soroban-cli
```

### Build

```bash
cargo build --release --target wasm32-unknown-unknown
```

### Test

```bash
cargo test
```

### Run Exploit Demos

```bash
cargo test exploit -- --nocapture
```

---

## Learning Path

1. Read the vulnerability write-up in `docs/<contract>/`
2. Review the vulnerable contract in `contracts/vulnerable/<contract>/`
3. Run the exploit test to see the attack succeed
4. Compare with the patched version in `contracts/patched/<contract>/`
5. Run the patch validation test to confirm the fix

---

## Contributing

Security researchers and educators are welcome to contribute. This project is funded on [Drips Network](https://drips.network) — contributors who build out the open items above are eligible for rewards.

Open an issue or PR against the [SoroSec](https://github.com/SoroSec) org.

---

## License

MIT — free to use for education, CTFs, and security research.
