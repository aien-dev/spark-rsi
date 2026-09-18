# Contributing to spark-rsi

We welcome contributions from sovereign systems engineers and developers passionate about autonomous agent infrastructure.

## Sovereign Principles & Invariants

All contributions must adhere to our engineering invariants:
1. Unslop Standard: Zero em dashes or en dashes. Use standard punctuation (commas, colons, parentheses, periods). Forbid AI buzzwords ("delve", "tapestry", "game-changer", "beacon").
2. Native Performance: Pure compiled native Rust and Mojo architecture. Eliminate runtime interpreter overhead.
3. Hardware Key Vault: Never commit plaintext .env files, credentials, or private keys.
4. Upstream Contribution: Public components modified to work on our stack must be contributed back upstream.

## Verification
```bash
cargo test --verbose
```
