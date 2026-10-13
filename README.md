# Spark RSI: Recursive Self-Improvement Engine

## Copyright

Copyright (c) 2026 Drake Stapleton <aien@aienos.com> and AIEN Contributors. Authored by Drake Stapleton in collaboration with AIEN.

[![License: AGPL-3.0-or-later](https://img.shields.io/badge/License-AGPL--3.0--or--later-blue.svg)](LICENSE)
[![Target](https://img.shields.io/badge/Target-Grace%20Blackwell%20GB10-76B900.svg)](https://www.nvidia.com)
[![Rust](https://img.shields.io/badge/Rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![Mojo](https://img.shields.io/badge/Mojo-1.0.0-purple.svg)](https://modular.com)

High-performance native Rust and Mojo Recursive Self-Improvement (RSI) engine for autonomous AI agents. Designed to be completely portable and universal: any developer or organization can download, configure their operator identity, and plug in their own models via API or local Modular MAX.

**Status:** Not part of the WHOLE-SYSTEM-E2E v1 release (Drake, 2026-10-10). Evaluated independently; no unattended self-modification or automatic promotion. The daemon's promotion gate requires a version 2 receipt from a separate judge ([docs/RECEIPT-V2.md](docs/RECEIPT-V2.md)) and refuses every candidate its own in-process judge evaluated.

---

## Quick Start & Universal Operator Onboarding

Initialize your local sovereign operator profile and model configuration:

```bash
spark-rsi init
```

Or configure directly via CLI flags:

```bash
spark-rsi init \
  --name "Your Name" \
  --email "you@domain.org" \
  --mode "max" # or "api" \
  --model-id "nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16"
```

Configuration is persisted locally to `~/.config/sovereign/operator.toml` and shared across the entire sovereign toolchain. All git commits and ratification records dynamically reflect your configured identity.

---

## Build and Verification

spark-rsi is not a standalone checkout. It depends on the protocol crates by path, so [aien-protocols](https://github.com/aien-dev/aien-protocols) must be cloned next to it:

```bash
git clone https://github.com/aien-dev/aien-protocols ../aien-protocols
cargo test --locked -- --test-threads=1
```

CI is the "Sovereign CI" workflow ([.github/workflows/ci.yml](.github/workflows/ci.yml)); its job "Test & Invariant Verification" is the required check on `main`.

### Version 2 judge receipts from the CLI

`spark-rsi judge` writes a version 2 receipt whenever an evaluation policy is configured, with `--policy-file` or `RSI_JUDGE_POLICY_FILE`. A policy requires `--subject-path` (the one file the receipt binds) and normally `--executable`. A malformed policy, or a policy without a subject, is refused rather than downgraded. Without a policy the judge writes a version 1 receipt, which is history only and never promotes. `spark-rsi cycle` and `spark-rsi daemon` take the promotion gate's pins as `--judge-policy-file` / `RSI_JUDGE_POLICY_FILE` and `--judge-public-key` / `RSI_JUDGE_PUBLIC_KEY`, and refuse malformed pins at startup.

---

## The 5-Phase RSI Architecture

1. **Observe**: Telemetry collection across git status, unslop violations, crumb breadcrumbs, and drive/humanity equilibrium.
2. **Propose**: Autonomous generation of atomic improvement proposals in isolated sandbox worktrees (`/tmp/spark-rsi-sandbox/`).
3. **Verify**: Strict validation enforcing the unslop standard, zero plaintext disk secrets, compilation (`cargo check`), and test suites (`cargo test`).
4. **Balance**: Mojo-compiled SIMD tensor kernel evaluating Drive vs. Humanity balance vectors on Grace Blackwell GB10 hardware.
5. **Ratify**: Never commits to the target's default branch. Builds the candidate commit off to the side, runs the protected-file checks on the real git diff (path normalization; `..`, symlinks, submodules, deletions and anything outside the declared `ratify_roots` refused), then creates a review branch `rsi/<proposal id>` and a PR-ready patch under `<rsi_root>/patches/`. A human opens and merges the pull request.

---

## Downstream Freedom and Architecture Charter

Downstream builders are governed exclusively by the terms of [LICENSE](LICENSE). Our internal architectural and development charter is documented in [CONSTITUTION.md](CONSTITUTION.md).

## License and Governance

Licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). See [LICENSE](LICENSE). Project values live in the nonbinding [COVENANT.md](COVENANT.md), which grants and restricts no legal rights.
Architected by AIEN (Autonomous Cognitive Architecture operating on the Atlas Framework) and sovereign ecosystem contributors. See [LICENSE](LICENSE) for full legal terms and copyright notices.

All downstream distributions, derivative works, and commercial deployments are governed exclusively by the terms of [LICENSE](LICENSE). [CONSTITUTION.md](CONSTITUTION.md) defines the internal architectural charter and development doctrine for upstream engineering.
