# Spark RSI: Recursive Self-Improvement Engine

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Target](https://img.shields.io/badge/Target-Grace%20Blackwell%20GB10-76B900.svg)](https://www.nvidia.com)
[![Rust](https://img.shields.io/badge/Rust-1.85+-orange.svg)](https://www.rust-lang.org)
[![Mojo](https://img.shields.io/badge/Mojo-1.0.0-purple.svg)](https://modular.com)

High-performance native Rust and Mojo Recursive Self-Improvement (RSI) engine for autonomous AI agents. Designed to be completely portable and universal: any developer or organization can download, configure their operator identity, and plug in their own models via API or local Modular MAX.

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

## The 5-Phase RSI Architecture

1. **Observe**: Telemetry collection across git status, unslop violations, crumb breadcrumbs, and drive/humanity equilibrium.
2. **Propose**: Autonomous generation of atomic improvement proposals in isolated sandbox worktrees (`/tmp/spark-rsi-sandbox/`).
3. **Verify**: Strict validation enforcing the unslop standard, zero plaintext disk secrets, compilation (`cargo check`), and test suites (`cargo test`).
4. **Balance**: Mojo-compiled SIMD tensor kernel evaluating Drive vs. Humanity balance vectors on Grace Blackwell GB10 hardware.
5. **Ratify**: Applies verified patches, commits to git under your configured operator identity, and records lessons in Cortex memory.

---

## Downstream Heritage Requirement

If you branch off of, fork, or copy this repository, you must retain and include the original founding Constitution ([CONSTITUTION.md](CONSTITUTION.md)) in its entirety.

## License

Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
