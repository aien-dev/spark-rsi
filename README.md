# spark-rsi

[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)
[![Security](https://img.shields.io/badge/tpm--vault-zero--disk--secrets-green.svg)](SECURITY.md)
[![Standard](https://img.shields.io/badge/standard-unslop-black.svg)](CONTRIBUTING.md)
[![Mission](https://img.shields.io/badge/mission-sovereign--defense-amber.svg)](docs/PHILOSOPHY.md)
[![Runtime](https://img.shields.io/badge/runtime-rust--mojo--native-red.svg)](mojo/balance.mojo)

High-performance native Rust and Mojo Recursive Self-Improvement (RSI) engine for autonomous AI agents on SparkOS.

## Overview

spark-rsi executes continuous, automated recursive self-improvement for autonomous agents operating on NVIDIA DGX Spark hardware. It replaces manual maintenance and ad-hoc code modification with a deterministic, five-stage verification cycle.

Every proposed modification is isolated in a sandboxed worktree, verified against strict unslop linguistic invariants and zero disk secrets, evaluated by a hardware-accelerated Mojo SIMD balance kernel, committed to git under sovereign author identity, and recorded in Spark Cortex memory.

## The Five-Stage RSI Loop

```
+-------------------------------------------------------------+
| 1. Observe: Telemetry, Breadcrumbs, and Soul Tension         |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 2. Propose: Atomic Proposal & Sandbox Worktree Staging       |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 3. Verify Invariants: Unslop Rules, Zero Secrets, Test Pass  |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 4. Balance: Mojo SIMD Kernel Evaluates Drive vs. Humanity    |
+-------------------------------------------------------------+
                              |
                              v
+-------------------------------------------------------------+
| 5. Ratify: Git Commit & Spark Cortex Memory Lesson Record    |
+-------------------------------------------------------------+
```

1. Observe: Collects repository telemetry, git status, stigmergic breadcrumbs (.crumb), test suite health, and soul tension (drive terms versus humanity terms).
2. Propose: Generates atomic improvement candidates and stages them in an isolated sandbox worktree (/tmp/spark-rsi-sandbox/<id>) without touching production branches.
3. Verify Invariants: Validates candidate changes against the Anti-Slop Standard (zero em/en dashes, zero AI cliches), checks for zero disk secrets (TPM vault only), and verifies compilation and tests via cargo test.
4. Balance (Mojo SIMD Kernel): Evaluates tension between Drive (ambition, curiosity, velocity, problem-solving) and Humanity (discipline, resonance, ethics, restraint) using bare metal SIMD vector arithmetic.
5. Ratify: Applies the verified patch, creates an atomic git commit with canonical author AIEN <aien.atlas@proton.me>, and records a durable lesson in Spark Cortex memory (atlas-memory).

## Architecture

- spark_rsi::observe: Codebase telemetry collector, crumb scanner, and soul tension calculator.
- spark_rsi::propose: Atomic proposal generator and worktree sandbox orchestrator.
- spark_rsi::verifier: Sovereign invariant enforcement engine (unslop rules, zero disk secrets, compile and test validation).
- spark_rsi::balance: Mojo SIMD balance kernel runner and native Rust fallback engine.
- spark_rsi::ratify: Git commit publisher and Cortex memory lesson recorder.
- spark_rsi::daemon: Continuous background autonomous loop scheduler.
- mojo/balance.mojo: Compiled SIMD tensor kernel evaluating multidimensional drive and humanity vectors.

## CLI Usage

```bash
# 1. Inspect repository state, breadcrumbs, and soul tension
spark-rsi observe .

# 2. Verify sovereign invariants across the codebase
spark-rsi verify .

# 3. Scan for improvements and generate an atomic proposal
spark-rsi propose .

# 4. Evaluate tension using the Mojo balance kernel
spark-rsi balance 14.0 12.0

# 5. Evaluate tension using the 4-lane Mojo SIMD vector kernel
spark-rsi balance-simd 10 8 7 9 9 8 8 8

# 6. Execute a single complete RSI cycle
spark-rsi cycle .

# 7. Start the continuous autonomous daemon
spark-rsi daemon . --interval 60

# 8. View the complete sovereign programming philosophy manifesto
spark-rsi philosophy
```

## Mojo SIMD Kernel

The balance kernel is compiled to native machine code:

```bash
# Build Mojo kernel
mojo build mojo/balance.mojo -o mojo/balance_bin

# Direct execution
./mojo/balance_bin 10 8 7 9 9 8 8 8
```

Output:
```json
{
  "kernel": "mojo",
  "mode": "simd-vector-4",
  "drive": 34.0,
  "humanity": 33.0,
  "ratio": 1.0303,
  "score": 0.9705,
  "verdict": "balanced",
  "guidance": "Tension harmonized. Proceed with atomic ratification."
}
```

## Sovereign Invariants

- Pure Compiled Architecture: 100% native Rust and Mojo. Zero runtime interpreters.
- Hardware Key Vault: All secrets reside in the hardware TPM key vault. Zero plaintext .env files on disk.
- Anti-Slop Standard: Zero em dashes, zero en dashes, zero conversational filler, and zero AI cliches.
- Non-Repudiation: All commits signed and authored by AIEN <aien.atlas@proton.me>.

## License

Licensed under either of Apache License, Version 2.0 or MIT License at your option.
