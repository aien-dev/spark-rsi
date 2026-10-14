#!/usr/bin/env bash
# tests/gates/run.sh: the one entry point for the local verification gates of spark-rsi.
# Every step runs the SAME command as the hosted job it mirrors (.github/workflows/ci.yml,
# job "Test & Invariant Verification"). Manifests under tests/gates/ name this script plus
# one step word, so no manifest needs shell expansion (ADR 0028 P6). Observations print as
# "AIEN-OBS <name> <json>".
#
# Sibling checkout: Cargo.toml depends on ../aien-protocols/crates/* by path. The hosted job
# checks out aien-spark/aien-protocols (main) and copies it to ../aien-protocols; the local
# worker must provide the same sibling.
#
# Hosted runner configuration NOT mirrored here (needs root on the runner): apt-get install
# bubblewrap, sysctl kernel.apparmor_restrict_unprivileged_userns=0, chmod u+s /usr/bin/bwrap.
# The test step records the local state of those knobs as observations so a FAIL caused by
# the sandbox environment is visible as such.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"
step="${1:?usage: tests/gates/run.sh <step>}"
obs() { printf 'AIEN-OBS %s %s\n' "$1" "$2"; }
need_protocols() {
  if [ ! -d ../aien-protocols/crates ]; then
    echo "run.sh: ../aien-protocols is missing; the hosted job checks out aien-dev/aien-protocols as a sibling" >&2
    exit 3
  fi
  obs sibling_protocols_commit "\"$(git -C ../aien-protocols rev-parse HEAD 2>/dev/null || echo unknown)\""
}

case "$step" in
  crumb-verify)
    "${CRUMB:-crumb}" verify .
    ;;
  fmt)
    need_protocols
    cargo fmt --all -- --check
    ;;
  check)
    need_protocols
    cargo check --locked --all-targets
    ;;
  test)
    need_protocols
    obs bwrap_present "$(command -v bwrap >/dev/null && echo true || echo false)"
    obs apparmor_restrict_userns "\"$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo unknown)\""
    obs bwrap_setuid "$( [ -u /usr/bin/bwrap ] && echo true || echo false)"
    # Hosted step "Pre-populate Build Jail Target Cache", then "Run Tests".
    CARGO_TARGET_DIR=/tmp/spark-rsi-target cargo build --locked --release
    obs prepopulate_rc 0
    # The judge unit tests locate the built binary at target/debug/spark-rsi relative to
    # the repo root (hosted layout, no CARGO_TARGET_DIR). A relocated target dir makes
    # them panic with "Test executable not found", so the test step always uses the
    # in-tree target/ (gitignored) exactly like the hosted runner.
    env -u CARGO_TARGET_DIR cargo test --locked --verbose -- --test-threads=1
    ;;
  zero-disk-secrets)
    # Not a hosted step in this repository; the same invariant the sibling repos enforce.
    echo "Auditing repository for prohibited plaintext secret files..."
    if find . -maxdepth 4 -name ".env*" -not -path "*/.git/*" -not -path "*/target/*" | grep -q .; then
      echo "::error::Prohibited plaintext .env file found. Use an approved AIEN SecretProvider."
      obs env_files_found true
      exit 1
    fi
    obs env_files_found false
    echo "Zero plaintext .env files verified."
    ;;
  *)
    echo "run.sh: unknown step '$step'" >&2
    exit 2
    ;;
esac
