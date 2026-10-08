# Evaluation receipt, version 2

A version 2 receipt is the judge's signed statement that one exact change was evaluated against
one exact holdout set under one exact policy by one exact judge binary, with the results it
records. The invariant it serves:

> No code change may be promoted unless its exact identity matches the identity covered by a
> valid, independently signed evaluation.

Approved by the operator on 2026-10-08 (VAC mission, M5 Option 1).

## Fields

The receipt keeps every version 1 field and adds:

| Field | Meaning |
|---|---|
| `format_version` | `2`. Absent in old records, which load as `1`. |
| `binding.subject_path` | The one file the change touches, relative to the tree root. |
| `binding.subject_sha256` | SHA-256 of the exact bytes of that file as evaluated. |
| `binding.holdout_set_sha256` | Digest of the whole holdout directory (below). |
| `binding.holdouts_total` / `holdouts_passed` | Holdout counts from this run. |
| `binding.policy_sha256` | SHA-256 of the exact policy file bytes. |
| `binding.evaluator_binary_sha256` | SHA-256 of the running judge executable (the evaluator, not the candidate program). |

## Digest

`receipt_digest` is the lowercase hex SHA-256 of a sequence of fields. Each field is written as
its length in bytes (u64, little-endian) followed by the bytes. Strings are UTF-8, numbers are
little-endian, flags are one byte (0 or 1), floats are their IEEE-754 bit pattern as a u64.

1. the string `spark-rsi.evaluation-receipt.v2`
2. `cycle_id`, `candidate_id`, `parent_id`, `evaluated_at`, `evaluator_version`
3. `binding.evaluator_binary_sha256`, `binding.subject_path`, `binding.subject_sha256`,
   `binding.holdout_set_sha256`, `binding.policy_sha256` (as their hex strings)
4. `binding.holdouts_total`, `binding.holdouts_passed` (u64)
5. flags `admitted`, `passed_all_hard_invariants`, `passed_statistical_gates`
6. the number of layers (u64), then for each layer in order: `layer_name`, flag
   `is_hard_invariant`, flag `passed`, `score` (f64 bits), `summary`, the number of
   `violations` (u64), then each violation string
7. `metrics_summary`: one byte 0 if absent; otherwise one byte 1, then `latency_delta_pct`,
   `p_value`, `p95_ci_upper_degradation_pct`, `p99_ci_upper_degradation_pct`,
   `rss_growth_pct` (f64 bits) and `candidate_resident_mb` (u64)

Every field of the receipt except `receipt_digest` and `signature` is covered. The domain string
binds the format, so a version 2 digest cannot be read as version 1.

## Signature

`signature` is `tpm2-p256:` followed by the hex of a 64-byte P-256 ECDSA signature (r||s) over
the 32 raw digest bytes, the same scheme as version 1. The judge's public key is distributed out
of band as an uncompressed SEC1 point in hex (`spark-rsi-judge --public-key`). A receipt never
carries the key that verifies it.

## Holdout set digest

The judge loads the holdout directory strictly. It fails closed when the directory is missing or
empty, when an entry is anything other than a regular `.json` file (subdirectories, symlinks and
stray files are refused), when a file does not parse, when a suite has no cases, when a case has
an empty `id` or `expected_output`, or when two cases share an `id`. Nothing is skipped.

The digest is SHA-256 over length-prefixed fields: the string `spark-rsi.holdout-set.v1`, the
number of files (u64), then for each file sorted by name: the file name, then the 32 raw bytes of
SHA-256 of the file contents.

## Policy

The operator's policy file (JSON, unknown fields refused):

```json
{
  "policy_id": "vac-m5",
  "holdout_set_sha256": "<64 hex>",
  "min_holdout_pass_ratio": 1.0,
  "require_admitted": true,
  "allowed_targets": ["README.md"],
  "protected_paths": ["holdouts", "policy"]
}
```

`require_admitted` must be `true`; `min_holdout_pass_ratio` must be in (0, 1]; `allowed_targets` must name at least one file; every path in `allowed_targets` and `protected_paths` must be a clean relative path (no `.`, `..`, empty or leading `/` component), because paths are compared as strings. A ratio below 1 is recorded faithfully, but each failed holdout also fails the replay layer, so in practice any failed holdout keeps the change from being admitted. An optional
`non_inferiority_margin_pct` sets the latency margin for this evaluation; being part of the policy
bytes, it is covered by the signed `policy_sha256`.

Before running any candidate code the judge refuses when the holdout directory does not hash to
the policy's `holdout_set_sha256`, when the subject is not a clean relative path, is not in
`allowed_targets` or lies under a `protected_paths` entry, or when the candidate tree differs from
the parent tree in anything other than the subject file. That comparison includes dotfiles and
skips only `.git` and the top-level `target` directory; symlinks and special files are refused.
The program that runs the holdouts must come from the compared trees: a version 2 evaluation names its executable (`--executable`, never searched for), and either the judge builds both trees itself (`--build-release`) or the executable is a clean relative path outside `.git` and `target`, which the comparison skips. Only the root `.git` and `target` are skipped; a nested `.git` entry is refused.

Everything the judge does with candidate source runs in one bubblewrap sandbox (`isolation::sandboxed_cargo`): the release build (`--build-release`) and the correctness layer's `cargo check` and `cargo test`. The sandbox has no network and a cleared environment, the tree read-only, only a fresh target directory writable, the toolchain read-only, and nothing of the judge's home (where its key lives). Build scripts, proc macros, `include_bytes!` and the candidate's own tests run or read only inside it, and all cargo runs are `--offline --locked`, so a tree without its `Cargo.lock` fails. There is no unsandboxed fallback. The holdouts run the built binary in the existing candidate jail, which also clears the environment; that jail keeps its older fallback of running with the network when the host cannot set up a network namespace (the binary still sees nothing of the judge's home).

`parent_id` is the identity the caller passes (`--parent-id`, the commit the parent tree was checked out from); the judge signs it but does not derive it from the parent tree. The promotion gate and the INTERPLANE verifier (against the bundle's `source_pin.commit`) refuse a receipt whose parent is not the one the change applies on.

After the run the judge re-hashes the subject and refuses to sign if it changed. A run below the
pass ratio is recorded as not admitted.

## Promotion

Promotion (`EvaluationReceipt::verify_for_promotion`, `promotion_gate::check_v2_promotion`)
requires all of:

- `format_version == 2` with a binding; version 1 receipts stay verifiable for history with
  `verify_signature` but are never sufficient for a new promotion;
- a valid signature under the operator-pinned judge key, which must differ from the promoter's
  own key;
- `parent_id` equal to the parent the caller applies the change on;
- `subject_path` equal to the file the change replaces, and `subject_sha256` equal both to the digest of the change's bytes and to the digest of that file read back from the generation being promoted, right before the swap;
- `policy_sha256` equal to the digest of the operator's policy file as it is now, and
  `holdout_set_sha256` equal to the digest that policy pins;
- `admitted`, the subject listed in the policy's `allowed_targets`, and
  `holdouts_passed >= min_holdout_pass_ratio * holdouts_total` with a non-zero total.

The daemon checks this right before its symlink swap and fails closed when
`judge_public_key_hex` or `judge_policy_file` is not configured. The daemon's own cycle produces only a version 1 receipt from its in-process judge, so until an externally judged version 2 receipt is supplied to it, self-promotion by the spark-rsi daemon is refused every time. (The daemon's parent is the label it hands its own judge, and it re-reads only the subject file of the staged generation; the judge's strict tree comparison is what rules out other changed files.) That is the intended direction: promotion of an RSI change goes through the operator's approved path (the INTERPLANE M5 slice), not through the proposer's own daemon.

## Key separation

The judge's private key lives only in the judge account's home (`/var/lib/aien-judge`, mode
700). The proposing agent runs as a different account with no sudo and cannot read it. The
operator account can still read it through sudo; that is the operator's authority, not the
agent's.
