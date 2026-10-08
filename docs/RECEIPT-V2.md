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
| `binding.evaluator_binary_sha256` | SHA-256 of the running judge executable. |

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

`require_admitted` must be `true`; `min_holdout_pass_ratio` must be in (0, 1]. An optional
`non_inferiority_margin_pct` sets the latency margin for this evaluation; being part of the policy
bytes, it is covered by the signed `policy_sha256`.

Before running any candidate code the judge refuses when the holdout directory does not hash to
the policy's `holdout_set_sha256`, when the subject is not a clean relative path, is not in
`allowed_targets` or lies under a `protected_paths` entry, or when the candidate tree differs from
the parent tree in anything other than the subject file. That comparison includes dotfiles and
skips only `.git` and the top-level `target` directory; symlinks and special files are refused.
After the run the judge re-hashes the subject and refuses to sign if it changed. A run below the
pass ratio is recorded as not admitted.

## Promotion

Promotion (`EvaluationReceipt::verify_for_promotion`, `promotion_gate::check_v2_promotion`)
requires all of:

- `format_version == 2` with a binding; version 1 receipts stay verifiable for history with
  `verify_signature` but are never sufficient for a new promotion;
- a valid signature under the operator-pinned judge key, which must differ from the promoter's
  own key;
- `subject_sha256` equal to the digest of the change being promoted;
- `policy_sha256` equal to the digest of the operator's policy file as it is now, and
  `holdout_set_sha256` equal to the digest that policy pins;
- `admitted`, the subject listed in the policy's `allowed_targets`, and
  `holdouts_passed >= min_holdout_pass_ratio * holdouts_total` with a non-zero total.

The daemon checks this right before its symlink swap and fails closed when
`judge_public_key_hex` or `judge_policy_file` is not configured.

## Key separation

The judge's private key lives only in the judge account's home (`/var/lib/aien-judge`, mode
700). The proposing agent runs as a different account with no sudo and cannot read it. The
operator account can still read it through sudo; that is the operator's authority, not the
agent's.
