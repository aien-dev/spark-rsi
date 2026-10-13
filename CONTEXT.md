# spark-rsi domain glossary

Vocabulary for the recursive self-improvement engine. Terms here are the canonical names; code and docs should use
them unchanged.

## Cycle and measurement

- **Cycle**: one run of the RSI pipeline over a target repository, from observation to ratification.
- **Stage**: one named step of a cycle: Observe, Propose, BuildJail, JudgeEvaluation, SupervisorCanary, CortexCommit.
- **Stage sample**: the measured duration and outcome of one stage in one completed cycle, with its workload key and
  execution-profile fingerprint.
- **Partial cycle**: a cycle that failed or was cancelled before completing. Its samples are kept but never eligible
  for ranking.
- **Workload key**: what makes two cycles comparable: target repository identity, effective execution configuration,
  model name. The target commit is provenance, not part of the key.
- **Execution-profile fingerprint**: the machine and configuration identity stamped on every sample. Samples with
  different fingerprints are never aggregated.
- **Measured**: a value derived from stage samples that meet the sufficiency rule.
- **Unavailable**: an explicit state meaning no qualifying measurement exists. Never represented by zero.
- **Declared**: a value asserted rather than measured. Not used for production ranking.
- **Cold start**: ranking when stages lack sufficient samples; uses graph topology only.
- **Bottleneck ranking**: the ordered list of stages by composite score, ties broken by stage id.

## Candidate and canary

- **Candidate**: a proposed change plus the artifact built from it in the build jail, identified by digest.
- **Generation**: one staged candidate under supervisor control, identified by generation id.
- **Canary**: the supervised trial of a generation against the canary workload.
- **Canary adapter manifest**: the declaration a target repository ships to say how its built artifact can be
  exercised as a worker. A target without one is not eligible for canary.
- **Worker**: the generation's process launched by the supervisor and spoken to over its generation socket.
- **Canary workload**: the digest-pinned set of requests, expected outcomes and deadlines the supervisor issues.
- **Request**: one challenge the supervisor sends to the worker. The supervisor records that it issued it.
- **Observation**: the supervisor's verified record of one issued request and its checked outcome, with
  supervisor-measured elapsed time. The only thing that counts toward the quota.
- **Self-report**: anything the worker says about its own success or latency. Diagnostic only.
- **Observation log**: the per-generation append-only record of observations.
- **Sealed**: an observation log closed with a final digest record and committed to the ledger.
- **Quota**: the configured minimum number of qualifying observations. Judged only by the quota validator.
- **Durable**: the state a generation reaches only after quota admission, safety envelope and the promotion gate.
- **Rollback**: returning to the parent generation on failure or insufficient evidence.

## Verification words shared with the wider AIEN system

- **Closure**: the existing dependency-graph proof check (`verify-closure`). Not about objectives.
- **Discharge**: an objective whose required outcomes all have qualifying evidence. Planned, not implemented.
- **Obligation**: one required outcome of an objective. Planned as an extended proof Gate requirement.
- **Receipt**: a signed evidence record from the proof or evaluation protocol.
- **Ledger**: this repository's hash-chained record store with signed checkpoints.
