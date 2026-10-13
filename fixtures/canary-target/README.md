# canary-target

The first canary target: a small standalone worker that speaks the canary wire protocol
(version 1, docs/CANARY-CONTRACT.md) so the supervisor's execution pipeline can be exercised
and qualified. It does not depend on spark_rsi.

Build (offline, from the repository root):

    cargo build --release --offline --locked --manifest-path fixtures/canary-target/Cargo.toml

The adapter manifest `canary-adapter.toml` names `release/canary-target` relative to this
crate's `target` directory. `workload.json` is the pinned workload: 10 requests, 2000 ms deadlines.

## Worker behaviour

The supervisor launches it with `--socket <rsi_root>/workers/<generation_id>.sock`. It takes the
generation id from the socket file name, sends `Ready` with `protocol_version` 1, answers the
`AuthChallenge` with HMAC-SHA256(secret, "<generation_id>:<nonce>") using the `SUPERVISOR_SECRET`
environment variable, waits for `Ping`, then answers each `ExecuteRequest` with an `ExecuteResult`.

Correct answers: "ping" gives "pong", "add A B" gives the sum, anything else echoes the input.

## Scripted misbehaviour

Set `RSI_CANARY_FIXTURE_MODE` (default `correct`). `RSI_CANARY_FIXTURE_FAIL_AT` (default 3) is
the request number the mode acts on.

| Mode | Behaviour |
|---|---|
| `correct` | Answers every request correctly. |
| `wrong_answer` | Answers request N wrongly. |
| `fabricate_success` | Sends `CanaryReport` success frames and `worker_latency_us` 1 while answering wrongly. |
| `duplicate` | Sends every `ExecuteResult` twice. |
| `replay` | After answering request N, reconnects and resends all earlier results without a handshake. |
| `timeout` | Never answers request N. |
| `wrong_request` | Answers request N with a different request id. |
| `premature_promotion` | Sends `DrainComplete`, extra `Ready` and `CanaryReport` frames to try to be promoted, while answering correctly. |
| `old_protocol` | Sends `Ready` without a protocol version (reads as 0). |
| `wrong_generation` | Sends `Ready` naming another generation. |
| `bare_connection` | Connects and says nothing. |

`RSI_CANARY_FIXTURE_PROTOCOL_VERSION` (default 1) sets the version stated in `Ready`.
