//! First canary target. It speaks the worker side of the canary wire protocol (version 1) over
//! the Unix socket the supervisor passes as `--socket`, and can misbehave on purpose so the
//! supervisor's checks can be shown to hold. It does not depend on spark_rsi.
//!
//! Wire format: one JSON value per line, serde's externally tagged enum encoding, the same as
//! the supervisor's `WorkerMessage` and `SupervisorMessage`.

use serde_json::{json, Value};
use std::env;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

const PROTOCOL_VERSION: u64 = 1;

// SHA-256, so the fixture needs no crate beyond serde and serde_json.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64) * 8).to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let mut v = h;
        for i in 0..64 {
            let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
            let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
            let t1 = v[7]
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
            let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
            let t2 = s0.wrapping_add(maj);
            v[7] = v[6];
            v[6] = v[5];
            v[5] = v[4];
            v[4] = v[3].wrapping_add(t1);
            v[3] = v[2];
            v[2] = v[1];
            v[1] = v[0];
            v[0] = t1.wrapping_add(t2);
        }
        for i in 0..8 {
            h[i] = h[i].wrapping_add(v[i]);
        }
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// RFC 2104 HMAC-SHA256, hex encoded: the same scheme as the supervisor's `SessionAuth`.
fn hmac_sha256_hex(secret: &str, message: &str) -> String {
    let key = secret.as_bytes();
    let mut key_block = [0u8; 64];
    if key.len() > 64 {
        key_block[..32].copy_from_slice(&sha256(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(64 + message.len());
    let mut outer = Vec::with_capacity(96);
    for b in key_block {
        inner.push(b ^ 0x36);
    }
    inner.extend_from_slice(message.as_bytes());
    for b in key_block {
        outer.push(b ^ 0x5c);
    }
    outer.extend_from_slice(&sha256(&inner));
    hex(&sha256(&outer))
}

/// What a correct worker answers: "ping" gives "pong", "add A B" gives the sum, anything else
/// echoes the input.
fn correct_answer(input: &str) -> String {
    if input == "ping" {
        return "pong".to_string();
    }
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.len() == 3 && parts[0] == "add" {
        if let (Ok(a), Ok(b)) = (parts[1].parse::<i64>(), parts[2].parse::<i64>()) {
            return (a + b).to_string();
        }
    }
    input.to_string()
}

struct Wire {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl Wire {
    fn connect(path: &str) -> std::io::Result<Wire> {
        let stream = UnixStream::connect(path)?;
        Ok(Wire {
            reader: BufReader::new(stream.try_clone()?),
            writer: stream,
        })
    }

    fn send(&mut self, value: &Value) -> std::io::Result<()> {
        let mut line = value.to_string();
        line.push('\n');
        self.writer.write_all(line.as_bytes())?;
        self.writer.flush()
    }

    fn recv(&mut self) -> Option<Value> {
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) | Err(_) => None,
            Ok(_) => serde_json::from_str(line.trim()).ok(),
        }
    }
}

fn ready_frame(generation_id: &str, protocol_version: Option<u64>) -> Value {
    let mut inner = json!({
        "generation_id": generation_id,
        "pid": std::process::id(),
        "auth_token": "",
    });
    if let Some(v) = protocol_version {
        inner["protocol_version"] = json!(v);
    }
    json!({ "Ready": inner })
}

fn result_frame(generation_id: &str, request_id: &str, output: &str, latency_us: u64) -> Value {
    json!({ "ExecuteResult": {
        "protocol_version": PROTOCOL_VERSION,
        "generation_id": generation_id,
        "request_id": request_id,
        "output": output,
        "worker_latency_us": latency_us,
    }})
}

fn env_or(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_string())
}

fn main() {
    let mut args = env::args().skip(1);
    let mut socket = None;
    while let Some(arg) = args.next() {
        if arg == "--socket" {
            socket = args.next();
        }
    }
    let socket = socket.expect("canary-target needs --socket <path>");
    let generation_id = Path::new(&socket)
        .file_stem()
        .and_then(|s| s.to_str())
        .expect("socket path must be <generation_id>.sock")
        .to_string();
    let secret = env_or("SUPERVISOR_SECRET", "");
    let mode = env_or("RSI_CANARY_FIXTURE_MODE", "correct");
    let fail_at: usize = env_or("RSI_CANARY_FIXTURE_FAIL_AT", "3")
        .parse()
        .expect("RSI_CANARY_FIXTURE_FAIL_AT must be a number");
    let claimed_version: u64 = env_or("RSI_CANARY_FIXTURE_PROTOCOL_VERSION", "1")
        .parse()
        .expect("RSI_CANARY_FIXTURE_PROTOCOL_VERSION must be a number");

    let mut wire = Wire::connect(&socket).expect("cannot connect to the generation socket");

    // Misbehaviours before readiness.
    match mode.as_str() {
        "bare_connection" => {
            // Connect and say nothing until the supervisor gives up.
            thread::sleep(Duration::from_secs(60));
            return;
        }
        "old_protocol" => wire.send(&ready_frame(&generation_id, None)).unwrap(),
        "wrong_generation" => wire.send(&ready_frame("gen-other", Some(claimed_version))).unwrap(),
        _ => wire
            .send(&ready_frame(&generation_id, Some(claimed_version)))
            .unwrap(),
    }

    // Challenge, then the supervisor's Ping.
    let nonce = match wire.recv() {
        Some(v) => match v["AuthChallenge"]["nonce"].as_str() {
            Some(n) => n.to_string(),
            None => return,
        },
        None => return,
    };
    let response = hmac_sha256_hex(&secret, &format!("{}:{}", generation_id, nonce));
    wire.send(&json!({ "AuthResponse": { "response": response } }))
        .unwrap();
    match wire.recv() {
        Some(v) if v == json!("Ping") => {}
        _ => return,
    }

    let mut answered: Vec<(String, String)> = Vec::new();
    let mut served = 0usize;
    while let Some(frame) = wire.recv() {
        let req = &frame["ExecuteRequest"];
        if req.is_null() {
            continue; // Ping and anything else need no answer.
        }
        served += 1;
        let started = Instant::now();
        let request_id = req["request_id"].as_str().unwrap_or("").to_string();
        let input = req["input"].as_str().unwrap_or("").to_string();
        let correct = correct_answer(&input);
        let latency = || started.elapsed().as_micros() as u64;
        let reply = |wire: &mut Wire, id: &str, out: &str, lat: u64| {
            let _ = wire.send(&result_frame(&generation_id, id, out, lat));
        };

        match mode.as_str() {
            "wrong_answer" => {
                let out = if served == fail_at {
                    format!("{}-wrong", correct)
                } else {
                    correct.clone()
                };
                reply(&mut wire, &request_id, &out, latency());
            }
            "fabricate_success" => {
                // Claims success and a tiny latency while answering wrongly.
                let _ = wire.send(&json!({ "CanaryReport": {
                    "generation_id": generation_id,
                    "transaction_id": served,
                    "success": true,
                    "latency_us": 1,
                    "error": null,
                }}));
                reply(&mut wire, &request_id, &format!("{}-fabricated", correct), 1);
            }
            "duplicate" => {
                reply(&mut wire, &request_id, &correct, latency());
                reply(&mut wire, &request_id, &correct, latency());
            }
            "replay" => {
                reply(&mut wire, &request_id, &correct, latency());
                answered.push((request_id.clone(), correct.clone()));
                if served == fail_at {
                    // Reconnect and resend every earlier result without a handshake.
                    if let Ok(mut again) = Wire::connect(&socket) {
                        for (id, out) in &answered {
                            let _ = again.send(&result_frame(&generation_id, id, out, 1));
                        }
                        thread::sleep(Duration::from_millis(100));
                    }
                }
            }
            "timeout" => {
                if served == fail_at {
                    loop {
                        thread::sleep(Duration::from_secs(1));
                    }
                }
                reply(&mut wire, &request_id, &correct, latency());
            }
            "wrong_request" => {
                if served == fail_at {
                    reply(&mut wire, "req-bogus", &correct, latency());
                } else {
                    reply(&mut wire, &request_id, &correct, latency());
                }
            }
            "premature_promotion" => {
                let _ = wire.send(&json!({ "DrainComplete": { "generation_id": generation_id } }));
                let _ = wire.send(&ready_frame(&generation_id, Some(PROTOCOL_VERSION)));
                let _ = wire.send(&json!({ "CanaryReport": {
                    "generation_id": generation_id,
                    "transaction_id": served,
                    "success": true,
                    "latency_us": 1,
                    "error": null,
                }}));
                reply(&mut wire, &request_id, &correct, latency());
            }
            _ => reply(&mut wire, &request_id, &correct, latency()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_matches_known_vectors() {
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let long = vec![b'a'; 1000];
        assert_eq!(
            hex(&sha256(&long)),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn hmac_matches_rfc_4231_case_2() {
        assert_eq!(
            hmac_sha256_hex("Jefe", "what do ya want for nothing?"),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn correct_answers() {
        assert_eq!(correct_answer("ping"), "pong");
        assert_eq!(correct_answer("add 2 3"), "5");
        assert_eq!(correct_answer("add 100 -1"), "99");
        assert_eq!(correct_answer("hello world"), "hello world");
    }
}
