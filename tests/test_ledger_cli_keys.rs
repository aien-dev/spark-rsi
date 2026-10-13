//! Signing keys stay off the command line (issue #49), and `ledger verify` names what it did not
//! check (issue #50). Pre-registered rows:
//!
//! 1. A `ledger checkpoint` key from `--signing-key-file` or `RSI_LEDGER_SIGNING_KEY` gives the
//!    same signature as the same key passed with `--signing-key-hex`.
//! 2. Precedence follows the judge: hex flag, then key file, then environment.
//! 3. A missing or empty key file is refused and never falls back to another source.
//! 4. `soak` reads its signing key from `--signing-key-file` and `RSI_SOAK_SIGNING_KEY`.
//! 5. `ledger verify` prints PASS only when the latest checkpoint covers the whole ledger and its
//!    signature was checked. Otherwise it prints PARTIAL and names the gap.

use p256::ecdsa::SigningKey;
use spark_rsi::ledger::{BlockType, ImprovementLedger, MerkleCheckpoint};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const LEDGER_ENV: &str = "RSI_LEDGER_SIGNING_KEY";
const SOAK_ENV: &str = "RSI_SOAK_SIGNING_KEY";

fn bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_spark-rsi"))
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

fn key_hex(seed: u8) -> String {
    hex::encode([seed; 32])
}

fn pub_hex(seed: u8) -> String {
    hex::encode(key(seed).verifying_key().to_sec1_point(false).as_bytes())
}

/// A ledger with three blocks after genesis.
fn ledger() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join(".rsi");
    let ledger = ImprovementLedger::open(&root).unwrap();
    for i in 1..=3 {
        ledger
            .append_block(
                BlockType::Evaluation,
                format!("{{\"eval\": {}}}", i),
                Vec::new(),
            )
            .unwrap();
    }
    (tmp, root)
}

/// `spark-rsi <args>` with no key in the environment unless the test sets one.
fn cli(args: &[&str]) -> Command {
    let mut cmd = Command::new(bin());
    cmd.args(args)
        .env_remove(LEDGER_ENV)
        .env_remove(SOAK_ENV)
        .env("RUST_LOG", "error");
    cmd
}

fn run(mut cmd: Command) -> Output {
    cmd.output().unwrap()
}

/// The checkpoint `ledger checkpoint` printed.
fn checkpoint(out: Output) -> MerkleCheckpoint {
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(
        out.status.success(),
        "checkpoint failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let json = &stdout[stdout.find("Merkle Checkpoint Created").unwrap()..];
    let json = &json[json.find('{').unwrap()..];
    serde_json::Deserializer::from_str(json)
        .into_iter::<MerkleCheckpoint>()
        .next()
        .unwrap()
        .unwrap()
}

fn write_key_file(dir: &Path, name: &str, contents: &str) -> String {
    let path = dir.join(name);
    fs::write(&path, contents).unwrap();
    path.to_str().unwrap().to_string()
}

#[test]
fn checkpoint_key_from_file_or_env_signs_like_the_hex_flag() {
    let (tmp, root) = ledger();
    let root = root.to_str().unwrap();
    let file = write_key_file(tmp.path(), "checkpoint.key", &format!("{}\n", key_hex(7)));

    let by_flag = checkpoint(run(cli(&[
        "ledger",
        "checkpoint",
        root,
        "--signing-key-hex",
        &key_hex(7),
    ])));
    let by_file = checkpoint(run(cli(&[
        "ledger",
        "checkpoint",
        root,
        "--signing-key-file",
        &file,
    ])));
    let mut env_cmd = cli(&["ledger", "checkpoint", root]);
    env_cmd.env(LEDGER_ENV, key_hex(7));
    let by_env = checkpoint(run(env_cmd));

    let flag_sig = by_flag.signature.clone().expect("hex flag signs");
    assert_eq!(by_file.signature.as_deref(), Some(flag_sig.as_str()));
    assert_eq!(by_env.signature.as_deref(), Some(flag_sig.as_str()));
    assert!(by_env.verify_signature(key(7).verifying_key()));

    let unsigned = checkpoint(run(cli(&["ledger", "checkpoint", root])));
    assert_eq!(unsigned.signature, None);
}

#[test]
fn checkpoint_key_precedence_is_flag_then_file_then_env() {
    let (tmp, root) = ledger();
    let root = root.to_str().unwrap();
    let file = write_key_file(tmp.path(), "checkpoint.key", &key_hex(2));

    let mut all_three = cli(&[
        "ledger",
        "checkpoint",
        root,
        "--signing-key-hex",
        &key_hex(1),
        "--signing-key-file",
        &file,
    ]);
    all_three.env(LEDGER_ENV, key_hex(3));
    assert!(checkpoint(run(all_three)).verify_signature(key(1).verifying_key()));

    let mut file_and_env = cli(&["ledger", "checkpoint", root, "--signing-key-file", &file]);
    file_and_env.env(LEDGER_ENV, key_hex(3));
    assert!(checkpoint(run(file_and_env)).verify_signature(key(2).verifying_key()));
}

#[test]
fn missing_or_empty_key_file_is_refused() {
    let (tmp, root) = ledger();
    let root_str = root.to_str().unwrap();
    let empty = write_key_file(tmp.path(), "empty.key", "\n");
    let missing = tmp.path().join("missing.key");

    let mut empty_cmd = cli(&[
        "ledger",
        "checkpoint",
        root_str,
        "--signing-key-file",
        &empty,
    ]);
    empty_cmd.env(LEDGER_ENV, key_hex(3));
    let out = run(empty_cmd);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("is empty"));

    let out = run(cli(&[
        "ledger",
        "checkpoint",
        root_str,
        "--signing-key-file",
        missing.to_str().unwrap(),
    ]));
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot read key file"));

    let ledger = ImprovementLedger::open(&root).unwrap();
    assert!(ledger.latest_checkpoint().unwrap().is_none());
}

#[test]
fn soak_reads_its_signing_key_from_file_and_env() {
    // A key that is not hex stops the soak at key parsing, before any cycle runs, so the error
    // shows which source the soak read.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().to_str().unwrap();
    let file = write_key_file(tmp.path(), "soak.key", "not-hex");
    let soak = |extra: &[&str], env: Option<&str>| {
        let mut args = vec!["soak", "--path", path, "--cycles", "1"];
        args.extend_from_slice(extra);
        let mut cmd = cli(&args);
        if let Some(v) = env {
            cmd.env(SOAK_ENV, v);
        }
        let out = run(cmd);
        assert!(!out.status.success());
        String::from_utf8_lossy(&out.stderr).to_string()
    };

    assert!(soak(&[], None).contains("Missing cryptographic signing key"));
    assert!(soak(&[], Some("not-hex")).contains("Invalid signing_key_hex"));
    assert!(soak(&["--signing-key-file", &file], None).contains("Invalid signing_key_hex"));
}

#[test]
fn verify_headline_names_what_was_not_checked() {
    let (_tmp, root) = ledger();
    let root_str = root.to_str().unwrap();
    let pk = pub_hex(7);
    let verify = |with_key: bool| {
        let mut args = vec!["ledger", "verify", root_str];
        if with_key {
            args.extend_from_slice(&["--verifying-key-hex", &pk]);
        }
        let out = run(cli(&args));
        assert!(out.status.success());
        let stdout = String::from_utf8(out.stdout).unwrap();
        stdout
            .lines()
            .find(|l| l.contains("Ledger Verification"))
            .unwrap()
            .to_string()
    };

    let headline = verify(false);
    assert!(headline.contains("PARTIAL"), "{headline}");
    assert!(
        headline.contains("no Merkle checkpoint is stored"),
        "{headline}"
    );

    checkpoint(run(cli(&[
        "ledger",
        "checkpoint",
        root_str,
        "--signing-key-hex",
        &key_hex(7),
    ])));
    let headline = verify(true);
    assert!(
        headline.ends_with("Ledger Verification: PASS"),
        "{headline}"
    );

    ImprovementLedger::open(&root)
        .unwrap()
        .append_block(
            BlockType::Evaluation,
            "{\"eval\": 4}".to_string(),
            Vec::new(),
        )
        .unwrap();
    let headline = verify(true);
    assert!(headline.contains("PARTIAL"), "{headline}");
    assert!(
        headline.contains("1 block(s) after checkpoint #3 are not covered by any checkpoint"),
        "{headline}"
    );
}
