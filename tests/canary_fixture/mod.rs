//! Builds the canary fixture crate once per test binary and hands back its executable.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/canary-target")
}

/// `cargo build --release --offline --locked --manifest-path fixtures/canary-target/Cargo.toml`,
/// run once, returning `fixtures/canary-target/target/release/canary-target`.
pub fn fixture_executable() -> &'static Path {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(|| {
        let manifest = fixture_dir().join("Cargo.toml");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let out = Command::new(cargo)
            .args([
                "build",
                "--release",
                "--offline",
                "--locked",
                "--manifest-path",
            ])
            .arg(&manifest)
            .env_remove("CARGO_TARGET_DIR")
            .output()
            .expect("cannot run cargo to build the canary fixture");
        assert!(
            out.status.success(),
            "canary fixture build failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let exe = fixture_dir().join("target/release/canary-target");
        assert!(exe.is_file(), "fixture executable missing at {:?}", exe);
        exe
    })
}
