//! The canary adapter manifest: what a target repository ships to declare how its built
//! artifact can be exercised as a worker. A target without one is not eligible for canary and
//! fails closed. The manifest names the executable and arguments; it never names the workload
//! content or any passing criterion, which belong to the operator's pinned workload.

use super::{sha256_hex, ADAPTER_MANIFEST_VERSION, CANARY_PROTOCOL_VERSION};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// File name at the root of the target repository (and so of the evaluated tree).
pub const ADAPTER_MANIFEST_FILE: &str = "canary-adapter.toml";
/// The only response format of protocol version 1: the worker answers with UTF-8 text that
/// must equal the expected output byte for byte.
pub const RESPONSE_FORMAT_UTF8_EXACT: &str = "utf8-exact";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanaryAdapterManifest {
    pub manifest_version: u16,
    pub protocol_version: u16,
    /// Path of the executable relative to the build output root the engine passes. Never
    /// absolute, never climbing.
    pub executable: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Must equal the `workload_id` of the operator's pinned workload.
    pub workload_id: String,
    pub response_format: String,
}

/// A manifest read from a tree together with the digest of its exact bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedAdapterManifest {
    pub manifest: CanaryAdapterManifest,
    pub digest: String,
    pub path: PathBuf,
}

impl CanaryAdapterManifest {
    pub fn parse(text: &str) -> Result<Self, String> {
        let manifest: Self = toml::from_str(text)
            .map_err(|e| format!("canary adapter manifest does not parse: {}", e))?;
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.manifest_version != ADAPTER_MANIFEST_VERSION {
            return Err(format!(
                "canary adapter manifest version {} is not supported (expected {})",
                self.manifest_version, ADAPTER_MANIFEST_VERSION
            ));
        }
        if self.protocol_version != CANARY_PROTOCOL_VERSION {
            return Err(format!(
                "canary adapter protocol version {} is not supported (expected {})",
                self.protocol_version, CANARY_PROTOCOL_VERSION
            ));
        }
        validate_relative_executable(&self.executable)?;
        for arg in &self.args {
            if arg.contains('\0') {
                return Err("canary adapter argument contains NUL".to_string());
            }
        }
        if self.workload_id.trim().is_empty() || self.workload_id.chars().any(char::is_control) {
            return Err("canary adapter workload id is required and must be printable".to_string());
        }
        if self.response_format != RESPONSE_FORMAT_UTF8_EXACT {
            return Err(format!(
                "canary adapter response format {:?} is not supported (expected {:?})",
                self.response_format, RESPONSE_FORMAT_UTF8_EXACT
            ));
        }
        Ok(())
    }

    /// Whether `tree_root` declares an adapter at all. Declared is not the same as valid.
    pub fn is_declared(tree_root: &Path) -> bool {
        tree_root.join(ADAPTER_MANIFEST_FILE).is_file()
    }

    /// Reads and validates the manifest at the root of `tree_root`. A missing manifest is an
    /// error: the target is not eligible for canary.
    pub fn load_from_tree(tree_root: &Path) -> Result<LoadedAdapterManifest, String> {
        let path = tree_root.join(ADAPTER_MANIFEST_FILE);
        if !path.is_file() {
            return Err(format!(
                "target {:?} ships no {}: not eligible for canary",
                tree_root, ADAPTER_MANIFEST_FILE
            ));
        }
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("cannot read {:?}: {}", path, e))?;
        let manifest = Self::parse(&text)?;
        Ok(LoadedAdapterManifest {
            manifest,
            digest: sha256_hex(text.as_bytes()),
            path,
        })
    }

    /// Digest of the exact manifest bytes.
    pub fn digest_of_text(text: &str) -> String {
        sha256_hex(text.as_bytes())
    }

    /// Where the declared executable is expected inside `build_output_root`.
    pub fn executable_path(&self, build_output_root: &Path) -> PathBuf {
        build_output_root.join(&self.executable)
    }
}

fn validate_relative_executable(executable: &str) -> Result<(), String> {
    if executable.trim().is_empty() {
        return Err("canary adapter executable is required".to_string());
    }
    if executable.contains('\\') || executable.contains('\0') {
        return Err("canary adapter executable contains a backslash or NUL".to_string());
    }
    let path = Path::new(executable);
    if path.is_absolute() {
        return Err(format!(
            "canary adapter executable {:?} must be relative to the build output",
            executable
        ));
    }
    for comp in path.components() {
        match comp {
            Component::Normal(_) => {}
            _ => {
                return Err(format!(
                    "canary adapter executable {:?} must not climb or use special components",
                    executable
                ))
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID: &str = r#"
manifest_version = 1
protocol_version = 1
executable = "release/rsi-canary-fixture"
args = ["--adapter"]
workload_id = "fixture-v1"
response_format = "utf8-exact"
"#;

    #[test]
    fn parses_a_valid_manifest() {
        let m = CanaryAdapterManifest::parse(VALID).unwrap();
        assert_eq!(m.executable, "release/rsi-canary-fixture");
        assert_eq!(m.args, vec!["--adapter".to_string()]);
        assert_eq!(
            m.executable_path(Path::new("/tmp/out")),
            PathBuf::from("/tmp/out/release/rsi-canary-fixture")
        );
    }

    #[test]
    fn refuses_absolute_climbing_unknown_and_wrong_versions() {
        let abs = VALID.replace("release/rsi-canary-fixture", "/usr/bin/true");
        assert!(CanaryAdapterManifest::parse(&abs).is_err());
        let climb = VALID.replace("release/rsi-canary-fixture", "../outside");
        assert!(CanaryAdapterManifest::parse(&climb).is_err());
        let inner_climb = VALID.replace("release/rsi-canary-fixture", "release/../x");
        assert!(CanaryAdapterManifest::parse(&inner_climb).is_err());
        let fmt = VALID.replace("utf8-exact", "anything-goes");
        assert!(CanaryAdapterManifest::parse(&fmt).is_err());
        let proto = VALID.replace("protocol_version = 1", "protocol_version = 2");
        assert!(CanaryAdapterManifest::parse(&proto).is_err());
        let criteria = format!("{}\npass_if = \"always\"\n", VALID);
        assert!(CanaryAdapterManifest::parse(&criteria).is_err());
    }

    #[test]
    fn missing_manifest_is_not_eligible() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(!CanaryAdapterManifest::is_declared(tmp.path()));
        let err = CanaryAdapterManifest::load_from_tree(tmp.path()).unwrap_err();
        assert!(err.contains("not eligible for canary"));

        std::fs::write(tmp.path().join(ADAPTER_MANIFEST_FILE), VALID).unwrap();
        let loaded = CanaryAdapterManifest::load_from_tree(tmp.path()).unwrap();
        assert_eq!(loaded.digest, CanaryAdapterManifest::digest_of_text(VALID));
    }
}
