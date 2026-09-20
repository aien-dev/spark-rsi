use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorProfile {
    #[serde(default = "default_operator_name")]
    pub name: String,
    #[serde(default = "default_operator_email")]
    pub email: String,
    #[serde(default = "default_operator_handle")]
    pub handle: String,
    #[serde(default = "default_sign_commits")]
    pub sign_commits: bool,
}

impl Default for OperatorProfile {
    fn default() -> Self {
        Self {
            name: default_operator_name(),
            email: default_operator_email(),
            handle: default_operator_handle(),
            sign_commits: default_sign_commits(),
        }
    }
}

fn default_operator_name() -> String {
    "Sovereign Operator".to_string()
}
fn default_operator_email() -> String {
    "operator@local".to_string()
}
fn default_operator_handle() -> String {
    "operator".to_string()
}
fn default_sign_commits() -> bool {
    false
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_engine_mode")]
    pub mode: String, // "api" or "max"
    #[serde(default = "default_api_base_url")]
    pub api_base_url: String,
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_model_id")]
    pub model_id: String,
    #[serde(default = "default_max_port")]
    pub max_port: u16,
    #[serde(default = "default_context_window")]
    pub context_window: usize,
    #[serde(default = "default_temperature")]
    pub temperature: f32,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            mode: default_engine_mode(),
            api_base_url: default_api_base_url(),
            api_key: String::new(),
            model_id: default_model_id(),
            max_port: default_max_port(),
            context_window: default_context_window(),
            temperature: default_temperature(),
        }
    }
}

fn default_engine_mode() -> String {
    "max".to_string()
}
fn default_api_base_url() -> String {
    "http://127.0.0.1:18006/v1".to_string()
}
fn default_model_id() -> String {
    "nvidia/NVIDIA-Nemotron-3.5-Lightning-30B-A3B-BF16".to_string()
}
fn default_max_port() -> u16 {
    18006
}
fn default_context_window() -> usize {
    32768
}
fn default_temperature() -> f32 {
    0.7
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SovereignConfig {
    #[serde(default)]
    pub operator: OperatorProfile,
    #[serde(default)]
    pub engine: EngineConfig,
}

impl SovereignConfig {
    pub fn config_path() -> PathBuf {
        if let Ok(path) = std::env::var("SOVEREIGN_CONFIG_PATH") {
            return PathBuf::from(path);
        }
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
        PathBuf::from(home).join(".config/sovereign/operator.toml")
    }

    pub fn load() -> Self {
        let path = Self::config_path();
        let mut config = if path.exists() {
            match fs::read_to_string(&path) {
                Ok(content) => toml::from_str(&content).unwrap_or_default(),
                Err(_) => Self::default(),
            }
        } else {
            Self::default()
        };

        // Environment overrides
        if let Ok(name) = std::env::var("SOVEREIGN_OPERATOR_NAME") {
            config.operator.name = name;
        }
        if let Ok(email) = std::env::var("SOVEREIGN_OPERATOR_EMAIL") {
            config.operator.email = email;
        }
        if let Ok(handle) = std::env::var("SOVEREIGN_OPERATOR_HANDLE") {
            config.operator.handle = handle;
        }
        if let Ok(mode) = std::env::var("SOVEREIGN_ENGINE_MODE") {
            config.engine.mode = mode;
        }
        if let Ok(url) = std::env::var("SOVEREIGN_API_BASE_URL") {
            config.engine.api_base_url = url;
        }

        // Fallback to git config if name or email still default
        if config.operator.name == "Sovereign Operator" {
            if let Ok(out) = Command::new("git").args(["config", "user.name"]).output() {
                let git_name = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !git_name.is_empty() {
                    config.operator.name = git_name;
                }
            }
        }
        if config.operator.email == "operator@local" {
            if let Ok(out) = Command::new("git").args(["config", "user.email"]).output() {
                let git_email = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !git_email.is_empty() {
                    config.operator.email = git_email;
                }
            }
        }

        config
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::config_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create config dir: {}", e))?;
        }
        let serialized = toml::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize config: {}", e))?;
        fs::write(&path, serialized)
            .map_err(|e| format!("Failed to write config to {:?}: {}", path, e))?;
        Ok(())
    }

    pub fn author_string(&self) -> String {
        format!("{} <{}>", self.operator.name, self.operator.email)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_and_author_string() {
        let mut cfg = SovereignConfig::default();
        cfg.operator.name = "Alice".to_string();
        cfg.operator.email = "alice@domain.org".to_string();
        assert_eq!(cfg.author_string(), "Alice <alice@domain.org>");
        assert_eq!(cfg.engine.mode, "max");
    }

    #[test]
    fn test_serialization_roundtrip() {
        let cfg = SovereignConfig::default();
        let serialized = toml::to_string_pretty(&cfg).unwrap();
        let deserialized: SovereignConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.operator.name, cfg.operator.name);
        assert_eq!(deserialized.engine.mode, cfg.engine.mode);
    }
}
