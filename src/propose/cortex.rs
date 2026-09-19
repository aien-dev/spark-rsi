use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CortexSearchResult {
    pub id: String,
    #[serde(default, rename = "canonicalName")]
    pub canonical_name: Option<String>,
    pub content: String,
    #[serde(default)]
    pub score: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CortexSearchEnvelope {
    #[serde(default)]
    pub results: Vec<CortexSearchResult>,
}

#[derive(Debug, Clone)]
pub struct CortexExperienceClient {
    pub base_url: String,
    pub space: String,
    pub token: Option<String>,
    client: reqwest::Client,
}

impl CortexExperienceClient {
    pub fn new(base_url: &str) -> Self {
        let token = Self::resolve_token();
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            space: "atlas-memory".to_string(),
            token,
            client,
        }
    }

    pub fn with_space(mut self, space: &str) -> Self {
        self.space = space.to_string();
        self
    }

    pub fn with_token(mut self, token: &str) -> Self {
        self.token = Some(token.to_string());
        self
    }

    fn resolve_token() -> Option<String> {
        if let Ok(tok) = std::env::var("CORTEX_TOKEN") {
            let t = tok.trim().to_string();
            if !t.is_empty() {
                return Some(t);
            }
        }

        let home = std::env::var("HOME").unwrap_or_else(|_| "/home/drakestapleton".to_string());
        let token_path = PathBuf::from(home).join(".config/cortex/token");
        if token_path.exists() {
            if let Ok(content) = fs::read_to_string(&token_path) {
                let t = content.trim().to_string();
                if !t.is_empty() {
                    return Some(t);
                }
            }
        }
        None
    }

    pub async fn recall_lessons(&self, query: &str, limit: usize) -> Vec<String> {
        let url = format!("{}/api/cortex/search", self.base_url);
        let limit_str = limit.to_string();
        let mut req = self.client.get(&url).query(&[
            ("q", query),
            ("space", &self.space),
            ("limit", &limit_str),
        ]);

        if let Some(ref tok) = self.token {
            req = req.bearer_auth(tok);
        }

        match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(envelope) = resp.json::<CortexSearchEnvelope>().await {
                    envelope
                        .results
                        .into_iter()
                        .map(|r| {
                            if let Some(ref name) = r.canonical_name {
                                format!("[{}] {}", name, r.content)
                            } else {
                                r.content
                            }
                        })
                        .collect()
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
        }
    }
}
