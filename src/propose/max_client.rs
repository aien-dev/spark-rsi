use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessageResponse {
    pub role: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub reasoning: Option<String>,
    #[serde(default)]
    pub reasoning_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatChoice {
    pub index: usize,
    pub message: ChatMessageResponse,
    #[serde(default)]
    pub finish_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub choices: Vec<ChatChoice>,
}

#[derive(Debug, Clone)]
pub struct MaxClient {
    pub base_url: String,
    pub model_id: String,
    client: reqwest::Client,
}

impl MaxClient {
    pub fn new(base_url: &str, model_id: &str) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(120))
            .build()
            .unwrap_or_default();

        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            model_id: model_id.to_string(),
            client,
        }
    }

    pub async fn is_available(&self) -> bool {
        let url = format!("{}/models", self.base_url);
        match self.client.get(&url).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(_) => false,
        }
    }

    pub async fn complete(
        &self,
        messages: &[ChatMessage],
        max_tokens: usize,
        temperature: f32,
    ) -> Result<String, String> {
        let url = format!("{}/chat/completions", self.base_url);
        let req = ChatCompletionRequest {
            model: self.model_id.clone(),
            messages: messages.to_vec(),
            max_tokens: Some(max_tokens),
            temperature: Some(temperature),
        };

        let resp = self
            .client
            .post(&url)
            .json(&req)
            .send()
            .await
            .map_err(|e| format!("MAX completion request failed: {}", e))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(format!("MAX endpoint returned HTTP {}: {}", status, body));
        }

        let body: ChatCompletionResponse = resp
            .json()
            .await
            .map_err(|e| format!("Failed to parse MAX response: {}", e))?;

        let choice = body
            .choices
            .first()
            .ok_or_else(|| "MAX response returned empty choices array".to_string())?;

        let content = choice
            .message
            .content
            .as_deref()
            .unwrap_or_default()
            .trim();

        if content.is_empty() {
            return Err("MAX assistant message content is empty".to_string());
        }

        Ok(content.to_string())
    }
}
