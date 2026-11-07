use serde::{Deserialize, Serialize};

/// Standard GenAI Systems conforming to CNCF OpenTelemetry Semantic Conventions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GenAiSystem {
    Anthropic,
    OpenAi,
    Google,
    Meta,
    Mistral,
    Custom(String),
}

impl std::fmt::Display for GenAiSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Anthropic => write!(f, "anthropic"),
            Self::OpenAi => write!(f, "openai"),
            Self::Google => write!(f, "google"),
            Self::Meta => write!(f, "meta"),
            Self::Mistral => write!(f, "mistral"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

/// Strongly typed Autonomous AI Agent Event adhering to OpenTelemetry GenAI Semantic Conventions
/// and Vortex Cryptographic Flight Recording requirements.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GenAiEvent {
    /// Distributed tracing trace ID (hex string, e.g. 32 chars)
    pub trace_id: String,

    /// Distributed tracing span ID (hex string, e.g. 16 chars)
    pub span_id: String,

    /// AI provider system (e.g., anthropic, openai)
    pub system: GenAiSystem,

    /// Exact model identifier (e.g., claude-3-7-sonnet, gpt-4o)
    pub model: String,

    /// Input prompt or conversation messages
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,

    /// Model completion or generated response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion: Option<String>,

    /// Invoked tool / function name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_name: Option<String>,

    /// JSON parameters passed to the tool
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_parameters: Option<serde_json::Value>,

    /// JSON execution result returned from the tool
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_result: Option<serde_json::Value>,

    /// Cryptographic hash of model checkpoint/weights (if self-hosted or audited)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_weights_hash: Option<String>,

    /// Identity of human-in-the-loop supervisor or approver (EU AI Act Article 14)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervisor_id: Option<String>,

    /// Prompt tokens consumed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_tokens: Option<u64>,

    /// Completion tokens consumed
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completion_tokens: Option<u64>,

    /// High-resolution UTC timestamp in nanoseconds
    pub timestamp_ns: u64,
}

impl GenAiEvent {
    /// Create a new GenAiEvent with minimal required fields and current UTC timestamp
    pub fn new(
        trace_id: impl Into<String>,
        span_id: impl Into<String>,
        system: GenAiSystem,
        model: impl Into<String>,
    ) -> Self {
        let timestamp_ns = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);

        Self {
            trace_id: trace_id.into(),
            span_id: span_id.into(),
            system,
            model: model.into(),
            prompt: None,
            completion: None,
            tool_name: None,
            tool_parameters: None,
            tool_result: None,
            model_weights_hash: None,
            supervisor_id: None,
            prompt_tokens: None,
            completion_tokens: None,
            timestamp_ns,
        }
    }

    /// Builder method to attach a prompt
    pub fn with_prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    /// Builder method to attach a completion
    pub fn with_completion(mut self, completion: impl Into<String>) -> Self {
        self.completion = Some(completion.into());
        self
    }

    /// Builder method to attach tool execution details
    pub fn with_tool(
        mut self,
        name: impl Into<String>,
        parameters: Option<serde_json::Value>,
        result: Option<serde_json::Value>,
    ) -> Self {
        self.tool_name = Some(name.into());
        self.tool_parameters = parameters;
        self.tool_result = result;
        self
    }

    /// Builder method to attach human supervisor ID (EU AI Act Article 14)
    pub fn with_supervisor(mut self, supervisor_id: impl Into<String>) -> Self {
        self.supervisor_id = Some(supervisor_id.into());
        self
    }

    /// Builder method to attach model weights hash
    pub fn with_model_weights_hash(mut self, hash: impl Into<String>) -> Self {
        self.model_weights_hash = Some(hash.into());
        self
    }

    /// Serialize event to JSON bytes for log record payload
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Parse event from JSON bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Computes a deterministic Blake3 commitment binding prompt, model, tool, and supervisor
    pub fn compute_action_commitment(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(self.trace_id.as_bytes());
        hasher.update(self.span_id.as_bytes());
        hasher.update(self.system.to_string().as_bytes());
        hasher.update(self.model.as_bytes());
        if let Some(prompt) = &self.prompt {
            hasher.update(prompt.as_bytes());
        }
        if let Some(tool) = &self.tool_name {
            hasher.update(tool.as_bytes());
        }
        if let Some(params) = &self.tool_parameters {
            hasher.update(params.to_string().as_bytes());
        }
        if let Some(weights) = &self.model_weights_hash {
            hasher.update(weights.as_bytes());
        }
        if let Some(sup) = &self.supervisor_id {
            hasher.update(sup.as_bytes());
        }
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_ai_event_roundtrip() {
        let event = GenAiEvent::new(
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "00f067aa0ba902b7",
            GenAiSystem::Anthropic,
            "claude-3-7-sonnet",
        )
        .with_prompt("Deploy production migration v2.4")
        .with_tool(
            "sql_migrate",
            Some(serde_json::json!({"table": "users", "action": "add_column"})),
            Some(serde_json::json!({"status": "success", "duration_ms": 42})),
        )
        .with_supervisor("secops-lead@enterprise.com");

        let bytes = event.to_bytes().expect("serialization failed");
        let decoded = GenAiEvent::from_bytes(&bytes).expect("deserialization failed");

        assert_eq!(event, decoded);
        assert_eq!(decoded.system, GenAiSystem::Anthropic);
        assert_eq!(decoded.model, "claude-3-7-sonnet");
        assert_eq!(decoded.supervisor_id, Some("secops-lead@enterprise.com".to_string()));

        let commitment = decoded.compute_action_commitment();
        assert_ne!(commitment, [0u8; 32]);
    }
}

