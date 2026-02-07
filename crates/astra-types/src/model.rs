// SPDX-License-Identifier: MIT OR Apache-2.0
//! Model Gateway types for LLM interactions.
//!
//! This module defines the input/output types for the Model Gateway, which normalizes
//! all LLM interactions (chat, tool calling, embeddings) into a unified internal API.
//! This enables provider-agnostic model access across ASTRA_.
//!
//! # Design
//!
//! - `ModelInvocation` is the input to the Model Gateway
//! - `ModelResult` is the output from the Model Gateway
//! - Provider adapters translate between these types and provider-specific formats
//! - All types are serializable for logging, persistence, and wire transport
//!
//! # Example
//!
//! ```
//! use astra_types::{ModelInvocation, Message, InferenceParams, Validate};
//!
//! // Simple chat invocation
//! let invocation = ModelInvocation::new(
//!     "claude-sonnet",
//!     vec![
//!         Message::system("You are a helpful coding assistant."),
//!         Message::user("How do I read a file in Rust?"),
//!     ],
//! );
//!
//! assert!(invocation.is_valid());
//!
//! // With custom parameters
//! let invocation = ModelInvocation::new("claude-sonnet", vec![Message::user("Hello")])
//!     .with_params(InferenceParams {
//!         temperature: 0.0,
//!         max_tokens: Some(4096),
//!         ..Default::default()
//!     })
//!     .with_correlation_id("task-001");
//! ```

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;

use crate::error::{AstraError, ErrorContext};
use crate::validate::Validate;

// ============================================================================
// Role enum
// ============================================================================

/// Role of a message in a conversation.
///
/// Defines who sent the message in the conversation history.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// System prompt or instructions that guide model behavior.
    System,
    /// User input or query.
    User,
    /// Assistant (model) response.
    Assistant,
    /// Tool/function result returned to the model.
    Tool,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => write!(f, "system"),
            Self::User => write!(f, "user"),
            Self::Assistant => write!(f, "assistant"),
            Self::Tool => write!(f, "tool"),
        }
    }
}

// ============================================================================
// ToolCall struct
// ============================================================================

/// A tool call requested by the model.
///
/// When a model wants to use a tool, it generates a ToolCall with the tool
/// name and arguments. The system executes the tool and returns the result
/// via a Tool-role message with matching `tool_call_id`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    /// Unique ID for this tool call (for matching with results).
    pub id: String,

    /// Name of the tool to call.
    pub name: String,

    /// Arguments as JSON (should validate against tool's parameter schema).
    pub arguments: Value,
}

// ============================================================================
// Message struct
// ============================================================================

/// A message in a conversation.
///
/// Messages form the conversation history sent to the model. Each message has
/// a role indicating who sent it, content, and optional tool-related fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    /// Role of this message (who sent it).
    pub role: Role,

    /// Text content of the message (may be empty for tool-only messages).
    #[serde(default)]
    pub content: String,

    /// Tool calls made by assistant (only populated for Role::Assistant).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,

    /// Tool call ID this message responds to (only for Role::Tool).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,

    /// Optional name for multi-agent scenarios.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

impl Message {
    /// Create a system message with the given content.
    ///
    /// System messages typically contain instructions that guide model behavior.
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::Message;
    ///
    /// let msg = Message::system("You are a helpful coding assistant.");
    /// ```
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
            name: None,
        }
    }

    /// Create a user message with the given content.
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::Message;
    ///
    /// let msg = Message::user("How do I read a file in Rust?");
    /// ```
    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: Role::User,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
            name: None,
        }
    }

    /// Create an assistant message with the given content.
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::Message;
    ///
    /// let msg = Message::assistant("Here's how to read a file...");
    /// ```
    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: Role::Assistant,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: None,
            name: None,
        }
    }

    /// Create a tool result message.
    ///
    /// Tool messages return the result of a tool call back to the model.
    /// The `tool_call_id` must match the ID from the corresponding `ToolCall`.
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::Message;
    ///
    /// let msg = Message::tool_result("call_123", r#"{"result": "success"}"#);
    /// ```
    pub fn tool_result(tool_call_id: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: Role::Tool,
            content: content.into(),
            tool_calls: Vec::new(),
            tool_call_id: Some(tool_call_id.into()),
            name: None,
        }
    }

    /// Add tool calls to this message (chainable).
    ///
    /// Typically used with assistant messages when the model requests tool use.
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::{Message, ToolCall};
    /// use serde_json::json;
    ///
    /// let msg = Message::assistant("")
    ///     .with_tool_calls(vec![
    ///         ToolCall {
    ///             id: "call_123".into(),
    ///             name: "read_file".into(),
    ///             arguments: json!({"path": "src/main.rs"}),
    ///         },
    ///     ]);
    /// ```
    pub fn with_tool_calls(mut self, tool_calls: Vec<ToolCall>) -> Self {
        self.tool_calls = tool_calls;
        self
    }

    /// Set the name for this message (chainable).
    ///
    /// Names are used in multi-agent scenarios to identify which agent
    /// sent the message.
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::Message;
    ///
    /// let msg = Message::user("Review this code")
    ///     .with_name("code-reviewer");
    /// ```
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }
}

// ============================================================================
// Tool struct
// ============================================================================

/// A tool/function that can be called by the model.
///
/// Tools are defined with a name, description, and JSON Schema for parameters.
/// When provided to a model, it can choose to call tools to accomplish tasks.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tool {
    /// Unique tool identifier.
    pub name: String,

    /// Human-readable description for the model.
    pub description: String,

    /// JSON Schema for the tool's input parameters.
    pub parameters: Value,
}

// ============================================================================
// InferenceParams struct
// ============================================================================

/// Parameters controlling model inference.
///
/// These parameters affect how the model generates responses. All have sensible
/// defaults that work well for most use cases.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceParams {
    /// Temperature (0.0 = deterministic, 1.0+ = creative).
    #[serde(default = "InferenceParams::default_temperature")]
    pub temperature: f32,

    /// Maximum tokens to generate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u32>,

    /// Top-p nucleus sampling (0.0 to 1.0).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,

    /// Stop sequences that halt generation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stop: Vec<String>,

    /// Request JSON mode output from the model.
    #[serde(default)]
    pub json_mode: bool,

    /// Seed for deterministic generation (if supported by provider).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
}

impl InferenceParams {
    fn default_temperature() -> f32 {
        0.7
    }
}

impl Default for InferenceParams {
    fn default() -> Self {
        Self {
            temperature: Self::default_temperature(),
            max_tokens: None,
            top_p: None,
            stop: Vec::new(),
            json_mode: false,
            seed: None,
        }
    }
}

impl Validate for InferenceParams {
    fn validate(&self) -> Result<(), AstraError> {
        // VAL-030: temperature must be non-negative and finite
        if !self.temperature.is_finite() || self.temperature < 0.0 {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-030",
                    "temperature must be >= 0.0 and finite",
                ),
                field: Some("temperature".into()),
                message: format!(
                    "temperature must be non-negative and finite, got {}",
                    self.temperature
                ),
            });
        }

        // VAL-031: max_tokens must be > 0 if set
        if let Some(max_tokens) = self.max_tokens {
            if max_tokens == 0 {
                return Err(AstraError::ValidationFailed {
                    context: ErrorContext::validation(
                        "VAL-031",
                        "max_tokens must be greater than 0",
                    ),
                    field: Some("max_tokens".into()),
                    message: "max_tokens must be greater than 0".into(),
                });
            }
        }

        // VAL-032: top_p must be in [0.0, 1.0] if set
        if let Some(top_p) = self.top_p {
            if !(0.0..=1.0).contains(&top_p) {
                return Err(AstraError::ValidationFailed {
                    context: ErrorContext::validation(
                        "VAL-032",
                        "top_p must be between 0.0 and 1.0",
                    ),
                    field: Some("top_p".into()),
                    message: format!("top_p must be in [0.0, 1.0], got {}", top_p),
                });
            }
        }

        Ok(())
    }
}

// ============================================================================
// ModelInvocation struct
// ============================================================================

/// Input to the Model Gateway.
///
/// Contains everything needed to make a model request: the target model,
/// conversation messages, available tools, and inference parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelInvocation {
    /// Target model ID (from Model Registry).
    pub model_id: String,

    /// Conversation messages.
    pub messages: Vec<Message>,

    /// Available tools (empty if no tool calling).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<Tool>,

    /// Inference parameters.
    #[serde(default)]
    pub params: InferenceParams,

    /// Correlation ID for request tracing.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,

    /// Additional provider-specific options (escape hatch).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, Value>,
}

impl ModelInvocation {
    /// Create a new model invocation with defaults.
    ///
    /// # Arguments
    ///
    /// * `model_id` - Target model identifier from the Model Registry
    /// * `messages` - Conversation history
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::{ModelInvocation, Message};
    ///
    /// let invocation = ModelInvocation::new(
    ///     "claude-sonnet",
    ///     vec![Message::user("Hello!")],
    /// );
    /// ```
    pub fn new(model_id: impl Into<String>, messages: Vec<Message>) -> Self {
        Self {
            model_id: model_id.into(),
            messages,
            tools: Vec::new(),
            params: InferenceParams::default(),
            correlation_id: None,
            extra: HashMap::new(),
        }
    }

    /// Set available tools (chainable).
    pub fn with_tools(mut self, tools: Vec<Tool>) -> Self {
        self.tools = tools;
        self
    }

    /// Set inference parameters (chainable).
    pub fn with_params(mut self, params: InferenceParams) -> Self {
        self.params = params;
        self
    }

    /// Set correlation ID for tracing (chainable).
    pub fn with_correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }
}

impl Validate for ModelInvocation {
    fn validate(&self) -> Result<(), AstraError> {
        // VAL-034: model_id must not be empty
        if self.model_id.is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-034",
                    "Specify a model ID from the Model Registry",
                ),
                field: Some("model_id".into()),
                message: "model_id cannot be empty".into(),
            });
        }

        // VAL-033: messages must not be empty
        if self.messages.is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-033",
                    "Provide at least one message in the conversation",
                ),
                field: Some("messages".into()),
                message: "messages cannot be empty".into(),
            });
        }

        // Delegate to params validation
        self.params.validate()?;

        Ok(())
    }
}

// ============================================================================
// Usage struct
// ============================================================================

/// Token usage statistics from a model invocation.
///
/// Tracks prompt and completion tokens for budget enforcement and cost tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Usage {
    /// Number of tokens in the input/prompt.
    pub prompt_tokens: u32,

    /// Number of tokens in the output/completion.
    pub completion_tokens: u32,

    /// Total tokens (prompt + completion).
    pub total_tokens: u32,
}

impl Usage {
    /// Compute total from components.
    ///
    /// Use this to verify `total_tokens` matches the sum of components,
    /// or to calculate total when only components are known.
    /// Uses saturating addition to prevent overflow.
    pub fn calculated_total(&self) -> u32 {
        self.prompt_tokens.saturating_add(self.completion_tokens)
    }
}

impl fmt::Display for Usage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} prompt + {} completion = {} total tokens",
            self.prompt_tokens, self.completion_tokens, self.total_tokens
        )
    }
}

// ============================================================================
// StopReason enum
// ============================================================================

/// Reason the model stopped generating.
///
/// Indicates why the model finished its response, which affects how the
/// result should be interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Natural end of response (model finished its thought).
    EndTurn,
    /// Hit the max_tokens limit (response may be truncated).
    MaxTokens,
    /// Hit a stop sequence.
    StopSequence,
    /// Model wants to call one or more tools.
    ToolUse,
}

impl fmt::Display for StopReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndTurn => write!(f, "end_turn"),
            Self::MaxTokens => write!(f, "max_tokens"),
            Self::StopSequence => write!(f, "stop_sequence"),
            Self::ToolUse => write!(f, "tool_use"),
        }
    }
}

// ============================================================================
// ModelResult struct
// ============================================================================

/// Output from the Model Gateway.
///
/// Contains the model's response along with metadata about token usage,
/// cost, and latency for observability and budget tracking.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModelResult {
    /// The assistant's response message.
    pub message: Message,

    /// Why generation stopped.
    pub stop_reason: StopReason,

    /// Token usage for this invocation.
    pub usage: Usage,

    /// Estimated cost in USD.
    pub cost_usd: f64,

    /// Latency in milliseconds (provider time only).
    pub latency_ms: u64,

    /// Model ID that actually handled the request (may differ from requested).
    pub model_id: String,

    /// Provider-specific response ID (for debugging).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_request_id: Option<String>,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    // ========================================================================
    // Constructor tests
    // ========================================================================

    #[test]
    fn message_system_constructor() {
        let msg = Message::system("You are helpful.");
        assert_eq!(msg.role, Role::System);
        assert_eq!(msg.content, "You are helpful.");
        assert!(msg.tool_calls.is_empty());
        assert!(msg.tool_call_id.is_none());
        assert!(msg.name.is_none());
    }

    #[test]
    fn message_user_constructor() {
        let msg = Message::user("Hello!");
        assert_eq!(msg.role, Role::User);
        assert_eq!(msg.content, "Hello!");
    }

    #[test]
    fn message_assistant_constructor() {
        let msg = Message::assistant("Hi there!");
        assert_eq!(msg.role, Role::Assistant);
        assert_eq!(msg.content, "Hi there!");
    }

    #[test]
    fn message_tool_result_constructor() {
        let msg = Message::tool_result("call_123", r#"{"result": "ok"}"#);
        assert_eq!(msg.role, Role::Tool);
        assert_eq!(msg.content, r#"{"result": "ok"}"#);
        assert_eq!(msg.tool_call_id, Some("call_123".into()));
    }

    #[test]
    fn message_with_tool_calls_chainable() {
        let tool_call = ToolCall {
            id: "call_1".into(),
            name: "read_file".into(),
            arguments: json!({"path": "test.txt"}),
        };
        let msg = Message::assistant("").with_tool_calls(vec![tool_call.clone()]);
        assert_eq!(msg.tool_calls.len(), 1);
        assert_eq!(msg.tool_calls[0].id, "call_1");
    }

    #[test]
    fn message_with_name_chainable() {
        let msg = Message::user("Review this").with_name("reviewer-agent");
        assert_eq!(msg.name, Some("reviewer-agent".into()));
    }

    #[test]
    fn model_invocation_new() {
        let invocation = ModelInvocation::new("claude-sonnet", vec![Message::user("Hi")]);
        assert_eq!(invocation.model_id, "claude-sonnet");
        assert_eq!(invocation.messages.len(), 1);
        assert!(invocation.tools.is_empty());
        assert!(invocation.correlation_id.is_none());
        assert!(invocation.extra.is_empty());
    }

    #[test]
    fn inference_params_default() {
        let params = InferenceParams::default();
        assert!((params.temperature - 0.7).abs() < f32::EPSILON);
        assert!(params.max_tokens.is_none());
        assert!(params.top_p.is_none());
        assert!(params.stop.is_empty());
        assert!(!params.json_mode);
        assert!(params.seed.is_none());
    }

    // ========================================================================
    // Builder chain tests
    // ========================================================================

    #[test]
    fn model_invocation_full_builder_chain() {
        let tool = Tool {
            name: "read_file".into(),
            description: "Read a file".into(),
            parameters: json!({"type": "object"}),
        };
        let params = InferenceParams {
            temperature: 0.0,
            max_tokens: Some(1000),
            ..Default::default()
        };

        let invocation = ModelInvocation::new("claude-sonnet", vec![Message::user("Hi")])
            .with_tools(vec![tool])
            .with_params(params)
            .with_correlation_id("task-001");

        assert_eq!(invocation.tools.len(), 1);
        assert_eq!(invocation.params.temperature, 0.0);
        assert_eq!(invocation.correlation_id, Some("task-001".into()));
    }

    #[test]
    fn model_invocation_with_tools() {
        let tool = Tool {
            name: "test".into(),
            description: "Test tool".into(),
            parameters: json!({}),
        };
        let invocation =
            ModelInvocation::new("model", vec![Message::user("Hi")]).with_tools(vec![tool]);
        assert_eq!(invocation.tools.len(), 1);
        assert_eq!(invocation.tools[0].name, "test");
    }

    #[test]
    fn model_invocation_with_params() {
        let params = InferenceParams {
            temperature: 0.5,
            ..Default::default()
        };
        let invocation =
            ModelInvocation::new("model", vec![Message::user("Hi")]).with_params(params);
        assert!((invocation.params.temperature - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn model_invocation_with_correlation_id() {
        let invocation = ModelInvocation::new("model", vec![Message::user("Hi")])
            .with_correlation_id("trace-123");
        assert_eq!(invocation.correlation_id, Some("trace-123".into()));
    }

    // ========================================================================
    // Validation tests
    // ========================================================================

    #[test]
    fn inference_params_valid_passes() {
        let params = InferenceParams {
            temperature: 0.5,
            max_tokens: Some(100),
            top_p: Some(0.9),
            ..Default::default()
        };
        assert!(params.is_valid());
    }

    #[test]
    fn inference_params_negative_temperature_fails() {
        let params = InferenceParams {
            temperature: -0.1,
            ..Default::default()
        };
        let result = params.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-030");
        assert_eq!(field, Some("temperature".into()));
    }

    #[test]
    fn inference_params_nan_temperature_fails() {
        let params = InferenceParams {
            temperature: f32::NAN,
            ..Default::default()
        };
        let result = params.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-030");
        assert_eq!(field, Some("temperature".into()));
    }

    #[test]
    fn inference_params_infinity_temperature_fails() {
        let params = InferenceParams {
            temperature: f32::INFINITY,
            ..Default::default()
        };
        let result = params.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-030");
        assert_eq!(field, Some("temperature".into()));
    }

    #[test]
    fn inference_params_neg_infinity_temperature_fails() {
        let params = InferenceParams {
            temperature: f32::NEG_INFINITY,
            ..Default::default()
        };
        let result = params.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-030");
        assert_eq!(field, Some("temperature".into()));
    }

    #[test]
    fn inference_params_zero_max_tokens_fails() {
        let params = InferenceParams {
            max_tokens: Some(0),
            ..Default::default()
        };
        let result = params.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-031");
        assert_eq!(field, Some("max_tokens".into()));
    }

    #[test]
    fn inference_params_top_p_below_zero_fails() {
        let params = InferenceParams {
            top_p: Some(-0.1),
            ..Default::default()
        };
        let result = params.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-032");
        assert_eq!(field, Some("top_p".into()));
    }

    #[test]
    fn inference_params_top_p_above_one_fails() {
        let params = InferenceParams {
            top_p: Some(1.1),
            ..Default::default()
        };
        let result = params.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-032");
    }

    #[test]
    fn model_invocation_valid_passes() {
        let invocation = ModelInvocation::new("claude-sonnet", vec![Message::user("Hi")]);
        assert!(invocation.is_valid());
    }

    #[test]
    fn model_invocation_empty_model_id_fails() {
        let invocation = ModelInvocation::new("", vec![Message::user("Hi")]);
        let result = invocation.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-034");
        assert_eq!(field, Some("model_id".into()));
    }

    #[test]
    fn model_invocation_empty_messages_fails() {
        let invocation = ModelInvocation::new("claude-sonnet", vec![]);
        let result = invocation.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-033");
        assert_eq!(field, Some("messages".into()));
    }

    #[test]
    fn model_invocation_invalid_params_propagates() {
        let invocation = ModelInvocation::new("claude-sonnet", vec![Message::user("Hi")])
            .with_params(InferenceParams {
                temperature: -1.0,
                ..Default::default()
            });
        let result = invocation.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-030");
    }

    #[test]
    fn is_valid_convenience_method() {
        let valid = ModelInvocation::new("model", vec![Message::user("Hi")]);
        let invalid = ModelInvocation::new("", vec![]);
        assert!(valid.is_valid());
        assert!(!invalid.is_valid());
    }

    // ========================================================================
    // Serde tests
    // ========================================================================

    #[test]
    fn role_serializes_lowercase() {
        let Ok(json) = serde_json::to_string(&Role::System) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"system\"");

        let Ok(json) = serde_json::to_string(&Role::Assistant) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"assistant\"");
    }

    #[test]
    fn stop_reason_serializes_snake_case() {
        let Ok(json) = serde_json::to_string(&StopReason::EndTurn) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"end_turn\"");

        let Ok(json) = serde_json::to_string(&StopReason::MaxTokens) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"max_tokens\"");

        let Ok(json) = serde_json::to_string(&StopReason::ToolUse) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"tool_use\"");
    }

    #[test]
    fn message_roundtrip_all_fields() {
        let msg = Message {
            role: Role::Assistant,
            content: "Hello".into(),
            tool_calls: vec![ToolCall {
                id: "call_1".into(),
                name: "test".into(),
                arguments: json!({"key": "value"}),
            }],
            tool_call_id: None,
            name: Some("agent-1".into()),
        };

        let Ok(json) = serde_json::to_string(&msg) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<Message>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(msg, decoded);
    }

    #[test]
    fn message_roundtrip_minimal_fields() {
        let msg = Message::user("Hi");
        let Ok(json) = serde_json::to_string(&msg) else {
            panic!("serialization should succeed");
        };

        // Verify skip_serializing_if works
        assert!(!json.contains("tool_calls"));
        assert!(!json.contains("tool_call_id"));
        assert!(!json.contains("name"));

        let Ok(decoded) = serde_json::from_str::<Message>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(msg.role, decoded.role);
        assert_eq!(msg.content, decoded.content);
    }

    #[test]
    fn tool_roundtrip_with_json_schema() {
        let tool = Tool {
            name: "read_file".into(),
            description: "Read contents of a file".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "path": { "type": "string", "description": "File path" }
                },
                "required": ["path"]
            }),
        };

        let Ok(json) = serde_json::to_string(&tool) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<Tool>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(tool, decoded);
    }

    #[test]
    fn tool_call_roundtrip() {
        let call = ToolCall {
            id: "call_abc123".into(),
            name: "search".into(),
            arguments: json!({"query": "rust file io", "limit": 10}),
        };

        let Ok(json) = serde_json::to_string(&call) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<ToolCall>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(call, decoded);
    }

    #[test]
    fn inference_params_roundtrip_defaults() {
        let params = InferenceParams::default();
        let Ok(json) = serde_json::to_string(&params) else {
            panic!("serialization should succeed");
        };

        // Verify skip_serializing_if works for None values
        assert!(!json.contains("max_tokens"));
        assert!(!json.contains("top_p"));
        assert!(!json.contains("seed"));

        let Ok(decoded) = serde_json::from_str::<InferenceParams>(&json) else {
            panic!("deserialization should succeed");
        };
        assert!((params.temperature - decoded.temperature).abs() < f32::EPSILON);
    }

    #[test]
    fn inference_params_roundtrip_all_fields() {
        let params = InferenceParams {
            temperature: 0.5,
            max_tokens: Some(2000),
            top_p: Some(0.95),
            stop: vec!["END".into(), "STOP".into()],
            json_mode: true,
            seed: Some(42),
        };

        let Ok(json) = serde_json::to_string(&params) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<InferenceParams>(&json) else {
            panic!("deserialization should succeed");
        };

        assert!((params.temperature - decoded.temperature).abs() < f32::EPSILON);
        assert_eq!(params.max_tokens, decoded.max_tokens);
        assert_eq!(params.top_p, decoded.top_p);
        assert_eq!(params.stop, decoded.stop);
        assert_eq!(params.json_mode, decoded.json_mode);
        assert_eq!(params.seed, decoded.seed);
    }

    #[test]
    fn model_invocation_roundtrip() {
        let invocation = ModelInvocation::new(
            "claude-sonnet",
            vec![Message::system("Be helpful"), Message::user("Hi")],
        )
        .with_correlation_id("trace-001");

        let Ok(json) = serde_json::to_string(&invocation) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<ModelInvocation>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(invocation, decoded);
    }

    #[test]
    fn usage_roundtrip() {
        let usage = Usage {
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
        };

        let Ok(json) = serde_json::to_string(&usage) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<Usage>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(usage, decoded);
    }

    #[test]
    fn model_result_roundtrip() {
        let result = ModelResult {
            message: Message::assistant("Here's the answer"),
            stop_reason: StopReason::EndTurn,
            usage: Usage {
                prompt_tokens: 50,
                completion_tokens: 100,
                total_tokens: 150,
            },
            cost_usd: 0.0015,
            latency_ms: 1234,
            model_id: "claude-sonnet".into(),
            provider_request_id: Some("req_abc123".into()),
        };

        let Ok(json) = serde_json::to_string(&result) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<ModelResult>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(result, decoded);
    }

    #[test]
    fn extra_field_handles_arbitrary_json() {
        let mut extra = HashMap::new();
        extra.insert("custom_key".into(), json!({"nested": true, "count": 42}));

        let invocation = ModelInvocation {
            model_id: "model".into(),
            messages: vec![Message::user("Hi")],
            tools: Vec::new(),
            params: InferenceParams::default(),
            correlation_id: None,
            extra,
        };

        let Ok(json) = serde_json::to_string(&invocation) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<ModelInvocation>(&json) else {
            panic!("deserialization should succeed");
        };

        assert!(decoded.extra.contains_key("custom_key"));
        assert_eq!(decoded.extra["custom_key"]["nested"], json!(true));
    }

    // ========================================================================
    // Display tests
    // ========================================================================

    #[test]
    fn role_display_all_variants() {
        assert_eq!(Role::System.to_string(), "system");
        assert_eq!(Role::User.to_string(), "user");
        assert_eq!(Role::Assistant.to_string(), "assistant");
        assert_eq!(Role::Tool.to_string(), "tool");
    }

    #[test]
    fn stop_reason_display_all_variants() {
        assert_eq!(StopReason::EndTurn.to_string(), "end_turn");
        assert_eq!(StopReason::MaxTokens.to_string(), "max_tokens");
        assert_eq!(StopReason::StopSequence.to_string(), "stop_sequence");
        assert_eq!(StopReason::ToolUse.to_string(), "tool_use");
    }

    #[test]
    fn usage_display_format() {
        let usage = Usage {
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
        };
        assert_eq!(
            usage.to_string(),
            "100 prompt + 50 completion = 150 total tokens"
        );
    }

    #[test]
    fn display_outputs_are_human_readable() {
        // Verify displays don't contain debug formatting like struct names
        let role_display = Role::System.to_string();
        let stop_display = StopReason::EndTurn.to_string();
        let usage_display = Usage::default().to_string();

        assert!(!role_display.contains("Role"));
        assert!(!stop_display.contains("StopReason"));
        assert!(!usage_display.contains("Usage"));
    }

    // ========================================================================
    // Helper method tests
    // ========================================================================

    #[test]
    fn usage_calculated_total_correct() {
        let usage = Usage {
            prompt_tokens: 100,
            completion_tokens: 50,
            total_tokens: 150,
        };
        assert_eq!(usage.calculated_total(), 150);
    }

    #[test]
    fn usage_calculated_total_saturates_on_overflow() {
        let usage = Usage {
            prompt_tokens: u32::MAX,
            completion_tokens: 1,
            total_tokens: 0, // Intentionally wrong
        };
        assert_eq!(usage.calculated_total(), u32::MAX);
    }

    #[test]
    fn default_usage_has_zero_values() {
        let usage = Usage::default();
        assert_eq!(usage.prompt_tokens, 0);
        assert_eq!(usage.completion_tokens, 0);
        assert_eq!(usage.total_tokens, 0);
    }

    // ========================================================================
    // Edge case tests
    // ========================================================================

    #[test]
    fn message_with_empty_content_is_valid() {
        let msg = Message::assistant("");
        assert_eq!(msg.content, "");
        // Empty content is allowed (e.g., tool-only responses)
    }

    #[test]
    fn tool_with_complex_nested_json_schema() {
        let tool = Tool {
            name: "complex_tool".into(),
            description: "A tool with complex schema".into(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "config": {
                        "type": "object",
                        "properties": {
                            "nested": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "name": { "type": "string" },
                                        "value": { "type": "number" }
                                    }
                                }
                            }
                        }
                    }
                }
            }),
        };

        let Ok(json) = serde_json::to_string(&tool) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<Tool>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(tool, decoded);
    }

    #[test]
    fn tool_call_with_object_arguments() {
        let call = ToolCall {
            id: "call_1".into(),
            name: "api_call".into(),
            arguments: json!({
                "endpoint": "/users",
                "method": "POST",
                "body": {
                    "name": "John",
                    "email": "john@example.com"
                }
            }),
        };

        // Verify arguments are preserved correctly
        assert_eq!(call.arguments["endpoint"], json!("/users"));
        assert_eq!(call.arguments["body"]["name"], json!("John"));
    }

    #[test]
    fn model_invocation_with_empty_tools_is_valid() {
        let invocation = ModelInvocation::new("model", vec![Message::user("Hi")]);
        assert!(invocation.tools.is_empty());
        assert!(invocation.is_valid());
    }

    // ========================================================================
    // Hash tests (for Role and StopReason)
    // ========================================================================

    #[test]
    fn role_can_be_used_as_hash_key() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Role::System);
        set.insert(Role::User);
        set.insert(Role::System); // Duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn stop_reason_can_be_used_as_hash_key() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(StopReason::EndTurn);
        set.insert(StopReason::ToolUse);
        set.insert(StopReason::EndTurn); // Duplicate
        assert_eq!(set.len(), 2);
    }
}
