// SPDX-License-Identifier: MIT OR Apache-2.0
//! Unified error taxonomy for ASTRA_.
//!
//! All errors in the system carry rich metadata for observability and debugging.
//! The grep-friendly format `[ASTRA-{CATEGORY}-{CODE}]` enables log analysis.
//!
//! # Design
//!
//! Single enum with exhaustive variants enables compile-time matching.
//! Every variant embeds `ErrorContext` for uniform metadata access.
//!
//! # Error Codes
//!
//! | Prefix | Category |
//! |--------|----------|
//! | POL | Policy violations |
//! | BUD | Budget exceeded |
//! | SBX | Sandbox violations |
//! | CON | Contract mismatches |
//! | BAK | Backend failures |
//! | PRV | Provider errors |
//! | VAL | Validation failures |
//! | CFL | Conflicts |

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;

/// Type alias for error sources that can be sent across threads.
pub type BoxedError = Arc<dyn std::error::Error + Send + Sync + 'static>;

/// Severity level for errors and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// System is unusable, immediate intervention required.
    Critical,
    /// Operation failed, requires attention.
    #[default]
    Error,
    /// Potential issue, operation continued.
    Warning,
    /// Informational, no action needed.
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::Error => write!(f, "ERROR"),
            Self::Warning => write!(f, "WARNING"),
            Self::Info => write!(f, "INFO"),
        }
    }
}

/// Budget categories tracked by the system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BudgetType {
    /// LLM token consumption.
    Tokens,
    /// Wall-clock execution time in milliseconds.
    TimeMs,
    /// Estimated cost in USD.
    CostUsd,
    /// Number of discrete actions taken.
    Actions,
}

impl fmt::Display for BudgetType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tokens => write!(f, "tokens"),
            Self::TimeMs => write!(f, "time_ms"),
            Self::CostUsd => write!(f, "cost_usd"),
            Self::Actions => write!(f, "actions"),
        }
    }
}

/// Metadata attached to every error for observability.
///
/// Note: `PartialEq` is not derived because of the `source` field.
/// Use `error_code` for error identification in tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorContext {
    /// Unique error code (e.g., "POL-001").
    pub error_code: String,
    /// Component that generated the error (e.g., "astra-policy").
    pub component: String,
    /// Request trace ID for correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    /// Error severity level.
    pub severity: Severity,
    /// Actionable guidance for resolution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation_hint: Option<String>,
    /// Original error that caused this error (for error chaining).
    #[serde(skip)]
    pub source: Option<BoxedError>,
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self {
            error_code: "UNKNOWN".into(),
            component: "unknown".into(),
            correlation_id: None,
            severity: Severity::Error,
            remediation_hint: None,
            source: None,
        }
    }
}

impl ErrorContext {
    /// Create a new builder for ErrorContext.
    pub fn builder() -> ErrorContextBuilder {
        ErrorContextBuilder::default()
    }
}

/// Builder for constructing ErrorContext with validation.
#[derive(Default)]
pub struct ErrorContextBuilder {
    error_code: Option<String>,
    component: Option<String>,
    correlation_id: Option<String>,
    severity: Severity,
    remediation_hint: Option<String>,
    source: Option<BoxedError>,
}

impl fmt::Debug for ErrorContextBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ErrorContextBuilder")
            .field("error_code", &self.error_code)
            .field("component", &self.component)
            .field("correlation_id", &self.correlation_id)
            .field("severity", &self.severity)
            .field("remediation_hint", &self.remediation_hint)
            .field("source", &self.source.as_ref().map(|e| e.to_string()))
            .finish()
    }
}

impl ErrorContextBuilder {
    /// Set the error code (required).
    pub fn error_code(mut self, code: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self
    }

    /// Set the component name (required).
    pub fn component(mut self, component: impl Into<String>) -> Self {
        self.component = Some(component.into());
        self
    }

    /// Set the correlation ID for request tracing.
    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Set the severity level.
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Set an actionable remediation hint.
    pub fn remediation_hint(mut self, hint: impl Into<String>) -> Self {
        self.remediation_hint = Some(hint.into());
        self
    }

    /// Set the source error for error chaining.
    pub fn source(mut self, err: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Arc::new(err));
        self
    }

    /// Build the ErrorContext. Returns None if required fields are missing.
    pub fn build(self) -> Option<ErrorContext> {
        Some(ErrorContext {
            error_code: self.error_code?,
            component: self.component?,
            correlation_id: self.correlation_id,
            severity: self.severity,
            remediation_hint: self.remediation_hint,
            source: self.source,
        })
    }
}

/// Unified error type for all ASTRA_ operations.
///
/// Each variant carries full context for debugging and observability.
/// Display format: `[ASTRA-{CODE}] {message}` for grep-friendly logs.
///
/// Note: `PartialEq`/`Eq` are not derived because `ErrorContext` contains
/// an error source. Use `error_code()` for error identification in tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
#[allow(missing_docs)] // Variant fields documented at variant level
pub enum AstraError {
    /// Action blocked by policy rules.
    ///
    /// Fields: `context`, `policy_id`, `action`, `reason`
    PolicyDenied {
        context: ErrorContext,
        policy_id: String,
        action: String,
        reason: String,
    },

    /// Resource budget limit exceeded.
    ///
    /// Fields: `context`, `budget_type`, `limit`, `used`
    BudgetExceeded {
        context: ErrorContext,
        budget_type: BudgetType,
        limit: u64,
        used: u64,
    },

    /// Operation attempted outside sandbox permissions.
    ///
    /// Fields: `context`, `sandbox_tier`, `attempted_action`, `allowed_actions`
    SandboxViolation {
        context: ErrorContext,
        sandbox_tier: u8,
        attempted_action: String,
        allowed_actions: Vec<String>,
    },

    /// Capability input/output doesn't match contract.
    ///
    /// Fields: `context`, `capability_id`, `expected`, `actual`
    ContractMismatch {
        context: ErrorContext,
        capability_id: String,
        expected: String,
        actual: String,
    },

    /// Backend service unavailable.
    ///
    /// Fields: `context`, `backend_type`, `backend_id`, `reason`
    BackendUnavailable {
        context: ErrorContext,
        backend_type: String,
        backend_id: String,
        reason: String,
    },

    /// Model provider returned an error.
    ///
    /// Fields: `context`, `provider`, `status_code`, `message`
    ProviderError {
        context: ErrorContext,
        provider: String,
        status_code: Option<u16>,
        message: String,
    },

    /// Input validation failed.
    ///
    /// Fields: `context`, `field`, `message`
    ValidationFailed {
        context: ErrorContext,
        field: Option<String>,
        message: String,
    },

    /// Resource or state conflict.
    ///
    /// Fields: `context`, `resource_type`, `resource_id`, `description`
    Conflict {
        context: ErrorContext,
        resource_type: String,
        resource_id: String,
        description: String,
    },
}

impl AstraError {
    /// Extract the error context from any variant.
    pub fn context(&self) -> &ErrorContext {
        match self {
            Self::PolicyDenied { context, .. } => context,
            Self::BudgetExceeded { context, .. } => context,
            Self::SandboxViolation { context, .. } => context,
            Self::ContractMismatch { context, .. } => context,
            Self::BackendUnavailable { context, .. } => context,
            Self::ProviderError { context, .. } => context,
            Self::ValidationFailed { context, .. } => context,
            Self::Conflict { context, .. } => context,
        }
    }

    /// Get the error code for this error.
    pub fn error_code(&self) -> &str {
        &self.context().error_code
    }

    /// Get the severity level for this error.
    pub fn severity(&self) -> Severity {
        self.context().severity
    }

    /// Create a ValidationFailed error from an I/O error.
    ///
    /// The original I/O error is preserved and accessible via `source()`.
    pub fn from_io(err: std::io::Error, component: impl Into<String>) -> Self {
        let message = err.to_string();
        Self::ValidationFailed {
            context: ErrorContext {
                error_code: "VAL-001".into(),
                component: component.into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: Some("Check file permissions and path".into()),
                source: Some(Arc::new(err)),
            },
            field: None,
            message,
        }
    }

    /// Create a ValidationFailed error from a JSON error.
    ///
    /// The original JSON error is preserved and accessible via `source()`.
    pub fn from_json(err: serde_json::Error, component: impl Into<String>) -> Self {
        let message = err.to_string();
        Self::ValidationFailed {
            context: ErrorContext {
                error_code: "VAL-002".into(),
                component: component.into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: Some("Verify JSON structure matches expected schema".into()),
                source: Some(Arc::new(err)),
            },
            field: None,
            message,
        }
    }
}

impl fmt::Display for AstraError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = &self.context().error_code;
        match self {
            Self::PolicyDenied {
                policy_id,
                action,
                reason,
                ..
            } => {
                write!(
                    f,
                    "[ASTRA-{code}] policy '{policy_id}' denied action '{action}': {reason}"
                )
            }
            Self::BudgetExceeded {
                budget_type,
                limit,
                used,
                ..
            } => {
                write!(
                    f,
                    "[ASTRA-{code}] {budget_type} budget exceeded: used {used}, limit {limit}"
                )
            }
            Self::SandboxViolation {
                sandbox_tier,
                attempted_action,
                ..
            } => {
                write!(
                    f,
                    "[ASTRA-{code}] sandbox tier {sandbox_tier} violation: '{attempted_action}' not permitted"
                )
            }
            Self::ContractMismatch {
                capability_id,
                expected,
                actual,
                ..
            } => {
                write!(
                    f,
                    "[ASTRA-{code}] contract mismatch for '{capability_id}': expected {expected}, got {actual}"
                )
            }
            Self::BackendUnavailable {
                backend_type,
                backend_id,
                reason,
                ..
            } => {
                write!(
                    f,
                    "[ASTRA-{code}] {backend_type} backend '{backend_id}' unavailable: {reason}"
                )
            }
            Self::ProviderError {
                provider,
                status_code,
                message,
                ..
            } => {
                if let Some(http_code) = status_code {
                    write!(
                        f,
                        "[ASTRA-{code}] provider '{provider}' error (HTTP {http_code}): {message}"
                    )
                } else {
                    write!(f, "[ASTRA-{code}] provider '{provider}' error: {message}")
                }
            }
            Self::ValidationFailed { field, message, .. } => {
                if let Some(field) = field {
                    write!(
                        f,
                        "[ASTRA-{code}] validation failed for '{field}': {message}"
                    )
                } else {
                    write!(f, "[ASTRA-{code}] validation failed: {message}")
                }
            }
            Self::Conflict {
                resource_type,
                resource_id,
                description,
                ..
            } => {
                write!(
                    f,
                    "[ASTRA-{code}] conflict on {resource_type} '{resource_id}': {description}"
                )
            }
        }
    }
}

impl std::error::Error for AstraError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.context()
            .source
            .as_ref()
            .map(|s| s.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// Convenient Result type alias for ASTRA_ operations.
pub type Result<T> = std::result::Result<T, AstraError>;

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn severity_display() {
        assert_eq!(Severity::Critical.to_string(), "CRITICAL");
        assert_eq!(Severity::Error.to_string(), "ERROR");
        assert_eq!(Severity::Warning.to_string(), "WARNING");
        assert_eq!(Severity::Info.to_string(), "INFO");
    }

    #[test]
    fn severity_default() {
        assert_eq!(Severity::default(), Severity::Error);
    }

    #[test]
    fn budget_type_display() {
        assert_eq!(BudgetType::Tokens.to_string(), "tokens");
        assert_eq!(BudgetType::TimeMs.to_string(), "time_ms");
        assert_eq!(BudgetType::CostUsd.to_string(), "cost_usd");
        assert_eq!(BudgetType::Actions.to_string(), "actions");
    }

    #[test]
    fn error_context_builder() {
        let Some(ctx) = ErrorContext::builder()
            .error_code("POL-001")
            .component("astra-policy")
            .correlation_id("req-123")
            .severity(Severity::Critical)
            .remediation_hint("Check policy configuration")
            .build()
        else {
            panic!("builder should succeed with all required fields");
        };

        assert_eq!(ctx.error_code, "POL-001");
        assert_eq!(ctx.component, "astra-policy");
        assert_eq!(ctx.correlation_id, Some("req-123".into()));
        assert_eq!(ctx.severity, Severity::Critical);
        assert_eq!(
            ctx.remediation_hint,
            Some("Check policy configuration".into())
        );
        assert!(ctx.source.is_none());
    }

    #[test]
    fn error_context_builder_with_source() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let Some(ctx) = ErrorContext::builder()
            .error_code("VAL-001")
            .component("astra-types")
            .source(io_err)
            .build()
        else {
            panic!("builder should succeed");
        };

        assert!(ctx.source.is_some());
        assert!(ctx
            .source
            .as_ref()
            .is_some_and(|s| s.to_string().contains("file not found")));
    }

    #[test]
    fn error_context_builder_missing_required() {
        let result = ErrorContext::builder().error_code("POL-001").build();
        assert!(result.is_none(), "missing component should fail");

        let result = ErrorContext::builder().component("astra-policy").build();
        assert!(result.is_none(), "missing error_code should fail");
    }

    #[test]
    fn policy_denied_display() {
        let err = AstraError::PolicyDenied {
            context: ErrorContext {
                error_code: "POL-001".into(),
                component: "astra-policy".into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: None,
                source: None,
            },
            policy_id: "no-network".into(),
            action: "http_request".into(),
            reason: "network access denied in sandbox tier 1".into(),
        };

        let display = err.to_string();
        assert!(display.contains("[ASTRA-POL-001]"));
        assert!(display.contains("no-network"));
        assert!(display.contains("http_request"));
    }

    #[test]
    fn budget_exceeded_display() {
        let err = AstraError::BudgetExceeded {
            context: ErrorContext {
                error_code: "BUD-001".into(),
                component: "astra-runtime".into(),
                correlation_id: Some("task-456".into()),
                severity: Severity::Error,
                remediation_hint: Some("Request budget increase".into()),
                source: None,
            },
            budget_type: BudgetType::Tokens,
            limit: 10000,
            used: 12500,
        };

        let display = err.to_string();
        assert!(display.contains("[ASTRA-BUD-001]"));
        assert!(display.contains("tokens"));
        assert!(display.contains("12500"));
        assert!(display.contains("10000"));
    }

    #[test]
    fn sandbox_violation_display() {
        let err = AstraError::SandboxViolation {
            context: ErrorContext {
                error_code: "SBX-001".into(),
                component: "astra-sandbox".into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: None,
                source: None,
            },
            sandbox_tier: 1,
            attempted_action: "network_connect".into(),
            allowed_actions: vec!["file_read".into()],
        };

        let display = err.to_string();
        assert!(display.contains("[ASTRA-SBX-001]"));
        assert!(display.contains("tier 1"));
        assert!(display.contains("network_connect"));
    }

    #[test]
    fn contract_mismatch_display() {
        let err = AstraError::ContractMismatch {
            context: ErrorContext {
                error_code: "CON-001".into(),
                component: "astra-capability".into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: None,
                source: None,
            },
            capability_id: "repo.read".into(),
            expected: "string".into(),
            actual: "number".into(),
        };

        let display = err.to_string();
        assert!(display.contains("[ASTRA-CON-001]"));
        assert!(display.contains("repo.read"));
        assert!(display.contains("expected string"));
        assert!(display.contains("got number"));
    }

    #[test]
    fn backend_unavailable_display() {
        let err = AstraError::BackendUnavailable {
            context: ErrorContext {
                error_code: "BAK-001".into(),
                component: "astra-context".into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: None,
                source: None,
            },
            backend_type: "sqlite".into(),
            backend_id: "main-db".into(),
            reason: "connection refused".into(),
        };

        let display = err.to_string();
        assert!(display.contains("[ASTRA-BAK-001]"));
        assert!(display.contains("sqlite"));
        assert!(display.contains("main-db"));
        assert!(display.contains("connection refused"));
    }

    #[test]
    fn provider_error_with_status_display() {
        let err = AstraError::ProviderError {
            context: ErrorContext {
                error_code: "PRV-001".into(),
                component: "astra-gateway".into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: None,
                source: None,
            },
            provider: "openai".into(),
            status_code: Some(429),
            message: "rate limited".into(),
        };

        let display = err.to_string();
        assert!(display.contains("[ASTRA-PRV-001]"));
        assert!(display.contains("openai"));
        assert!(display.contains("HTTP 429"));
        assert!(display.contains("rate limited"));
    }

    #[test]
    fn provider_error_without_status_display() {
        let err = AstraError::ProviderError {
            context: ErrorContext {
                error_code: "PRV-002".into(),
                component: "astra-gateway".into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: None,
                source: None,
            },
            provider: "anthropic".into(),
            status_code: None,
            message: "timeout".into(),
        };

        let display = err.to_string();
        assert!(display.contains("[ASTRA-PRV-002]"));
        assert!(display.contains("anthropic"));
        assert!(!display.contains("HTTP"));
        assert!(display.contains("timeout"));
    }

    #[test]
    fn conflict_display() {
        let err = AstraError::Conflict {
            context: ErrorContext {
                error_code: "CFL-001".into(),
                component: "astra-persistence".into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: None,
                source: None,
            },
            resource_type: "artifact".into(),
            resource_id: "art-123".into(),
            description: "version mismatch".into(),
        };

        let display = err.to_string();
        assert!(display.contains("[ASTRA-CFL-001]"));
        assert!(display.contains("artifact"));
        assert!(display.contains("art-123"));
        assert!(display.contains("version mismatch"));
    }

    #[test]
    fn context_extraction() {
        let err = AstraError::ValidationFailed {
            context: ErrorContext {
                error_code: "VAL-001".into(),
                component: "astra-types".into(),
                correlation_id: Some("test-id".into()),
                severity: Severity::Warning,
                remediation_hint: None,
                source: None,
            },
            field: Some("name".into()),
            message: "cannot be empty".into(),
        };

        assert_eq!(err.error_code(), "VAL-001");
        assert_eq!(err.severity(), Severity::Warning);
        assert_eq!(err.context().component, "astra-types");
    }

    #[test]
    fn serialization_roundtrip() {
        let err = AstraError::ContractMismatch {
            context: ErrorContext {
                error_code: "CON-001".into(),
                component: "astra-capability".into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: Some("Update capability contract".into()),
                source: None,
            },
            capability_id: "repo.read".into(),
            expected: "string".into(),
            actual: "number".into(),
        };

        let Ok(json) = serde_json::to_string(&err) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<AstraError>(&json) else {
            panic!("deserialization should succeed");
        };

        // Compare by error code and variant fields (source is not serialized)
        assert_eq!(err.error_code(), decoded.error_code());
        let AstraError::ContractMismatch {
            capability_id,
            expected,
            actual,
            ..
        } = decoded
        else {
            panic!("expected ContractMismatch variant");
        };
        assert_eq!(capability_id, "repo.read");
        assert_eq!(expected, "string");
        assert_eq!(actual, "number");
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = AstraError::from_io(io_err, "astra-persistence");

        assert_eq!(err.error_code(), "VAL-001");
        assert!(err.to_string().contains("file not found"));

        // Verify error chaining works
        use std::error::Error;
        let source = err.source();
        assert!(source.is_some());
        assert!(source.is_some_and(|s| s.to_string().contains("file not found")));
    }

    #[test]
    fn from_json_error() {
        let Err(json_err) = serde_json::from_str::<String>("not valid json") else {
            panic!("invalid json should fail to parse");
        };
        let err = AstraError::from_json(json_err, "astra-types");

        assert_eq!(err.error_code(), "VAL-002");
        assert!(err.to_string().contains("validation failed"));

        // Verify error chaining works
        use std::error::Error;
        let source = err.source();
        assert!(source.is_some());
    }

    #[test]
    fn error_chain_traversal() {
        // Create a chain: AstraError -> io::Error
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied");
        let err = AstraError::from_io(io_err, "astra-persistence");

        // Traverse the chain
        use std::error::Error;
        let mut current: &dyn Error = &err;
        let mut chain = vec![current.to_string()];

        while let Some(source) = current.source() {
            chain.push(source.to_string());
            current = source;
        }

        assert_eq!(chain.len(), 2);
        assert!(chain[0].contains("ASTRA-VAL-001"));
        assert!(chain[1].contains("access denied"));
    }

    #[test]
    fn severity_serialization() {
        let Ok(json) = serde_json::to_string(&Severity::Critical) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"critical\"");

        let Ok(decoded) = serde_json::from_str::<Severity>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(decoded, Severity::Critical);
    }

    #[test]
    fn budget_type_serialization() {
        let Ok(json) = serde_json::to_string(&BudgetType::CostUsd) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"cost_usd\"");

        let Ok(decoded) = serde_json::from_str::<BudgetType>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(decoded, BudgetType::CostUsd);
    }
}
