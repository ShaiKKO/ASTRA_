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
    /// Formats the severity as an uppercase ASCII label (`CRITICAL`, `ERROR`, `WARNING`, `INFO`).
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::error::Severity;
    /// assert_eq!(format!("{}", Severity::Warning), "WARNING");
    /// ```
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
    /// Estimated cost in USD (microdollars for precision).
    CostUsd,
    /// Number of discrete actions taken.
    Actions,
}

impl fmt::Display for BudgetType {
    /// Formats the `BudgetType` as its lowercase, snake_case identifier.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::error::BudgetType;
    /// assert_eq!(format!("{}", BudgetType::Tokens), "tokens");
    /// assert_eq!(format!("{}", BudgetType::TimeMs), "time_ms");
    /// assert_eq!(format!("{}", BudgetType::CostUsd), "cost_usd");
    /// assert_eq!(format!("{}", BudgetType::Actions), "actions");
    /// ```
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
}

impl Default for ErrorContext {
    /// Creates a default `ErrorContext` with empty `error_code` and `component`, `None` for
    /// `correlation_id` and `remediation_hint`, and `severity` set to `Severity::Error`.
    ///
    /// # Examples
    ///
    /// ```
    /// let ctx = ErrorContext::default();
    /// assert_eq!(ctx.error_code, "");
    /// assert_eq!(ctx.component, "");
    /// assert_eq!(ctx.correlation_id, None);
    /// assert_eq!(ctx.remediation_hint, None);
    /// assert_eq!(ctx.severity, Severity::Error);
    /// ```
    fn default() -> Self {
        Self {
            error_code: String::new(),
            component: String::new(),
            correlation_id: None,
            severity: Severity::Error,
            remediation_hint: None,
        }
    }
}

impl ErrorContext {
    /// Creates a new `ErrorContextBuilder` to construct an `ErrorContext`.
    ///
    /// # Examples
    ///
    /// ```
    /// let ctx = astra_types::error::ErrorContext::builder()
    ///     .error_code("GEN-000")
    ///     .component("ingest")
    ///     .severity(astra_types::error::Severity::Warning)
    ///     .remediation_hint("Retry the request")
    ///     .build()
    ///     .expect("required fields set");
    /// assert_eq!(ctx.error_code, "GEN-000");
    /// assert_eq!(ctx.component, "ingest");
    /// ```
    pub fn builder() -> ErrorContextBuilder {
        ErrorContextBuilder::default()
    }
}

/// Builder for constructing ErrorContext with validation.
#[derive(Debug, Default)]
pub struct ErrorContextBuilder {
    error_code: Option<String>,
    component: Option<String>,
    correlation_id: Option<String>,
    severity: Severity,
    remediation_hint: Option<String>,
}

impl ErrorContextBuilder {
    /// Sets the builder's error code.
    ///
    /// The provided code becomes the `error_code` of the resulting `ErrorContext` and is required
    /// for `build()` to succeed. Accepts any value convertible to `String` and returns the builder
    /// to allow method chaining.
    ///
    /// # Examples
    ///
    /// ```
    /// let ctx = ErrorContext::builder()
    ///     .error_code("VAL-001")
    ///     .component("parser")
    ///     .build()
    ///     .expect("missing required fields");
    /// assert_eq!(ctx.error_code, "VAL-001");
    /// ```
    pub fn error_code(mut self, code: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self
    }

    /// Sets the component name on the builder; this field is required for `build()` to succeed.
    ///
    /// # Examples
    ///
    /// ```
    /// let b = ErrorContext::builder().error_code("VAL-001").component("auth");
    /// let ctx = b.build().unwrap();
    /// assert_eq!(ctx.component, "auth");
    /// ```
    pub fn component(mut self, component: impl Into<String>) -> Self {
        self.component = Some(component.into());
        self
    }

    /// Sets the correlation ID used for request tracing and returns the builder.
    ///
    /// # Examples
    ///
    /// ```
    /// let ctx = crate::ErrorContext::builder()
    ///     .error_code("GEN-001")
    ///     .component("auth")
    ///     .correlation_id("req-123")
    ///     .build()
    ///     .unwrap();
    ///
    /// assert_eq!(ctx.correlation_id.as_deref(), Some("req-123"));
    /// ```
    pub fn correlation_id(mut self, id: impl Into<String>) -> Self {
        self.correlation_id = Some(id.into());
        self
    }

    /// Set the diagnostic severity for the `ErrorContext` being built.
    ///
    /// By default the builder uses `Severity::Error`; calling this overrides that default.
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::error::{ErrorContext, ErrorContextBuilder, Severity};
    ///
    /// let ctx = ErrorContext::builder()
    ///     .error_code("GEN-001")
    ///     .component("auth")
    ///     .severity(Severity::Critical)
    ///     .build()
    ///     .expect("required fields set");
    ///
    /// assert_eq!(ctx.severity, Severity::Critical);
    /// ```
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = severity;
        self
    }

    /// Sets the remediation hint to guide operators or callers and returns the builder for chaining.
    ///
    /// # Examples
    ///
    /// ```
    /// let ctx = ErrorContext::builder()
    ///     .error_code("VAL-001")
    ///     .component("io")
    ///     .remediation_hint("Check file permissions")
    ///     .build()
    ///     .unwrap();
    /// assert_eq!(ctx.remediation_hint.as_deref(), Some("Check file permissions"));
    /// ```
    pub fn remediation_hint(mut self, hint: impl Into<String>) -> Self {
        self.remediation_hint = Some(hint.into());
        self
    }

    /// Constructs an ErrorContext when the builder contains the required fields.
    ///
    /// Returns `Some(ErrorContext)` when both `error_code` and `component` were set on the builder, otherwise `None`.
    ///
    /// # Examples
    ///
    /// ```
    /// let ctx = ErrorContext::builder()
    ///     .error_code("VAL-001")
    ///     .component("parser")
    ///     .build()
    ///     .expect("builder should produce context");
    /// assert_eq!(ctx.error_code, "VAL-001");
    /// assert_eq!(ctx.component, "parser");
    /// ```
    pub fn build(self) -> Option<ErrorContext> {
        Some(ErrorContext {
            error_code: self.error_code?,
            component: self.component?,
            correlation_id: self.correlation_id,
            severity: self.severity,
            remediation_hint: self.remediation_hint,
        })
    }
}

/// Unified error type for all ASTRA_ operations.
///
/// Each variant carries full context for debugging and observability.
/// Display format: `[ASTRA-{CODE}] {message}` for grep-friendly logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Returns a reference to the `ErrorContext` embedded in the error.
    ///
    /// # Examples
    ///
    /// ```
    /// let ctx = ErrorContext::builder()
    ///     .error_code("GEN-001")
    ///     .component("auth")
    ///     .build()
    ///     .unwrap();
    ///
    /// let err = AstraError::ValidationFailed {
    ///     context: ctx,
    ///     field: Some("email".into()),
    ///     message: "invalid format".into(),
    /// };
    ///
    /// assert_eq!(err.context().component, "auth");
    /// ```
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

    /// Retrieve the error code from the error's embedded context.
    ///
    /// # Returns
    ///
    /// `&str` slice containing the error code.
    ///
    /// # Examples
    ///
    /// ```
    /// let ctx = ErrorContext::builder()
    ///     .error_code("VAL-001")
    ///     .component("parser")
    ///     .build()
    ///     .unwrap();
    /// let err = AstraError::ValidationFailed { context: ctx, field: None, message: "invalid".into() };
    /// assert_eq!(err.error_code(), "VAL-001");
    /// ```
    pub fn error_code(&self) -> &str {
        &self.context().error_code
    }

    /// Retrieve the diagnostic severity associated with the error.
    ///
    /// # Returns
    ///
    /// `Severity` for this error.
    ///
    /// # Examples
    ///
    /// ```
    /// let err = AstraError::ValidationFailed {
    ///     context: ErrorContext::builder()
    ///         .error_code("VAL-001")
    ///         .component("parser")
    ///         .build()
    ///         .unwrap(),
    ///     field: None,
    ///     message: "io error".into(),
    /// };
    /// assert_eq!(err.severity(), Severity::Error);
    /// ```
    pub fn severity(&self) -> Severity {
        self.context().severity
    }

    /// Constructs an `AstraError::ValidationFailed` from an I/O error for the specified component.
    ///
    /// The produced error carries a validation error code and a remediation hint appropriate for I/O failures.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io;
    /// let io_err = io::Error::new(io::ErrorKind::NotFound, "file missing");
    /// let err = crate::AstraError::from_io(io_err, "storage");
    /// match err {
    ///     crate::AstraError::ValidationFailed { context, field: None, message } => {
    ///         assert_eq!(context.error_code, "VAL-001");
    ///         assert_eq!(context.component, "storage");
    ///         assert!(message.contains("file missing"));
    ///     }
    ///     _ => panic!("expected ValidationFailed"),
    /// }
    /// ```
    pub fn from_io(err: std::io::Error, component: impl Into<String>) -> Self {
        Self::ValidationFailed {
            context: ErrorContext {
                error_code: "VAL-001".into(),
                component: component.into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: Some("Check file permissions and path".into()),
            },
            field: None,
            message: err.to_string(),
        }
    }

    /// Constructs an `AstraError::ValidationFailed` from a `serde_json::Error`.
    ///
    /// The created error embeds an `ErrorContext` with the error code `VAL-002`,
    /// severity `Error`, and a remediation hint instructing to verify the JSON
    /// structure.
    ///
    /// # Parameters
    ///
    /// - `err`: the JSON parsing error whose message will be used as the validation message.
    /// - `component`: identifier of the component that produced the error; stored in the error context.
    ///
    /// # Returns
    ///
    /// An `AstraError::ValidationFailed` containing the JSON error message and an `ErrorContext` with `error_code = "VAL-002"`.
    ///
    /// # Examples
    ///
    /// ```
    /// let json_err = serde_json::from_str::<serde_json::Value>("invalid").unwrap_err();
    /// let ae = crate::AstraError::from_json(json_err, "parser");
    /// match ae {
    ///     crate::AstraError::ValidationFailed { context, message, .. } => {
    ///         assert_eq!(context.error_code, "VAL-002");
    ///         assert!(message.contains("expected value"));
    ///     }
    ///     _ => panic!("unexpected variant"),
    /// }
    /// ```
    pub fn from_json(err: serde_json::Error, component: impl Into<String>) -> Self {
        Self::ValidationFailed {
            context: ErrorContext {
                error_code: "VAL-002".into(),
                component: component.into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: Some("Verify JSON structure matches expected schema".into()),
            },
            field: None,
            message: err.to_string(),
        }
    }
}

impl fmt::Display for AstraError {
    /// Formats an `AstraError` into a compact, grep-friendly, human-readable message.
    ///
    /// The output is prefixed with the error code in the form `[ASTRA-{CODE}]` and includes
    /// variant-specific details (e.g., policy id and action for policy denials, budget type and values
    /// for budget exceeded, provider and optional HTTP code for provider errors, etc.).
    ///
    /// # Examples
    ///
    /// ```
    /// use crate::{AstraError, ErrorContext};
    ///
    /// let ctx = ErrorContext::builder()
    ///     .error_code("VAL-001")
    ///     .component("validator")
    ///     .build()
    ///     .unwrap();
    ///
    /// let err = AstraError::ValidationFailed {
    ///     context: ctx,
    ///     field: Some("email".into()),
    ///     message: "missing '@'".into(),
    /// };
    ///
    /// let s = format!("{}", err);
    /// assert!(s.contains("[ASTRA-VAL-001]"));
    /// assert!(s.contains("validation failed"));
    /// assert!(s.contains("email"));
    /// ```
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

impl std::error::Error for AstraError {}

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
    fn context_extraction() {
        let err = AstraError::ValidationFailed {
            context: ErrorContext {
                error_code: "VAL-001".into(),
                component: "astra-types".into(),
                correlation_id: Some("test-id".into()),
                severity: Severity::Warning,
                remediation_hint: None,
            },
            field: Some("name".into()),
            message: "cannot be empty".into(),
        };

        assert_eq!(err.error_code(), "VAL-001");
        assert_eq!(err.severity(), Severity::Warning);
        assert_eq!(err.context().component, "astra-types");
    }

    /// Verifies that a `ContractMismatch` error round-trips through JSON serialization.
    ///
    /// Serializes an `AstraError::ContractMismatch` to JSON and ensures deserializing produces an equal value.
    ///
    /// # Examples
    ///
    /// ```
    /// let err = AstraError::ContractMismatch {
    ///     context: ErrorContext {
    ///         error_code: "CON-001".into(),
    ///         component: "astra-capability".into(),
    ///         correlation_id: None,
    ///         severity: Severity::Error,
    ///         remediation_hint: Some("Update capability contract".into()),
    ///     },
    ///     capability_id: "repo.read".into(),
    ///     expected: "string".into(),
    ///     actual: "number".into(),
    /// };
    ///
    /// let json = serde_json::to_string(&err).unwrap();
    /// let decoded: AstraError = serde_json::from_str(&json).unwrap();
    /// assert_eq!(err, decoded);
    /// ```
    #[test]
    fn serialization_roundtrip() {
        let err = AstraError::ContractMismatch {
            context: ErrorContext {
                error_code: "CON-001".into(),
                component: "astra-capability".into(),
                correlation_id: None,
                severity: Severity::Error,
                remediation_hint: Some("Update capability contract".into()),
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

        assert_eq!(err, decoded);
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err = AstraError::from_io(io_err, "astra-persistence");

        assert_eq!(err.error_code(), "VAL-001");
        assert!(err.to_string().contains("file not found"));
    }

    #[test]
    fn from_json_error() {
        let Err(json_err) = serde_json::from_str::<String>("not valid json") else {
            panic!("invalid json should fail to parse");
        };
        let err = AstraError::from_json(json_err, "astra-types");

        assert_eq!(err.error_code(), "VAL-002");
        assert!(err.to_string().contains("validation failed"));
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