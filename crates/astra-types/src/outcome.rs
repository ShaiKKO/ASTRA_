// SPDX-License-Identifier: MIT OR Apache-2.0
//! Outcome — the result of agent task execution.
//!
//! Every `TaskEnvelope` dispatched to an agent results in an `Outcome` containing
//! the execution status, produced artifacts, metrics, and suggested next actions.
//! Together, `TaskEnvelope` and `Outcome` define the agent communication protocol.
//!
//! # Design
//!
//! - `OutcomeStatus` captures nuanced completion states (not just success/failure)
//! - `OutcomeMetrics` provides measurements for observability and budget tracking
//! - Typed IDs (`TaskId`, `ArtifactId`) ensure compile-time safety
//! - Builder pattern for ergonomic construction
//!
//! # Example
//!
//! ```
//! use astra_types::{Outcome, OutcomeMetrics, OutcomeStatus, TaskId, ArtifactId};
//!
//! // Successful outcome
//! let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default())
//!     .with_summary("Implemented input validation for registration form")
//!     .with_artifacts(vec![ArtifactId::new()]);
//!
//! assert!(outcome.is_success());
//! assert!(!outcome.is_failure());
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::id::{ArtifactId, TaskId};

// ============================================================================
// OutcomeStatus enum
// ============================================================================

/// Status of task execution.
///
/// Four states capture the nuances of task completion:
/// - `Success`: All objectives met
/// - `Partial`: Some objectives met, but not all
/// - `Failed`: Task could not complete due to errors
/// - `Aborted`: Task was stopped by policy, budget limits, or operator intervention
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutcomeStatus {
    /// Task completed successfully - all objectives met.
    Success,
    /// Task partially completed - some objectives met but not all.
    Partial,
    /// Task failed to complete due to errors.
    Failed,
    /// Task was aborted by policy, budget, or operator.
    Aborted,
}

impl fmt::Display for OutcomeStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Partial => write!(f, "partial"),
            Self::Failed => write!(f, "failed"),
            Self::Aborted => write!(f, "aborted"),
        }
    }
}

// ============================================================================
// OutcomeMetrics struct
// ============================================================================

/// Execution metrics for observability and budget tracking.
///
/// Captures measurements from task execution for monitoring, debugging,
/// and budget enforcement.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct OutcomeMetrics {
    /// Wall-clock duration in milliseconds.
    pub duration_ms: u64,

    /// Total LLM tokens consumed (input + output).
    pub tokens_used: u64,

    /// Number of times policy blocked an action.
    pub policy_blocks: u32,

    /// Whether all validations passed.
    pub validation_passed: bool,

    /// Number of tool/capability invocations.
    #[serde(default)]
    pub actions_taken: u32,

    /// Estimated cost in USD.
    #[serde(default)]
    pub cost_usd: f64,
}

impl fmt::Display for OutcomeMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}ms, {} tokens, {} actions, ${:.4}",
            self.duration_ms, self.tokens_used, self.actions_taken, self.cost_usd
        )
    }
}

// ============================================================================
// OutcomeError struct
// ============================================================================

/// Error details for failed or aborted outcomes.
///
/// Provides structured information about what went wrong, including
/// whether the error might be recoverable with a retry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutcomeError {
    /// Error code (e.g., "ASTRA-POL-001").
    pub code: String,

    /// Human-readable error message.
    pub message: String,

    /// Whether this error is potentially recoverable.
    pub recoverable: bool,
}

impl OutcomeError {
    /// Create a new outcome error.
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::OutcomeError;
    ///
    /// let error = OutcomeError::new("ASTRA-POL-001", "Network access denied", false);
    /// assert!(!error.recoverable);
    /// ```
    pub fn new(code: impl Into<String>, message: impl Into<String>, recoverable: bool) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            recoverable,
        }
    }
}

// ============================================================================
// Outcome struct
// ============================================================================

/// Result of agent task execution.
///
/// Every `TaskEnvelope` dispatched to an agent eventually produces an `Outcome`
/// containing the status, any artifacts produced, metrics, and suggested next actions.
///
/// # Example
///
/// ```
/// use astra_types::{Outcome, OutcomeMetrics, OutcomeError, TaskId, ArtifactId};
///
/// // Create a successful outcome
/// let task_id = TaskId::new();
/// let outcome = Outcome::success(task_id, OutcomeMetrics {
///     duration_ms: 1500,
///     tokens_used: 2500,
///     actions_taken: 3,
///     cost_usd: 0.015,
///     ..Default::default()
/// })
/// .with_summary("Added input validation")
/// .with_artifacts(vec![ArtifactId::new()]);
///
/// assert!(outcome.is_success());
///
/// // Create a failed outcome
/// let error = OutcomeError::new("VAL-001", "Schema validation failed", true);
/// let failed = Outcome::failed(TaskId::new(), error, OutcomeMetrics::default());
/// assert!(failed.is_failure());
/// ```
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Outcome {
    /// ID of the task this outcome corresponds to.
    pub task_id: TaskId,

    /// Execution status.
    pub status: OutcomeStatus,

    /// Human-readable summary of what was accomplished.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,

    /// References to artifacts produced during execution.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactId>,

    /// Suggested follow-up actions or tasks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub next_actions: Vec<String>,

    /// Execution metrics for observability.
    pub metrics: OutcomeMetrics,

    /// Error details if status is Failed or Aborted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<OutcomeError>,
}

impl Outcome {
    /// Create a successful outcome.
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::{Outcome, OutcomeMetrics, TaskId};
    ///
    /// let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default());
    /// assert!(outcome.is_success());
    /// ```
    pub fn success(task_id: TaskId, metrics: OutcomeMetrics) -> Self {
        Self {
            task_id,
            status: OutcomeStatus::Success,
            summary: None,
            artifacts: Vec::new(),
            next_actions: Vec::new(),
            metrics,
            error: None,
        }
    }

    /// Create a partial completion outcome.
    ///
    /// Use when some objectives were met but not all.
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::{Outcome, OutcomeMetrics, TaskId};
    ///
    /// let outcome = Outcome::partial(TaskId::new(), OutcomeMetrics::default())
    ///     .with_summary("Completed 3 of 5 subtasks");
    /// assert!(outcome.is_partial());
    /// ```
    pub fn partial(task_id: TaskId, metrics: OutcomeMetrics) -> Self {
        Self {
            task_id,
            status: OutcomeStatus::Partial,
            summary: None,
            artifacts: Vec::new(),
            next_actions: Vec::new(),
            metrics,
            error: None,
        }
    }

    /// Create a failed outcome with error details.
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::{Outcome, OutcomeMetrics, OutcomeError, TaskId};
    ///
    /// let error = OutcomeError::new("COMPILE-001", "Build failed", true);
    /// let outcome = Outcome::failed(TaskId::new(), error, OutcomeMetrics::default());
    /// assert!(outcome.is_failure());
    /// assert!(outcome.error.is_some());
    /// ```
    pub fn failed(task_id: TaskId, error: OutcomeError, metrics: OutcomeMetrics) -> Self {
        Self {
            task_id,
            status: OutcomeStatus::Failed,
            summary: None,
            artifacts: Vec::new(),
            next_actions: Vec::new(),
            metrics,
            error: Some(error),
        }
    }

    /// Create an aborted outcome with a reason.
    ///
    /// The error is automatically created with code "ASTRA-ABORT-001"
    /// and marked as non-recoverable.
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::{Outcome, OutcomeMetrics, TaskId};
    ///
    /// let outcome = Outcome::aborted(
    ///     TaskId::new(),
    ///     "Budget limit exceeded",
    ///     OutcomeMetrics::default()
    /// );
    /// assert!(outcome.is_failure());
    /// ```
    pub fn aborted(task_id: TaskId, reason: impl Into<String>, metrics: OutcomeMetrics) -> Self {
        Self {
            task_id,
            status: OutcomeStatus::Aborted,
            summary: None,
            artifacts: Vec::new(),
            next_actions: Vec::new(),
            metrics,
            error: Some(OutcomeError {
                code: "ASTRA-ABORT-001".to_string(),
                message: reason.into(),
                recoverable: false,
            }),
        }
    }

    /// Add a summary describing what was accomplished (chainable).
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::{Outcome, OutcomeMetrics, TaskId};
    ///
    /// let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default())
    ///     .with_summary("Refactored authentication module");
    /// assert!(outcome.summary.is_some());
    /// ```
    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    /// Set the artifacts produced during execution (chainable).
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::{Outcome, OutcomeMetrics, TaskId, ArtifactId};
    ///
    /// let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default())
    ///     .with_artifacts(vec![ArtifactId::new(), ArtifactId::new()]);
    /// assert_eq!(outcome.artifacts.len(), 2);
    /// ```
    pub fn with_artifacts(mut self, artifacts: Vec<ArtifactId>) -> Self {
        self.artifacts = artifacts;
        self
    }

    /// Set suggested follow-up actions (chainable).
    ///
    /// # Example
    ///
    /// ```
    /// use astra_types::{Outcome, OutcomeMetrics, TaskId};
    ///
    /// let outcome = Outcome::partial(TaskId::new(), OutcomeMetrics::default())
    ///     .with_next_actions(vec![
    ///         "Run integration tests".to_string(),
    ///         "Update documentation".to_string(),
    ///     ]);
    /// assert_eq!(outcome.next_actions.len(), 2);
    /// ```
    pub fn with_next_actions(mut self, actions: Vec<String>) -> Self {
        self.next_actions = actions;
        self
    }

    /// Check if this outcome represents success.
    pub fn is_success(&self) -> bool {
        self.status == OutcomeStatus::Success
    }

    /// Check if this outcome represents partial completion.
    pub fn is_partial(&self) -> bool {
        self.status == OutcomeStatus::Partial
    }

    /// Check if this outcome represents any form of failure.
    ///
    /// Returns `true` for both `Failed` and `Aborted` statuses.
    pub fn is_failure(&self) -> bool {
        matches!(self.status, OutcomeStatus::Failed | OutcomeStatus::Aborted)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    // ========================================================================
    // Constructor tests
    // ========================================================================

    #[test]
    fn outcome_success_constructor() {
        let task_id = TaskId::new();
        let outcome = Outcome::success(task_id, OutcomeMetrics::default());

        assert_eq!(outcome.status, OutcomeStatus::Success);
        assert!(outcome.error.is_none());
        assert!(outcome.summary.is_none());
        assert!(outcome.artifacts.is_empty());
        assert!(outcome.next_actions.is_empty());
    }

    #[test]
    fn outcome_partial_constructor() {
        let task_id = TaskId::new();
        let outcome = Outcome::partial(task_id, OutcomeMetrics::default());

        assert_eq!(outcome.status, OutcomeStatus::Partial);
        assert!(outcome.error.is_none());
    }

    #[test]
    fn outcome_failed_constructor() {
        let task_id = TaskId::new();
        let error = OutcomeError::new("TEST-001", "Test error", true);
        let outcome = Outcome::failed(task_id, error, OutcomeMetrics::default());

        assert_eq!(outcome.status, OutcomeStatus::Failed);
        let Some(err) = outcome.error.as_ref() else {
            panic!("expected error to be present");
        };
        assert_eq!(err.code, "TEST-001");
        assert_eq!(err.message, "Test error");
        assert!(err.recoverable);
    }

    #[test]
    fn outcome_aborted_constructor() {
        let task_id = TaskId::new();
        let outcome = Outcome::aborted(task_id, "Budget exceeded", OutcomeMetrics::default());

        assert_eq!(outcome.status, OutcomeStatus::Aborted);
        let Some(err) = outcome.error.as_ref() else {
            panic!("expected error to be present");
        };
        assert_eq!(err.code, "ASTRA-ABORT-001");
        assert_eq!(err.message, "Budget exceeded");
        assert!(!err.recoverable);
    }

    #[test]
    fn outcome_metrics_default() {
        let metrics = OutcomeMetrics::default();

        assert_eq!(metrics.duration_ms, 0);
        assert_eq!(metrics.tokens_used, 0);
        assert_eq!(metrics.policy_blocks, 0);
        assert!(!metrics.validation_passed);
        assert_eq!(metrics.actions_taken, 0);
        assert!((metrics.cost_usd - 0.0).abs() < f64::EPSILON);
    }

    // ========================================================================
    // Builder chain tests
    // ========================================================================

    #[test]
    fn outcome_with_summary() {
        let outcome =
            Outcome::success(TaskId::new(), OutcomeMetrics::default()).with_summary("Test summary");

        assert_eq!(outcome.summary, Some("Test summary".into()));
    }

    #[test]
    fn outcome_with_artifacts() {
        let artifacts = vec![ArtifactId::new(), ArtifactId::new()];
        let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default())
            .with_artifacts(artifacts.clone());

        assert_eq!(outcome.artifacts.len(), 2);
        assert_eq!(outcome.artifacts, artifacts);
    }

    #[test]
    fn outcome_with_next_actions() {
        let actions = vec!["Action 1".to_string(), "Action 2".to_string()];
        let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default())
            .with_next_actions(actions.clone());

        assert_eq!(outcome.next_actions, actions);
    }

    #[test]
    fn outcome_full_builder_chain() {
        let task_id = TaskId::new();
        let artifacts = vec![ArtifactId::new()];
        let actions = vec!["Next task".to_string()];

        let outcome = Outcome::success(
            task_id,
            OutcomeMetrics {
                duration_ms: 1000,
                tokens_used: 500,
                actions_taken: 2,
                ..Default::default()
            },
        )
        .with_summary("Did something")
        .with_artifacts(artifacts)
        .with_next_actions(actions);

        assert_eq!(outcome.summary, Some("Did something".into()));
        assert_eq!(outcome.artifacts.len(), 1);
        assert_eq!(outcome.next_actions.len(), 1);
        assert_eq!(outcome.metrics.duration_ms, 1000);
    }

    // ========================================================================
    // Helper method tests
    // ========================================================================

    #[test]
    fn is_success_true_for_success() {
        let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default());
        assert!(outcome.is_success());
    }

    #[test]
    fn is_success_false_for_others() {
        let partial = Outcome::partial(TaskId::new(), OutcomeMetrics::default());
        let failed = Outcome::failed(
            TaskId::new(),
            OutcomeError::new("E", "e", false),
            OutcomeMetrics::default(),
        );
        let aborted = Outcome::aborted(TaskId::new(), "reason", OutcomeMetrics::default());

        assert!(!partial.is_success());
        assert!(!failed.is_success());
        assert!(!aborted.is_success());
    }

    #[test]
    fn is_partial_true_for_partial() {
        let outcome = Outcome::partial(TaskId::new(), OutcomeMetrics::default());
        assert!(outcome.is_partial());
    }

    #[test]
    fn is_partial_false_for_others() {
        let success = Outcome::success(TaskId::new(), OutcomeMetrics::default());
        let failed = Outcome::failed(
            TaskId::new(),
            OutcomeError::new("E", "e", false),
            OutcomeMetrics::default(),
        );
        let aborted = Outcome::aborted(TaskId::new(), "reason", OutcomeMetrics::default());

        assert!(!success.is_partial());
        assert!(!failed.is_partial());
        assert!(!aborted.is_partial());
    }

    #[test]
    fn is_failure_true_for_failed_and_aborted() {
        let failed = Outcome::failed(
            TaskId::new(),
            OutcomeError::new("E", "e", false),
            OutcomeMetrics::default(),
        );
        let aborted = Outcome::aborted(TaskId::new(), "reason", OutcomeMetrics::default());

        assert!(failed.is_failure());
        assert!(aborted.is_failure());
    }

    #[test]
    fn is_failure_false_for_success_and_partial() {
        let success = Outcome::success(TaskId::new(), OutcomeMetrics::default());
        let partial = Outcome::partial(TaskId::new(), OutcomeMetrics::default());

        assert!(!success.is_failure());
        assert!(!partial.is_failure());
    }

    // ========================================================================
    // Serde tests
    // ========================================================================

    #[test]
    fn outcome_status_serializes_lowercase() {
        let Ok(json) = serde_json::to_string(&OutcomeStatus::Success) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"success\"");

        let Ok(json) = serde_json::to_string(&OutcomeStatus::Partial) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"partial\"");

        let Ok(json) = serde_json::to_string(&OutcomeStatus::Failed) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"failed\"");

        let Ok(json) = serde_json::to_string(&OutcomeStatus::Aborted) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"aborted\"");
    }

    #[test]
    fn outcome_roundtrip_all_fields() {
        let outcome = Outcome {
            task_id: TaskId::new(),
            status: OutcomeStatus::Success,
            summary: Some("Test summary".into()),
            artifacts: vec![ArtifactId::new()],
            next_actions: vec!["Next".into()],
            metrics: OutcomeMetrics {
                duration_ms: 100,
                tokens_used: 200,
                policy_blocks: 1,
                validation_passed: true,
                actions_taken: 3,
                cost_usd: 0.05,
            },
            error: None,
        };

        let Ok(json) = serde_json::to_string(&outcome) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<Outcome>(&json) else {
            panic!("deserialization should succeed");
        };

        assert_eq!(outcome.task_id, decoded.task_id);
        assert_eq!(outcome.status, decoded.status);
        assert_eq!(outcome.summary, decoded.summary);
        assert_eq!(outcome.artifacts, decoded.artifacts);
        assert_eq!(outcome.next_actions, decoded.next_actions);
    }

    #[test]
    fn outcome_roundtrip_minimal_fields() {
        let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default());

        let Ok(json) = serde_json::to_string(&outcome) else {
            panic!("serialization should succeed");
        };

        // Verify skip_serializing_if works
        assert!(!json.contains("summary"));
        assert!(!json.contains("artifacts"));
        assert!(!json.contains("next_actions"));
        assert!(!json.contains("error"));

        let Ok(decoded) = serde_json::from_str::<Outcome>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(outcome.status, decoded.status);
    }

    #[test]
    fn outcome_metrics_roundtrip() {
        let metrics = OutcomeMetrics {
            duration_ms: 1500,
            tokens_used: 3000,
            policy_blocks: 2,
            validation_passed: true,
            actions_taken: 5,
            cost_usd: 0.123,
        };

        let Ok(json) = serde_json::to_string(&metrics) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<OutcomeMetrics>(&json) else {
            panic!("deserialization should succeed");
        };

        assert_eq!(metrics.duration_ms, decoded.duration_ms);
        assert_eq!(metrics.tokens_used, decoded.tokens_used);
        assert_eq!(metrics.policy_blocks, decoded.policy_blocks);
        assert_eq!(metrics.validation_passed, decoded.validation_passed);
        assert_eq!(metrics.actions_taken, decoded.actions_taken);
        assert!((metrics.cost_usd - decoded.cost_usd).abs() < f64::EPSILON);
    }

    #[test]
    fn outcome_error_roundtrip() {
        let error = OutcomeError::new("TEST-001", "Test message", true);

        let Ok(json) = serde_json::to_string(&error) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<OutcomeError>(&json) else {
            panic!("deserialization should succeed");
        };

        assert_eq!(error, decoded);
    }

    #[test]
    fn task_id_serializes_as_uuid() {
        let task_id = TaskId::new();
        let outcome = Outcome::success(task_id, OutcomeMetrics::default());

        let Ok(json) = serde_json::to_string(&outcome) else {
            panic!("serialization should succeed");
        };

        // TaskId should appear as UUID string
        assert!(json.contains(&task_id.to_string()));
    }

    #[test]
    fn artifact_id_serializes_as_uuid() {
        let artifact_id = ArtifactId::new();
        let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default())
            .with_artifacts(vec![artifact_id]);

        let Ok(json) = serde_json::to_string(&outcome) else {
            panic!("serialization should succeed");
        };

        // ArtifactId should appear as UUID string
        assert!(json.contains(&artifact_id.to_string()));
    }

    #[test]
    fn empty_artifacts_omitted() {
        let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default());

        let Ok(json) = serde_json::to_string(&outcome) else {
            panic!("serialization should succeed");
        };

        assert!(!json.contains("\"artifacts\""));
    }

    #[test]
    fn empty_next_actions_omitted() {
        let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default());

        let Ok(json) = serde_json::to_string(&outcome) else {
            panic!("serialization should succeed");
        };

        assert!(!json.contains("\"next_actions\""));
    }

    #[test]
    fn null_summary_omitted() {
        let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default());

        let Ok(json) = serde_json::to_string(&outcome) else {
            panic!("serialization should succeed");
        };

        assert!(!json.contains("\"summary\""));
    }

    // ========================================================================
    // Display tests
    // ========================================================================

    #[test]
    fn outcome_status_display_all_variants() {
        assert_eq!(OutcomeStatus::Success.to_string(), "success");
        assert_eq!(OutcomeStatus::Partial.to_string(), "partial");
        assert_eq!(OutcomeStatus::Failed.to_string(), "failed");
        assert_eq!(OutcomeStatus::Aborted.to_string(), "aborted");
    }

    #[test]
    fn outcome_metrics_display_format() {
        let metrics = OutcomeMetrics {
            duration_ms: 1500,
            tokens_used: 2000,
            actions_taken: 5,
            cost_usd: 0.0234,
            ..Default::default()
        };

        let display = metrics.to_string();
        assert!(display.contains("1500ms"));
        assert!(display.contains("2000 tokens"));
        assert!(display.contains("5 actions"));
        assert!(display.contains("$0.0234"));
    }

    // ========================================================================
    // Hash tests
    // ========================================================================

    #[test]
    fn outcome_status_hash_key() {
        use std::collections::HashSet;

        let mut set = HashSet::new();
        set.insert(OutcomeStatus::Success);
        set.insert(OutcomeStatus::Failed);
        set.insert(OutcomeStatus::Success); // Duplicate

        assert_eq!(set.len(), 2);
    }

    // ========================================================================
    // Edge case tests
    // ========================================================================

    #[test]
    fn outcome_with_empty_artifacts_valid() {
        let outcome =
            Outcome::success(TaskId::new(), OutcomeMetrics::default()).with_artifacts(vec![]);

        assert!(outcome.artifacts.is_empty());
    }

    #[test]
    fn outcome_with_empty_next_actions_valid() {
        let outcome =
            Outcome::success(TaskId::new(), OutcomeMetrics::default()).with_next_actions(vec![]);

        assert!(outcome.next_actions.is_empty());
    }

    #[test]
    fn outcome_error_with_empty_message() {
        let error = OutcomeError::new("CODE", "", false);
        assert_eq!(error.message, "");
    }

    #[test]
    fn outcome_metrics_with_zero_values() {
        let metrics = OutcomeMetrics {
            duration_ms: 0,
            tokens_used: 0,
            policy_blocks: 0,
            validation_passed: false,
            actions_taken: 0,
            cost_usd: 0.0,
        };

        // Should be valid and serializable
        let Ok(_json) = serde_json::to_string(&metrics) else {
            panic!("serialization should succeed");
        };
    }

    // ========================================================================
    // Integration tests
    // ========================================================================

    #[test]
    fn outcome_with_real_task_id() {
        let task_id = TaskId::new();
        let outcome = Outcome::success(task_id, OutcomeMetrics::default());

        // Verify the task_id is preserved
        assert_eq!(outcome.task_id, task_id);
        assert_eq!(outcome.task_id.as_uuid().get_version_num(), 4);
    }

    #[test]
    fn outcome_with_real_artifact_ids() {
        let art1 = ArtifactId::new();
        let art2 = ArtifactId::new();
        let outcome = Outcome::success(TaskId::new(), OutcomeMetrics::default())
            .with_artifacts(vec![art1, art2]);

        assert_eq!(outcome.artifacts.len(), 2);
        assert_eq!(outcome.artifacts[0].as_uuid().get_version_num(), 4);
        assert_eq!(outcome.artifacts[1].as_uuid().get_version_num(), 4);
    }

    #[test]
    fn outcome_error_new_constructor() {
        let error = OutcomeError::new("ASTRA-POL-001", "Policy denied", false);

        assert_eq!(error.code, "ASTRA-POL-001");
        assert_eq!(error.message, "Policy denied");
        assert!(!error.recoverable);
    }

    #[test]
    fn outcome_status_all_variants_distinct() {
        let statuses = [
            OutcomeStatus::Success,
            OutcomeStatus::Partial,
            OutcomeStatus::Failed,
            OutcomeStatus::Aborted,
        ];

        // All should be different
        for (i, s1) in statuses.iter().enumerate() {
            for (j, s2) in statuses.iter().enumerate() {
                if i == j {
                    assert_eq!(s1, s2);
                } else {
                    assert_ne!(s1, s2);
                }
            }
        }
    }
}
