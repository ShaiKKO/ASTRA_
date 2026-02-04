// SPDX-License-Identifier: MIT OR Apache-2.0
//! TaskEnvelope — the fundamental unit of work assignment in ASTRA_.
//!
//! Every task dispatched to an agent is wrapped in a TaskEnvelope containing
//! the goal, budget limits, constraints, and references to context/artifacts.
//!
//! # Design
//!
//! - Strongly typed fields catch errors at compile time
//! - Builder pattern for ergonomic construction with validation
//! - Sensible defaults for Budget (not unlimited) and Constraints (default-deny)
//!
//! # Example
//!
//! ```
//! use astra_types::{TaskEnvelope, Budget, Constraints};
//!
//! let task = TaskEnvelope::builder()
//!     .id("task-001")
//!     .task_type("implement")
//!     .goal("Add input validation to registration form")
//!     .workspace("my-project")
//!     .build();
//! ```

use serde::{Deserialize, Serialize};

use crate::error::{AstraError, ErrorContext, Severity};

/// Resource budget for task execution.
///
/// All fields have sensible defaults that prevent runaway consumption
/// while allowing reasonable work to complete.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Budget {
    /// Maximum tokens (LLM input + output combined).
    #[serde(default = "Budget::default_tokens")]
    pub tokens: u64,

    /// Maximum wall-clock time in milliseconds.
    #[serde(default = "Budget::default_time_ms")]
    pub time_ms: u64,

    /// Maximum estimated cost in USD.
    #[serde(default = "Budget::default_cost_usd")]
    pub cost_usd: f64,

    /// Maximum discrete actions (tool calls, file writes, etc.).
    #[serde(default = "Budget::default_max_actions")]
    pub max_actions: u32,
}

impl Budget {
    fn default_tokens() -> u64 {
        100_000
    }
    fn default_time_ms() -> u64 {
        300_000 // 5 minutes
    }
    fn default_cost_usd() -> f64 {
        1.0
    }
    fn default_max_actions() -> u32 {
        100
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            tokens: Self::default_tokens(),
            time_ms: Self::default_time_ms(),
            cost_usd: Self::default_cost_usd(),
            max_actions: Self::default_max_actions(),
        }
    }
}

impl Budget {
    /// Validate budget values are sensible.
    #[allow(clippy::result_large_err)]
    pub fn validate(&self) -> Result<(), AstraError> {
        if !self.cost_usd.is_finite() || self.cost_usd < 0.0 {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::builder()
                    .error_code("VAL-014")
                    .component("astra-types")
                    .severity(Severity::Error)
                    .remediation_hint("cost_usd must be a non-negative finite number")
                    .build()
                    .unwrap_or_default(),
                field: Some("cost_usd".into()),
                message: format!(
                    "Invalid cost_usd value: {} (must be >= 0 and finite)",
                    self.cost_usd
                ),
            });
        }
        Ok(())
    }
}

/// Security constraints for task execution.
///
/// Follows default-deny: egress is disabled and scopes are empty unless
/// explicitly configured.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Constraints {
    /// Whether network egress is allowed. Defaults to `false` (deny).
    #[serde(default)]
    pub egress_allowed: bool,

    /// Allowed filesystem write paths (glob patterns).
    #[serde(default)]
    pub write_scopes: Vec<String>,

    /// Allowed network endpoints (host:port or URLs).
    #[serde(default)]
    pub network_scopes: Vec<String>,

    /// Whether human approval is required before execution.
    #[serde(default)]
    pub requires_human_approval: bool,
}

/// The fundamental unit of work assignment in ASTRA_.
///
/// TaskEnvelope wraps every task dispatched to an agent, carrying the goal,
/// budget limits, security constraints, and references to relevant context.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TaskEnvelope {
    /// Unique identifier for this task.
    pub id: String,

    /// Task type for routing (e.g., "implement", "review", "test").
    #[serde(rename = "type")]
    pub task_type: String,

    /// Human-readable goal description.
    pub goal: String,

    /// Workspace/project identifier.
    pub workspace: String,

    /// References to relevant context items.
    #[serde(default)]
    pub context_refs: Vec<String>,

    /// References to input artifacts.
    #[serde(default)]
    pub artifact_refs: Vec<String>,

    /// Resource budget for this task.
    #[serde(default)]
    pub budget: Budget,

    /// Security constraints.
    #[serde(default)]
    pub constraints: Constraints,
}

impl TaskEnvelope {
    /// Create a new builder for TaskEnvelope.
    pub fn builder() -> TaskEnvelopeBuilder {
        TaskEnvelopeBuilder::default()
    }

    /// Validate the envelope has all required fields with valid values.
    #[allow(clippy::result_large_err)]
    pub fn validate(&self) -> Result<(), AstraError> {
        if self.id.is_empty() {
            return Err(field_empty_error(
                "VAL-010",
                "id",
                "Task ID cannot be empty",
            ));
        }
        if self.task_type.is_empty() {
            return Err(field_empty_error(
                "VAL-011",
                "type",
                "Task type cannot be empty",
            ));
        }
        if self.goal.is_empty() {
            return Err(field_empty_error(
                "VAL-012",
                "goal",
                "Task goal cannot be empty",
            ));
        }
        if self.workspace.is_empty() {
            return Err(field_empty_error(
                "VAL-013",
                "workspace",
                "Workspace cannot be empty",
            ));
        }
        self.budget.validate()?;
        Ok(())
    }
}

/// Helper to create a validation error for empty/missing fields.
fn field_empty_error(code: &str, field: &str, message: &str) -> AstraError {
    AstraError::ValidationFailed {
        context: ErrorContext::builder()
            .error_code(code)
            .component("astra-types")
            .severity(Severity::Error)
            .build()
            .unwrap_or_default(),
        field: Some(field.into()),
        message: message.into(),
    }
}

/// Builder for TaskEnvelope with validation on build.
#[derive(Debug, Default)]
pub struct TaskEnvelopeBuilder {
    id: Option<String>,
    task_type: Option<String>,
    goal: Option<String>,
    workspace: Option<String>,
    context_refs: Vec<String>,
    artifact_refs: Vec<String>,
    budget: Budget,
    constraints: Constraints,
}

impl TaskEnvelopeBuilder {
    /// Set the task ID (required).
    pub fn id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Set the task type for routing (required).
    pub fn task_type(mut self, task_type: impl Into<String>) -> Self {
        self.task_type = Some(task_type.into());
        self
    }

    /// Set the goal description (required).
    pub fn goal(mut self, goal: impl Into<String>) -> Self {
        self.goal = Some(goal.into());
        self
    }

    /// Set the workspace identifier (required).
    pub fn workspace(mut self, workspace: impl Into<String>) -> Self {
        self.workspace = Some(workspace.into());
        self
    }

    /// Add a context reference.
    pub fn context_ref(mut self, ref_id: impl Into<String>) -> Self {
        self.context_refs.push(ref_id.into());
        self
    }

    /// Add an artifact reference.
    pub fn artifact_ref(mut self, ref_id: impl Into<String>) -> Self {
        self.artifact_refs.push(ref_id.into());
        self
    }

    /// Set the resource budget.
    pub fn budget(mut self, budget: Budget) -> Self {
        self.budget = budget;
        self
    }

    /// Set the security constraints.
    pub fn constraints(mut self, constraints: Constraints) -> Self {
        self.constraints = constraints;
        self
    }

    /// Build the TaskEnvelope, returning error if required fields are missing.
    #[allow(clippy::result_large_err)]
    pub fn build(self) -> Result<TaskEnvelope, AstraError> {
        // Use same error codes as validate() for consistency
        let id = self
            .id
            .ok_or_else(|| field_empty_error("VAL-010", "id", "Task ID is required"))?;
        let task_type = self
            .task_type
            .ok_or_else(|| field_empty_error("VAL-011", "type", "Task type is required"))?;
        let goal = self
            .goal
            .ok_or_else(|| field_empty_error("VAL-012", "goal", "Task goal is required"))?;
        let workspace = self
            .workspace
            .ok_or_else(|| field_empty_error("VAL-013", "workspace", "Workspace is required"))?;

        // Validate budget before constructing
        self.budget.validate()?;

        let envelope = TaskEnvelope {
            id,
            task_type,
            goal,
            workspace,
            context_refs: self.context_refs,
            artifact_refs: self.artifact_refs,
            budget: self.budget,
            constraints: self.constraints,
        };

        // Final validation catches empty strings (e.g., .id(""))
        envelope.validate()?;
        Ok(envelope)
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn budget_default_values() {
        let budget = Budget::default();
        assert_eq!(budget.tokens, 100_000);
        assert_eq!(budget.time_ms, 300_000);
        assert!((budget.cost_usd - 1.0).abs() < f64::EPSILON);
        assert_eq!(budget.max_actions, 100);
    }

    #[test]
    fn constraints_default_deny() {
        let constraints = Constraints::default();
        assert!(!constraints.egress_allowed);
        assert!(constraints.write_scopes.is_empty());
        assert!(constraints.network_scopes.is_empty());
        assert!(!constraints.requires_human_approval);
    }

    #[test]
    fn builder_happy_path() {
        let result = TaskEnvelope::builder()
            .id("task-001")
            .task_type("implement")
            .goal("Add validation")
            .workspace("my-project")
            .context_ref("ctx-001")
            .artifact_ref("art-001")
            .build();

        let Ok(task) = result else {
            panic!("builder should succeed with all required fields");
        };

        assert_eq!(task.id, "task-001");
        assert_eq!(task.task_type, "implement");
        assert_eq!(task.goal, "Add validation");
        assert_eq!(task.workspace, "my-project");
        assert_eq!(task.context_refs, vec!["ctx-001"]);
        assert_eq!(task.artifact_refs, vec!["art-001"]);
    }

    #[test]
    fn builder_missing_id() {
        let result = TaskEnvelope::builder()
            .task_type("implement")
            .goal("Add validation")
            .workspace("my-project")
            .build();

        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { field, .. }) = result else {
            panic!("expected ValidationFailed error");
        };
        assert_eq!(field, Some("id".into()));
    }

    #[test]
    fn builder_missing_type() {
        let result = TaskEnvelope::builder()
            .id("task-001")
            .goal("Add validation")
            .workspace("my-project")
            .build();

        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { field, .. }) = result else {
            panic!("expected ValidationFailed error");
        };
        assert_eq!(field, Some("type".into()));
    }

    #[test]
    fn builder_missing_goal() {
        let result = TaskEnvelope::builder()
            .id("task-001")
            .task_type("implement")
            .workspace("my-project")
            .build();

        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { field, .. }) = result else {
            panic!("expected ValidationFailed error");
        };
        assert_eq!(field, Some("goal".into()));
    }

    #[test]
    fn builder_missing_workspace() {
        let result = TaskEnvelope::builder()
            .id("task-001")
            .task_type("implement")
            .goal("Add validation")
            .build();

        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { field, .. }) = result else {
            panic!("expected ValidationFailed error");
        };
        assert_eq!(field, Some("workspace".into()));
    }

    #[test]
    fn validate_empty_id() {
        let task = TaskEnvelope {
            id: String::new(),
            task_type: "implement".into(),
            goal: "Add validation".into(),
            workspace: "my-project".into(),
            context_refs: Vec::new(),
            artifact_refs: Vec::new(),
            budget: Budget::default(),
            constraints: Constraints::default(),
        };

        let result = task.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(field, Some("id".into()));
    }

    #[test]
    fn validate_empty_type() {
        let task = TaskEnvelope {
            id: "task-001".into(),
            task_type: String::new(),
            goal: "Add validation".into(),
            workspace: "my-project".into(),
            context_refs: Vec::new(),
            artifact_refs: Vec::new(),
            budget: Budget::default(),
            constraints: Constraints::default(),
        };

        let result = task.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(field, Some("type".into()));
    }

    #[test]
    fn validate_empty_goal() {
        let task = TaskEnvelope {
            id: "task-001".into(),
            task_type: "implement".into(),
            goal: String::new(),
            workspace: "my-project".into(),
            context_refs: Vec::new(),
            artifact_refs: Vec::new(),
            budget: Budget::default(),
            constraints: Constraints::default(),
        };

        let result = task.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(field, Some("goal".into()));
    }

    #[test]
    fn validate_empty_workspace() {
        let task = TaskEnvelope {
            id: "task-001".into(),
            task_type: "implement".into(),
            goal: "Add validation".into(),
            workspace: String::new(),
            context_refs: Vec::new(),
            artifact_refs: Vec::new(),
            budget: Budget::default(),
            constraints: Constraints::default(),
        };

        let result = task.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(field, Some("workspace".into()));
    }

    #[test]
    fn validate_negative_cost() {
        let budget = Budget {
            tokens: 100_000,
            time_ms: 300_000,
            cost_usd: -1.0,
            max_actions: 100,
        };

        let result = budget.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(field, Some("cost_usd".into()));
    }

    #[test]
    fn validate_nan_cost() {
        let budget = Budget {
            tokens: 100_000,
            time_ms: 300_000,
            cost_usd: f64::NAN,
            max_actions: 100,
        };

        let result = budget.validate();
        assert!(result.is_err());
    }

    #[test]
    fn validate_infinite_cost() {
        let budget = Budget {
            tokens: 100_000,
            time_ms: 300_000,
            cost_usd: f64::INFINITY,
            max_actions: 100,
        };

        let result = budget.validate();
        assert!(result.is_err());
    }

    #[test]
    fn serialization_roundtrip() {
        let Ok(task) = TaskEnvelope::builder()
            .id("task-001")
            .task_type("implement")
            .goal("Add validation")
            .workspace("my-project")
            .build()
        else {
            panic!("builder should succeed");
        };

        let Ok(json) = serde_json::to_string(&task) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<TaskEnvelope>(&json) else {
            panic!("deserialization should succeed");
        };

        assert_eq!(task, decoded);
    }

    #[test]
    fn json_type_field_rename() {
        let Ok(task) = TaskEnvelope::builder()
            .id("task-001")
            .task_type("review")
            .goal("Review code")
            .workspace("my-project")
            .build()
        else {
            panic!("builder should succeed");
        };

        let Ok(json) = serde_json::to_string(&task) else {
            panic!("serialization should succeed");
        };

        // Verify JSON contains "type" not "task_type"
        assert!(json.contains("\"type\":\"review\""));
        assert!(!json.contains("task_type"));
    }

    #[test]
    fn custom_budget_and_constraints() {
        let budget = Budget {
            tokens: 50_000,
            time_ms: 60_000,
            cost_usd: 0.5,
            max_actions: 20,
        };

        let constraints = Constraints {
            egress_allowed: true,
            write_scopes: vec!["src/**".into()],
            network_scopes: vec!["api.example.com".into()],
            requires_human_approval: true,
        };

        let Ok(task) = TaskEnvelope::builder()
            .id("task-002")
            .task_type("deploy")
            .goal("Deploy to staging")
            .workspace("my-project")
            .budget(budget.clone())
            .constraints(constraints.clone())
            .build()
        else {
            panic!("builder should succeed");
        };

        assert_eq!(task.budget, budget);
        assert_eq!(task.constraints, constraints);
    }
}
