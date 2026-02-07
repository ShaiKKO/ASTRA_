// SPDX-License-Identifier: MIT OR Apache-2.0
//! RunReport — complete execution trace of a workflow run.
//!
//! Captures the full timeline, budget consumption, policy decisions, and operator
//! interventions for debugging, replay, and compliance.
//!
//! # Design
//!
//! - Timeline events are a discriminated union enabling filtering and analysis
//! - Interventions (pause, kill, budget grant) are first-class citizens
//! - Budget snapshots track allocation vs consumption
//! - Immutable once created; reports are append-only during run, then finalized
//!
//! # Example
//!
//! ```
//! use astra_types::{RunReport, TimelineEvent, OutcomeStatus, TaskId, Timestamp};
//!
//! let mut report = RunReport::new("run-001", Timestamp::now());
//!
//! report.add_event(TimelineEvent::RunStarted {
//!     timestamp: Timestamp::now(),
//!     task_id: TaskId::new(),
//! });
//!
//! report.complete(OutcomeStatus::Success, Timestamp::now());
//! assert_eq!(report.status, OutcomeStatus::Success);
//! ```

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{AstraError, ErrorContext};
use crate::id::{ArtifactId, CapabilityId, DecisionId, TaskId};
use crate::outcome::OutcomeStatus;
use crate::policy::PolicyEffect;
use crate::task::Budget;
use crate::time::Timestamp;
use crate::validate::Validate;

// ============================================================================
// TimelineEvent
// ============================================================================

/// Events in the run timeline.
///
/// Each variant captures a discrete occurrence during run execution. Use the
/// `timestamp()` method to get the event time without pattern matching.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TimelineEvent {
    /// Run started.
    RunStarted {
        /// When the run started.
        timestamp: Timestamp,
        /// The root task for this run.
        task_id: TaskId,
    },

    /// Agent spawned.
    AgentSpawned {
        /// When the agent was spawned.
        timestamp: Timestamp,
        /// Agent identifier. Design: String until AgentId is defined.
        agent_id: String,
        /// Profile used to spawn the agent. Design: String until ProfileId is typed.
        profile_id: String,
    },

    /// Task dispatched to agent.
    TaskDispatched {
        /// When the task was dispatched.
        timestamp: Timestamp,
        /// The dispatched task.
        task_id: TaskId,
        /// Target agent. Design: String until AgentId is defined.
        agent_id: String,
    },

    /// Capability invoked.
    CapabilityInvoked {
        /// When the capability was invoked.
        timestamp: Timestamp,
        /// Which capability was invoked.
        capability_id: CapabilityId,
        /// Agent that invoked the capability. Design: String until AgentId is defined.
        agent_id: String,
        /// How long the invocation took in milliseconds.
        duration_ms: u64,
    },

    /// Model called.
    ModelCalled {
        /// When the model was called.
        timestamp: Timestamp,
        /// Model identifier (e.g., "gpt-4", "claude-3").
        model_id: String,
        /// Tokens consumed (input + output).
        tokens_used: u64,
        /// How long the call took in milliseconds.
        duration_ms: u64,
    },

    /// Policy decision made.
    PolicyEvaluated {
        /// When the policy was evaluated.
        timestamp: Timestamp,
        /// Reference to the full PolicyDecision.
        decision_id: DecisionId,
        /// The decision result.
        effect: PolicyEffect,
    },

    /// Artifact created or modified.
    ArtifactMutated {
        /// When the mutation occurred.
        timestamp: Timestamp,
        /// The affected artifact.
        artifact_id: ArtifactId,
        /// Type of mutation (e.g., "created", "updated", "state_changed").
        mutation: String,
    },

    /// Agent completed.
    AgentCompleted {
        /// When the agent completed.
        timestamp: Timestamp,
        /// Which agent completed. Design: String until AgentId is defined.
        agent_id: String,
        /// How the agent completed.
        status: OutcomeStatus,
    },

    /// Run completed.
    RunCompleted {
        /// When the run completed.
        timestamp: Timestamp,
        /// Final run status.
        status: OutcomeStatus,
    },

    /// Error occurred.
    ErrorOccurred {
        /// When the error occurred.
        timestamp: Timestamp,
        /// Error code for categorization.
        error_code: String,
        /// Human-readable error message.
        message: String,
    },
}

impl TimelineEvent {
    /// Get the timestamp of this event.
    pub fn timestamp(&self) -> &Timestamp {
        match self {
            Self::RunStarted { timestamp, .. } => timestamp,
            Self::AgentSpawned { timestamp, .. } => timestamp,
            Self::TaskDispatched { timestamp, .. } => timestamp,
            Self::CapabilityInvoked { timestamp, .. } => timestamp,
            Self::ModelCalled { timestamp, .. } => timestamp,
            Self::PolicyEvaluated { timestamp, .. } => timestamp,
            Self::ArtifactMutated { timestamp, .. } => timestamp,
            Self::AgentCompleted { timestamp, .. } => timestamp,
            Self::RunCompleted { timestamp, .. } => timestamp,
            Self::ErrorOccurred { timestamp, .. } => timestamp,
        }
    }

    /// Get the event type name.
    pub fn event_type(&self) -> &'static str {
        match self {
            Self::RunStarted { .. } => "run_started",
            Self::AgentSpawned { .. } => "agent_spawned",
            Self::TaskDispatched { .. } => "task_dispatched",
            Self::CapabilityInvoked { .. } => "capability_invoked",
            Self::ModelCalled { .. } => "model_called",
            Self::PolicyEvaluated { .. } => "policy_evaluated",
            Self::ArtifactMutated { .. } => "artifact_mutated",
            Self::AgentCompleted { .. } => "agent_completed",
            Self::RunCompleted { .. } => "run_completed",
            Self::ErrorOccurred { .. } => "error_occurred",
        }
    }
}

impl fmt::Display for TimelineEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.event_type(), self.timestamp())
    }
}

// ============================================================================
// Intervention
// ============================================================================

/// Operator intervention during a run.
///
/// Captures human or system actions that affect run execution.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Intervention {
    /// Paused execution.
    Pause {
        /// When the pause was issued.
        timestamp: Timestamp,
        /// Why execution was paused.
        reason: String,
    },

    /// Resumed execution.
    Resume {
        /// When execution was resumed.
        timestamp: Timestamp,
    },

    /// Killed run or agent.
    Kill {
        /// When the kill was issued.
        timestamp: Timestamp,
        /// What was killed (run_id or agent_id).
        target: String,
        /// Why execution was killed.
        reason: String,
    },

    /// Granted additional budget.
    BudgetGrant {
        /// When the grant was issued.
        timestamp: Timestamp,
        /// Budget type (e.g., "tokens", "time_ms", "cost_usd").
        budget_type: String,
        /// Amount granted.
        amount: u64,
    },

    /// Overrode a policy decision.
    PolicyOverride {
        /// When the override was issued.
        timestamp: Timestamp,
        /// Which decision was overridden.
        decision_id: DecisionId,
        /// The new effect to apply.
        new_effect: PolicyEffect,
    },
}

impl Intervention {
    /// Get the timestamp of this intervention.
    pub fn timestamp(&self) -> &Timestamp {
        match self {
            Self::Pause { timestamp, .. } => timestamp,
            Self::Resume { timestamp } => timestamp,
            Self::Kill { timestamp, .. } => timestamp,
            Self::BudgetGrant { timestamp, .. } => timestamp,
            Self::PolicyOverride { timestamp, .. } => timestamp,
        }
    }

    /// Get the intervention type name.
    pub fn intervention_type(&self) -> &'static str {
        match self {
            Self::Pause { .. } => "pause",
            Self::Resume { .. } => "resume",
            Self::Kill { .. } => "kill",
            Self::BudgetGrant { .. } => "budget_grant",
            Self::PolicyOverride { .. } => "policy_override",
        }
    }
}

impl fmt::Display for Intervention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.intervention_type(), self.timestamp())
    }
}

// ============================================================================
// BudgetSnapshot
// ============================================================================

/// Budget consumption snapshot at a point in time.
///
/// Tracks allocated, consumed, and remaining budget across all resource types.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetSnapshot {
    /// Allocated budget limits.
    pub allocated: Budget,
    /// Budget consumed so far.
    pub consumed: Budget,
    /// Remaining budget.
    pub remaining: Budget,
}

impl BudgetSnapshot {
    /// Create a new budget snapshot from allocated budget.
    ///
    /// Consumed is zeroed, remaining equals allocated.
    pub fn new(allocated: Budget) -> Self {
        Self {
            allocated: allocated.clone(),
            consumed: Budget {
                tokens: 0,
                time_ms: 0,
                cost_usd: 0.0,
                max_actions: 0,
            },
            remaining: allocated,
        }
    }

    /// Create an empty snapshot with zero budgets.
    pub fn empty() -> Self {
        let zero = Budget {
            tokens: 0,
            time_ms: 0,
            cost_usd: 0.0,
            max_actions: 0,
        };
        Self {
            allocated: zero.clone(),
            consumed: zero.clone(),
            remaining: zero,
        }
    }
}

impl Default for BudgetSnapshot {
    fn default() -> Self {
        Self::empty()
    }
}

impl fmt::Display for BudgetSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Budget(tokens: {}/{}, time: {}ms/{}ms, cost: ${:.2}/${:.2})",
            self.consumed.tokens,
            self.allocated.tokens,
            self.consumed.time_ms,
            self.allocated.time_ms,
            self.consumed.cost_usd,
            self.allocated.cost_usd
        )
    }
}

// ============================================================================
// RunReport
// ============================================================================

/// Complete execution trace of a workflow run.
///
/// Captures timeline, budget consumption, policy decisions, and interventions
/// for debugging, replay, and compliance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunReport {
    /// Unique run identifier.
    ///
    /// Design: String until RunId is defined (matches ArtifactLinks.run_id).
    pub run_id: String,

    /// Overall run status.
    pub status: OutcomeStatus,

    /// Start timestamp.
    pub started_at: Timestamp,

    /// End timestamp (set when completed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<Timestamp>,

    /// Chronological event timeline.
    #[serde(default)]
    pub timeline: Vec<TimelineEvent>,

    /// Artifact IDs produced/modified.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactId>,

    /// Budget snapshot at end of run.
    #[serde(default)]
    pub budgets: BudgetSnapshot,

    /// Policy decision IDs made during run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_decisions: Vec<DecisionId>,

    /// Operator interventions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub interventions: Vec<Intervention>,

    /// Error summary if failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Agent IDs involved in this run.
    ///
    /// Design: Vec<String> until AgentId is defined.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agents: Vec<String>,
}

impl RunReport {
    /// Create a new run report.
    ///
    /// Status starts as `Partial` (in progress).
    pub fn new(run_id: impl Into<String>, started_at: Timestamp) -> Self {
        Self {
            run_id: run_id.into(),
            status: OutcomeStatus::Partial,
            started_at,
            completed_at: None,
            timeline: Vec::new(),
            artifacts: Vec::new(),
            budgets: BudgetSnapshot::default(),
            policy_decisions: Vec::new(),
            interventions: Vec::new(),
            error: None,
            agents: Vec::new(),
        }
    }

    /// Add an event to the timeline.
    pub fn add_event(&mut self, event: TimelineEvent) {
        self.timeline.push(event);
    }

    /// Add an artifact to the report.
    pub fn add_artifact(&mut self, artifact_id: ArtifactId) {
        self.artifacts.push(artifact_id);
    }

    /// Add a policy decision to the report.
    pub fn add_policy_decision(&mut self, decision_id: DecisionId) {
        self.policy_decisions.push(decision_id);
    }

    /// Add an intervention to the report.
    pub fn add_intervention(&mut self, intervention: Intervention) {
        self.interventions.push(intervention);
    }

    /// Add an agent to the report.
    pub fn add_agent(&mut self, agent_id: impl Into<String>) {
        self.agents.push(agent_id.into());
    }

    /// Set the budget snapshot.
    pub fn set_budgets(&mut self, budgets: BudgetSnapshot) {
        self.budgets = budgets;
    }

    /// Set the error message.
    pub fn set_error(&mut self, error: impl Into<String>) {
        self.error = Some(error.into());
    }

    /// Mark run as completed.
    pub fn complete(&mut self, status: OutcomeStatus, completed_at: Timestamp) {
        self.status = status;
        self.completed_at = Some(completed_at);
    }

    /// Get duration in milliseconds if completed.
    ///
    /// Returns `None` if the run is not yet completed or if timestamps are invalid.
    pub fn duration_ms(&self) -> Option<u64> {
        let completed = self.completed_at.as_ref()?;
        let start_ms = self.started_at.as_millis();
        let end_ms = completed.as_millis();

        if end_ms >= start_ms {
            Some((end_ms - start_ms) as u64)
        } else {
            // Clock skew - started_at is after completed_at
            None
        }
    }

    /// Check if the run is still in progress.
    pub fn is_in_progress(&self) -> bool {
        self.completed_at.is_none()
    }

    /// Check if the run completed successfully.
    pub fn is_success(&self) -> bool {
        self.status == OutcomeStatus::Success
    }

    /// Check if the run failed.
    pub fn is_failure(&self) -> bool {
        matches!(self.status, OutcomeStatus::Failed | OutcomeStatus::Aborted)
    }
}

impl fmt::Display for RunReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(duration) = self.duration_ms() {
            write!(
                f,
                "RunReport({}, status={}, duration={}ms, events={})",
                self.run_id,
                self.status,
                duration,
                self.timeline.len()
            )
        } else {
            write!(
                f,
                "RunReport({}, status={}, events={})",
                self.run_id,
                self.status,
                self.timeline.len()
            )
        }
    }
}

impl Validate for RunReport {
    fn validate(&self) -> Result<(), AstraError> {
        // VAL-084: run_id cannot be empty
        if self.run_id.trim().is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-084",
                    "Provide a non-empty run_id for RunReport",
                ),
                field: Some("run_id".into()),
                message: "RunReport.run_id cannot be empty".into(),
            });
        }

        // VAL-085: started_at must not be after completed_at
        if let Some(completed) = &self.completed_at {
            if self.started_at.as_millis() > completed.as_millis() {
                return Err(AstraError::ValidationFailed {
                    context: ErrorContext::validation(
                        "VAL-085",
                        "started_at must not be after completed_at",
                    ),
                    field: Some("started_at".into()),
                    message: format!(
                        "RunReport.started_at ({}) is after completed_at ({})",
                        self.started_at, completed
                    ),
                });
            }
        }

        Ok(())
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    // ========================================================================
    // TimelineEvent tests
    // ========================================================================

    #[test]
    fn timeline_event_run_started() {
        let task_id = TaskId::new();
        let event = TimelineEvent::RunStarted {
            timestamp: Timestamp::now(),
            task_id,
        };

        assert_eq!(event.event_type(), "run_started");
        assert!(!event.timestamp().is_future());
    }

    #[test]
    fn timeline_event_agent_spawned() {
        let event = TimelineEvent::AgentSpawned {
            timestamp: Timestamp::now(),
            agent_id: "agent-001".into(),
            profile_id: "profile-001".into(),
        };

        assert_eq!(event.event_type(), "agent_spawned");
    }

    #[test]
    fn timeline_event_capability_invoked() {
        let Ok(cap_id) = CapabilityId::new("repo.read") else {
            panic!("valid capability id should parse");
        };
        let event = TimelineEvent::CapabilityInvoked {
            timestamp: Timestamp::now(),
            capability_id: cap_id,
            agent_id: "agent-001".into(),
            duration_ms: 42,
        };

        assert_eq!(event.event_type(), "capability_invoked");
    }

    #[test]
    fn timeline_event_policy_evaluated() {
        let event = TimelineEvent::PolicyEvaluated {
            timestamp: Timestamp::now(),
            decision_id: DecisionId::new(),
            effect: PolicyEffect::Allow,
        };

        assert_eq!(event.event_type(), "policy_evaluated");
    }

    #[test]
    fn timeline_event_timestamp_accessor() {
        let ts = Timestamp::now();
        let event = TimelineEvent::ErrorOccurred {
            timestamp: ts.clone(),
            error_code: "ERR-001".into(),
            message: "Something went wrong".into(),
        };

        assert_eq!(event.timestamp(), &ts);
    }

    #[test]
    fn timeline_event_display() {
        let event = TimelineEvent::RunCompleted {
            timestamp: Timestamp::now(),
            status: OutcomeStatus::Success,
        };
        let display = event.to_string();

        assert!(display.contains("run_completed"));
        assert!(display.contains("@"));
    }

    #[test]
    fn timeline_event_serde_roundtrip() {
        let events = vec![
            TimelineEvent::RunStarted {
                timestamp: Timestamp::now(),
                task_id: TaskId::new(),
            },
            TimelineEvent::ModelCalled {
                timestamp: Timestamp::now(),
                model_id: "gpt-4".into(),
                tokens_used: 1500,
                duration_ms: 2300,
            },
            TimelineEvent::RunCompleted {
                timestamp: Timestamp::now(),
                status: OutcomeStatus::Success,
            },
        ];

        for event in events {
            let Ok(json) = serde_json::to_string(&event) else {
                panic!("serialization should succeed");
            };
            let Ok(decoded) = serde_json::from_str::<TimelineEvent>(&json) else {
                panic!("deserialization should succeed");
            };
            assert_eq!(event.event_type(), decoded.event_type());
        }
    }

    #[test]
    fn timeline_event_serde_tagged() {
        let event = TimelineEvent::RunStarted {
            timestamp: Timestamp::now(),
            task_id: TaskId::new(),
        };

        let Ok(json) = serde_json::to_string(&event) else {
            panic!("serialization should succeed");
        };

        assert!(json.contains("\"type\":\"run_started\""));
    }

    // ========================================================================
    // Intervention tests
    // ========================================================================

    #[test]
    fn intervention_pause() {
        let intervention = Intervention::Pause {
            timestamp: Timestamp::now(),
            reason: "User requested pause".into(),
        };

        assert_eq!(intervention.intervention_type(), "pause");
    }

    #[test]
    fn intervention_resume() {
        let intervention = Intervention::Resume {
            timestamp: Timestamp::now(),
        };

        assert_eq!(intervention.intervention_type(), "resume");
    }

    #[test]
    fn intervention_kill() {
        let intervention = Intervention::Kill {
            timestamp: Timestamp::now(),
            target: "agent-001".into(),
            reason: "Unresponsive".into(),
        };

        assert_eq!(intervention.intervention_type(), "kill");
    }

    #[test]
    fn intervention_budget_grant() {
        let intervention = Intervention::BudgetGrant {
            timestamp: Timestamp::now(),
            budget_type: "tokens".into(),
            amount: 50000,
        };

        assert_eq!(intervention.intervention_type(), "budget_grant");
    }

    #[test]
    fn intervention_policy_override() {
        let intervention = Intervention::PolicyOverride {
            timestamp: Timestamp::now(),
            decision_id: DecisionId::new(),
            new_effect: PolicyEffect::Allow,
        };

        assert_eq!(intervention.intervention_type(), "policy_override");
    }

    #[test]
    fn intervention_timestamp_accessor() {
        let ts = Timestamp::now();
        let intervention = Intervention::Resume {
            timestamp: ts.clone(),
        };

        assert_eq!(intervention.timestamp(), &ts);
    }

    #[test]
    fn intervention_display() {
        let intervention = Intervention::Pause {
            timestamp: Timestamp::now(),
            reason: "Test".into(),
        };
        let display = intervention.to_string();

        assert!(display.contains("pause"));
        assert!(display.contains("@"));
    }

    #[test]
    fn intervention_serde_roundtrip() {
        let interventions = vec![
            Intervention::Pause {
                timestamp: Timestamp::now(),
                reason: "Test pause".into(),
            },
            Intervention::Resume {
                timestamp: Timestamp::now(),
            },
            Intervention::Kill {
                timestamp: Timestamp::now(),
                target: "run-001".into(),
                reason: "Timeout".into(),
            },
        ];

        for intervention in interventions {
            let Ok(json) = serde_json::to_string(&intervention) else {
                panic!("serialization should succeed");
            };
            let Ok(decoded) = serde_json::from_str::<Intervention>(&json) else {
                panic!("deserialization should succeed");
            };
            assert_eq!(
                intervention.intervention_type(),
                decoded.intervention_type()
            );
        }
    }

    #[test]
    fn intervention_serde_tagged() {
        let intervention = Intervention::BudgetGrant {
            timestamp: Timestamp::now(),
            budget_type: "tokens".into(),
            amount: 1000,
        };

        let Ok(json) = serde_json::to_string(&intervention) else {
            panic!("serialization should succeed");
        };

        assert!(json.contains("\"type\":\"budget_grant\""));
    }

    // ========================================================================
    // BudgetSnapshot tests
    // ========================================================================

    #[test]
    fn budget_snapshot_new() {
        let allocated = Budget {
            tokens: 100_000,
            time_ms: 300_000,
            cost_usd: 1.0,
            max_actions: 100,
        };

        let snapshot = BudgetSnapshot::new(allocated.clone());

        assert_eq!(snapshot.allocated, allocated);
        assert_eq!(snapshot.consumed.tokens, 0);
        assert_eq!(snapshot.consumed.time_ms, 0);
        assert_eq!(snapshot.consumed.cost_usd, 0.0);
        assert_eq!(snapshot.consumed.max_actions, 0);
        assert_eq!(snapshot.remaining, allocated);
    }

    #[test]
    fn budget_snapshot_empty() {
        let snapshot = BudgetSnapshot::empty();

        assert_eq!(snapshot.allocated.tokens, 0);
        assert_eq!(snapshot.consumed.tokens, 0);
        assert_eq!(snapshot.remaining.tokens, 0);
    }

    #[test]
    fn budget_snapshot_default_is_empty() {
        let snapshot = BudgetSnapshot::default();

        assert_eq!(snapshot.allocated.tokens, 0);
        assert_eq!(snapshot.consumed.tokens, 0);
        assert_eq!(snapshot.remaining.tokens, 0);
    }

    #[test]
    fn budget_snapshot_display() {
        let mut snapshot = BudgetSnapshot::new(Budget {
            tokens: 100_000,
            time_ms: 300_000,
            cost_usd: 1.0,
            max_actions: 100,
        });
        snapshot.consumed = Budget {
            tokens: 50_000,
            time_ms: 150_000,
            cost_usd: 0.5,
            max_actions: 50,
        };

        let display = snapshot.to_string();
        assert!(display.contains("50000/100000"));
        assert!(display.contains("150000ms/300000ms"));
    }

    #[test]
    fn budget_snapshot_serde_roundtrip() {
        let snapshot = BudgetSnapshot::new(Budget::default());

        let Ok(json) = serde_json::to_string(&snapshot) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<BudgetSnapshot>(&json) else {
            panic!("deserialization should succeed");
        };

        assert_eq!(snapshot, decoded);
    }

    // ========================================================================
    // RunReport tests
    // ========================================================================

    #[test]
    fn run_report_new() {
        let report = RunReport::new("run-001", Timestamp::now());

        assert_eq!(report.run_id, "run-001");
        assert_eq!(report.status, OutcomeStatus::Partial);
        assert!(report.completed_at.is_none());
        assert!(report.timeline.is_empty());
        assert!(report.is_in_progress());
    }

    #[test]
    fn run_report_add_event() {
        let mut report = RunReport::new("run-001", Timestamp::now());

        report.add_event(TimelineEvent::RunStarted {
            timestamp: Timestamp::now(),
            task_id: TaskId::new(),
        });

        assert_eq!(report.timeline.len(), 1);
    }

    #[test]
    fn run_report_add_artifact() {
        let mut report = RunReport::new("run-001", Timestamp::now());
        let artifact_id = ArtifactId::new();

        report.add_artifact(artifact_id);

        assert_eq!(report.artifacts.len(), 1);
    }

    #[test]
    fn run_report_add_policy_decision() {
        let mut report = RunReport::new("run-001", Timestamp::now());
        let decision_id = DecisionId::new();

        report.add_policy_decision(decision_id);

        assert_eq!(report.policy_decisions.len(), 1);
    }

    #[test]
    fn run_report_add_intervention() {
        let mut report = RunReport::new("run-001", Timestamp::now());

        report.add_intervention(Intervention::Pause {
            timestamp: Timestamp::now(),
            reason: "Test".into(),
        });

        assert_eq!(report.interventions.len(), 1);
    }

    #[test]
    fn run_report_add_agent() {
        let mut report = RunReport::new("run-001", Timestamp::now());

        report.add_agent("agent-001");
        report.add_agent("agent-002");

        assert_eq!(report.agents.len(), 2);
    }

    #[test]
    fn run_report_set_budgets() {
        let mut report = RunReport::new("run-001", Timestamp::now());
        let budgets = BudgetSnapshot::new(Budget::default());

        report.set_budgets(budgets.clone());

        assert_eq!(report.budgets, budgets);
    }

    #[test]
    fn run_report_set_error() {
        let mut report = RunReport::new("run-001", Timestamp::now());

        report.set_error("Something went wrong");

        assert_eq!(report.error, Some("Something went wrong".into()));
    }

    #[test]
    fn run_report_complete() {
        let mut report = RunReport::new("run-001", Timestamp::now());

        report.complete(OutcomeStatus::Success, Timestamp::now());

        assert_eq!(report.status, OutcomeStatus::Success);
        assert!(report.completed_at.is_some());
        assert!(!report.is_in_progress());
        assert!(report.is_success());
    }

    #[test]
    fn run_report_duration_ms() {
        let start = Timestamp::from(Utc::now() - Duration::milliseconds(1000));
        let end = Timestamp::now();

        let mut report = RunReport::new("run-001", start);
        report.complete(OutcomeStatus::Success, end);

        let duration = report.duration_ms();
        assert!(duration.is_some());

        // Should be approximately 1000ms (allow some tolerance)
        let Some(ms) = duration else {
            panic!("duration should be Some");
        };
        assert!((900..=1100).contains(&ms));
    }

    #[test]
    fn run_report_duration_ms_none_when_not_completed() {
        let report = RunReport::new("run-001", Timestamp::now());
        assert!(report.duration_ms().is_none());
    }

    #[test]
    fn run_report_duration_ms_zero_for_instant() {
        let ts = Timestamp::now();
        let mut report = RunReport::new("run-001", ts.clone());
        report.complete(OutcomeStatus::Success, ts);

        let duration = report.duration_ms();
        assert_eq!(duration, Some(0));
    }

    #[test]
    fn run_report_is_success() {
        let mut report = RunReport::new("run-001", Timestamp::now());

        assert!(!report.is_success());

        report.complete(OutcomeStatus::Success, Timestamp::now());
        assert!(report.is_success());
    }

    #[test]
    fn run_report_is_failure() {
        let mut report = RunReport::new("run-001", Timestamp::now());

        assert!(!report.is_failure());

        report.complete(OutcomeStatus::Failed, Timestamp::now());
        assert!(report.is_failure());

        let mut report2 = RunReport::new("run-002", Timestamp::now());
        report2.complete(OutcomeStatus::Aborted, Timestamp::now());
        assert!(report2.is_failure());
    }

    #[test]
    fn run_report_display_in_progress() {
        let report = RunReport::new("run-001", Timestamp::now());
        let display = report.to_string();

        assert!(display.contains("run-001"));
        assert!(display.contains("partial"));
        assert!(!display.contains("duration"));
    }

    #[test]
    fn run_report_display_completed() {
        let start = Timestamp::from(Utc::now() - Duration::milliseconds(1000));
        let mut report = RunReport::new("run-001", start);
        report.add_event(TimelineEvent::RunStarted {
            timestamp: Timestamp::now(),
            task_id: TaskId::new(),
        });
        report.complete(OutcomeStatus::Success, Timestamp::now());

        let display = report.to_string();

        assert!(display.contains("run-001"));
        assert!(display.contains("success"));
        assert!(display.contains("duration"));
        assert!(display.contains("events=1"));
    }

    #[test]
    fn run_report_validate_success() {
        let report = RunReport::new("run-001", Timestamp::now());
        assert!(report.validate().is_ok());
    }

    #[test]
    fn run_report_validate_empty_run_id() {
        let report = RunReport::new("", Timestamp::now());
        let result = report.validate();

        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-084");
    }

    #[test]
    fn run_report_validate_whitespace_run_id() {
        let report = RunReport::new("   ", Timestamp::now());
        let result = report.validate();

        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-084");
    }

    #[test]
    fn run_report_validate_started_after_completed() {
        let now = Timestamp::now();
        let earlier = Timestamp::from(Utc::now() - Duration::hours(1));

        let mut report = RunReport::new("run-001", now);
        report.completed_at = Some(earlier);

        let result = report.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-085");
    }

    #[test]
    fn run_report_validate_same_start_end_ok() {
        let ts = Timestamp::now();
        let mut report = RunReport::new("run-001", ts.clone());
        report.completed_at = Some(ts);

        assert!(report.validate().is_ok());
    }

    #[test]
    fn run_report_serde_roundtrip() {
        let mut report = RunReport::new("run-001", Timestamp::now());
        report.add_event(TimelineEvent::RunStarted {
            timestamp: Timestamp::now(),
            task_id: TaskId::new(),
        });
        report.add_artifact(ArtifactId::new());
        report.add_policy_decision(DecisionId::new());
        report.add_intervention(Intervention::Pause {
            timestamp: Timestamp::now(),
            reason: "Test".into(),
        });
        report.add_agent("agent-001");
        report.set_budgets(BudgetSnapshot::new(Budget::default()));
        report.complete(OutcomeStatus::Success, Timestamp::now());

        let Ok(json) = serde_json::to_string(&report) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<RunReport>(&json) else {
            panic!("deserialization should succeed");
        };

        assert_eq!(report.run_id, decoded.run_id);
        assert_eq!(report.status, decoded.status);
        assert_eq!(report.timeline.len(), decoded.timeline.len());
        assert_eq!(report.artifacts.len(), decoded.artifacts.len());
        assert_eq!(
            report.policy_decisions.len(),
            decoded.policy_decisions.len()
        );
        assert_eq!(report.interventions.len(), decoded.interventions.len());
        assert_eq!(report.agents.len(), decoded.agents.len());
    }

    #[test]
    fn run_report_serde_skips_empty_collections() {
        let report = RunReport::new("run-001", Timestamp::now());

        let Ok(json) = serde_json::to_string(&report) else {
            panic!("serialization should succeed");
        };

        assert!(!json.contains("\"artifacts\""));
        assert!(!json.contains("\"policy_decisions\""));
        assert!(!json.contains("\"interventions\""));
        assert!(!json.contains("\"agents\""));
    }

    #[test]
    fn run_report_serde_skips_none_fields() {
        let report = RunReport::new("run-001", Timestamp::now());

        let Ok(json) = serde_json::to_string(&report) else {
            panic!("serialization should succeed");
        };

        assert!(!json.contains("\"completed_at\""));
        assert!(!json.contains("\"error\""));
    }
}
