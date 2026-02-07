// SPDX-License-Identifier: MIT OR Apache-2.0
//! PolicyDecision — recorded policy evaluations for audit and compliance.
//!
//! Every policy evaluation (allow, deny, escalate) is recorded as a `PolicyDecision`
//! with full context for audit trail, compliance reporting, and policy tuning.
//!
//! # Design
//!
//! - Every decision is recorded, including allows (needed for audit completeness)
//! - Hierarchical policy source tracks which level (global/domain/capability/session)
//! - Correlation ID links decisions to the originating run/task
//! - Evaluation duration enables performance monitoring of policy checks
//!
//! # Example
//!
//! ```
//! use astra_types::{PolicyDecision, PolicyEffect, PolicyLevel, PolicySource};
//!
//! let source = PolicySource::new("rule-001", PolicyLevel::Global);
//!
//! // Allow decision
//! let allow = PolicyDecision::allow("file.read", "agent-123", source.clone());
//! assert!(!allow.is_denied());
//!
//! // Deny decision
//! let deny = PolicyDecision::deny(
//!     "network.egress",
//!     "agent-456",
//!     source,
//!     "Egress not permitted at Tier 1",
//! );
//! assert!(deny.is_denied());
//! ```

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{AstraError, ErrorContext};
use crate::id::{CorrelationId, DecisionId};
use crate::time::Timestamp;
use crate::validate::Validate;

// ============================================================================
// PolicyEffect
// ============================================================================

/// Result of a policy evaluation.
///
/// Three outcomes are possible:
/// - `Allow`: Action proceeds
/// - `Deny`: Action is blocked
/// - `Escalate`: Action requires human approval before proceeding
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyEffect {
    /// Action is allowed to proceed.
    Allow,
    /// Action is denied.
    Deny,
    /// Action requires escalation to human operator for approval.
    Escalate,
}

impl Default for PolicyEffect {
    fn default() -> Self {
        Self::Deny
    }
}

impl fmt::Display for PolicyEffect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "Allow"),
            Self::Deny => write!(f, "Deny"),
            Self::Escalate => write!(f, "Escalate"),
        }
    }
}

impl PolicyEffect {
    /// Check if this effect blocks the action.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny)
    }

    /// Check if this effect allows the action.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Check if this effect requires escalation.
    pub fn requires_escalation(&self) -> bool {
        matches!(self, Self::Escalate)
    }
}

// ============================================================================
// PolicyLevel
// ============================================================================

/// Hierarchy level where a policy rule is defined.
///
/// Rules at higher levels (lower in the enum) override rules at lower levels.
/// Order from most general to most specific: Global < Domain < Capability < Session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyLevel {
    /// Organization-wide policies applying to all agents and capabilities.
    Global,
    /// Domain-specific policies (e.g., "security", "compliance").
    Domain,
    /// Capability-specific policies (e.g., "repo.write" restrictions).
    Capability,
    /// Session-specific overrides for a single run.
    Session,
}

impl Default for PolicyLevel {
    fn default() -> Self {
        Self::Global
    }
}

impl fmt::Display for PolicyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global => write!(f, "Global"),
            Self::Domain => write!(f, "Domain"),
            Self::Capability => write!(f, "Capability"),
            Self::Session => write!(f, "Session"),
        }
    }
}

impl PolicyLevel {
    /// Check if this level overrides another.
    ///
    /// More specific levels (Session > Capability > Domain > Global) override
    /// more general levels.
    pub fn overrides(&self, other: PolicyLevel) -> bool {
        *self > other
    }
}

// ============================================================================
// PolicySource
// ============================================================================

/// Source of a policy rule.
///
/// Tracks provenance: which rule triggered the decision, at what level,
/// and optionally where the rule is defined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySource {
    /// Rule identifier (e.g., "rule-001", "sandbox-tier-check").
    pub rule_id: String,

    /// Hierarchy level where the rule is defined.
    pub level: PolicyLevel,

    /// Optional file/config path where rule is defined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

impl PolicySource {
    /// Create a new policy source.
    pub fn new(rule_id: impl Into<String>, level: PolicyLevel) -> Self {
        Self {
            rule_id: rule_id.into(),
            level,
            path: None,
        }
    }

    /// Set the path where the rule is defined.
    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }
}

impl fmt::Display for PolicySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.rule_id, self.level)
    }
}

impl Validate for PolicySource {
    fn validate(&self) -> Result<(), AstraError> {
        // VAL-080: rule_id cannot be empty
        if self.rule_id.trim().is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-080",
                    "Provide a non-empty rule_id for PolicySource",
                ),
                field: Some("rule_id".into()),
                message: "PolicySource.rule_id cannot be empty".into(),
            });
        }
        Ok(())
    }
}

// ============================================================================
// PolicyDecision
// ============================================================================

/// A recorded policy decision.
///
/// Captures the full context of a policy evaluation for audit, compliance,
/// and policy tuning. Every decision (including allows) should be recorded.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyDecision {
    /// Unique decision identifier.
    pub id: DecisionId,

    /// When the decision was made.
    pub timestamp: Timestamp,

    /// Correlation ID linking to the originating run/task.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<CorrelationId>,

    /// What action was being evaluated (e.g., "file.write", "network.egress").
    pub action: String,

    /// Agent/component requesting the action.
    pub requester: String,

    /// The decision result.
    pub effect: PolicyEffect,

    /// Source of the deciding rule.
    pub source: PolicySource,

    /// Human-readable reason for the decision.
    pub reason: String,

    /// Additional context (e.g., matched patterns, values checked).
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub context: HashMap<String, Value>,

    /// Duration of policy evaluation in microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eval_duration_us: Option<u64>,
}

impl PolicyDecision {
    /// Create an Allow decision.
    ///
    /// ID and timestamp are auto-generated. Reason defaults to a standard message.
    pub fn allow(
        action: impl Into<String>,
        requester: impl Into<String>,
        source: PolicySource,
    ) -> Self {
        Self {
            id: DecisionId::new(),
            timestamp: Timestamp::now(),
            correlation_id: None,
            action: action.into(),
            requester: requester.into(),
            effect: PolicyEffect::Allow,
            source,
            reason: "Policy allows this action".into(),
            context: HashMap::new(),
            eval_duration_us: None,
        }
    }

    /// Create a Deny decision.
    ///
    /// ID and timestamp are auto-generated. Reason is required for denials.
    pub fn deny(
        action: impl Into<String>,
        requester: impl Into<String>,
        source: PolicySource,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: DecisionId::new(),
            timestamp: Timestamp::now(),
            correlation_id: None,
            action: action.into(),
            requester: requester.into(),
            effect: PolicyEffect::Deny,
            source,
            reason: reason.into(),
            context: HashMap::new(),
            eval_duration_us: None,
        }
    }

    /// Create an Escalate decision.
    ///
    /// ID and timestamp are auto-generated. Reason explains why escalation is needed.
    pub fn escalate(
        action: impl Into<String>,
        requester: impl Into<String>,
        source: PolicySource,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            id: DecisionId::new(),
            timestamp: Timestamp::now(),
            correlation_id: None,
            action: action.into(),
            requester: requester.into(),
            effect: PolicyEffect::Escalate,
            source,
            reason: reason.into(),
            context: HashMap::new(),
            eval_duration_us: None,
        }
    }

    /// Set the correlation ID.
    pub fn with_correlation_id(mut self, correlation_id: CorrelationId) -> Self {
        self.correlation_id = Some(correlation_id);
        self
    }

    /// Override the reason.
    pub fn with_reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = reason.into();
        self
    }

    /// Add context data.
    pub fn with_context(mut self, key: impl Into<String>, value: Value) -> Self {
        self.context.insert(key.into(), value);
        self
    }

    /// Set the evaluation duration in microseconds.
    pub fn with_eval_duration_us(mut self, duration_us: u64) -> Self {
        self.eval_duration_us = Some(duration_us);
        self
    }

    /// Check if this decision denies the action.
    pub fn is_denied(&self) -> bool {
        self.effect.is_denied()
    }

    /// Check if this decision allows the action.
    pub fn is_allowed(&self) -> bool {
        self.effect.is_allowed()
    }

    /// Check if this decision requires escalation.
    pub fn requires_escalation(&self) -> bool {
        self.effect.requires_escalation()
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PolicyDecision({}, {}: {} by {})",
            self.id, self.effect, self.action, self.requester
        )
    }
}

impl Validate for PolicyDecision {
    fn validate(&self) -> Result<(), AstraError> {
        // VAL-081: action cannot be empty
        if self.action.trim().is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-081",
                    "Provide a non-empty action for PolicyDecision",
                ),
                field: Some("action".into()),
                message: "PolicyDecision.action cannot be empty".into(),
            });
        }

        // VAL-082: requester cannot be empty
        if self.requester.trim().is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-082",
                    "Provide a non-empty requester for PolicyDecision",
                ),
                field: Some("requester".into()),
                message: "PolicyDecision.requester cannot be empty".into(),
            });
        }

        // VAL-083: reason cannot be empty for Deny/Escalate
        if (self.effect == PolicyEffect::Deny || self.effect == PolicyEffect::Escalate)
            && self.reason.trim().is_empty()
        {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-083",
                    "Provide a non-empty reason for Deny/Escalate decisions",
                ),
                field: Some("reason".into()),
                message: format!(
                    "PolicyDecision.reason cannot be empty for {} effect",
                    self.effect
                ),
            });
        }

        // Validate nested source
        self.source.validate()?;

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

    // ========================================================================
    // PolicyEffect tests
    // ========================================================================

    #[test]
    fn policy_effect_default_is_deny() {
        assert_eq!(PolicyEffect::default(), PolicyEffect::Deny);
    }

    #[test]
    fn policy_effect_display() {
        assert_eq!(PolicyEffect::Allow.to_string(), "Allow");
        assert_eq!(PolicyEffect::Deny.to_string(), "Deny");
        assert_eq!(PolicyEffect::Escalate.to_string(), "Escalate");
    }

    #[test]
    fn policy_effect_is_denied() {
        assert!(!PolicyEffect::Allow.is_denied());
        assert!(PolicyEffect::Deny.is_denied());
        assert!(!PolicyEffect::Escalate.is_denied());
    }

    #[test]
    fn policy_effect_is_allowed() {
        assert!(PolicyEffect::Allow.is_allowed());
        assert!(!PolicyEffect::Deny.is_allowed());
        assert!(!PolicyEffect::Escalate.is_allowed());
    }

    #[test]
    fn policy_effect_requires_escalation() {
        assert!(!PolicyEffect::Allow.requires_escalation());
        assert!(!PolicyEffect::Deny.requires_escalation());
        assert!(PolicyEffect::Escalate.requires_escalation());
    }

    #[test]
    fn policy_effect_serde_roundtrip() {
        for effect in [
            PolicyEffect::Allow,
            PolicyEffect::Deny,
            PolicyEffect::Escalate,
        ] {
            let Ok(json) = serde_json::to_string(&effect) else {
                panic!("serialization should succeed");
            };
            let Ok(decoded) = serde_json::from_str::<PolicyEffect>(&json) else {
                panic!("deserialization should succeed");
            };
            assert_eq!(effect, decoded);
        }
    }

    #[test]
    fn policy_effect_serde_names() {
        let Ok(allow) = serde_json::to_string(&PolicyEffect::Allow) else {
            panic!("serialization should succeed");
        };
        assert_eq!(allow, "\"allow\"");

        let Ok(deny) = serde_json::to_string(&PolicyEffect::Deny) else {
            panic!("serialization should succeed");
        };
        assert_eq!(deny, "\"deny\"");

        let Ok(escalate) = serde_json::to_string(&PolicyEffect::Escalate) else {
            panic!("serialization should succeed");
        };
        assert_eq!(escalate, "\"escalate\"");
    }

    // ========================================================================
    // PolicyLevel tests
    // ========================================================================

    #[test]
    fn policy_level_default_is_global() {
        assert_eq!(PolicyLevel::default(), PolicyLevel::Global);
    }

    #[test]
    fn policy_level_display() {
        assert_eq!(PolicyLevel::Global.to_string(), "Global");
        assert_eq!(PolicyLevel::Domain.to_string(), "Domain");
        assert_eq!(PolicyLevel::Capability.to_string(), "Capability");
        assert_eq!(PolicyLevel::Session.to_string(), "Session");
    }

    #[test]
    fn policy_level_ordering() {
        assert!(PolicyLevel::Global < PolicyLevel::Domain);
        assert!(PolicyLevel::Domain < PolicyLevel::Capability);
        assert!(PolicyLevel::Capability < PolicyLevel::Session);
    }

    #[test]
    fn policy_level_overrides() {
        assert!(PolicyLevel::Session.overrides(PolicyLevel::Capability));
        assert!(PolicyLevel::Session.overrides(PolicyLevel::Domain));
        assert!(PolicyLevel::Session.overrides(PolicyLevel::Global));
        assert!(PolicyLevel::Capability.overrides(PolicyLevel::Domain));
        assert!(PolicyLevel::Capability.overrides(PolicyLevel::Global));
        assert!(PolicyLevel::Domain.overrides(PolicyLevel::Global));

        assert!(!PolicyLevel::Global.overrides(PolicyLevel::Domain));
        assert!(!PolicyLevel::Global.overrides(PolicyLevel::Global));
    }

    #[test]
    fn policy_level_serde_roundtrip() {
        for level in [
            PolicyLevel::Global,
            PolicyLevel::Domain,
            PolicyLevel::Capability,
            PolicyLevel::Session,
        ] {
            let Ok(json) = serde_json::to_string(&level) else {
                panic!("serialization should succeed");
            };
            let Ok(decoded) = serde_json::from_str::<PolicyLevel>(&json) else {
                panic!("deserialization should succeed");
            };
            assert_eq!(level, decoded);
        }
    }

    #[test]
    fn policy_level_serde_names() {
        let Ok(global) = serde_json::to_string(&PolicyLevel::Global) else {
            panic!("serialization should succeed");
        };
        assert_eq!(global, "\"global\"");

        let Ok(session) = serde_json::to_string(&PolicyLevel::Session) else {
            panic!("serialization should succeed");
        };
        assert_eq!(session, "\"session\"");
    }

    // ========================================================================
    // PolicySource tests
    // ========================================================================

    #[test]
    fn policy_source_new() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        assert_eq!(source.rule_id, "rule-001");
        assert_eq!(source.level, PolicyLevel::Global);
        assert!(source.path.is_none());
    }

    #[test]
    fn policy_source_with_path() {
        let source = PolicySource::new("rule-002", PolicyLevel::Domain)
            .with_path("/etc/astra/policies/domain.yaml");
        assert_eq!(source.rule_id, "rule-002");
        assert_eq!(source.level, PolicyLevel::Domain);
        assert_eq!(source.path, Some("/etc/astra/policies/domain.yaml".into()));
    }

    #[test]
    fn policy_source_display() {
        let source = PolicySource::new("sandbox-check", PolicyLevel::Capability);
        assert_eq!(source.to_string(), "sandbox-check@Capability");
    }

    #[test]
    fn policy_source_validate_success() {
        let source = PolicySource::new("valid-rule", PolicyLevel::Global);
        assert!(source.validate().is_ok());
    }

    #[test]
    fn policy_source_validate_empty_rule_id() {
        let source = PolicySource::new("", PolicyLevel::Global);
        let result = source.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-080");
    }

    #[test]
    fn policy_source_validate_whitespace_rule_id() {
        let source = PolicySource::new("   ", PolicyLevel::Global);
        let result = source.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-080");
    }

    #[test]
    fn policy_source_serde_roundtrip() {
        let source =
            PolicySource::new("rule-001", PolicyLevel::Domain).with_path("/path/to/policy.yaml");

        let Ok(json) = serde_json::to_string(&source) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<PolicySource>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(source, decoded);
    }

    #[test]
    fn policy_source_serde_skips_none_path() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let Ok(json) = serde_json::to_string(&source) else {
            panic!("serialization should succeed");
        };
        assert!(!json.contains("\"path\""));
    }

    // ========================================================================
    // PolicyDecision tests
    // ========================================================================

    #[test]
    fn policy_decision_allow() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let decision = PolicyDecision::allow("file.read", "agent-123", source);

        assert_eq!(decision.action, "file.read");
        assert_eq!(decision.requester, "agent-123");
        assert_eq!(decision.effect, PolicyEffect::Allow);
        assert!(decision.is_allowed());
        assert!(!decision.is_denied());
        assert!(!decision.requires_escalation());
    }

    #[test]
    fn policy_decision_deny() {
        let source = PolicySource::new("rule-002", PolicyLevel::Domain);
        let decision = PolicyDecision::deny(
            "network.egress",
            "agent-456",
            source,
            "Egress blocked at sandbox tier 1",
        );

        assert_eq!(decision.action, "network.egress");
        assert_eq!(decision.requester, "agent-456");
        assert_eq!(decision.effect, PolicyEffect::Deny);
        assert_eq!(decision.reason, "Egress blocked at sandbox tier 1");
        assert!(decision.is_denied());
        assert!(!decision.is_allowed());
    }

    #[test]
    fn policy_decision_escalate() {
        let source = PolicySource::new("rule-003", PolicyLevel::Capability);
        let decision = PolicyDecision::escalate(
            "admin.delete",
            "agent-789",
            source,
            "Destructive action requires human approval",
        );

        assert_eq!(decision.action, "admin.delete");
        assert_eq!(decision.effect, PolicyEffect::Escalate);
        assert!(decision.requires_escalation());
        assert!(!decision.is_allowed());
        assert!(!decision.is_denied());
    }

    #[test]
    fn policy_decision_builder_methods() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let correlation = CorrelationId::new();

        let decision = PolicyDecision::allow("test.action", "test-agent", source)
            .with_correlation_id(correlation)
            .with_reason("Custom reason")
            .with_context("key", Value::String("value".into()))
            .with_eval_duration_us(150);

        assert!(decision.correlation_id.is_some());
        assert_eq!(decision.reason, "Custom reason");
        assert_eq!(
            decision.context.get("key"),
            Some(&Value::String("value".into()))
        );
        assert_eq!(decision.eval_duration_us, Some(150));
    }

    #[test]
    fn policy_decision_display() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let decision = PolicyDecision::deny("file.write", "agent-001", source, "Blocked");
        let display = decision.to_string();

        assert!(display.contains("PolicyDecision"));
        assert!(display.contains("Deny"));
        assert!(display.contains("file.write"));
        assert!(display.contains("agent-001"));
    }

    #[test]
    fn policy_decision_validate_success() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let decision = PolicyDecision::allow("valid.action", "valid-agent", source);
        assert!(decision.validate().is_ok());
    }

    #[test]
    fn policy_decision_validate_empty_action() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let mut decision = PolicyDecision::allow("action", "agent", source);
        decision.action = "".into();

        let result = decision.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-081");
    }

    #[test]
    fn policy_decision_validate_whitespace_action() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let mut decision = PolicyDecision::allow("action", "agent", source);
        decision.action = "   ".into();

        let result = decision.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-081");
    }

    #[test]
    fn policy_decision_validate_empty_requester() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let mut decision = PolicyDecision::allow("action", "agent", source);
        decision.requester = "".into();

        let result = decision.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-082");
    }

    #[test]
    fn policy_decision_validate_empty_reason_deny() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let mut decision = PolicyDecision::deny("action", "agent", source, "reason");
        decision.reason = "".into();

        let result = decision.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-083");
    }

    #[test]
    fn policy_decision_validate_empty_reason_escalate() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let mut decision = PolicyDecision::escalate("action", "agent", source, "reason");
        decision.reason = "   ".into();

        let result = decision.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-083");
    }

    #[test]
    fn policy_decision_validate_empty_reason_allow_ok() {
        // Allow decisions can have empty reasons
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let mut decision = PolicyDecision::allow("action", "agent", source);
        decision.reason = "".into();

        assert!(decision.validate().is_ok());
    }

    #[test]
    fn policy_decision_validate_invalid_source() {
        let source = PolicySource::new("", PolicyLevel::Global); // Invalid
        let decision = PolicyDecision::allow("action", "agent", source);

        let result = decision.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-080");
    }

    #[test]
    fn policy_decision_serde_roundtrip() {
        let source =
            PolicySource::new("rule-001", PolicyLevel::Domain).with_path("/path/to/policy.yaml");
        let correlation = CorrelationId::new();

        let decision =
            PolicyDecision::deny("file.delete", "agent-cleanup", source, "Not permitted")
                .with_correlation_id(correlation)
                .with_context("target", Value::String("/tmp/sensitive".into()))
                .with_eval_duration_us(42);

        let Ok(json) = serde_json::to_string(&decision) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<PolicyDecision>(&json) else {
            panic!("deserialization should succeed");
        };

        assert_eq!(decision.id, decoded.id);
        assert_eq!(decision.action, decoded.action);
        assert_eq!(decision.requester, decoded.requester);
        assert_eq!(decision.effect, decoded.effect);
        assert_eq!(decision.reason, decoded.reason);
        assert_eq!(decision.source, decoded.source);
        assert_eq!(decision.eval_duration_us, decoded.eval_duration_us);
    }

    #[test]
    fn policy_decision_serde_skips_empty_context() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let decision = PolicyDecision::allow("action", "agent", source);

        let Ok(json) = serde_json::to_string(&decision) else {
            panic!("serialization should succeed");
        };
        assert!(!json.contains("\"context\""));
    }

    #[test]
    fn policy_decision_serde_skips_none_fields() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let decision = PolicyDecision::allow("action", "agent", source);

        let Ok(json) = serde_json::to_string(&decision) else {
            panic!("serialization should succeed");
        };
        assert!(!json.contains("\"correlation_id\""));
        assert!(!json.contains("\"eval_duration_us\""));
    }

    #[test]
    fn policy_decision_id_auto_generated() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let d1 = PolicyDecision::allow("action", "agent", source.clone());
        let d2 = PolicyDecision::allow("action", "agent", source);

        assert_ne!(d1.id, d2.id);
    }

    #[test]
    fn policy_decision_timestamp_auto_generated() {
        let source = PolicySource::new("rule-001", PolicyLevel::Global);
        let decision = PolicyDecision::allow("action", "agent", source);

        // Timestamp should be recent (within last second)
        assert!(!decision.timestamp.is_future());
    }
}
