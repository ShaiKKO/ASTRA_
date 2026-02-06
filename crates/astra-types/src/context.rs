// SPDX-License-Identifier: MIT OR Apache-2.0
//! ContextItem — shared knowledge units with visibility and provenance.
//!
//! Context items are facts, hypotheses, and decisions that flow through the
//! agent system. They have scoped visibility, promotion rules, and confidence
//! tracking for uncertainty handling.
//!
//! See blueprint §8.1-8.3 for context service requirements.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::{AstraError, ErrorContext, Severity};
use crate::id::ContextId;
use crate::time::Timestamp;
use crate::validate::Validate;

// ============================================================================
// ContextScope
// ============================================================================

/// Visibility scope of a context item.
///
/// Scopes form a hierarchy: AgentLocal < TeamShared < Project < Global.
/// Items can be promoted to wider scopes but never demoted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextScope {
    /// Visible only to the creating agent.
    AgentLocal,
    /// Shared within the agent team (default).
    TeamShared,
    /// Visible across the entire project.
    Project,
    /// Globally visible to all agents.
    Global,
}

impl Default for ContextScope {
    fn default() -> Self {
        Self::TeamShared
    }
}

impl fmt::Display for ContextScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AgentLocal => write!(f, "AgentLocal"),
            Self::TeamShared => write!(f, "TeamShared"),
            Self::Project => write!(f, "Project"),
            Self::Global => write!(f, "Global"),
        }
    }
}

impl ContextScope {
    /// Check if this scope includes another scope.
    ///
    /// A wider scope includes all narrower scopes. For example, Project
    /// includes TeamShared and AgentLocal.
    pub fn includes(&self, other: ContextScope) -> bool {
        *self >= other
    }

    /// Check if this is the narrowest scope.
    pub fn is_agent_local(&self) -> bool {
        matches!(self, Self::AgentLocal)
    }

    /// Check if this is the widest scope.
    pub fn is_global(&self) -> bool {
        matches!(self, Self::Global)
    }
}

// ============================================================================
// ContextKind
// ============================================================================

/// Classification of context item content.
///
/// Determines how the item should be treated by consuming agents:
/// - Facts are verified and reliable
/// - Hypotheses need validation before use
/// - Decisions record choices made
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextKind {
    /// Verified information that can be relied upon.
    Fact,
    /// Unverified assumption requiring validation.
    Hypothesis,
    /// Recorded decision with rationale.
    Decision,
}

impl Default for ContextKind {
    fn default() -> Self {
        Self::Hypothesis
    }
}

impl fmt::Display for ContextKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fact => write!(f, "Fact"),
            Self::Hypothesis => write!(f, "Hypothesis"),
            Self::Decision => write!(f, "Decision"),
        }
    }
}

impl ContextKind {
    /// Check if this kind can be promoted to a Fact.
    ///
    /// Only Hypothesis can be promoted to Fact (after validation).
    /// Facts are already facts, and Decisions are records, not claims.
    pub fn can_promote_to_fact(&self) -> bool {
        matches!(self, Self::Hypothesis)
    }

    /// Check if this kind requires validation before use.
    pub fn requires_validation(&self) -> bool {
        matches!(self, Self::Hypothesis)
    }
}

// ============================================================================
// ContextItem
// ============================================================================

/// A unit of shared knowledge with visibility and provenance.
///
/// Context items flow through the agent system carrying facts, hypotheses,
/// and decisions. They have scoped visibility, confidence tracking, and
/// cross-references for building knowledge graphs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContextItem {
    /// Unique identifier.
    pub id: ContextId,

    /// Visibility scope.
    #[serde(default)]
    pub scope: ContextScope,

    /// Content classification.
    #[serde(default)]
    pub kind: ContextKind,

    /// The actual content/information.
    pub content: String,

    /// Source of this information (agent ID, tool, user, etc.).
    pub source: String,

    /// When this item was created.
    pub timestamp: Timestamp,

    /// Confidence level (0.0-1.0) for probabilistic reasoning.
    ///
    /// - 1.0: Certain (e.g., Facts)
    /// - 0.5-0.9: Likely (e.g., strong Hypotheses)
    /// - 0.1-0.5: Uncertain (e.g., weak Hypotheses)
    /// - None: Confidence not applicable (e.g., Decisions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,

    /// Tags for categorization and filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// References to related context items.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<ContextId>,
}

impl ContextItem {
    /// Create a new context item with required fields.
    pub fn new(content: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            id: ContextId::new(),
            scope: ContextScope::default(),
            kind: ContextKind::default(),
            content: content.into(),
            source: source.into(),
            timestamp: Timestamp::now(),
            confidence: None,
            tags: Vec::new(),
            references: Vec::new(),
        }
    }

    /// Create a new Fact.
    pub fn fact(content: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            kind: ContextKind::Fact,
            confidence: Some(1.0),
            ..Self::new(content, source)
        }
    }

    /// Create a new Hypothesis with confidence.
    pub fn hypothesis(
        content: impl Into<String>,
        source: impl Into<String>,
        confidence: f32,
    ) -> Self {
        Self {
            kind: ContextKind::Hypothesis,
            confidence: Some(confidence),
            ..Self::new(content, source)
        }
    }

    /// Create a new Decision.
    pub fn decision(content: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            kind: ContextKind::Decision,
            confidence: None,
            ..Self::new(content, source)
        }
    }

    /// Set the visibility scope.
    pub fn with_scope(mut self, scope: ContextScope) -> Self {
        self.scope = scope;
        self
    }

    /// Set the kind.
    pub fn with_kind(mut self, kind: ContextKind) -> Self {
        self.kind = kind;
        self
    }

    /// Set the confidence level.
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = Some(confidence);
        self
    }

    /// Add a tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Add multiple tags.
    pub fn with_tags(mut self, tags: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.tags.extend(tags.into_iter().map(Into::into));
        self
    }

    /// Add a reference to another context item.
    pub fn with_reference(mut self, reference: ContextId) -> Self {
        self.references.push(reference);
        self
    }

    /// Promote a Hypothesis to a Fact.
    ///
    /// # Errors
    /// Returns `AstraError::ValidationFailed` with code VAL-076 if the
    /// item is not a Hypothesis.
    #[allow(clippy::result_large_err)]
    pub fn promote_to_fact(&mut self) -> Result<(), AstraError> {
        if self.kind.can_promote_to_fact() {
            self.kind = ContextKind::Fact;
            self.confidence = Some(1.0);
            Ok(())
        } else {
            Err(AstraError::ValidationFailed {
                context: ErrorContext::builder()
                    .error_code("VAL-076")
                    .component("astra-types")
                    .severity(Severity::Error)
                    .remediation_hint("Only Hypothesis can be promoted to Fact")
                    .build()
                    .unwrap_or_default(),
                field: Some("kind".into()),
                message: format!("Cannot promote {} to Fact", self.kind),
            })
        }
    }

    /// Widen the visibility scope.
    ///
    /// Scope can only be widened, never narrowed. Returns true if the
    /// scope was actually changed.
    pub fn widen_scope(&mut self, new_scope: ContextScope) -> bool {
        if new_scope > self.scope {
            self.scope = new_scope;
            true
        } else {
            false
        }
    }

    /// Check if this item is visible in the given scope.
    pub fn is_visible_in(&self, scope: ContextScope) -> bool {
        scope.includes(self.scope)
    }

    /// Check if this item has a tag.
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

impl fmt::Display for ContextItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ContextItem({}, kind={}, scope={})",
            self.id, self.kind, self.scope
        )
    }
}

impl Validate for ContextItem {
    #[allow(clippy::result_large_err)]
    fn validate(&self) -> Result<(), AstraError> {
        // VAL-073: Content cannot be empty
        if self.content.trim().is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::builder()
                    .error_code("VAL-073")
                    .component("astra-types")
                    .severity(Severity::Error)
                    .remediation_hint("Provide non-empty content for the context item")
                    .build()
                    .unwrap_or_default(),
                field: Some("content".into()),
                message: "ContextItem.content cannot be empty".into(),
            });
        }

        // VAL-074: Source cannot be empty
        if self.source.trim().is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::builder()
                    .error_code("VAL-074")
                    .component("astra-types")
                    .severity(Severity::Error)
                    .remediation_hint("Provide non-empty source for the context item")
                    .build()
                    .unwrap_or_default(),
                field: Some("source".into()),
                message: "ContextItem.source cannot be empty".into(),
            });
        }

        // VAL-075 and VAL-077: Confidence must be 0.0-1.0 and finite
        if let Some(conf) = self.confidence {
            // VAL-077: Must be finite
            if !conf.is_finite() {
                return Err(AstraError::ValidationFailed {
                    context: ErrorContext::builder()
                        .error_code("VAL-077")
                        .component("astra-types")
                        .severity(Severity::Error)
                        .remediation_hint("Confidence must be a finite number")
                        .build()
                        .unwrap_or_default(),
                    field: Some("confidence".into()),
                    message: "ContextItem.confidence must be finite".into(),
                });
            }

            // VAL-075: Must be in range
            if !(0.0..=1.0).contains(&conf) {
                return Err(AstraError::ValidationFailed {
                    context: ErrorContext::builder()
                        .error_code("VAL-075")
                        .component("astra-types")
                        .severity(Severity::Error)
                        .remediation_hint("Confidence must be between 0.0 and 1.0 inclusive")
                        .build()
                        .unwrap_or_default(),
                    field: Some("confidence".into()),
                    message: format!("ContextItem.confidence must be 0.0-1.0, got {}", conf),
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

    // ========================================================================
    // ContextScope tests
    // ========================================================================

    #[test]
    fn context_scope_default_is_team_shared() {
        assert_eq!(ContextScope::default(), ContextScope::TeamShared);
    }

    #[test]
    fn context_scope_display() {
        assert_eq!(ContextScope::AgentLocal.to_string(), "AgentLocal");
        assert_eq!(ContextScope::TeamShared.to_string(), "TeamShared");
        assert_eq!(ContextScope::Project.to_string(), "Project");
        assert_eq!(ContextScope::Global.to_string(), "Global");
    }

    #[test]
    fn context_scope_ordering() {
        assert!(ContextScope::AgentLocal < ContextScope::TeamShared);
        assert!(ContextScope::TeamShared < ContextScope::Project);
        assert!(ContextScope::Project < ContextScope::Global);
    }

    #[test]
    fn context_scope_includes() {
        // Global includes everything
        assert!(ContextScope::Global.includes(ContextScope::Global));
        assert!(ContextScope::Global.includes(ContextScope::Project));
        assert!(ContextScope::Global.includes(ContextScope::TeamShared));
        assert!(ContextScope::Global.includes(ContextScope::AgentLocal));

        // Project includes narrower
        assert!(ContextScope::Project.includes(ContextScope::Project));
        assert!(ContextScope::Project.includes(ContextScope::TeamShared));
        assert!(ContextScope::Project.includes(ContextScope::AgentLocal));
        assert!(!ContextScope::Project.includes(ContextScope::Global));

        // TeamShared includes narrower
        assert!(ContextScope::TeamShared.includes(ContextScope::TeamShared));
        assert!(ContextScope::TeamShared.includes(ContextScope::AgentLocal));
        assert!(!ContextScope::TeamShared.includes(ContextScope::Project));

        // AgentLocal only includes itself
        assert!(ContextScope::AgentLocal.includes(ContextScope::AgentLocal));
        assert!(!ContextScope::AgentLocal.includes(ContextScope::TeamShared));
    }

    #[test]
    fn context_scope_is_agent_local() {
        assert!(ContextScope::AgentLocal.is_agent_local());
        assert!(!ContextScope::TeamShared.is_agent_local());
        assert!(!ContextScope::Global.is_agent_local());
    }

    #[test]
    fn context_scope_is_global() {
        assert!(ContextScope::Global.is_global());
        assert!(!ContextScope::Project.is_global());
        assert!(!ContextScope::AgentLocal.is_global());
    }

    #[test]
    fn context_scope_serde_roundtrip() {
        for scope in [
            ContextScope::AgentLocal,
            ContextScope::TeamShared,
            ContextScope::Project,
            ContextScope::Global,
        ] {
            let Ok(json) = serde_json::to_string(&scope) else {
                panic!("serialization should succeed");
            };
            let Ok(decoded) = serde_json::from_str::<ContextScope>(&json) else {
                panic!("deserialization should succeed");
            };
            assert_eq!(scope, decoded);
        }
    }

    #[test]
    fn context_scope_serde_names() {
        let Ok(local) = serde_json::to_string(&ContextScope::AgentLocal) else {
            panic!("serialization should succeed");
        };
        assert_eq!(local, "\"agent_local\"");

        let Ok(team) = serde_json::to_string(&ContextScope::TeamShared) else {
            panic!("serialization should succeed");
        };
        assert_eq!(team, "\"team_shared\"");

        let Ok(project) = serde_json::to_string(&ContextScope::Project) else {
            panic!("serialization should succeed");
        };
        assert_eq!(project, "\"project\"");

        let Ok(global) = serde_json::to_string(&ContextScope::Global) else {
            panic!("serialization should succeed");
        };
        assert_eq!(global, "\"global\"");
    }

    // ========================================================================
    // ContextKind tests
    // ========================================================================

    #[test]
    fn context_kind_default_is_hypothesis() {
        assert_eq!(ContextKind::default(), ContextKind::Hypothesis);
    }

    #[test]
    fn context_kind_display() {
        assert_eq!(ContextKind::Fact.to_string(), "Fact");
        assert_eq!(ContextKind::Hypothesis.to_string(), "Hypothesis");
        assert_eq!(ContextKind::Decision.to_string(), "Decision");
    }

    #[test]
    fn context_kind_can_promote_to_fact() {
        assert!(ContextKind::Hypothesis.can_promote_to_fact());
        assert!(!ContextKind::Fact.can_promote_to_fact());
        assert!(!ContextKind::Decision.can_promote_to_fact());
    }

    #[test]
    fn context_kind_requires_validation() {
        assert!(ContextKind::Hypothesis.requires_validation());
        assert!(!ContextKind::Fact.requires_validation());
        assert!(!ContextKind::Decision.requires_validation());
    }

    #[test]
    fn context_kind_serde_roundtrip() {
        for kind in [
            ContextKind::Fact,
            ContextKind::Hypothesis,
            ContextKind::Decision,
        ] {
            let Ok(json) = serde_json::to_string(&kind) else {
                panic!("serialization should succeed");
            };
            let Ok(decoded) = serde_json::from_str::<ContextKind>(&json) else {
                panic!("deserialization should succeed");
            };
            assert_eq!(kind, decoded);
        }
    }

    #[test]
    fn context_kind_serde_names() {
        let Ok(fact) = serde_json::to_string(&ContextKind::Fact) else {
            panic!("serialization should succeed");
        };
        assert_eq!(fact, "\"fact\"");

        let Ok(hypothesis) = serde_json::to_string(&ContextKind::Hypothesis) else {
            panic!("serialization should succeed");
        };
        assert_eq!(hypothesis, "\"hypothesis\"");

        let Ok(decision) = serde_json::to_string(&ContextKind::Decision) else {
            panic!("serialization should succeed");
        };
        assert_eq!(decision, "\"decision\"");
    }

    // ========================================================================
    // ContextItem tests
    // ========================================================================

    #[test]
    fn context_item_new() {
        let item = ContextItem::new("Test content", "test-agent");
        assert_eq!(item.content, "Test content");
        assert_eq!(item.source, "test-agent");
        assert_eq!(item.scope, ContextScope::TeamShared);
        assert_eq!(item.kind, ContextKind::Hypothesis);
        assert!(item.confidence.is_none());
        assert!(item.tags.is_empty());
        assert!(item.references.is_empty());
    }

    #[test]
    fn context_item_fact() {
        let item = ContextItem::fact("The sky is blue", "observation-agent");
        assert_eq!(item.kind, ContextKind::Fact);
        assert_eq!(item.confidence, Some(1.0));
    }

    #[test]
    fn context_item_hypothesis() {
        let item = ContextItem::hypothesis("User prefers dark mode", "ui-agent", 0.7);
        assert_eq!(item.kind, ContextKind::Hypothesis);
        assert_eq!(item.confidence, Some(0.7));
    }

    #[test]
    fn context_item_decision() {
        let item = ContextItem::decision("Use PostgreSQL for persistence", "architect-agent");
        assert_eq!(item.kind, ContextKind::Decision);
        assert!(item.confidence.is_none());
    }

    #[test]
    fn context_item_builder_methods() {
        let ref_id = ContextId::new();
        let item = ContextItem::new("Test", "source")
            .with_scope(ContextScope::Project)
            .with_kind(ContextKind::Fact)
            .with_confidence(0.95)
            .with_tag("important")
            .with_tags(["verified", "reviewed"])
            .with_reference(ref_id);

        assert_eq!(item.scope, ContextScope::Project);
        assert_eq!(item.kind, ContextKind::Fact);
        assert_eq!(item.confidence, Some(0.95));
        assert_eq!(item.tags, vec!["important", "verified", "reviewed"]);
        assert_eq!(item.references.len(), 1);
    }

    #[test]
    fn context_item_promote_to_fact_success() {
        let mut item = ContextItem::hypothesis("Water boils at 100C", "science-agent", 0.8);
        assert!(item.promote_to_fact().is_ok());
        assert_eq!(item.kind, ContextKind::Fact);
        assert_eq!(item.confidence, Some(1.0));
    }

    #[test]
    fn context_item_promote_to_fact_fails_for_fact() {
        let mut item = ContextItem::fact("Already a fact", "agent");
        let result = item.promote_to_fact();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-076");
    }

    #[test]
    fn context_item_promote_to_fact_fails_for_decision() {
        let mut item = ContextItem::decision("A decision", "agent");
        let result = item.promote_to_fact();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-076");
    }

    #[test]
    fn context_item_widen_scope() {
        let mut item = ContextItem::new("Test", "agent").with_scope(ContextScope::AgentLocal);

        // Widen to TeamShared
        assert!(item.widen_scope(ContextScope::TeamShared));
        assert_eq!(item.scope, ContextScope::TeamShared);

        // Widen to Global
        assert!(item.widen_scope(ContextScope::Global));
        assert_eq!(item.scope, ContextScope::Global);

        // Cannot narrow
        assert!(!item.widen_scope(ContextScope::Project));
        assert_eq!(item.scope, ContextScope::Global);

        // Same scope returns false
        assert!(!item.widen_scope(ContextScope::Global));
    }

    #[test]
    fn context_item_is_visible_in() {
        let item = ContextItem::new("Test", "agent").with_scope(ContextScope::TeamShared);

        // Visible in wider scopes
        assert!(item.is_visible_in(ContextScope::Project));
        assert!(item.is_visible_in(ContextScope::Global));
        assert!(item.is_visible_in(ContextScope::TeamShared));

        // Not visible in narrower scope
        assert!(!item.is_visible_in(ContextScope::AgentLocal));
    }

    #[test]
    fn context_item_has_tag() {
        let item = ContextItem::new("Test", "agent").with_tags(["important", "verified"]);

        assert!(item.has_tag("important"));
        assert!(item.has_tag("verified"));
        assert!(!item.has_tag("unverified"));
    }

    #[test]
    fn context_item_display() {
        let item = ContextItem::fact("Content", "source");
        let display = item.to_string();
        assert!(display.contains("ContextItem"));
        assert!(display.contains("Fact"));
        assert!(display.contains("TeamShared"));
    }

    #[test]
    fn context_item_validate_success() {
        let item = ContextItem::new("Valid content", "valid-source");
        assert!(item.validate().is_ok());
    }

    #[test]
    fn context_item_validate_empty_content() {
        let mut item = ContextItem::new("Content", "source");
        item.content = "".to_string();

        let result = item.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-073");
    }

    #[test]
    fn context_item_validate_whitespace_content() {
        let mut item = ContextItem::new("Content", "source");
        item.content = "   ".to_string();

        let result = item.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-073");
    }

    #[test]
    fn context_item_validate_empty_source() {
        let mut item = ContextItem::new("Content", "source");
        item.source = "".to_string();

        let result = item.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-074");
    }

    #[test]
    fn context_item_validate_whitespace_source() {
        let mut item = ContextItem::new("Content", "source");
        item.source = "   ".to_string();

        let result = item.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-074");
    }

    #[test]
    fn context_item_validate_confidence_out_of_range() {
        let item = ContextItem::new("Content", "source").with_confidence(1.5);

        let result = item.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-075");
    }

    #[test]
    fn context_item_validate_confidence_negative() {
        let item = ContextItem::new("Content", "source").with_confidence(-0.1);

        let result = item.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-075");
    }

    #[test]
    fn context_item_validate_confidence_nan() {
        let item = ContextItem::new("Content", "source").with_confidence(f32::NAN);

        let result = item.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-077");
    }

    #[test]
    fn context_item_validate_confidence_infinity() {
        let item = ContextItem::new("Content", "source").with_confidence(f32::INFINITY);

        let result = item.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-077");
    }

    #[test]
    fn context_item_validate_confidence_boundaries() {
        // 0.0 is valid
        let item = ContextItem::new("Content", "source").with_confidence(0.0);
        assert!(item.validate().is_ok());

        // 1.0 is valid
        let item = ContextItem::new("Content", "source").with_confidence(1.0);
        assert!(item.validate().is_ok());

        // None confidence is valid
        let item = ContextItem::new("Content", "source");
        assert!(item.validate().is_ok());
    }

    #[test]
    fn context_item_serde_roundtrip() {
        let ref_id = ContextId::new();
        let item = ContextItem::new("Test content", "test-source")
            .with_scope(ContextScope::Project)
            .with_kind(ContextKind::Fact)
            .with_confidence(0.95)
            .with_tags(["tag1", "tag2"])
            .with_reference(ref_id);

        let Ok(json) = serde_json::to_string(&item) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<ContextItem>(&json) else {
            panic!("deserialization should succeed");
        };

        assert_eq!(item.id, decoded.id);
        assert_eq!(item.scope, decoded.scope);
        assert_eq!(item.kind, decoded.kind);
        assert_eq!(item.content, decoded.content);
        assert_eq!(item.source, decoded.source);
        assert_eq!(item.confidence, decoded.confidence);
        assert_eq!(item.tags, decoded.tags);
        assert_eq!(item.references, decoded.references);
    }

    #[test]
    fn context_item_serde_skips_empty_collections() {
        let item = ContextItem::new("Content", "source");
        let Ok(json) = serde_json::to_string(&item) else {
            panic!("serialization should succeed");
        };

        // Empty tags and references should be skipped
        assert!(!json.contains("\"tags\""));
        assert!(!json.contains("\"references\""));
    }

    #[test]
    fn context_item_serde_skips_none_confidence() {
        let item = ContextItem::decision("Decision", "source");
        let Ok(json) = serde_json::to_string(&item) else {
            panic!("serialization should succeed");
        };

        // None confidence should be skipped
        assert!(!json.contains("\"confidence\""));
    }
}
