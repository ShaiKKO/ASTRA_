// SPDX-License-Identifier: MIT OR Apache-2.0
//! Artifact — versioned, auditable work products.
//!
//! Artifacts are the persistence primitives for ASTRA_: code patches, documents,
//! plans, reports. They have a lifecycle state machine, provenance links, and
//! support auditability and reconstructability.
//!
//! See blueprint §9.1-9.3 for schema and traceability requirements.

use std::collections::HashMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{AstraError, ErrorContext};
use crate::id::ArtifactId;
use crate::time::Timestamp;
use crate::validate::Validate;

// ============================================================================
// ArtifactState
// ============================================================================

/// Lifecycle state of an artifact.
///
/// States form a directed graph with valid transitions. Use `can_transition_to()`
/// to check if a transition is valid before attempting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactState {
    /// Initial working state.
    Draft,
    /// Submitted for review.
    Proposed,
    /// Passed validation checks.
    Validated,
    /// Approved by authority (human or automated).
    Approved,
    /// Released/published for use.
    Released,
    /// Superseded or retired.
    Deprecated,
}

impl Default for ArtifactState {
    fn default() -> Self {
        Self::Draft
    }
}

impl fmt::Display for ArtifactState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Draft => write!(f, "Draft"),
            Self::Proposed => write!(f, "Proposed"),
            Self::Validated => write!(f, "Validated"),
            Self::Approved => write!(f, "Approved"),
            Self::Released => write!(f, "Released"),
            Self::Deprecated => write!(f, "Deprecated"),
        }
    }
}

impl ArtifactState {
    /// Check if transition to target state is valid.
    ///
    /// Valid transitions:
    /// - Draft → Proposed
    /// - Proposed → Validated | Draft (rejection)
    /// - Validated → Approved | Draft (rejection)
    /// - Approved → Released
    /// - Released → Deprecated
    /// - Any → Deprecated (always allowed)
    pub fn can_transition_to(&self, target: ArtifactState) -> bool {
        use ArtifactState::*;
        matches!(
            (self, target),
            (Draft, Proposed)
                | (Proposed, Validated)
                | (Proposed, Draft) // Rejection
                | (Validated, Approved)
                | (Validated, Draft) // Rejection
                | (Approved, Released)
                | (Released, Deprecated)
                | (Draft, Deprecated)
                | (Proposed, Deprecated)
                | (Validated, Deprecated)
                | (Approved, Deprecated)
        )
    }

    /// Get valid next states from current state.
    ///
    /// Returns a static slice for zero allocation. Variant ordering within
    /// each slice is: forward progression first, then rejection, then deprecation.
    pub fn valid_transitions(&self) -> &'static [ArtifactState] {
        use ArtifactState::*;
        match self {
            Draft => &[Proposed, Deprecated],
            Proposed => &[Validated, Draft, Deprecated],
            Validated => &[Approved, Draft, Deprecated],
            Approved => &[Released, Deprecated],
            Released => &[Deprecated],
            Deprecated => &[],
        }
    }

    /// Check if this is a terminal state (no further transitions).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Deprecated)
    }
}

// ============================================================================
// ArtifactLinks
// ============================================================================

/// Links connecting an artifact to its provenance.
///
/// Enables traceability: which run created it, which agent, what policy
/// decisions affected it, and relationships to other artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ArtifactLinks {
    /// Run that created/modified this artifact.
    ///
    /// Design: String for now; consider typed RunId when Run schema is defined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,

    /// Agent that created/modified this artifact.
    ///
    /// Design: String for now; consider typed AgentId when Agent schema is defined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,

    /// Policy decisions that affected this artifact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_decisions: Vec<String>,

    /// Parent artifact (if this is derived from another).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<ArtifactId>,

    /// Related artifacts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub related: Vec<ArtifactId>,
}

impl ArtifactLinks {
    /// Create new empty links.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the run ID.
    pub fn with_run_id(mut self, run_id: impl Into<String>) -> Self {
        self.run_id = Some(run_id.into());
        self
    }

    /// Set the agent ID.
    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = Some(agent_id.into());
        self
    }

    /// Add a policy decision.
    pub fn with_policy_decision(mut self, decision: impl Into<String>) -> Self {
        self.policy_decisions.push(decision.into());
        self
    }

    /// Set the parent artifact.
    pub fn with_parent(mut self, parent_id: ArtifactId) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    /// Add a related artifact.
    pub fn with_related(mut self, artifact_id: ArtifactId) -> Self {
        self.related.push(artifact_id);
        self
    }
}

// ============================================================================
// Artifact
// ============================================================================

/// Default version for new artifacts.
fn default_version() -> String {
    "1".to_string()
}

/// A versioned, auditable work product.
///
/// Artifacts are the persistence primitives: code patches, ADRs, test reports,
/// plans. They have lifecycle states, provenance links, and arbitrary metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Artifact {
    /// Unique identifier.
    pub id: ArtifactId,

    /// Artifact type (e.g., "PatchSet", "ADR", "TestReport").
    #[serde(rename = "type")]
    pub artifact_type: String,

    /// Current lifecycle state.
    pub state: ArtifactState,

    /// Version string (semver or sequential).
    #[serde(default = "default_version")]
    pub version: String,

    /// Arbitrary metadata.
    #[serde(default)]
    pub metadata: HashMap<String, Value>,

    /// Provenance links.
    #[serde(default)]
    pub links: ArtifactLinks,

    /// Content hash for integrity verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,

    /// Creation timestamp.
    pub created_at: Timestamp,

    /// Last modification timestamp.
    pub updated_at: Timestamp,
}

impl Artifact {
    /// Create a new draft artifact.
    pub fn new_draft(artifact_type: impl Into<String>) -> Self {
        let now = Timestamp::now();
        Self {
            id: ArtifactId::new(),
            artifact_type: artifact_type.into(),
            state: ArtifactState::Draft,
            version: default_version(),
            metadata: HashMap::new(),
            links: ArtifactLinks::default(),
            content_hash: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    /// Create a new draft artifact with a specific ID.
    pub fn new_draft_with_id(id: ArtifactId, artifact_type: impl Into<String>) -> Self {
        let now = Timestamp::now();
        Self {
            id,
            artifact_type: artifact_type.into(),
            state: ArtifactState::Draft,
            version: default_version(),
            metadata: HashMap::new(),
            links: ArtifactLinks::default(),
            content_hash: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    /// Set a metadata value.
    pub fn with_metadata(mut self, key: impl Into<String>, value: Value) -> Self {
        self.metadata.insert(key.into(), value);
        self
    }

    /// Set the provenance links.
    pub fn with_links(mut self, links: ArtifactLinks) -> Self {
        self.links = links;
        self
    }

    /// Set the content hash.
    pub fn with_content_hash(mut self, hash: impl Into<String>) -> Self {
        self.content_hash = Some(hash.into());
        self
    }

    /// Set the version.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = version.into();
        self
    }

    /// Transition to a new state.
    ///
    /// # Errors
    /// Returns `AstraError::ValidationFailed` with code VAL-072 if the
    /// transition is not valid from the current state.
    #[allow(clippy::result_large_err)]
    pub fn transition_to(&mut self, new_state: ArtifactState) -> Result<(), AstraError> {
        if self.state.can_transition_to(new_state) {
            self.state = new_state;
            self.updated_at = Timestamp::now();
            Ok(())
        } else {
            Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-072",
                    format!(
                        "Valid transitions from {}: {:?}",
                        self.state,
                        self.state.valid_transitions()
                    ),
                ),
                field: Some("state".into()),
                message: format!("Invalid transition from {} to {}", self.state, new_state),
            })
        }
    }

    /// Update the timestamp to now.
    pub fn touch(&mut self) {
        self.updated_at = Timestamp::now();
    }

    /// Get a metadata value.
    pub fn get_metadata(&self, key: &str) -> Option<&Value> {
        self.metadata.get(key)
    }
}

impl fmt::Display for Artifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Artifact({}, type={}, state={})",
            self.id, self.artifact_type, self.state
        )
    }
}

impl Validate for Artifact {
    #[allow(clippy::result_large_err)]
    fn validate(&self) -> Result<(), AstraError> {
        // VAL-070: Artifact type cannot be empty
        if self.artifact_type.trim().is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation("VAL-070", "Provide a non-empty artifact type"),
                field: Some("artifact_type".into()),
                message: "Artifact.artifact_type cannot be empty".into(),
            });
        }

        // VAL-071: Version cannot be empty
        if self.version.trim().is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-071",
                    "Provide a non-empty artifact version",
                ),
                field: Some("version".into()),
                message: "Artifact.version cannot be empty".into(),
            });
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
    // ArtifactState tests
    // ========================================================================

    #[test]
    fn artifact_state_default_is_draft() {
        assert_eq!(ArtifactState::default(), ArtifactState::Draft);
    }

    #[test]
    fn artifact_state_display() {
        assert_eq!(ArtifactState::Draft.to_string(), "Draft");
        assert_eq!(ArtifactState::Proposed.to_string(), "Proposed");
        assert_eq!(ArtifactState::Validated.to_string(), "Validated");
        assert_eq!(ArtifactState::Approved.to_string(), "Approved");
        assert_eq!(ArtifactState::Released.to_string(), "Released");
        assert_eq!(ArtifactState::Deprecated.to_string(), "Deprecated");
    }

    #[test]
    fn artifact_state_can_transition_draft_to_proposed() {
        assert!(ArtifactState::Draft.can_transition_to(ArtifactState::Proposed));
    }

    #[test]
    fn artifact_state_can_transition_proposed_to_validated() {
        assert!(ArtifactState::Proposed.can_transition_to(ArtifactState::Validated));
    }

    #[test]
    fn artifact_state_can_transition_proposed_to_draft() {
        // Rejection path
        assert!(ArtifactState::Proposed.can_transition_to(ArtifactState::Draft));
    }

    #[test]
    fn artifact_state_can_transition_validated_to_approved() {
        assert!(ArtifactState::Validated.can_transition_to(ArtifactState::Approved));
    }

    #[test]
    fn artifact_state_can_transition_validated_to_draft() {
        // Rejection path
        assert!(ArtifactState::Validated.can_transition_to(ArtifactState::Draft));
    }

    #[test]
    fn artifact_state_can_transition_approved_to_released() {
        assert!(ArtifactState::Approved.can_transition_to(ArtifactState::Released));
    }

    #[test]
    fn artifact_state_can_always_deprecate() {
        assert!(ArtifactState::Draft.can_transition_to(ArtifactState::Deprecated));
        assert!(ArtifactState::Proposed.can_transition_to(ArtifactState::Deprecated));
        assert!(ArtifactState::Validated.can_transition_to(ArtifactState::Deprecated));
        assert!(ArtifactState::Approved.can_transition_to(ArtifactState::Deprecated));
        assert!(ArtifactState::Released.can_transition_to(ArtifactState::Deprecated));
    }

    #[test]
    fn artifact_state_cannot_skip_states() {
        assert!(!ArtifactState::Draft.can_transition_to(ArtifactState::Validated));
        assert!(!ArtifactState::Draft.can_transition_to(ArtifactState::Approved));
        assert!(!ArtifactState::Draft.can_transition_to(ArtifactState::Released));
        assert!(!ArtifactState::Proposed.can_transition_to(ArtifactState::Approved));
        assert!(!ArtifactState::Proposed.can_transition_to(ArtifactState::Released));
    }

    #[test]
    fn artifact_state_deprecated_is_terminal() {
        assert!(ArtifactState::Deprecated.is_terminal());
        assert!(ArtifactState::Deprecated.valid_transitions().is_empty());
        assert!(!ArtifactState::Deprecated.can_transition_to(ArtifactState::Draft));
    }

    #[test]
    fn artifact_state_valid_transitions() {
        let transitions = ArtifactState::Draft.valid_transitions();
        assert!(transitions.contains(&ArtifactState::Proposed));
        assert!(transitions.contains(&ArtifactState::Deprecated));
        assert_eq!(transitions.len(), 2);

        let transitions = ArtifactState::Proposed.valid_transitions();
        assert!(transitions.contains(&ArtifactState::Validated));
        assert!(transitions.contains(&ArtifactState::Draft));
        assert!(transitions.contains(&ArtifactState::Deprecated));
        assert_eq!(transitions.len(), 3);
    }

    #[test]
    fn artifact_state_serde_roundtrip() {
        for state in [
            ArtifactState::Draft,
            ArtifactState::Proposed,
            ArtifactState::Validated,
            ArtifactState::Approved,
            ArtifactState::Released,
            ArtifactState::Deprecated,
        ] {
            let Ok(json) = serde_json::to_string(&state) else {
                panic!("serialization should succeed");
            };
            let Ok(decoded) = serde_json::from_str::<ArtifactState>(&json) else {
                panic!("deserialization should succeed");
            };
            assert_eq!(state, decoded);
        }
    }

    #[test]
    fn artifact_state_serde_names() {
        let Ok(draft) = serde_json::to_string(&ArtifactState::Draft) else {
            panic!("serialization should succeed");
        };
        assert_eq!(draft, "\"draft\"");

        let Ok(proposed) = serde_json::to_string(&ArtifactState::Proposed) else {
            panic!("serialization should succeed");
        };
        assert_eq!(proposed, "\"proposed\"");

        let Ok(deprecated) = serde_json::to_string(&ArtifactState::Deprecated) else {
            panic!("serialization should succeed");
        };
        assert_eq!(deprecated, "\"deprecated\"");
    }

    // ========================================================================
    // ArtifactLinks tests
    // ========================================================================

    #[test]
    fn artifact_links_default() {
        let links = ArtifactLinks::default();
        assert!(links.run_id.is_none());
        assert!(links.agent_id.is_none());
        assert!(links.policy_decisions.is_empty());
        assert!(links.parent_id.is_none());
        assert!(links.related.is_empty());
    }

    #[test]
    fn artifact_links_builder() {
        let parent = ArtifactId::new();
        let related = ArtifactId::new();

        let links = ArtifactLinks::new()
            .with_run_id("run-123")
            .with_agent_id("agent-456")
            .with_policy_decision("policy-789")
            .with_parent(parent)
            .with_related(related);

        assert_eq!(links.run_id, Some("run-123".to_string()));
        assert_eq!(links.agent_id, Some("agent-456".to_string()));
        assert_eq!(links.policy_decisions, vec!["policy-789"]);
        assert!(links.parent_id.is_some());
        assert_eq!(links.related.len(), 1);
    }

    #[test]
    fn artifact_links_serde_roundtrip() {
        let links = ArtifactLinks::new()
            .with_run_id("run-123")
            .with_agent_id("agent-456");

        let Ok(json) = serde_json::to_string(&links) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<ArtifactLinks>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(links, decoded);
    }

    #[test]
    fn artifact_links_skips_empty() {
        let links = ArtifactLinks::default();
        let Ok(json) = serde_json::to_string(&links) else {
            panic!("serialization should succeed");
        };
        // Should be an empty object since all fields are None/empty
        assert_eq!(json, "{}");
    }

    // ========================================================================
    // Artifact tests
    // ========================================================================

    #[test]
    fn artifact_new_draft() {
        let artifact = Artifact::new_draft("PatchSet");
        assert_eq!(artifact.artifact_type, "PatchSet");
        assert_eq!(artifact.state, ArtifactState::Draft);
        assert_eq!(artifact.version, "1");
        assert!(artifact.metadata.is_empty());
        assert!(artifact.content_hash.is_none());
    }

    #[test]
    fn artifact_builder_methods() {
        let links = ArtifactLinks::new().with_run_id("run-123");

        let artifact = Artifact::new_draft("ADR")
            .with_metadata("author", Value::String("alice".into()))
            .with_links(links)
            .with_content_hash("sha256:abc123")
            .with_version("2.0.0");

        assert_eq!(artifact.artifact_type, "ADR");
        assert_eq!(artifact.version, "2.0.0");
        assert_eq!(
            artifact.get_metadata("author"),
            Some(&Value::String("alice".into()))
        );
        assert_eq!(artifact.content_hash, Some("sha256:abc123".to_string()));
        assert_eq!(artifact.links.run_id, Some("run-123".to_string()));
    }

    #[test]
    fn artifact_transition_success() {
        let mut artifact = Artifact::new_draft("TestReport");
        assert!(artifact.transition_to(ArtifactState::Proposed).is_ok());
        assert_eq!(artifact.state, ArtifactState::Proposed);

        assert!(artifact.transition_to(ArtifactState::Validated).is_ok());
        assert_eq!(artifact.state, ArtifactState::Validated);
    }

    #[test]
    fn artifact_transition_failure() {
        let mut artifact = Artifact::new_draft("TestReport");
        let result = artifact.transition_to(ArtifactState::Released);
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-072");
    }

    #[test]
    fn artifact_validate_empty_type_fails() {
        let mut artifact = Artifact::new_draft("PatchSet");
        artifact.artifact_type = "".to_string();

        let result = artifact.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-070");
    }

    #[test]
    fn artifact_validate_whitespace_type_fails() {
        let mut artifact = Artifact::new_draft("PatchSet");
        artifact.artifact_type = "   ".to_string();

        let result = artifact.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-070");
    }

    #[test]
    fn artifact_validate_empty_version_fails() {
        let mut artifact = Artifact::new_draft("PatchSet");
        artifact.version = "".to_string();

        let result = artifact.validate();
        assert!(result.is_err());

        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-071");
    }

    #[test]
    fn artifact_validate_success() {
        let artifact = Artifact::new_draft("PatchSet");
        assert!(artifact.validate().is_ok());
    }

    #[test]
    fn artifact_serde_roundtrip() {
        let artifact = Artifact::new_draft("ADR")
            .with_metadata("title", Value::String("Architecture Decision".into()))
            .with_content_hash("sha256:def456");

        let Ok(json) = serde_json::to_string(&artifact) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<Artifact>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(artifact.id, decoded.id);
        assert_eq!(artifact.artifact_type, decoded.artifact_type);
        assert_eq!(artifact.state, decoded.state);
        assert_eq!(artifact.content_hash, decoded.content_hash);
    }

    #[test]
    fn artifact_serde_type_rename() {
        let artifact = Artifact::new_draft("PatchSet");
        let Ok(json) = serde_json::to_string(&artifact) else {
            panic!("serialization should succeed");
        };
        // Field should be "type", not "artifact_type"
        assert!(json.contains("\"type\""));
        assert!(!json.contains("\"artifact_type\""));
    }

    #[test]
    fn artifact_metadata_arbitrary_json() {
        let artifact = Artifact::new_draft("Report")
            .with_metadata("count", Value::Number(42.into()))
            .with_metadata("enabled", Value::Bool(true))
            .with_metadata(
                "nested",
                Value::Object(serde_json::Map::from_iter([(
                    "key".to_string(),
                    Value::String("value".into()),
                )])),
            );

        assert_eq!(
            artifact.get_metadata("count"),
            Some(&Value::Number(42.into()))
        );
        assert_eq!(artifact.get_metadata("enabled"), Some(&Value::Bool(true)));
        assert!(artifact.get_metadata("nested").is_some());
    }

    #[test]
    fn artifact_touch_updates_timestamp() {
        let mut artifact = Artifact::new_draft("PatchSet");
        let original = artifact.updated_at.clone();

        // Small delay to ensure timestamp changes
        std::thread::sleep(std::time::Duration::from_millis(10));

        artifact.touch();
        assert!(artifact.updated_at > original);
    }

    #[test]
    fn artifact_full_lifecycle() {
        let mut artifact = Artifact::new_draft("PatchSet");
        assert_eq!(artifact.state, ArtifactState::Draft);

        assert!(artifact.transition_to(ArtifactState::Proposed).is_ok());
        assert!(artifact.transition_to(ArtifactState::Validated).is_ok());
        assert!(artifact.transition_to(ArtifactState::Approved).is_ok());
        assert!(artifact.transition_to(ArtifactState::Released).is_ok());
        assert!(artifact.transition_to(ArtifactState::Deprecated).is_ok());

        assert!(artifact.state.is_terminal());
    }

    #[test]
    fn artifact_display() {
        let artifact = Artifact::new_draft("PatchSet");
        let display = artifact.to_string();
        assert!(display.contains("Artifact"));
        assert!(display.contains("PatchSet"));
        assert!(display.contains("Draft"));
    }

    #[test]
    fn artifact_rejection_workflow() {
        let mut artifact = Artifact::new_draft("PatchSet");

        // Submit for review
        assert!(artifact.transition_to(ArtifactState::Proposed).is_ok());

        // Reject back to draft
        assert!(artifact.transition_to(ArtifactState::Draft).is_ok());
        assert_eq!(artifact.state, ArtifactState::Draft);

        // Resubmit
        assert!(artifact.transition_to(ArtifactState::Proposed).is_ok());
        assert!(artifact.transition_to(ArtifactState::Validated).is_ok());

        // Reject at validation
        assert!(artifact.transition_to(ArtifactState::Draft).is_ok());
    }
}
