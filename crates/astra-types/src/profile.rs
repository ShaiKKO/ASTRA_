// SPDX-License-Identifier: MIT OR Apache-2.0
//! AgentProfile — composition of capabilities with constraints.
//!
//! Profiles define what an agent can do (capabilities), resource limits (budget),
//! security boundaries (sandbox tier), and behavioral constraints. They enable
//! static verification of agent composition before runtime.
//!
//! See blueprint §5.2-5.3 for profile catalog and compliance rules.

use serde::{Deserialize, Serialize};

use crate::error::{AstraError, ErrorContext, Severity};
use crate::id::{CapabilityId, ProfileId};
use crate::task::Budget;
use crate::validate::Validate;

// ============================================================================
// SandboxTier
// ============================================================================

/// Sandbox execution tier controlling I/O permissions.
///
/// Tiers are ordered from most restrictive (Tier0) to least restrictive (Tier4).
/// Default is Tier1 (scoped read access only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SandboxTier {
    /// Pure computation, no I/O whatsoever.
    #[serde(rename = "tier_0")]
    Tier0,
    /// Scoped read access only (default).
    #[serde(rename = "tier_1")]
    Tier1,
    /// Scoped read/write + subprocess execution.
    #[serde(rename = "tier_2")]
    Tier2,
    /// Allowlisted network access.
    #[serde(rename = "tier_3")]
    Tier3,
    /// Admin level (disabled by default).
    #[serde(rename = "tier_4")]
    Tier4,
}

impl Default for SandboxTier {
    fn default() -> Self {
        Self::Tier1
    }
}

impl SandboxTier {
    /// Returns true if this tier allows write operations.
    pub fn allows_write(&self) -> bool {
        *self >= Self::Tier2
    }

    /// Returns true if this tier allows network access.
    pub fn allows_network(&self) -> bool {
        *self >= Self::Tier3
    }

    /// Returns true if this tier allows spawning sub-agents.
    pub fn allows_spawn(&self) -> bool {
        *self >= Self::Tier2
    }
}

// ============================================================================
// CapabilityRef
// ============================================================================

/// Reference to a capability with optional version constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRef {
    /// Capability identifier.
    pub id: CapabilityId,

    /// Semver version constraint (e.g., "^1.0.0", ">=2.0").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

impl CapabilityRef {
    /// Create a new capability reference.
    pub fn new(id: CapabilityId) -> Self {
        Self { id, version: None }
    }

    /// Set the version constraint.
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }
}

impl From<CapabilityId> for CapabilityRef {
    fn from(id: CapabilityId) -> Self {
        Self::new(id)
    }
}

// ============================================================================
// AgentProfile
// ============================================================================

/// Agent profile defining composition and constraints.
///
/// Profiles are the "class definition" for agents — they specify capabilities,
/// budget defaults, sandbox tier, and behavioral constraints.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentProfile {
    /// Unique profile identifier.
    pub id: ProfileId,

    /// Human-readable name.
    pub name: String,

    /// Profile version (semver).
    pub version: String,

    /// Purpose description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Required capabilities.
    pub capabilities: Vec<CapabilityRef>,

    /// Default budget envelope.
    #[serde(default)]
    pub default_budget: Budget,

    /// Minimum required sandbox tier.
    #[serde(default)]
    pub sandbox_tier: SandboxTier,

    /// Input schema reference (JSON Schema $id or path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<String>,

    /// Output artifact types this profile produces.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub output_artifacts: Vec<String>,

    /// Tags for categorization.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Whether this profile can spawn sub-agents.
    #[serde(default)]
    pub can_spawn_agents: bool,

    /// Maximum concurrent sub-agents (if can_spawn_agents is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_sub_agents: Option<u32>,
}

impl AgentProfile {
    /// Create a new profile with required fields.
    #[allow(clippy::result_large_err)]
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
    ) -> Result<Self, AstraError> {
        Ok(Self {
            id: ProfileId::new(id)?,
            name: name.into(),
            version: version.into(),
            description: None,
            capabilities: Vec::new(),
            default_budget: Budget::default(),
            sandbox_tier: SandboxTier::default(),
            input_schema: None,
            output_artifacts: Vec::new(),
            tags: Vec::new(),
            can_spawn_agents: false,
            max_sub_agents: None,
        })
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Add a capability requirement.
    pub fn with_capability(mut self, capability: impl Into<CapabilityRef>) -> Self {
        self.capabilities.push(capability.into());
        self
    }

    /// Set all capabilities at once.
    pub fn with_capabilities(mut self, capabilities: Vec<CapabilityRef>) -> Self {
        self.capabilities = capabilities;
        self
    }

    /// Set the default budget.
    pub fn with_budget(mut self, budget: Budget) -> Self {
        self.default_budget = budget;
        self
    }

    /// Set the sandbox tier.
    pub fn with_sandbox_tier(mut self, tier: SandboxTier) -> Self {
        self.sandbox_tier = tier;
        self
    }

    /// Set the input schema reference.
    pub fn with_input_schema(mut self, schema: impl Into<String>) -> Self {
        self.input_schema = Some(schema.into());
        self
    }

    /// Add an output artifact type.
    pub fn with_output_artifact(mut self, artifact: impl Into<String>) -> Self {
        self.output_artifacts.push(artifact.into());
        self
    }

    /// Add a tag.
    pub fn with_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    /// Enable agent spawning with optional max sub-agents.
    pub fn with_spawning(mut self, max_sub_agents: Option<u32>) -> Self {
        self.can_spawn_agents = true;
        self.max_sub_agents = max_sub_agents;
        self
    }

    /// Check if this profile has a specific capability.
    pub fn has_capability(&self, id: &CapabilityId) -> bool {
        self.capabilities.iter().any(|c| &c.id == id)
    }

    /// Check if this profile requires at least the given sandbox tier.
    pub fn requires_tier(&self, tier: SandboxTier) -> bool {
        self.sandbox_tier >= tier
    }
}

impl Validate for AgentProfile {
    #[allow(clippy::result_large_err)]
    fn validate(&self) -> Result<(), AstraError> {
        // VAL-060: Profile ID cannot be empty (defense-in-depth for new_unchecked paths)
        if self.id.as_str().is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::builder()
                    .error_code("VAL-060")
                    .component("astra-types")
                    .severity(Severity::Error)
                    .remediation_hint("Provide a non-empty profile ID")
                    .build()
                    .unwrap_or_default(),
                field: Some("id".into()),
                message: "AgentProfile.id cannot be empty".into(),
            });
        }

        // VAL-061: Name cannot be empty
        if self.name.is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::builder()
                    .error_code("VAL-061")
                    .component("astra-types")
                    .severity(Severity::Error)
                    .remediation_hint("Provide a non-empty profile name")
                    .build()
                    .unwrap_or_default(),
                field: Some("name".into()),
                message: "AgentProfile.name cannot be empty".into(),
            });
        }

        // VAL-062: Version cannot be empty
        if self.version.is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::builder()
                    .error_code("VAL-062")
                    .component("astra-types")
                    .severity(Severity::Error)
                    .remediation_hint("Provide a non-empty profile version")
                    .build()
                    .unwrap_or_default(),
                field: Some("version".into()),
                message: "AgentProfile.version cannot be empty".into(),
            });
        }

        // VAL-063: Capabilities cannot be empty
        if self.capabilities.is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::builder()
                    .error_code("VAL-063")
                    .component("astra-types")
                    .severity(Severity::Error)
                    .remediation_hint("Add at least one capability to the profile")
                    .build()
                    .unwrap_or_default(),
                field: Some("capabilities".into()),
                message: "AgentProfile must have at least one capability".into(),
            });
        }

        // VAL-064: Spawning requires Tier2+
        if self.can_spawn_agents && !self.sandbox_tier.allows_spawn() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::builder()
                    .error_code("VAL-064")
                    .component("astra-types")
                    .severity(Severity::Error)
                    .remediation_hint(
                        "Set sandbox_tier to Tier2 or higher, or disable can_spawn_agents",
                    )
                    .build()
                    .unwrap_or_default(),
                field: Some("can_spawn_agents".into()),
                message: "can_spawn_agents requires sandbox_tier >= Tier2".into(),
            });
        }

        // VAL-065: max_sub_agents requires can_spawn_agents
        if self.max_sub_agents.is_some() && !self.can_spawn_agents {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::builder()
                    .error_code("VAL-065")
                    .component("astra-types")
                    .severity(Severity::Error)
                    .remediation_hint("Set can_spawn_agents to true, or remove max_sub_agents")
                    .build()
                    .unwrap_or_default(),
                field: Some("max_sub_agents".into()),
                message: "max_sub_agents set but can_spawn_agents is false".into(),
            });
        }

        Ok(())
    }
}

// ============================================================================
// Profile ID Constants
// ============================================================================

/// Standard profile IDs for the v1 catalog.
pub mod profiles {
    /// Meta orchestrator profile ID.
    pub const META_ORCHESTRATOR: &str = "meta_orchestrator";
    /// Architect profile ID.
    pub const ARCHITECT: &str = "architect";
    /// Planner profile ID.
    pub const PLANNER: &str = "planner";
    /// Implementer profile ID.
    pub const IMPLEMENTER: &str = "implementer";
    /// Test engineer profile ID.
    pub const TEST_ENGINEER: &str = "test_engineer";
    /// Reviewer profile ID.
    pub const REVIEWER: &str = "reviewer";
    /// Security analyst profile ID.
    pub const SECURITY_ANALYST: &str = "security_analyst";
    /// Integrator profile ID.
    pub const INTEGRATOR: &str = "integrator";
    /// Documentation writer profile ID.
    pub const DOC_WRITER: &str = "doc_writer";

    /// All v1 profile IDs.
    pub const ALL: &[&str] = &[
        META_ORCHESTRATOR,
        ARCHITECT,
        PLANNER,
        IMPLEMENTER,
        TEST_ENGINEER,
        REVIEWER,
        SECURITY_ANALYST,
        INTEGRATOR,
        DOC_WRITER,
    ];
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    // ========================================================================
    // SandboxTier tests
    // ========================================================================

    #[test]
    fn sandbox_tier_default_is_tier1() {
        assert_eq!(SandboxTier::default(), SandboxTier::Tier1);
    }

    #[test]
    fn sandbox_tier_ordering() {
        assert!(SandboxTier::Tier0 < SandboxTier::Tier1);
        assert!(SandboxTier::Tier1 < SandboxTier::Tier2);
        assert!(SandboxTier::Tier2 < SandboxTier::Tier3);
        assert!(SandboxTier::Tier3 < SandboxTier::Tier4);
    }

    #[test]
    fn sandbox_tier_equality() {
        assert_eq!(SandboxTier::Tier2, SandboxTier::Tier2);
    }

    #[test]
    fn sandbox_tier_inequality() {
        assert_ne!(SandboxTier::Tier1, SandboxTier::Tier2);
    }

    #[test]
    fn sandbox_tier_serde_json_roundtrip() {
        for tier in [
            SandboxTier::Tier0,
            SandboxTier::Tier1,
            SandboxTier::Tier2,
            SandboxTier::Tier3,
            SandboxTier::Tier4,
        ] {
            let Ok(json) = serde_json::to_string(&tier) else {
                panic!("serialization should succeed");
            };
            let Ok(decoded) = serde_json::from_str::<SandboxTier>(&json) else {
                panic!("deserialization should succeed");
            };
            assert_eq!(tier, decoded);
        }
    }

    #[test]
    fn sandbox_tier_serde_yaml_roundtrip() {
        for tier in [
            SandboxTier::Tier0,
            SandboxTier::Tier1,
            SandboxTier::Tier2,
            SandboxTier::Tier3,
            SandboxTier::Tier4,
        ] {
            let Ok(yaml) = serde_yaml::to_string(&tier) else {
                panic!("serialization should succeed");
            };
            let Ok(decoded) = serde_yaml::from_str::<SandboxTier>(&yaml) else {
                panic!("deserialization should succeed");
            };
            assert_eq!(tier, decoded);
        }
    }

    #[test]
    fn sandbox_tier_serde_names() {
        let Ok(tier0) = serde_json::to_string(&SandboxTier::Tier0) else {
            panic!("serialization should succeed");
        };
        assert_eq!(tier0, "\"tier_0\"");

        let Ok(tier1) = serde_json::to_string(&SandboxTier::Tier1) else {
            panic!("serialization should succeed");
        };
        assert_eq!(tier1, "\"tier_1\"");

        let Ok(tier2) = serde_json::to_string(&SandboxTier::Tier2) else {
            panic!("serialization should succeed");
        };
        assert_eq!(tier2, "\"tier_2\"");

        let Ok(tier3) = serde_json::to_string(&SandboxTier::Tier3) else {
            panic!("serialization should succeed");
        };
        assert_eq!(tier3, "\"tier_3\"");

        let Ok(tier4) = serde_json::to_string(&SandboxTier::Tier4) else {
            panic!("serialization should succeed");
        };
        assert_eq!(tier4, "\"tier_4\"");
    }

    #[test]
    fn sandbox_tier_all_variants_deserialize() {
        for (json, expected) in [
            ("\"tier_0\"", SandboxTier::Tier0),
            ("\"tier_1\"", SandboxTier::Tier1),
            ("\"tier_2\"", SandboxTier::Tier2),
            ("\"tier_3\"", SandboxTier::Tier3),
            ("\"tier_4\"", SandboxTier::Tier4),
        ] {
            let Ok(tier) = serde_json::from_str::<SandboxTier>(json) else {
                panic!("deserialization of {} should succeed", json);
            };
            assert_eq!(tier, expected);
        }
    }

    #[test]
    fn sandbox_tier_clone() {
        let tier = SandboxTier::Tier3;
        let cloned = tier;
        assert_eq!(tier, cloned);
    }

    #[test]
    fn sandbox_tier_hash_consistent() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(SandboxTier::Tier2);
        set.insert(SandboxTier::Tier2); // duplicate
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn sandbox_tier_allows_write() {
        assert!(!SandboxTier::Tier0.allows_write());
        assert!(!SandboxTier::Tier1.allows_write());
        assert!(SandboxTier::Tier2.allows_write());
        assert!(SandboxTier::Tier3.allows_write());
        assert!(SandboxTier::Tier4.allows_write());
    }

    #[test]
    fn sandbox_tier_allows_network() {
        assert!(!SandboxTier::Tier0.allows_network());
        assert!(!SandboxTier::Tier1.allows_network());
        assert!(!SandboxTier::Tier2.allows_network());
        assert!(SandboxTier::Tier3.allows_network());
        assert!(SandboxTier::Tier4.allows_network());
    }

    #[test]
    fn sandbox_tier_allows_spawn() {
        assert!(!SandboxTier::Tier0.allows_spawn());
        assert!(!SandboxTier::Tier1.allows_spawn());
        assert!(SandboxTier::Tier2.allows_spawn());
        assert!(SandboxTier::Tier3.allows_spawn());
        assert!(SandboxTier::Tier4.allows_spawn());
    }

    // ========================================================================
    // CapabilityRef tests
    // ========================================================================

    #[test]
    fn capability_ref_new() {
        let Ok(id) = CapabilityId::new("repo.read") else {
            panic!("valid capability ID should succeed");
        };
        let cap_ref = CapabilityRef::new(id.clone());
        assert_eq!(cap_ref.id, id);
        assert!(cap_ref.version.is_none());
    }

    #[test]
    fn capability_ref_with_version() {
        let Ok(id) = CapabilityId::new("repo.read") else {
            panic!("valid capability ID should succeed");
        };
        let cap_ref = CapabilityRef::new(id).with_version("^1.0.0");
        assert_eq!(cap_ref.version, Some("^1.0.0".to_string()));
    }

    #[test]
    fn capability_ref_from_capability_id() {
        let Ok(id) = CapabilityId::new("build.build") else {
            panic!("valid capability ID should succeed");
        };
        let cap_ref: CapabilityRef = id.clone().into();
        assert_eq!(cap_ref.id, id);
    }

    #[test]
    fn capability_ref_equality_same() {
        let Ok(id) = CapabilityId::new("test.unit") else {
            panic!("valid capability ID should succeed");
        };
        let ref1 = CapabilityRef::new(id.clone()).with_version("1.0.0");
        let ref2 = CapabilityRef::new(id).with_version("1.0.0");
        assert_eq!(ref1, ref2);
    }

    #[test]
    fn capability_ref_equality_different_version() {
        let Ok(id) = CapabilityId::new("test.unit") else {
            panic!("valid capability ID should succeed");
        };
        let ref1 = CapabilityRef::new(id.clone()).with_version("1.0.0");
        let ref2 = CapabilityRef::new(id).with_version("2.0.0");
        assert_ne!(ref1, ref2);
    }

    #[test]
    fn capability_ref_serde_json_roundtrip() {
        let Ok(id) = CapabilityId::new("repo.diff") else {
            panic!("valid capability ID should succeed");
        };
        let cap_ref = CapabilityRef::new(id).with_version(">=1.0");
        let Ok(json) = serde_json::to_string(&cap_ref) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<CapabilityRef>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(cap_ref, decoded);
    }

    #[test]
    fn capability_ref_serde_without_version_skips_field() {
        let Ok(id) = CapabilityId::new("repo.read") else {
            panic!("valid capability ID should succeed");
        };
        let cap_ref = CapabilityRef::new(id);
        let Ok(json) = serde_json::to_string(&cap_ref) else {
            panic!("serialization should succeed");
        };
        assert!(!json.contains("version"));
    }

    #[test]
    fn capability_ref_serde_with_version_includes_field() {
        let Ok(id) = CapabilityId::new("repo.read") else {
            panic!("valid capability ID should succeed");
        };
        let cap_ref = CapabilityRef::new(id).with_version("1.0.0");
        let Ok(json) = serde_json::to_string(&cap_ref) else {
            panic!("serialization should succeed");
        };
        assert!(json.contains("version"));
        assert!(json.contains("1.0.0"));
    }

    #[test]
    fn capability_ref_clone() {
        let Ok(id) = CapabilityId::new("analysis.lint") else {
            panic!("valid capability ID should succeed");
        };
        let cap_ref = CapabilityRef::new(id).with_version("^2.0");
        let cloned = cap_ref.clone();
        assert_eq!(cap_ref, cloned);
    }

    // ========================================================================
    // AgentProfile tests
    // ========================================================================

    fn make_test_capability() -> CapabilityRef {
        let Ok(id) = CapabilityId::new("repo.read") else {
            panic!("valid capability ID should succeed");
        };
        CapabilityRef::new(id)
    }

    #[test]
    fn agent_profile_new_minimal() {
        let Ok(profile) = AgentProfile::new("test_profile", "Test Profile", "1.0.0") else {
            panic!("valid profile should succeed");
        };
        assert_eq!(profile.id.as_str(), "test_profile");
        assert_eq!(profile.name, "Test Profile");
        assert_eq!(profile.version, "1.0.0");
        assert!(profile.capabilities.is_empty());
        assert_eq!(profile.sandbox_tier, SandboxTier::Tier1);
        assert!(!profile.can_spawn_agents);
    }

    #[test]
    fn agent_profile_builder_full() {
        let Ok(profile) = AgentProfile::new("implementer", "Implementer", "1.0.0") else {
            panic!("valid profile should succeed");
        };
        let profile = profile
            .with_description("Produces code changes")
            .with_capability(make_test_capability())
            .with_budget(Budget::default())
            .with_sandbox_tier(SandboxTier::Tier2)
            .with_input_schema("schemas/task.json")
            .with_output_artifact("PatchSet")
            .with_tag("coding")
            .with_spawning(Some(5));

        assert_eq!(
            profile.description,
            Some("Produces code changes".to_string())
        );
        assert_eq!(profile.capabilities.len(), 1);
        assert_eq!(profile.sandbox_tier, SandboxTier::Tier2);
        assert_eq!(profile.input_schema, Some("schemas/task.json".to_string()));
        assert_eq!(profile.output_artifacts, vec!["PatchSet"]);
        assert_eq!(profile.tags, vec!["coding"]);
        assert!(profile.can_spawn_agents);
        assert_eq!(profile.max_sub_agents, Some(5));
    }

    #[test]
    fn agent_profile_validate_success() {
        let Ok(profile) = AgentProfile::new("test", "Test", "1.0.0") else {
            panic!("valid profile should succeed");
        };
        let profile = profile.with_capability(make_test_capability());
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn agent_profile_validate_empty_id_fails() {
        // Use ProfileId::new_unchecked to bypass ID validation
        let profile = AgentProfile {
            id: ProfileId::new_unchecked(""),
            name: "Test".into(),
            version: "1.0.0".into(),
            description: None,
            capabilities: vec![make_test_capability()],
            default_budget: Budget::default(),
            sandbox_tier: SandboxTier::default(),
            input_schema: None,
            output_artifacts: Vec::new(),
            tags: Vec::new(),
            can_spawn_agents: false,
            max_sub_agents: None,
        };
        let result = profile.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-060");
    }

    #[test]
    fn agent_profile_validate_empty_name_fails() {
        let profile = AgentProfile {
            id: ProfileId::new_unchecked("test"),
            name: "".into(),
            version: "1.0.0".into(),
            description: None,
            capabilities: vec![make_test_capability()],
            default_budget: Budget::default(),
            sandbox_tier: SandboxTier::default(),
            input_schema: None,
            output_artifacts: Vec::new(),
            tags: Vec::new(),
            can_spawn_agents: false,
            max_sub_agents: None,
        };
        let result = profile.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-061");
    }

    #[test]
    fn agent_profile_validate_empty_version_fails() {
        let profile = AgentProfile {
            id: ProfileId::new_unchecked("test"),
            name: "Test".into(),
            version: "".into(),
            description: None,
            capabilities: vec![make_test_capability()],
            default_budget: Budget::default(),
            sandbox_tier: SandboxTier::default(),
            input_schema: None,
            output_artifacts: Vec::new(),
            tags: Vec::new(),
            can_spawn_agents: false,
            max_sub_agents: None,
        };
        let result = profile.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-062");
    }

    #[test]
    fn agent_profile_validate_empty_capabilities_fails() {
        let Ok(profile) = AgentProfile::new("test", "Test", "1.0.0") else {
            panic!("valid profile should succeed");
        };
        // No capabilities added
        let result = profile.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-063");
    }

    #[test]
    fn agent_profile_validate_spawn_tier0_fails() {
        let Ok(profile) = AgentProfile::new("test", "Test", "1.0.0") else {
            panic!("valid profile should succeed");
        };
        let profile = profile
            .with_capability(make_test_capability())
            .with_sandbox_tier(SandboxTier::Tier0)
            .with_spawning(None);
        let result = profile.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-064");
    }

    #[test]
    fn agent_profile_validate_spawn_tier1_fails() {
        let Ok(profile) = AgentProfile::new("test", "Test", "1.0.0") else {
            panic!("valid profile should succeed");
        };
        let profile = profile
            .with_capability(make_test_capability())
            .with_sandbox_tier(SandboxTier::Tier1)
            .with_spawning(None);
        let result = profile.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-064");
    }

    #[test]
    fn agent_profile_validate_spawn_tier2_succeeds() {
        let Ok(profile) = AgentProfile::new("test", "Test", "1.0.0") else {
            panic!("valid profile should succeed");
        };
        let profile = profile
            .with_capability(make_test_capability())
            .with_sandbox_tier(SandboxTier::Tier2)
            .with_spawning(Some(5));
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn agent_profile_validate_spawn_tier3_succeeds() {
        let Ok(profile) = AgentProfile::new("test", "Test", "1.0.0") else {
            panic!("valid profile should succeed");
        };
        let profile = profile
            .with_capability(make_test_capability())
            .with_sandbox_tier(SandboxTier::Tier3)
            .with_spawning(None);
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn agent_profile_validate_spawn_tier4_succeeds() {
        let Ok(profile) = AgentProfile::new("test", "Test", "1.0.0") else {
            panic!("valid profile should succeed");
        };
        let profile = profile
            .with_capability(make_test_capability())
            .with_sandbox_tier(SandboxTier::Tier4)
            .with_spawning(Some(10));
        assert!(profile.validate().is_ok());
    }

    #[test]
    fn agent_profile_validate_max_sub_without_spawn_fails() {
        let profile = AgentProfile {
            id: ProfileId::new_unchecked("test"),
            name: "Test".into(),
            version: "1.0.0".into(),
            description: None,
            capabilities: vec![make_test_capability()],
            default_budget: Budget::default(),
            sandbox_tier: SandboxTier::Tier2,
            input_schema: None,
            output_artifacts: Vec::new(),
            tags: Vec::new(),
            can_spawn_agents: false,
            max_sub_agents: Some(5), // Set without can_spawn_agents
        };
        let result = profile.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-065");
    }

    #[test]
    fn agent_profile_has_capability_found() {
        let Ok(id) = CapabilityId::new("repo.read") else {
            panic!("valid capability ID should succeed");
        };
        let Ok(profile) = AgentProfile::new("test", "Test", "1.0.0") else {
            panic!("valid profile should succeed");
        };
        let profile = profile.with_capability(CapabilityRef::new(id.clone()));
        assert!(profile.has_capability(&id));
    }

    #[test]
    fn agent_profile_has_capability_not_found() {
        let Ok(search_id) = CapabilityId::new("build.build") else {
            panic!("valid capability ID should succeed");
        };
        let Ok(profile) = AgentProfile::new("test", "Test", "1.0.0") else {
            panic!("valid profile should succeed");
        };
        let profile = profile.with_capability(make_test_capability());
        assert!(!profile.has_capability(&search_id));
    }

    #[test]
    fn agent_profile_serde_json_roundtrip() {
        let Ok(profile) = AgentProfile::new("implementer", "Implementer", "1.0.0") else {
            panic!("valid profile should succeed");
        };
        let profile = profile
            .with_description("Code implementer")
            .with_capability(make_test_capability())
            .with_sandbox_tier(SandboxTier::Tier2);

        let Ok(json) = serde_json::to_string(&profile) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<AgentProfile>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(profile, decoded);
    }

    #[test]
    fn agent_profile_serde_yaml_roundtrip() {
        let Ok(profile) = AgentProfile::new("reviewer", "Reviewer", "2.0.0") else {
            panic!("valid profile should succeed");
        };
        let profile = profile
            .with_capability(make_test_capability())
            .with_tag("review");

        let Ok(yaml) = serde_yaml::to_string(&profile) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_yaml::from_str::<AgentProfile>(&yaml) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(profile, decoded);
    }

    // ========================================================================
    // Profile constants tests
    // ========================================================================

    #[test]
    fn profiles_all_has_nine_entries() {
        assert_eq!(profiles::ALL.len(), 9);
    }

    #[test]
    fn profiles_all_unique() {
        use std::collections::HashSet;
        let set: HashSet<_> = profiles::ALL.iter().collect();
        assert_eq!(set.len(), profiles::ALL.len());
    }

    #[test]
    fn profiles_constants_are_valid_profile_ids() {
        for id in profiles::ALL {
            let result = ProfileId::new(*id);
            assert!(result.is_ok(), "Profile ID '{}' should be valid", id);
        }
    }
}
