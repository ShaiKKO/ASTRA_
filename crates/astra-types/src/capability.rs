// SPDX-License-Identifier: MIT OR Apache-2.0
//! Capability contract types for ASTRA_.
//!
//! Formal specifications for what capabilities do, enabling composition
//! verification, conflict detection, and policy enforcement.
//!
//! - [`CapabilityContract`] - Full capability specification
//! - [`SideEffects`] - Declared state modifications with scope
//! - [`SideEffectType`] - Categories of effects (read, write, network, etc.)
//! - [`Safety`] - Pre/post conditions and error classes
//! - [`ValidationLevel`] - Trust tiers (declared, verified, audited)

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;

use crate::error::{AstraError, ErrorContext};
use crate::id::CapabilityId;
use crate::validate::Validate;

// ============================================================================
// SideEffectType enum
// ============================================================================

/// Categories of side effects a capability may have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SideEffectType {
    /// Read from filesystem.
    FileRead,
    /// Write to filesystem.
    FileWrite,
    /// Network access (HTTP, TCP, etc.).
    Network,
    /// Spawn subprocess.
    ProcessSpawn,
    /// Write to repository (git operations).
    RepoWrite,
    /// Write to database.
    DbWrite,
}

impl SideEffectType {
    /// Returns true if this effect modifies local state.
    ///
    /// Only effects that directly mutate locally-scoped state are writes.
    /// Network and ProcessSpawn are excluded because their mutations occur
    /// in external systems - conflict detection is delegated to policy.
    pub fn is_write(&self) -> bool {
        matches!(self, Self::FileWrite | Self::RepoWrite | Self::DbWrite)
    }
}

// Display uses underscores for readability; serde uses lowercase per blueprint §6.1.
impl fmt::Display for SideEffectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileRead => write!(f, "file_read"),
            Self::FileWrite => write!(f, "file_write"),
            Self::Network => write!(f, "network"),
            Self::ProcessSpawn => write!(f, "process_spawn"),
            Self::RepoWrite => write!(f, "repo_write"),
            Self::DbWrite => write!(f, "db_write"),
        }
    }
}

// ============================================================================
// ValidationLevel enum
// ============================================================================

/// Trust level of a capability contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationLevel {
    /// Self-declared by developer, not verified.
    Declared,
    /// Verified at runtime by sandbox monitoring.
    RuntimeVerified,
    /// Audited by external review process.
    ExternallyAudited,
}

impl Default for ValidationLevel {
    fn default() -> Self {
        Self::Declared
    }
}

impl fmt::Display for ValidationLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Declared => write!(f, "declared"),
            Self::RuntimeVerified => write!(f, "runtime_verified"),
            Self::ExternallyAudited => write!(f, "externally_audited"),
        }
    }
}

// ============================================================================
// Safety struct
// ============================================================================

/// Pre/post conditions and error classes for a capability.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct Safety {
    /// Conditions that must be true before execution.
    #[serde(default)]
    pub preconditions: Vec<String>,

    /// Conditions guaranteed after successful execution.
    #[serde(default)]
    pub postconditions: Vec<String>,

    /// Error types this capability may produce.
    #[serde(default)]
    pub error_classes: Vec<String>,
}

impl Safety {
    /// Create a new Safety specification.
    pub fn new(
        preconditions: Vec<String>,
        postconditions: Vec<String>,
        error_classes: Vec<String>,
    ) -> Self {
        Self {
            preconditions,
            postconditions,
            error_classes,
        }
    }

    /// Create Safety with only preconditions.
    pub fn with_preconditions(preconditions: Vec<String>) -> Self {
        Self {
            preconditions,
            postconditions: Vec::new(),
            error_classes: Vec::new(),
        }
    }

    /// Create Safety with only postconditions.
    pub fn with_postconditions(postconditions: Vec<String>) -> Self {
        Self {
            preconditions: Vec::new(),
            postconditions,
            error_classes: Vec::new(),
        }
    }

    /// Create Safety with only error classes.
    pub fn with_error_classes(error_classes: Vec<String>) -> Self {
        Self {
            preconditions: Vec::new(),
            postconditions: Vec::new(),
            error_classes,
        }
    }
}

// ============================================================================
// SideEffects struct
// ============================================================================

/// Declared side effects with scoped boundaries.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SideEffects {
    /// Effect types this capability may cause.
    #[serde(default)]
    pub effects: Vec<SideEffectType>,

    /// Scope boundaries (paths, endpoints, tables, etc.).
    #[serde(default)]
    pub scope: Vec<String>,
}

impl SideEffects {
    /// Create empty side effects (pure).
    pub fn none() -> Self {
        Self::default()
    }

    /// Create file read effects.
    pub fn file_read(paths: Vec<String>) -> Self {
        Self {
            effects: vec![SideEffectType::FileRead],
            scope: paths,
        }
    }

    /// Create file write effects.
    pub fn file_write(paths: Vec<String>) -> Self {
        Self {
            effects: vec![SideEffectType::FileWrite],
            scope: paths,
        }
    }

    /// Create network access effects.
    pub fn network(endpoints: Vec<String>) -> Self {
        Self {
            effects: vec![SideEffectType::Network],
            scope: endpoints,
        }
    }

    /// Create process spawn effects.
    pub fn process_spawn(commands: Vec<String>) -> Self {
        Self {
            effects: vec![SideEffectType::ProcessSpawn],
            scope: commands,
        }
    }

    /// Create repository write effects.
    pub fn repo_write(paths: Vec<String>) -> Self {
        Self {
            effects: vec![SideEffectType::RepoWrite],
            scope: paths,
        }
    }

    /// Create database write effects.
    pub fn db_write(tables: Vec<String>) -> Self {
        Self {
            effects: vec![SideEffectType::DbWrite],
            scope: tables,
        }
    }

    /// Returns true if no effects are declared.
    pub fn is_pure(&self) -> bool {
        self.effects.is_empty()
    }

    /// Returns true if any effect is a write.
    pub fn has_writes(&self) -> bool {
        self.effects.iter().any(|e| e.is_write())
    }

    /// Check if these effects conflict with another for parallel execution.
    ///
    /// Conflicts occur when at least one has writes and scopes overlap.
    /// Read-read operations do not conflict.
    pub fn conflicts_with(&self, other: &SideEffects) -> bool {
        // No conflict if either is pure
        if self.is_pure() || other.is_pure() {
            return false;
        }

        // Read-read: no conflict
        if !self.has_writes() && !other.has_writes() {
            return false;
        }

        // At least one writes - check scope overlap
        for s1 in &self.scope {
            for s2 in &other.scope {
                if scopes_overlap(s1, s2) {
                    return true;
                }
            }
        }

        false
    }
}

/// Check if two scopes potentially overlap (prefix match, conservative).
fn scopes_overlap(a: &str, b: &str) -> bool {
    a == b || a.starts_with(b) || b.starts_with(a)
}

// ============================================================================
// CapabilityContract struct
// ============================================================================

/// Formal contract specifying what a capability does.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityContract {
    /// Unique identifier.
    pub id: CapabilityId,

    /// Human-readable name.
    pub name: String,

    /// Semantic version.
    pub version: String,

    /// Taxonomy category.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taxonomy: Option<String>,

    /// JSON Schema for inputs.
    pub inputs: Value,

    /// JSON Schema for outputs.
    pub outputs: Value,

    /// Declared side effects.
    #[serde(default)]
    pub side_effects: SideEffects,

    /// Required resources.
    #[serde(default)]
    pub resources: Vec<String>,

    /// Safety constraints.
    #[serde(default)]
    pub safety: Safety,

    /// Trust level.
    #[serde(default)]
    pub validation_level: ValidationLevel,

    /// Origin/author.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<String>,
}

impl CapabilityContract {
    /// Create a new contract with required fields.
    pub fn new(id: CapabilityId, name: impl Into<String>, version: impl Into<String>) -> Self {
        Self {
            id,
            name: name.into(),
            version: version.into(),
            taxonomy: None,
            inputs: Value::Object(Default::default()),
            outputs: Value::Object(Default::default()),
            side_effects: SideEffects::default(),
            resources: Vec::new(),
            safety: Safety::default(),
            validation_level: ValidationLevel::default(),
            provenance: None,
        }
    }

    /// Set the taxonomy.
    pub fn with_taxonomy(mut self, taxonomy: impl Into<String>) -> Self {
        self.taxonomy = Some(taxonomy.into());
        self
    }

    /// Set the inputs schema.
    pub fn with_inputs(mut self, inputs: Value) -> Self {
        self.inputs = inputs;
        self
    }

    /// Set the outputs schema.
    pub fn with_outputs(mut self, outputs: Value) -> Self {
        self.outputs = outputs;
        self
    }

    /// Set the side effects.
    pub fn with_side_effects(mut self, side_effects: SideEffects) -> Self {
        self.side_effects = side_effects;
        self
    }

    /// Set the resources.
    pub fn with_resources(mut self, resources: Vec<String>) -> Self {
        self.resources = resources;
        self
    }

    /// Set the safety constraints.
    pub fn with_safety(mut self, safety: Safety) -> Self {
        self.safety = safety;
        self
    }

    /// Set the validation level.
    pub fn with_validation_level(mut self, level: ValidationLevel) -> Self {
        self.validation_level = level;
        self
    }

    /// Set the provenance.
    pub fn with_provenance(mut self, provenance: impl Into<String>) -> Self {
        self.provenance = Some(provenance.into());
        self
    }

    /// Check if this contract conflicts with another for parallel execution.
    pub fn conflicts_with(&self, other: &CapabilityContract) -> bool {
        self.side_effects.conflicts_with(&other.side_effects)
    }

    /// Returns true if this capability has no side effects.
    pub fn is_pure(&self) -> bool {
        self.side_effects.is_pure()
    }
}

impl Validate for CapabilityContract {
    fn validate(&self) -> Result<(), AstraError> {
        // VAL-050: name must be non-empty
        if self.name.is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-050",
                    "Provide a non-empty name for the capability",
                ),
                field: Some("name".into()),
                message: "CapabilityContract name cannot be empty".into(),
            });
        }

        // VAL-051: version must be non-empty
        if self.version.is_empty() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-051",
                    "Provide a semantic version string (e.g., \"1.0.0\")",
                ),
                field: Some("version".into()),
                message: "CapabilityContract version cannot be empty".into(),
            });
        }

        // VAL-052: inputs must be a JSON object
        if !self.inputs.is_object() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-052",
                    "Provide a JSON object for inputs (e.g., JSON Schema)",
                ),
                field: Some("inputs".into()),
                message: format!(
                    "CapabilityContract inputs must be a JSON object, got {}",
                    value_type_name(&self.inputs)
                ),
            });
        }

        // VAL-053: outputs must be a JSON object
        if !self.outputs.is_object() {
            return Err(AstraError::ValidationFailed {
                context: ErrorContext::validation(
                    "VAL-053",
                    "Provide a JSON object for outputs (e.g., JSON Schema)",
                ),
                field: Some("outputs".into()),
                message: format!(
                    "CapabilityContract outputs must be a JSON object, got {}",
                    value_type_name(&self.outputs)
                ),
            });
        }

        Ok(())
    }
}

/// Get a human-readable name for a JSON Value type.
fn value_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashSet;

    // ========================================================================
    // SideEffectType tests
    // ========================================================================

    #[test]
    fn side_effect_type_is_write_true_for_file_write() {
        assert!(SideEffectType::FileWrite.is_write());
    }

    #[test]
    fn side_effect_type_is_write_true_for_repo_write() {
        assert!(SideEffectType::RepoWrite.is_write());
    }

    #[test]
    fn side_effect_type_is_write_true_for_db_write() {
        assert!(SideEffectType::DbWrite.is_write());
    }

    #[test]
    fn side_effect_type_is_write_false_for_file_read() {
        assert!(!SideEffectType::FileRead.is_write());
    }

    #[test]
    fn side_effect_type_is_write_false_for_network() {
        assert!(!SideEffectType::Network.is_write());
    }

    #[test]
    fn side_effect_type_is_write_false_for_process_spawn() {
        assert!(!SideEffectType::ProcessSpawn.is_write());
    }

    #[test]
    fn side_effect_type_display_all_variants() {
        assert_eq!(SideEffectType::FileRead.to_string(), "file_read");
        assert_eq!(SideEffectType::FileWrite.to_string(), "file_write");
        assert_eq!(SideEffectType::Network.to_string(), "network");
        assert_eq!(SideEffectType::ProcessSpawn.to_string(), "process_spawn");
        assert_eq!(SideEffectType::RepoWrite.to_string(), "repo_write");
        assert_eq!(SideEffectType::DbWrite.to_string(), "db_write");
    }

    #[test]
    fn side_effect_type_can_be_used_as_hash_key() {
        let mut set = HashSet::new();
        set.insert(SideEffectType::FileRead);
        set.insert(SideEffectType::FileWrite);
        set.insert(SideEffectType::FileRead); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn side_effect_type_serializes_lowercase() {
        let Ok(json) = serde_json::to_string(&SideEffectType::FileRead) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"fileread\"");

        let Ok(json) = serde_json::to_string(&SideEffectType::ProcessSpawn) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"processspawn\"");
    }

    #[test]
    fn side_effect_type_deserializes_lowercase() {
        let Ok(effect) = serde_json::from_str::<SideEffectType>("\"filewrite\"") else {
            panic!("deserialization should succeed");
        };
        assert_eq!(effect, SideEffectType::FileWrite);

        let Ok(effect) = serde_json::from_str::<SideEffectType>("\"repowrite\"") else {
            panic!("deserialization should succeed");
        };
        assert_eq!(effect, SideEffectType::RepoWrite);
    }

    // ========================================================================
    // ValidationLevel tests
    // ========================================================================

    #[test]
    fn validation_level_default_is_declared() {
        assert_eq!(ValidationLevel::default(), ValidationLevel::Declared);
    }

    #[test]
    fn validation_level_display_all_variants() {
        assert_eq!(ValidationLevel::Declared.to_string(), "declared");
        assert_eq!(
            ValidationLevel::RuntimeVerified.to_string(),
            "runtime_verified"
        );
        assert_eq!(
            ValidationLevel::ExternallyAudited.to_string(),
            "externally_audited"
        );
    }

    #[test]
    fn validation_level_can_be_used_as_hash_key() {
        let mut set = HashSet::new();
        set.insert(ValidationLevel::Declared);
        set.insert(ValidationLevel::RuntimeVerified);
        set.insert(ValidationLevel::Declared); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn validation_level_serializes_snake_case() {
        let Ok(json) = serde_json::to_string(&ValidationLevel::RuntimeVerified) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"runtime_verified\"");

        let Ok(json) = serde_json::to_string(&ValidationLevel::ExternallyAudited) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"externally_audited\"");
    }

    #[test]
    fn validation_level_roundtrip() {
        for level in [
            ValidationLevel::Declared,
            ValidationLevel::RuntimeVerified,
            ValidationLevel::ExternallyAudited,
        ] {
            let Ok(json) = serde_json::to_string(&level) else {
                panic!("serialization should succeed");
            };
            let Ok(decoded) = serde_json::from_str::<ValidationLevel>(&json) else {
                panic!("deserialization should succeed");
            };
            assert_eq!(level, decoded);
        }
    }

    // ========================================================================
    // Safety tests
    // ========================================================================

    #[test]
    fn safety_default_is_empty() {
        let safety = Safety::default();
        assert!(safety.preconditions.is_empty());
        assert!(safety.postconditions.is_empty());
        assert!(safety.error_classes.is_empty());
    }

    #[test]
    fn safety_new_constructor() {
        let safety = Safety::new(
            vec!["pre1".into(), "pre2".into()],
            vec!["post1".into()],
            vec!["Error1".into(), "Error2".into()],
        );
        assert_eq!(safety.preconditions.len(), 2);
        assert_eq!(safety.postconditions.len(), 1);
        assert_eq!(safety.error_classes.len(), 2);
    }

    #[test]
    fn safety_with_preconditions() {
        let safety = Safety::with_preconditions(vec!["cond1".into(), "cond2".into()]);
        assert_eq!(safety.preconditions.len(), 2);
        assert!(safety.postconditions.is_empty());
        assert!(safety.error_classes.is_empty());
    }

    #[test]
    fn safety_with_postconditions() {
        let safety = Safety::with_postconditions(vec!["cond1".into()]);
        assert!(safety.preconditions.is_empty());
        assert_eq!(safety.postconditions.len(), 1);
        assert!(safety.error_classes.is_empty());
    }

    #[test]
    fn safety_with_error_classes() {
        let safety = Safety::with_error_classes(vec!["Err1".into(), "Err2".into()]);
        assert!(safety.preconditions.is_empty());
        assert!(safety.postconditions.is_empty());
        assert_eq!(safety.error_classes.len(), 2);
    }

    #[test]
    fn safety_roundtrip() {
        let safety = Safety::new(
            vec!["pre".into()],
            vec!["post".into()],
            vec!["Error".into()],
        );
        let Ok(json) = serde_json::to_string(&safety) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<Safety>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(safety, decoded);
    }

    // ========================================================================
    // SideEffects constructor tests
    // ========================================================================

    #[test]
    fn side_effects_none_creates_empty() {
        let effects = SideEffects::none();
        assert!(effects.effects.is_empty());
        assert!(effects.scope.is_empty());
    }

    #[test]
    fn side_effects_file_read_with_paths() {
        let effects = SideEffects::file_read(vec!["src/**".into(), "tests/**".into()]);
        assert_eq!(effects.effects, vec![SideEffectType::FileRead]);
        assert_eq!(effects.scope.len(), 2);
    }

    #[test]
    fn side_effects_file_write_with_paths() {
        let effects = SideEffects::file_write(vec!["output/".into()]);
        assert_eq!(effects.effects, vec![SideEffectType::FileWrite]);
        assert_eq!(effects.scope.len(), 1);
    }

    #[test]
    fn side_effects_network_with_endpoints() {
        let effects = SideEffects::network(vec!["api.example.com".into()]);
        assert_eq!(effects.effects, vec![SideEffectType::Network]);
        assert_eq!(effects.scope[0], "api.example.com");
    }

    #[test]
    fn side_effects_process_spawn_with_commands() {
        let effects = SideEffects::process_spawn(vec!["cargo".into(), "npm".into()]);
        assert_eq!(effects.effects, vec![SideEffectType::ProcessSpawn]);
        assert_eq!(effects.scope.len(), 2);
    }

    #[test]
    fn side_effects_repo_write_with_paths() {
        let effects = SideEffects::repo_write(vec!["src/".into()]);
        assert_eq!(effects.effects, vec![SideEffectType::RepoWrite]);
        assert_eq!(effects.scope.len(), 1);
    }

    #[test]
    fn side_effects_db_write_with_tables() {
        let effects = SideEffects::db_write(vec!["users".into(), "sessions".into()]);
        assert_eq!(effects.effects, vec![SideEffectType::DbWrite]);
        assert_eq!(effects.scope.len(), 2);
    }

    #[test]
    fn side_effects_default_is_empty() {
        let effects = SideEffects::default();
        assert!(effects.effects.is_empty());
        assert!(effects.scope.is_empty());
    }

    // ========================================================================
    // SideEffects method tests
    // ========================================================================

    #[test]
    fn side_effects_is_pure_true_for_empty() {
        let effects = SideEffects::none();
        assert!(effects.is_pure());
    }

    #[test]
    fn side_effects_is_pure_false_for_any_effect() {
        let effects = SideEffects::file_read(vec!["src/".into()]);
        assert!(!effects.is_pure());
    }

    #[test]
    fn side_effects_has_writes_true_for_file_write() {
        let effects = SideEffects::file_write(vec!["out/".into()]);
        assert!(effects.has_writes());
    }

    #[test]
    fn side_effects_has_writes_true_for_repo_write() {
        let effects = SideEffects::repo_write(vec!["src/".into()]);
        assert!(effects.has_writes());
    }

    #[test]
    fn side_effects_has_writes_true_for_db_write() {
        let effects = SideEffects::db_write(vec!["table".into()]);
        assert!(effects.has_writes());
    }

    #[test]
    fn side_effects_has_writes_false_for_read_only() {
        let effects = SideEffects::file_read(vec!["src/".into()]);
        assert!(!effects.has_writes());
    }

    #[test]
    fn side_effects_has_writes_false_for_network() {
        let effects = SideEffects::network(vec!["api.com".into()]);
        assert!(!effects.has_writes());
    }

    #[test]
    fn side_effects_has_writes_false_for_process_spawn() {
        let effects = SideEffects::process_spawn(vec!["ls".into()]);
        assert!(!effects.has_writes());
    }

    // ========================================================================
    // SideEffects conflict tests
    // ========================================================================

    #[test]
    fn side_effects_conflicts_with_same_scope() {
        let effects1 = SideEffects::file_write(vec!["src/".into()]);
        let effects2 = SideEffects::file_write(vec!["src/".into()]);
        assert!(effects1.conflicts_with(&effects2));
    }

    #[test]
    fn side_effects_conflicts_with_prefix_scope() {
        let effects1 = SideEffects::file_write(vec!["src/".into()]);
        let effects2 = SideEffects::file_write(vec!["src/lib.rs".into()]);
        assert!(effects1.conflicts_with(&effects2));
    }

    #[test]
    fn side_effects_conflicts_with_disjoint_scopes_false() {
        let effects1 = SideEffects::file_write(vec!["src/".into()]);
        let effects2 = SideEffects::file_write(vec!["tests/".into()]);
        assert!(!effects1.conflicts_with(&effects2));
    }

    #[test]
    fn side_effects_conflicts_with_read_read_false() {
        let effects1 = SideEffects::file_read(vec!["src/".into()]);
        let effects2 = SideEffects::file_read(vec!["src/".into()]);
        assert!(!effects1.conflicts_with(&effects2));
    }

    #[test]
    fn side_effects_conflicts_with_read_write_true() {
        let effects1 = SideEffects::file_read(vec!["src/".into()]);
        let effects2 = SideEffects::file_write(vec!["src/".into()]);
        assert!(effects1.conflicts_with(&effects2));
    }

    #[test]
    fn side_effects_conflicts_with_write_read_true() {
        let effects1 = SideEffects::file_write(vec!["src/".into()]);
        let effects2 = SideEffects::file_read(vec!["src/".into()]);
        assert!(effects1.conflicts_with(&effects2));
    }

    #[test]
    fn side_effects_conflicts_with_write_write_overlap() {
        let effects1 = SideEffects::repo_write(vec!["src/".into()]);
        let effects2 = SideEffects::file_write(vec!["src/main.rs".into()]);
        assert!(effects1.conflicts_with(&effects2));
    }

    #[test]
    fn side_effects_conflicts_with_empty_scopes_false() {
        let effects1 = SideEffects {
            effects: vec![SideEffectType::FileWrite],
            scope: vec![],
        };
        let effects2 = SideEffects {
            effects: vec![SideEffectType::FileWrite],
            scope: vec![],
        };
        assert!(!effects1.conflicts_with(&effects2));
    }

    #[test]
    fn side_effects_conflicts_with_one_empty_scope_false() {
        let effects1 = SideEffects::file_write(vec!["src/".into()]);
        let effects2 = SideEffects {
            effects: vec![SideEffectType::FileWrite],
            scope: vec![],
        };
        assert!(!effects1.conflicts_with(&effects2));
    }

    #[test]
    fn side_effects_conflicts_with_pure_never_conflicts() {
        let effects1 = SideEffects::none();
        let effects2 = SideEffects::file_write(vec!["src/".into()]);
        assert!(!effects1.conflicts_with(&effects2));
        assert!(!effects2.conflicts_with(&effects1));
    }

    #[test]
    fn scopes_overlap_equal() {
        assert!(scopes_overlap("src/", "src/"));
    }

    #[test]
    fn scopes_overlap_prefix() {
        assert!(scopes_overlap("src/", "src/lib.rs"));
        assert!(scopes_overlap("src/lib.rs", "src/"));
    }

    #[test]
    fn scopes_overlap_disjoint() {
        assert!(!scopes_overlap("src/", "tests/"));
    }

    #[test]
    fn side_effects_roundtrip() {
        let effects = SideEffects {
            effects: vec![SideEffectType::FileWrite, SideEffectType::Network],
            scope: vec!["src/".into(), "api.com".into()],
        };
        let Ok(json) = serde_json::to_string(&effects) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<SideEffects>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(effects, decoded);
    }

    // ========================================================================
    // CapabilityContract constructor tests
    // ========================================================================

    #[test]
    fn capability_contract_new_creates_valid_contract() {
        let Ok(id) = CapabilityId::new("test.capability") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test Capability", "1.0.0");

        assert_eq!(contract.name, "Test Capability");
        assert_eq!(contract.version, "1.0.0");
        assert!(contract.taxonomy.is_none());
        assert!(contract.is_valid());
    }

    #[test]
    fn capability_contract_default_values() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test", "1.0.0");

        assert!(contract.taxonomy.is_none());
        assert!(contract.inputs.is_object());
        assert!(contract.outputs.is_object());
        assert!(contract.side_effects.is_pure());
        assert!(contract.resources.is_empty());
        assert_eq!(contract.validation_level, ValidationLevel::Declared);
        assert!(contract.provenance.is_none());
    }

    // ========================================================================
    // CapabilityContract builder tests
    // ========================================================================

    #[test]
    fn capability_contract_with_taxonomy() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test", "1.0.0").with_taxonomy("file.read");

        assert_eq!(contract.taxonomy, Some("file.read".into()));
    }

    #[test]
    fn capability_contract_with_inputs() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let schema = json!({"type": "object", "properties": {"path": {"type": "string"}}});
        let contract = CapabilityContract::new(id, "Test", "1.0.0").with_inputs(schema.clone());

        assert_eq!(contract.inputs, schema);
    }

    #[test]
    fn capability_contract_with_outputs() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let schema = json!({"type": "object", "properties": {"result": {"type": "string"}}});
        let contract = CapabilityContract::new(id, "Test", "1.0.0").with_outputs(schema.clone());

        assert_eq!(contract.outputs, schema);
    }

    #[test]
    fn capability_contract_with_side_effects() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let effects = SideEffects::file_write(vec!["out/".into()]);
        let contract =
            CapabilityContract::new(id, "Test", "1.0.0").with_side_effects(effects.clone());

        assert_eq!(contract.side_effects, effects);
    }

    #[test]
    fn capability_contract_with_resources() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract =
            CapabilityContract::new(id, "Test", "1.0.0").with_resources(vec!["gpu".into()]);

        assert_eq!(contract.resources, vec!["gpu"]);
    }

    #[test]
    fn capability_contract_with_safety() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let safety = Safety::with_preconditions(vec!["file.exists()".into()]);
        let contract = CapabilityContract::new(id, "Test", "1.0.0").with_safety(safety.clone());

        assert_eq!(contract.safety, safety);
    }

    #[test]
    fn capability_contract_with_validation_level() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test", "1.0.0")
            .with_validation_level(ValidationLevel::ExternallyAudited);

        assert_eq!(
            contract.validation_level,
            ValidationLevel::ExternallyAudited
        );
    }

    #[test]
    fn capability_contract_with_provenance() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract =
            CapabilityContract::new(id, "Test", "1.0.0").with_provenance("astra-core-team");

        assert_eq!(contract.provenance, Some("astra-core-team".into()));
    }

    #[test]
    fn capability_contract_full_builder_chain() {
        let Ok(id) = CapabilityId::new("repo.apply_patch") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Apply Patch", "1.0.0")
            .with_taxonomy("repo.write")
            .with_inputs(json!({"type": "object"}))
            .with_outputs(json!({"type": "object"}))
            .with_side_effects(SideEffects::repo_write(vec!["src/".into()]))
            .with_resources(vec!["git".into()])
            .with_safety(Safety::with_preconditions(vec!["worktree.clean()".into()]))
            .with_validation_level(ValidationLevel::RuntimeVerified)
            .with_provenance("astra-core");

        assert!(contract.is_valid());
        assert_eq!(contract.taxonomy, Some("repo.write".into()));
        assert!(!contract.is_pure());
        assert_eq!(contract.provenance, Some("astra-core".into()));
    }

    // ========================================================================
    // CapabilityContract method tests
    // ========================================================================

    #[test]
    fn capability_contract_is_pure_true_for_no_effects() {
        let Ok(id) = CapabilityId::new("pure.function") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Pure Function", "1.0.0");

        assert!(contract.is_pure());
    }

    #[test]
    fn capability_contract_is_pure_false_for_effects() {
        let Ok(id) = CapabilityId::new("file.writer") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "File Writer", "1.0.0")
            .with_side_effects(SideEffects::file_write(vec!["out/".into()]));

        assert!(!contract.is_pure());
    }

    #[test]
    fn capability_contract_conflicts_with_overlapping() {
        let Ok(id1) = CapabilityId::new("writer.a") else {
            panic!("valid capability ID should succeed");
        };
        let Ok(id2) = CapabilityId::new("writer.b") else {
            panic!("valid capability ID should succeed");
        };
        let contract1 = CapabilityContract::new(id1, "Writer A", "1.0.0")
            .with_side_effects(SideEffects::file_write(vec!["src/".into()]));
        let contract2 = CapabilityContract::new(id2, "Writer B", "1.0.0")
            .with_side_effects(SideEffects::file_write(vec!["src/main.rs".into()]));

        assert!(contract1.conflicts_with(&contract2));
    }

    #[test]
    fn capability_contract_conflicts_with_disjoint() {
        let Ok(id1) = CapabilityId::new("writer.a") else {
            panic!("valid capability ID should succeed");
        };
        let Ok(id2) = CapabilityId::new("writer.b") else {
            panic!("valid capability ID should succeed");
        };
        let contract1 = CapabilityContract::new(id1, "Writer A", "1.0.0")
            .with_side_effects(SideEffects::file_write(vec!["src/".into()]));
        let contract2 = CapabilityContract::new(id2, "Writer B", "1.0.0")
            .with_side_effects(SideEffects::file_write(vec!["tests/".into()]));

        assert!(!contract1.conflicts_with(&contract2));
    }

    #[test]
    fn capability_contract_conflicts_with_pure_never_conflicts() {
        let Ok(id1) = CapabilityId::new("pure") else {
            panic!("valid capability ID should succeed");
        };
        let Ok(id2) = CapabilityId::new("writer") else {
            panic!("valid capability ID should succeed");
        };
        let contract1 = CapabilityContract::new(id1, "Pure", "1.0.0");
        let contract2 = CapabilityContract::new(id2, "Writer", "1.0.0")
            .with_side_effects(SideEffects::file_write(vec!["src/".into()]));

        assert!(!contract1.conflicts_with(&contract2));
        assert!(!contract2.conflicts_with(&contract1));
    }

    // ========================================================================
    // Validation tests
    // ========================================================================

    #[test]
    fn capability_contract_valid_passes() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test", "1.0.0");

        assert!(contract.is_valid());
    }

    #[test]
    fn capability_contract_empty_name_fails() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "", "1.0.0");
        let result = contract.validate();

        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-050");
        assert_eq!(field, Some("name".into()));
    }

    #[test]
    fn capability_contract_empty_version_fails() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test", "");
        let result = contract.validate();

        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, field, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-051");
        assert_eq!(field, Some("version".into()));
    }

    #[test]
    fn capability_contract_inputs_null_fails() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test", "1.0.0").with_inputs(Value::Null);
        let result = contract.validate();

        assert!(result.is_err());
        let Err(AstraError::ValidationFailed {
            context,
            field,
            message,
        }) = result
        else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-052");
        assert_eq!(field, Some("inputs".into()));
        assert!(message.contains("null"));
    }

    #[test]
    fn capability_contract_inputs_array_fails() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test", "1.0.0").with_inputs(json!([]));
        let result = contract.validate();

        assert!(result.is_err());
        let Err(AstraError::ValidationFailed {
            context,
            field,
            message,
        }) = result
        else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-052");
        assert_eq!(field, Some("inputs".into()));
        assert!(message.contains("array"));
    }

    #[test]
    fn capability_contract_inputs_string_fails() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract =
            CapabilityContract::new(id, "Test", "1.0.0").with_inputs(json!("not an object"));
        let result = contract.validate();

        assert!(result.is_err());
        let Err(AstraError::ValidationFailed {
            context,
            field,
            message,
        }) = result
        else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-052");
        assert_eq!(field, Some("inputs".into()));
        assert!(message.contains("string"));
    }

    #[test]
    fn capability_contract_outputs_null_fails() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test", "1.0.0").with_outputs(Value::Null);
        let result = contract.validate();

        assert!(result.is_err());
        let Err(AstraError::ValidationFailed {
            context,
            field,
            message,
        }) = result
        else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-053");
        assert_eq!(field, Some("outputs".into()));
        assert!(message.contains("null"));
    }

    #[test]
    fn capability_contract_outputs_number_fails() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test", "1.0.0").with_outputs(json!(42));
        let result = contract.validate();

        assert!(result.is_err());
        let Err(AstraError::ValidationFailed {
            context,
            field,
            message,
        }) = result
        else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-053");
        assert_eq!(field, Some("outputs".into()));
        assert!(message.contains("number"));
    }

    #[test]
    fn capability_contract_outputs_boolean_fails() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test", "1.0.0").with_outputs(json!(true));
        let result = contract.validate();

        assert!(result.is_err());
        let Err(AstraError::ValidationFailed {
            context,
            field,
            message,
        }) = result
        else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-053");
        assert_eq!(field, Some("outputs".into()));
        assert!(message.contains("boolean"));
    }

    // ========================================================================
    // Serde tests
    // ========================================================================

    #[test]
    fn capability_contract_roundtrip_full() {
        let Ok(id) = CapabilityId::new("repo.apply_patch") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Apply Patch", "1.0.0")
            .with_taxonomy("repo.write")
            .with_inputs(json!({"type": "object", "properties": {"patch": {"type": "string"}}}))
            .with_outputs(json!({"type": "object", "properties": {"sha": {"type": "string"}}}))
            .with_side_effects(SideEffects {
                effects: vec![SideEffectType::FileWrite, SideEffectType::RepoWrite],
                scope: vec!["src/".into()],
            })
            .with_resources(vec!["git".into()])
            .with_safety(Safety::new(
                vec!["clean".into()],
                vec!["committed".into()],
                vec!["MergeConflict".into()],
            ))
            .with_validation_level(ValidationLevel::RuntimeVerified)
            .with_provenance("astra-core");

        let Ok(json) = serde_json::to_string(&contract) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<CapabilityContract>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(contract, decoded);
    }

    #[test]
    fn capability_contract_roundtrip_minimal() {
        let Ok(id) = CapabilityId::new("minimal") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Minimal", "0.1.0");

        let Ok(json) = serde_json::to_string(&contract) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<CapabilityContract>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(contract, decoded);
    }

    #[test]
    fn capability_contract_skips_none_fields() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test", "1.0.0");

        let Ok(json) = serde_json::to_string(&contract) else {
            panic!("serialization should succeed");
        };

        // taxonomy and provenance should be skipped
        assert!(!json.contains("taxonomy"));
        assert!(!json.contains("provenance"));
    }

    #[test]
    fn capability_contract_includes_default_fields() {
        let Ok(id) = CapabilityId::new("test") else {
            panic!("valid capability ID should succeed");
        };
        let contract = CapabilityContract::new(id, "Test", "1.0.0");

        let Ok(json) = serde_json::to_string(&contract) else {
            panic!("serialization should succeed");
        };

        // These should be present even with defaults
        assert!(json.contains("side_effects"));
        assert!(json.contains("resources"));
        assert!(json.contains("safety"));
        assert!(json.contains("validation_level"));
    }

    #[test]
    fn capability_contract_deserialize_with_defaults() {
        // Minimal JSON with only required fields
        let json = r#"{
            "id": "test",
            "name": "Test",
            "version": "1.0.0",
            "inputs": {},
            "outputs": {}
        }"#;

        let Ok(contract) = serde_json::from_str::<CapabilityContract>(json) else {
            panic!("deserialization should succeed");
        };

        assert_eq!(contract.id.as_str(), "test");
        assert!(contract.side_effects.is_pure());
        assert!(contract.resources.is_empty());
        assert_eq!(contract.validation_level, ValidationLevel::Declared);
    }

    #[test]
    fn value_type_name_helper() {
        assert_eq!(value_type_name(&Value::Null), "null");
        assert_eq!(value_type_name(&json!(true)), "boolean");
        assert_eq!(value_type_name(&json!(42)), "number");
        assert_eq!(value_type_name(&json!("str")), "string");
        assert_eq!(value_type_name(&json!([])), "array");
        assert_eq!(value_type_name(&json!({})), "object");
    }
}
