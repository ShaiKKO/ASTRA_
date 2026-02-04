// SPDX-License-Identifier: MIT OR Apache-2.0
//! Type-safe ID wrappers for ASTRA_.
//!
//! Two categories of IDs:
//! - **UUID-based**: System-generated, always valid (TaskId, CorrelationId, etc.)
//! - **String-based**: User-provided, validated on construction (WorkspaceId, etc.)
//!
//! # Design
//!
//! IDs are newtypes that prevent mixing different identifier types at compile time.
//! UUID IDs auto-generate via `new()`, string IDs validate on construction.
//!
//! # Example
//!
//! ```
//! use astra_types::{TaskId, WorkspaceId, CapabilityId};
//!
//! // UUID IDs auto-generate
//! let task_id = TaskId::new();
//!
//! // String IDs validate on construction
//! let workspace = WorkspaceId::new("my-project").unwrap();
//! let capability = CapabilityId::new("repo.read").unwrap();
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::Hash;
use std::str::FromStr;
use uuid::Uuid;

use crate::error::{AstraError, ErrorContext, Severity};

/// Maximum length for WorkspaceId.
pub const WORKSPACE_ID_MAX_LEN: usize = 256;

/// Maximum length for CapabilityId.
pub const CAPABILITY_ID_MAX_LEN: usize = 128;

/// Maximum length for PolicyId.
pub const POLICY_ID_MAX_LEN: usize = 128;

/// Maximum length for ProfileId.
pub const PROFILE_ID_MAX_LEN: usize = 64;

/// Regex pattern for CapabilityId: lowercase alphanumeric with underscores, dot-separated.
/// Examples: "repo", "repo.read", "static_analysis.lint"
const CAPABILITY_ID_PATTERN: &str = r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$";

// ============================================================================
// UUID-based ID macro
// ============================================================================

/// Generates a UUID-based ID type.
macro_rules! define_uuid_id {
    (
        $(#[$meta:meta])*
        $name:ident
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generate a new random ID.
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Create an ID from an existing UUID.
            pub fn from_uuid(uuid: Uuid) -> Self {
                Self(uuid)
            }

            /// Get the underlying UUID.
            pub fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// Consume and return the underlying UUID.
            pub fn into_inner(self) -> Uuid {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = AstraError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Uuid::parse_str(s).map(Self).map_err(|e| {
                    AstraError::ValidationFailed {
                        context: ErrorContext::builder()
                            .error_code("VAL-024")
                            .component("astra-types")
                            .severity(Severity::Error)
                            .remediation_hint(format!(
                                "Provide a valid UUID for {}",
                                stringify!($name)
                            ))
                            .build()
                            .unwrap_or_default(),
                        field: Some(stringify!($name).into()),
                        message: format!("Invalid UUID format: {}", e),
                    }
                })
            }
        }

        impl AsRef<Uuid> for $name {
            fn as_ref(&self) -> &Uuid {
                &self.0
            }
        }
    };
}

// ============================================================================
// String-based ID macro (without pattern)
// ============================================================================

/// Generates a validated string-based ID type.
macro_rules! define_string_id {
    (
        $(#[$meta:meta])*
        $name:ident, max_len: $max_len:expr
    ) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Create a new ID, validating the input.
            ///
            /// # Errors
            /// Returns an error if:
            /// - The string is empty
            /// - The string exceeds the maximum length
            /// - The string has leading or trailing whitespace
            #[allow(clippy::result_large_err)]
            pub fn new(value: impl Into<String>) -> Result<Self, AstraError> {
                let value = value.into();
                Self::validate_string(&value)?;
                Ok(Self(value))
            }

            /// Create an ID without validation.
            ///
            /// # Safety
            /// This bypasses validation. Use only when deserializing
            /// from a trusted source or when the value is known to be valid.
            pub fn new_unchecked(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Get the underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume and return the underlying string.
            pub fn into_inner(self) -> String {
                self.0
            }

            /// Maximum allowed length for this ID type.
            pub const fn max_len() -> usize {
                $max_len
            }

            #[allow(clippy::result_large_err)]
            fn validate_string(value: &str) -> Result<(), AstraError> {
                if value.is_empty() {
                    return Err(AstraError::ValidationFailed {
                        context: ErrorContext::builder()
                            .error_code("VAL-020")
                            .component("astra-types")
                            .severity(Severity::Error)
                            .remediation_hint(format!("{} cannot be empty", stringify!($name)))
                            .build()
                            .unwrap_or_default(),
                        field: Some(stringify!($name).into()),
                        message: format!("{} cannot be empty", stringify!($name)),
                    });
                }

                if value.len() > $max_len {
                    return Err(AstraError::ValidationFailed {
                        context: ErrorContext::builder()
                            .error_code("VAL-021")
                            .component("astra-types")
                            .severity(Severity::Error)
                            .remediation_hint(format!(
                                "{} must be at most {} characters",
                                stringify!($name),
                                $max_len
                            ))
                            .build()
                            .unwrap_or_default(),
                        field: Some(stringify!($name).into()),
                        message: format!(
                            "{} exceeds maximum length of {} (got {})",
                            stringify!($name),
                            $max_len,
                            value.len()
                        ),
                    });
                }

                if value != value.trim() {
                    return Err(AstraError::ValidationFailed {
                        context: ErrorContext::builder()
                            .error_code("VAL-022")
                            .component("astra-types")
                            .severity(Severity::Error)
                            .remediation_hint(format!(
                                "{} must not have leading or trailing whitespace",
                                stringify!($name)
                            ))
                            .build()
                            .unwrap_or_default(),
                        field: Some(stringify!($name).into()),
                        message: format!(
                            "{} contains leading or trailing whitespace",
                            stringify!($name)
                        ),
                    });
                }

                Ok(())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = AstraError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = AstraError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = AstraError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

// ============================================================================
// String-based ID macro (with pattern)
// ============================================================================

/// Generates a validated string-based ID type with regex pattern.
macro_rules! define_string_id_with_pattern {
    (
        $(#[$meta:meta])*
        $name:ident, max_len: $max_len:expr, pattern: $pattern:expr, pattern_desc: $pattern_desc:expr
    ) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Create a new ID, validating the input.
            ///
            /// # Errors
            /// Returns an error if:
            /// - The string is empty
            /// - The string exceeds the maximum length
            /// - The string has leading or trailing whitespace
            /// - The string does not match the required pattern
            #[allow(clippy::result_large_err)]
            pub fn new(value: impl Into<String>) -> Result<Self, AstraError> {
                let value = value.into();
                Self::validate_string(&value)?;
                Ok(Self(value))
            }

            /// Create an ID without validation.
            ///
            /// # Safety
            /// This bypasses validation. Use only when deserializing
            /// from a trusted source or when the value is known to be valid.
            pub fn new_unchecked(value: impl Into<String>) -> Self {
                Self(value.into())
            }

            /// Get the underlying string.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consume and return the underlying string.
            pub fn into_inner(self) -> String {
                self.0
            }

            /// Maximum allowed length for this ID type.
            pub const fn max_len() -> usize {
                $max_len
            }

            /// The regex pattern this ID must match.
            pub const fn pattern() -> &'static str {
                $pattern
            }

            #[allow(clippy::result_large_err)]
            fn validate_string(value: &str) -> Result<(), AstraError> {
                if value.is_empty() {
                    return Err(AstraError::ValidationFailed {
                        context: ErrorContext::builder()
                            .error_code("VAL-020")
                            .component("astra-types")
                            .severity(Severity::Error)
                            .remediation_hint(format!("{} cannot be empty", stringify!($name)))
                            .build()
                            .unwrap_or_default(),
                        field: Some(stringify!($name).into()),
                        message: format!("{} cannot be empty", stringify!($name)),
                    });
                }

                if value.len() > $max_len {
                    return Err(AstraError::ValidationFailed {
                        context: ErrorContext::builder()
                            .error_code("VAL-021")
                            .component("astra-types")
                            .severity(Severity::Error)
                            .remediation_hint(format!(
                                "{} must be at most {} characters",
                                stringify!($name),
                                $max_len
                            ))
                            .build()
                            .unwrap_or_default(),
                        field: Some(stringify!($name).into()),
                        message: format!(
                            "{} exceeds maximum length of {} (got {})",
                            stringify!($name),
                            $max_len,
                            value.len()
                        ),
                    });
                }

                if value != value.trim() {
                    return Err(AstraError::ValidationFailed {
                        context: ErrorContext::builder()
                            .error_code("VAL-022")
                            .component("astra-types")
                            .severity(Severity::Error)
                            .remediation_hint(format!(
                                "{} must not have leading or trailing whitespace",
                                stringify!($name)
                            ))
                            .build()
                            .unwrap_or_default(),
                        field: Some(stringify!($name).into()),
                        message: format!(
                            "{} contains leading or trailing whitespace",
                            stringify!($name)
                        ),
                    });
                }

                // Pattern validation using a simple state machine instead of regex
                // Pattern: ^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$
                if !Self::matches_pattern(value) {
                    return Err(AstraError::ValidationFailed {
                        context: ErrorContext::builder()
                            .error_code("VAL-023")
                            .component("astra-types")
                            .severity(Severity::Error)
                            .remediation_hint(format!(
                                "{} must match pattern: {}",
                                stringify!($name),
                                $pattern_desc
                            ))
                            .build()
                            .unwrap_or_default(),
                        field: Some(stringify!($name).into()),
                        message: format!(
                            "{} does not match required pattern ({})",
                            stringify!($name),
                            $pattern_desc
                        ),
                    });
                }

                Ok(())
            }

            /// Check if value matches the capability ID pattern.
            /// Pattern: starts with lowercase letter, followed by lowercase letters,
            /// digits, or underscores, with optional dot-separated segments.
            fn matches_pattern(value: &str) -> bool {
                let mut chars = value.chars().peekable();

                // Must start with a lowercase letter
                match chars.next() {
                    Some(c) if c.is_ascii_lowercase() => {}
                    _ => return false,
                }

                // Process rest of first segment and subsequent segments
                loop {
                    // Consume [a-z0-9_]*
                    while let Some(&c) = chars.peek() {
                        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' {
                            chars.next();
                        } else {
                            break;
                        }
                    }

                    // Check what's next
                    match chars.next() {
                        None => return true, // End of string, valid
                        Some('.') => {
                            // Start of new segment, must have [a-z] next
                            match chars.next() {
                                Some(c) if c.is_ascii_lowercase() => {}
                                _ => return false, // Empty segment or invalid start
                            }
                        }
                        Some(_) => return false, // Invalid character
                    }
                }
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({:?})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl FromStr for $name {
            type Err = AstraError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::new(s)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = AstraError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = AstraError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

// ============================================================================
// UUID-based ID types
// ============================================================================

define_uuid_id!(
    /// Unique identifier for a task.
    ///
    /// Auto-generated as UUID v4. Used in `TaskEnvelope.id`.
    TaskId
);

define_uuid_id!(
    /// Correlation ID for request tracing.
    ///
    /// Auto-generated as UUID v4. Propagates through the entire request lifecycle
    /// for observability and debugging.
    CorrelationId
);

define_uuid_id!(
    /// Unique identifier for an artifact.
    ///
    /// Auto-generated as UUID v4. Used to reference build outputs, generated
    /// files, and other artifacts.
    ArtifactId
);

define_uuid_id!(
    /// Unique identifier for a context item.
    ///
    /// Auto-generated as UUID v4. Used to reference context items like
    /// file contents, search results, and other contextual data.
    ContextId
);

// ============================================================================
// String-based ID types
// ============================================================================

define_string_id!(
    /// Identifier for a workspace or project.
    ///
    /// User-provided, validated on construction. Maximum 256 characters.
    /// Must not be empty or contain leading/trailing whitespace.
    WorkspaceId,
    max_len: WORKSPACE_ID_MAX_LEN
);

define_string_id!(
    /// Identifier for a policy.
    ///
    /// User-provided, validated on construction. Maximum 128 characters.
    /// Must not be empty or contain leading/trailing whitespace.
    PolicyId,
    max_len: POLICY_ID_MAX_LEN
);

define_string_id!(
    /// Identifier for an agent profile.
    ///
    /// User-provided, validated on construction. Maximum 64 characters.
    /// Must not be empty or contain leading/trailing whitespace.
    ProfileId,
    max_len: PROFILE_ID_MAX_LEN
);

define_string_id_with_pattern!(
    /// Identifier for a capability.
    ///
    /// User-provided, validated on construction. Maximum 128 characters.
    /// Must match pattern: lowercase letters, digits, underscores, with
    /// optional dot-separated segments (e.g., "repo", "repo.read", "static_analysis.lint").
    CapabilityId,
    max_len: CAPABILITY_ID_MAX_LEN,
    pattern: CAPABILITY_ID_PATTERN,
    pattern_desc: "lowercase alphanumeric with underscores, dot-separated segments"
);

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ========================================================================
    // UUID ID tests
    // ========================================================================

    #[test]
    fn task_id_new_generates_valid_uuid() {
        let id = TaskId::new();
        // UUID v4 has version nibble = 4
        assert_eq!(id.as_uuid().get_version_num(), 4);
    }

    #[test]
    fn task_id_from_uuid_roundtrip() {
        let uuid = Uuid::new_v4();
        let id = TaskId::from_uuid(uuid);
        assert_eq!(id.into_inner(), uuid);
    }

    #[test]
    fn task_id_from_str_valid() {
        let uuid_str = "550e8400-e29b-41d4-a716-446655440000";
        let Ok(id) = uuid_str.parse::<TaskId>() else {
            panic!("valid UUID should parse");
        };
        assert_eq!(id.to_string(), uuid_str);
    }

    #[test]
    fn task_id_from_str_invalid() {
        let result: Result<TaskId, _> = "not-a-uuid".parse();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-024");
    }

    #[test]
    fn task_id_display() {
        let Ok(uuid) = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000") else {
            panic!("known valid UUID should parse");
        };
        let id = TaskId::from_uuid(uuid);
        assert_eq!(id.to_string(), "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn task_id_debug() {
        let Ok(uuid) = Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000") else {
            panic!("known valid UUID should parse");
        };
        let id = TaskId::from_uuid(uuid);
        let debug = format!("{:?}", id);
        assert!(debug.contains("TaskId"));
        assert!(debug.contains("550e8400"));
    }

    #[test]
    fn task_id_serialization_roundtrip() {
        let id = TaskId::new();
        let Ok(json) = serde_json::to_string(&id) else {
            panic!("serialization should succeed");
        };
        let Ok(decoded) = serde_json::from_str::<TaskId>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(id, decoded);
    }

    #[test]
    fn uuid_ids_are_unique() {
        let id1 = TaskId::new();
        let id2 = TaskId::new();
        assert_ne!(id1, id2);
    }

    #[test]
    fn uuid_ids_hash_correctly() {
        let id1 = TaskId::new();
        let id2 = TaskId::new();
        let mut set = HashSet::new();
        set.insert(id1);
        set.insert(id2);
        set.insert(id1); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn correlation_id_works() {
        let id = CorrelationId::new();
        assert_eq!(id.as_uuid().get_version_num(), 4);
    }

    #[test]
    fn artifact_id_works() {
        let id = ArtifactId::new();
        assert_eq!(id.as_uuid().get_version_num(), 4);
    }

    #[test]
    fn context_id_works() {
        let id = ContextId::new();
        assert_eq!(id.as_uuid().get_version_num(), 4);
    }

    #[test]
    fn uuid_id_default() {
        let id = TaskId::default();
        assert_eq!(id.as_uuid().get_version_num(), 4);
    }

    #[test]
    fn uuid_id_as_ref() {
        let id = TaskId::new();
        let uuid_ref: &Uuid = id.as_ref();
        assert_eq!(uuid_ref, id.as_uuid());
    }

    // ========================================================================
    // String ID tests (WorkspaceId, PolicyId)
    // ========================================================================

    #[test]
    fn workspace_id_new_valid() {
        let Ok(id) = WorkspaceId::new("my-project") else {
            panic!("valid workspace ID should succeed");
        };
        assert_eq!(id.as_str(), "my-project");
    }

    #[test]
    fn workspace_id_new_empty_error() {
        let result = WorkspaceId::new("");
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-020");
    }

    #[test]
    fn workspace_id_new_too_long_error() {
        let long_string = "a".repeat(WORKSPACE_ID_MAX_LEN + 1);
        let result = WorkspaceId::new(long_string);
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-021");
    }

    #[test]
    fn workspace_id_new_leading_whitespace_error() {
        let result = WorkspaceId::new("  my-project");
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-022");
    }

    #[test]
    fn workspace_id_new_trailing_whitespace_error() {
        let result = WorkspaceId::new("my-project  ");
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-022");
    }

    #[test]
    fn workspace_id_from_str() {
        let Ok(id) = "my-project".parse::<WorkspaceId>() else {
            panic!("valid workspace ID should parse");
        };
        assert_eq!(id.as_str(), "my-project");
    }

    #[test]
    fn workspace_id_display() {
        let Ok(id) = WorkspaceId::new("my-project") else {
            panic!("valid workspace ID should succeed");
        };
        assert_eq!(id.to_string(), "my-project");
    }

    #[test]
    fn workspace_id_debug() {
        let Ok(id) = WorkspaceId::new("my-project") else {
            panic!("valid workspace ID should succeed");
        };
        let debug = format!("{:?}", id);
        assert!(debug.contains("WorkspaceId"));
        assert!(debug.contains("my-project"));
    }

    #[test]
    fn workspace_id_serialization_roundtrip() {
        let Ok(id) = WorkspaceId::new("my-project") else {
            panic!("valid workspace ID should succeed");
        };
        let Ok(json) = serde_json::to_string(&id) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"my-project\"");
        let Ok(decoded) = serde_json::from_str::<WorkspaceId>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(id, decoded);
    }

    #[test]
    fn workspace_id_into_inner() {
        let Ok(id) = WorkspaceId::new("my-project") else {
            panic!("valid workspace ID should succeed");
        };
        let inner = id.into_inner();
        assert_eq!(inner, "my-project");
    }

    #[test]
    fn workspace_id_try_from_string() {
        let result = WorkspaceId::try_from("my-project".to_string());
        assert!(result.is_ok());
    }

    #[test]
    fn workspace_id_try_from_str() {
        let result = WorkspaceId::try_from("my-project");
        assert!(result.is_ok());
    }

    #[test]
    fn workspace_id_hash_correctly() {
        let Ok(id1) = WorkspaceId::new("project-a") else {
            panic!("valid workspace ID should succeed");
        };
        let Ok(id2) = WorkspaceId::new("project-b") else {
            panic!("valid workspace ID should succeed");
        };
        let mut set = HashSet::new();
        set.insert(id1.clone());
        set.insert(id2);
        set.insert(id1); // duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn workspace_id_new_unchecked() {
        // Even invalid values work with unchecked
        let id = WorkspaceId::new_unchecked("  invalid  ");
        assert_eq!(id.as_str(), "  invalid  ");
    }

    #[test]
    fn workspace_id_max_len() {
        assert_eq!(WorkspaceId::max_len(), 256);
    }

    #[test]
    fn workspace_id_as_ref() {
        let Ok(id) = WorkspaceId::new("my-project") else {
            panic!("valid workspace ID should succeed");
        };
        let str_ref: &str = id.as_ref();
        assert_eq!(str_ref, "my-project");
    }

    #[test]
    fn policy_id_works() {
        let Ok(id) = PolicyId::new("no-network-access") else {
            panic!("valid policy ID should succeed");
        };
        assert_eq!(id.as_str(), "no-network-access");
    }

    // ========================================================================
    // ProfileId tests
    // ========================================================================

    #[test]
    fn profile_id_valid() {
        let Ok(id) = ProfileId::new("meta_orchestrator") else {
            panic!("valid profile ID should succeed");
        };
        assert_eq!(id.as_str(), "meta_orchestrator");
    }

    #[test]
    fn profile_id_empty_fails() {
        let result = ProfileId::new("");
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-020");
    }

    #[test]
    fn profile_id_too_long_fails() {
        let long_id = "a".repeat(65);
        let result = ProfileId::new(long_id);
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-021");
    }

    #[test]
    fn profile_id_whitespace_fails() {
        let result = ProfileId::new("  meta_orchestrator");
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-022");
    }

    #[test]
    fn profile_id_serde_roundtrip() {
        let Ok(id) = ProfileId::new("implementer") else {
            panic!("valid profile ID should succeed");
        };
        let Ok(json) = serde_json::to_string(&id) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"implementer\"");
        let Ok(decoded) = serde_json::from_str::<ProfileId>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(id, decoded);
    }

    #[test]
    fn profile_id_max_len() {
        assert_eq!(ProfileId::max_len(), 64);
    }

    // ========================================================================
    // CapabilityId tests (with pattern validation)
    // ========================================================================

    #[test]
    fn capability_id_single_segment() {
        let Ok(id) = CapabilityId::new("repo") else {
            panic!("valid capability ID should succeed");
        };
        assert_eq!(id.as_str(), "repo");
    }

    #[test]
    fn capability_id_multi_segment() {
        let Ok(id) = CapabilityId::new("repo.read") else {
            panic!("valid capability ID should succeed");
        };
        assert_eq!(id.as_str(), "repo.read");
    }

    #[test]
    fn capability_id_with_underscore() {
        let Ok(id) = CapabilityId::new("static_analysis.lint") else {
            panic!("valid capability ID should succeed");
        };
        assert_eq!(id.as_str(), "static_analysis.lint");
    }

    #[test]
    fn capability_id_with_numbers() {
        let Ok(id) = CapabilityId::new("v2.api.call") else {
            panic!("valid capability ID should succeed");
        };
        assert_eq!(id.as_str(), "v2.api.call");
    }

    #[test]
    fn capability_id_complex() {
        let Ok(id) = CapabilityId::new("repo.read_file.v2") else {
            panic!("valid capability ID should succeed");
        };
        assert_eq!(id.as_str(), "repo.read_file.v2");
    }

    #[test]
    fn capability_id_uppercase_error() {
        let result = CapabilityId::new("Repo.Read");
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-023");
    }

    #[test]
    fn capability_id_starts_with_number_error() {
        let result = CapabilityId::new("2repo");
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-023");
    }

    #[test]
    fn capability_id_empty_segment_error() {
        let result = CapabilityId::new("repo..read");
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-023");
    }

    #[test]
    fn capability_id_trailing_dot_error() {
        let result = CapabilityId::new("repo.read.");
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-023");
    }

    #[test]
    fn capability_id_leading_dot_error() {
        let result = CapabilityId::new(".repo.read");
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-023");
    }

    #[test]
    fn capability_id_hyphen_error() {
        let result = CapabilityId::new("repo-read");
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-023");
    }

    #[test]
    fn capability_id_space_error() {
        let result = CapabilityId::new("repo read");
        assert!(result.is_err());
    }

    #[test]
    fn capability_id_segment_starts_with_number_error() {
        let result = CapabilityId::new("repo.2read");
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { context, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(context.error_code, "VAL-023");
    }

    #[test]
    fn capability_id_max_len() {
        assert_eq!(CapabilityId::max_len(), 128);
    }

    #[test]
    fn capability_id_pattern() {
        assert_eq!(
            CapabilityId::pattern(),
            r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$"
        );
    }

    #[test]
    fn capability_id_serialization_roundtrip() {
        let Ok(id) = CapabilityId::new("repo.read") else {
            panic!("valid capability ID should succeed");
        };
        let Ok(json) = serde_json::to_string(&id) else {
            panic!("serialization should succeed");
        };
        assert_eq!(json, "\"repo.read\"");
        let Ok(decoded) = serde_json::from_str::<CapabilityId>(&json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(id, decoded);
    }
}
