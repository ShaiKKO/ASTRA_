// SPDX-License-Identifier: MIT OR Apache-2.0
//! ASTRA_ Types — Shared data contracts.
//!
//! Canonical data structures used throughout ASTRA_: TaskEnvelope, Outcome,
//! AgentProfile, CapabilityContract, PolicyDecision, Artifact, ContextItem,
//! RunReport, ModelInvocation, and AstraError.
//!
//! # Design
//!
//! - All types derive Serialize/Deserialize
//! - Type-safe IDs prevent mixing different identifier types
//! - Validation-ready schemas via the `Validate` trait
//! - Correlation IDs propagate end-to-end for observability
//!
//! # Quick Start
//!
//! ```
//! use astra_types::prelude::*;
//!
//! // Build a task - TaskId is auto-generated
//! let task = TaskEnvelope::builder()
//!     .task_type("implement")
//!     .goal("Add input validation")
//!     .workspace(WorkspaceId::new("my-project").unwrap())
//!     .build()
//!     .unwrap();
//!
//! assert!(task.is_valid());
//! ```

mod error;
mod id;
mod sensitive;
mod task;
mod time;
mod validate;

/// Common imports for working with ASTRA_ types.
pub mod prelude;

// Re-export all public types at crate root for flexibility
pub use error::{
    AstraError, BoxedError, BudgetType, ErrorContext, ErrorContextBuilder, Result, Severity,
};
pub use id::{
    ArtifactId, CapabilityId, ContextId, CorrelationId, PolicyId, TaskId, WorkspaceId,
    CAPABILITY_ID_MAX_LEN, POLICY_ID_MAX_LEN, WORKSPACE_ID_MAX_LEN,
};
pub use sensitive::Sensitive;
pub use task::{Budget, Constraints, TaskEnvelope, TaskEnvelopeBuilder};
pub use time::Timestamp;
pub use validate::Validate;
