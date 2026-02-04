// SPDX-License-Identifier: MIT OR Apache-2.0
//! Common imports for working with ASTRA_ types.
//!
//! This module re-exports the most commonly used types for convenience.
//!
//! # Example
//!
//! ```
//! use astra_types::prelude::*;
//!
//! // All common types are now available
//! let task = TaskEnvelope::builder()
//!     .task_type("implement")
//!     .goal("Add validation")
//!     .workspace(WorkspaceId::new("my-project").unwrap())
//!     .build()
//!     .unwrap();
//!
//! assert!(task.is_valid());
//! ```

// Error handling
pub use crate::error::{
    AstraError, BudgetType, ErrorContext, ErrorContextBuilder, Result, Severity,
};

// Task types
pub use crate::task::{Budget, Constraints, TaskEnvelope, TaskEnvelopeBuilder};

// ID types
pub use crate::id::{
    ArtifactId, CapabilityId, ContextId, CorrelationId, PolicyId, TaskId, WorkspaceId,
};

// Time
pub use crate::time::Timestamp;

// Traits
pub use crate::validate::Validate;

// Wrappers
pub use crate::sensitive::Sensitive;

// Model types
pub use crate::model::{
    InferenceParams, Message, ModelInvocation, ModelResult, Role, StopReason, Tool, ToolCall, Usage,
};

// Outcome types
pub use crate::outcome::{Outcome, OutcomeError, OutcomeMetrics, OutcomeStatus};
