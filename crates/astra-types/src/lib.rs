// SPDX-License-Identifier: MIT OR Apache-2.0
//! ASTRA_ Types — Shared data contracts.
//!
//! Canonical data structures used throughout ASTRA_: TaskEnvelope, Outcome,
//! AgentProfile, CapabilityContract, PolicyDecision, Artifact, ContextItem,
//! RunReport, ModelInvocation, and AstraError.
//!
//! # Design
//! - All types derive Serialize/Deserialize.
//! - Validation-ready schemas.
//! - Correlation IDs propagate end-to-end.

mod error;
mod task;

pub use error::{AstraError, BudgetType, ErrorContext, ErrorContextBuilder, Result, Severity};
pub use task::{Budget, Constraints, TaskEnvelope, TaskEnvelopeBuilder};
