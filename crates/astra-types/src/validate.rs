// SPDX-License-Identifier: MIT OR Apache-2.0
//! Validation trait for ASTRA_ types.
//!
//! Provides a common interface for types that can validate their own invariants.
//!
//! # Example
//!
//! ```
//! use astra_types::{Validate, AstraError};
//!
//! // Types implementing Validate can check their own invariants
//! struct PositiveNumber(i32);
//!
//! impl Validate for PositiveNumber {
//!     fn validate(&self) -> Result<(), AstraError> {
//!         if self.0 > 0 { Ok(()) }
//!         else { Err(AstraError::ValidationFailed {
//!             context: Default::default(),
//!             field: Some("value".into()),
//!             message: "must be positive".into(),
//!         })}
//!     }
//! }
//!
//! assert!(PositiveNumber(42).is_valid());
//! assert!(!PositiveNumber(-1).is_valid());
//! ```

use crate::AstraError;

/// Types that can validate their own invariants.
///
/// Implementors should check all internal consistency rules and return
/// a descriptive error if any are violated. This trait provides a uniform
/// way to validate complex data structures before use.
///
/// # Implementation Notes
///
/// - `validate()` should check ALL invariants, not just the first failure
/// - Return `AstraError::ValidationFailed` with specific field and message
/// - The `is_valid()` method is provided for convenience
///
/// # Example
///
/// ```
/// use astra_types::{AstraError, Validate, ErrorContext};
///
/// struct Config {
///     timeout_ms: u64,
///     max_retries: u32,
/// }
///
/// impl Validate for Config {
///     fn validate(&self) -> Result<(), AstraError> {
///         if self.timeout_ms == 0 {
///             return Err(AstraError::ValidationFailed {
///                 context: ErrorContext::validation(
///                     "VAL-100",
///                     "timeout must be greater than 0",
///                 ),
///                 field: Some("timeout_ms".into()),
///                 message: "timeout must be greater than 0".into(),
///             });
///         }
///         Ok(())
///     }
/// }
///
/// let config = Config { timeout_ms: 1000, max_retries: 3 };
/// assert!(config.is_valid());
/// ```
pub trait Validate {
    /// Validate the value, returning an error describing any violations.
    ///
    /// # Errors
    ///
    /// Returns `AstraError::ValidationFailed` if validation fails, with
    /// details about which field failed and why.
    #[allow(clippy::result_large_err)]
    fn validate(&self) -> Result<(), AstraError>;

    /// Check validity without detailed error information.
    ///
    /// This is a convenience method that discards the error details.
    /// Use `validate()` when you need to know why validation failed.
    fn is_valid(&self) -> bool {
        self.validate().is_ok()
    }
}

/// Blanket implementation for references.
impl<T: Validate + ?Sized> Validate for &T {
    fn validate(&self) -> Result<(), AstraError> {
        (*self).validate()
    }
}

/// Blanket implementation for Box.
impl<T: Validate + ?Sized> Validate for Box<T> {
    fn validate(&self) -> Result<(), AstraError> {
        (**self).validate()
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;
    use crate::ErrorContext;

    struct AlwaysValid;

    impl Validate for AlwaysValid {
        fn validate(&self) -> Result<(), AstraError> {
            Ok(())
        }
    }

    struct AlwaysInvalid;

    impl Validate for AlwaysInvalid {
        fn validate(&self) -> Result<(), AstraError> {
            Err(AstraError::ValidationFailed {
                context: ErrorContext::validation("VAL-TEST", "always fails"),
                field: Some("test_field".into()),
                message: "always fails".into(),
            })
        }
    }

    #[test]
    fn is_valid_returns_true_for_valid() {
        let v = AlwaysValid;
        assert!(v.is_valid());
    }

    #[test]
    fn is_valid_returns_false_for_invalid() {
        let v = AlwaysInvalid;
        assert!(!v.is_valid());
    }

    #[test]
    fn validate_returns_ok_for_valid() {
        let v = AlwaysValid;
        assert!(v.validate().is_ok());
    }

    #[test]
    fn validate_returns_err_for_invalid() {
        let v = AlwaysInvalid;
        let result = v.validate();
        assert!(result.is_err());
        let Err(AstraError::ValidationFailed { field, message, .. }) = result else {
            panic!("expected ValidationFailed");
        };
        assert_eq!(field, Some("test_field".into()));
        assert_eq!(message, "always fails");
    }

    #[test]
    fn reference_impl_works() {
        let v = AlwaysValid;
        let v_ref: &dyn Validate = &v;
        assert!(v_ref.is_valid());
    }

    #[test]
    fn box_impl_works() {
        let v: Box<dyn Validate> = Box::new(AlwaysValid);
        assert!(v.is_valid());
    }
}
