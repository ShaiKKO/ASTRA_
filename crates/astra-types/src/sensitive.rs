// SPDX-License-Identifier: MIT OR Apache-2.0
//! Sensitive value wrapper for log redaction.
//!
//! Provides a wrapper type that prevents sensitive values from appearing
//! in debug output or logs. The actual value is preserved for use but
//! hidden from casual inspection.
//!
//! # Example
//!
//! ```
//! use astra_types::Sensitive;
//!
//! let api_key = Sensitive::new("sk-secret-key-12345");
//!
//! // Debug output is redacted
//! assert_eq!(format!("{:?}", api_key), "[REDACTED]");
//! assert_eq!(format!("{}", api_key), "[REDACTED]");
//!
//! // Access the actual value explicitly
//! assert_eq!(api_key.expose(), &"sk-secret-key-12345");
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

/// Wrapper for values that should not appear in logs or debug output.
///
/// The `Debug` and `Display` implementations show `[REDACTED]` instead
/// of the actual value. Use `.expose()` to access the inner value when
/// you actually need it (e.g., for API calls).
///
/// # Security Notes
///
/// - Always use `expose()` consciously and avoid logging the result
/// - Serialization preserves the actual value (for storage/transmission)
/// - Consider memory security for highly sensitive values (not addressed here)
///
/// # Example
///
/// ```
/// use astra_types::Sensitive;
///
/// struct Config {
///     api_key: Sensitive<String>,
///     debug_mode: bool,
/// }
///
/// let config = Config {
///     api_key: Sensitive::new("secret".to_string()),
///     debug_mode: true,
/// };
///
/// // Safe to log the entire struct - api_key will show as [REDACTED]
/// println!("{:?}", config.api_key);
///
/// // When you need the actual value:
/// let key = config.api_key.expose();
/// ```
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sensitive<T>(T);

impl<T> Sensitive<T> {
    /// Wrap a value as sensitive.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Expose the inner value.
    ///
    /// Use this when you actually need the value, such as when
    /// making an API call. Avoid logging the exposed value.
    pub fn expose(&self) -> &T {
        &self.0
    }

    /// Expose the inner value mutably.
    ///
    /// Use this when you need to modify the sensitive value in place.
    pub fn expose_mut(&mut self) -> &mut T {
        &mut self.0
    }

    /// Consume the wrapper and return the inner value.
    pub fn into_inner(self) -> T {
        self.0
    }

    /// Map the inner value to a new type.
    pub fn map<U, F>(self, f: F) -> Sensitive<U>
    where
        F: FnOnce(T) -> U,
    {
        Sensitive(f(self.0))
    }
}

impl<T> fmt::Debug for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<T> fmt::Display for Sensitive<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[REDACTED]")
    }
}

impl<T: Default> Default for Sensitive<T> {
    fn default() -> Self {
        Self(T::default())
    }
}

impl<T> From<T> for Sensitive<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T> AsRef<T> for Sensitive<T> {
    fn as_ref(&self) -> &T {
        &self.0
    }
}

impl<T> AsMut<T> for Sensitive<T> {
    fn as_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn new_and_expose_roundtrip() {
        let secret = "my-secret-value";
        let sensitive = Sensitive::new(secret);
        assert_eq!(sensitive.expose(), &secret);
    }

    #[test]
    fn into_inner_consumes() {
        let secret = String::from("my-secret");
        let sensitive = Sensitive::new(secret.clone());
        let recovered = sensitive.into_inner();
        assert_eq!(recovered, secret);
    }

    #[test]
    fn debug_shows_redacted() {
        let sensitive = Sensitive::new("secret");
        let debug = format!("{:?}", sensitive);
        assert_eq!(debug, "[REDACTED]");
        assert!(!debug.contains("secret"));
    }

    #[test]
    fn display_shows_redacted() {
        let sensitive = Sensitive::new("secret");
        let display = format!("{}", sensitive);
        assert_eq!(display, "[REDACTED]");
        assert!(!display.contains("secret"));
    }

    #[test]
    fn clone_works() {
        let sensitive = Sensitive::new(String::from("secret"));
        let cloned = sensitive.clone();
        assert_eq!(cloned.expose(), sensitive.expose());
    }

    #[test]
    fn partial_eq_compares_inner() {
        let a = Sensitive::new("secret");
        let b = Sensitive::new("secret");
        let c = Sensitive::new("different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn serialization_preserves_value() {
        let sensitive = Sensitive::new("secret-value");
        let Ok(json) = serde_json::to_string(&sensitive) else {
            panic!("serialization should succeed");
        };
        // The JSON should contain the actual value (for storage)
        assert_eq!(json, "\"secret-value\"");
    }

    #[test]
    fn deserialization_recovers_value() {
        let json = "\"recovered-secret\"";
        let Ok(sensitive) = serde_json::from_str::<Sensitive<String>>(json) else {
            panic!("deserialization should succeed");
        };
        assert_eq!(sensitive.expose(), "recovered-secret");
    }

    #[test]
    fn default_when_inner_has_default() {
        let sensitive: Sensitive<String> = Sensitive::default();
        assert_eq!(sensitive.expose(), "");
    }

    #[test]
    fn from_impl() {
        let sensitive: Sensitive<String> = "secret".to_string().into();
        assert_eq!(sensitive.expose(), "secret");
    }

    #[test]
    fn as_ref_works() {
        let sensitive = Sensitive::new("secret");
        let inner: &str = sensitive.as_ref();
        assert_eq!(inner, "secret");
    }

    #[test]
    fn expose_mut_works() {
        let mut sensitive = Sensitive::new(String::from("old"));
        sensitive.expose_mut().push_str("-new");
        assert_eq!(sensitive.expose(), "old-new");
    }

    #[test]
    fn map_transforms_value() {
        let sensitive = Sensitive::new(42);
        let mapped = sensitive.map(|n| n * 2);
        assert_eq!(*mapped.expose(), 84);
    }

    #[test]
    fn hash_works() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(Sensitive::new("a"));
        set.insert(Sensitive::new("b"));
        set.insert(Sensitive::new("a")); // duplicate
        assert_eq!(set.len(), 2);
    }
}
