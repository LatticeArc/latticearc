//! Regression Tests
//!
//! This module contains tests that prevent reintroduction of fixed bugs.
//! Each test file corresponds to a specific issue/bug that was fixed.
//!
//! ## File Naming Convention
//!
//! `issue_NNN_short_description.rs`
//!
//! Where NNN is the GitHub issue number (or internal tracking ID).
//!
//! ## Adding a New Regression Test
//!
//! 1. Create a new file: `issue_NNN_description.rs`
//! 2. Add module declaration here
//! 3. Include doc comment with:
//!    - Link to original issue
//!    - Description of the bug
//!    - Description of the fix
//! 4. Test should fail without the fix, pass with it

pub mod issue_001_kem_empty_ciphertext;
pub mod issue_002_signature_zero_message;

#[cfg(test)]
mod tests {
    /// Verify all regression test modules are loadable
    #[test]
    fn regression_modules_load() {
        // This test ensures all regression test modules compile correctly
        // Individual tests are in their respective modules
    }
}
