#![deny(unsafe_code)]
#![deny(missing_docs)]
#![deny(clippy::unwrap_used)]
#![deny(clippy::panic)]

//! Smart Cryptographic Defaults
//!
//! This module provides intelligent, use-case-aware cryptographic parameter selection.
//! It automatically chooses optimal algorithms, key sizes, and configurations based on:
//!
//! - Data characteristics (size, entropy, structure)
//! - Use case requirements (messaging, database, ML, healthcare, etc.)
//! - Performance preferences (speed, throughput, latency, memory)
//! - Security requirements (standard, high, maximum)
//!
//! # Module Organization
//!
//! - [`types`] - Basic enums for algorithm variants (MlKemVariant, HashFunction, FheScheme)
//! - [`params`] - Algorithm parameter configuration structs
//! - [`templates`] - Pre-configured optimized templates for different use cases
//! - [`registry`] - Template registry for template management
//! - [`detector`] - Use case detection from data and context
//! - [`defaults`] - Main smart defaults API
//!
//! # Usage
//!
//! ```rust,ignore
//! use latticearc::unified_api::smart_defaults::{SmartDefaults, UseCase};
//!
//! let ai = SmartDefaults::new()?;
//!
//! // Auto-detect from data
//! let template = ai.recommend_template(&my_data)?;
//!
//! // Get specific use case template
//! let template = ai.get_template(UseCase::Healthcare);
//!
//! // Detect from context string
//! let template = ai.get_template_for_context("patient_records")?;
//! ```

pub mod defaults;
pub mod detector;
pub mod params;
pub mod registry;
pub mod templates;
pub mod types;

// Re-export all public items
pub use defaults::SmartDefaults;
pub use detector::UseCaseDetector;
pub use params::{AeadParams, AlgorithmParams, FheParams, HashParams, KemParams};
pub use registry::TemplateRegistry;
pub use templates::OptimizedTemplate;
pub use types::{FheScheme, HashFunction, MlKemVariant};
