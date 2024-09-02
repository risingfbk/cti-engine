//! # Label Generators
//!
//! This module contains the label generators for the various data types in the database.
//!
//! The [`LabelGenerator`] trait is used to define the method that generates labels for the
//! different data types in the database.
//!
//! The [`nlp`] module contains the label generator that uses natural language processing
//! to generate labels for the techniques.
//!
//! In order to add a new label generator, creating a new module for the new label generator
//! is advised.
//!
//! For example, for a new label generator:
//! ```rust
//! pub struct NewLabelGenerator {
//!    // fields
//!    // ...
//! }
//!
//! #[async_trait]
//! impl LabelGenerator for NewLabelGenerator {
//!  // methods
//!  // ...
//!  }
//!
//! ```

use async_trait::async_trait;
use mongodb::Collection;

use crate::{
    db::models::{group::Group, technique::Technique},
    error::Result,
};

pub mod nlp;

/// Trait for generating labels for techniques
///
/// In order to add a new label generator, this trait must be implemented
/// for the new label generator type.
/// The method generate_\<type\>_labels should be called from the database
/// implementation to generate labels for various models.
#[async_trait]
pub trait LabelGenerator {
    async fn generate_technique_labels(&self, techniques: &mut Collection<Technique>)
        -> Result<()>;
    async fn generate_group_labels(&self, groups: &mut Collection<Group>) -> Result<()>;
}
