//! # Database module
//! Here we define the database methods that are used by the server.
//!
//! In order to add a new database, the [`DbMethods`] trait must be implemented.
//! It is advised to create a new module for the new database type, if a new
//! database is added.
//!
//! For example, for a PostgreSQL database:
//! ```rust
//! pub struct PostgreDb {
//!    // fields
//!    // ...
//! }
//!
//! #[async_trait]
//! impl DbMethods for PostgreDb {
//!   // methods
//!   // ...
//! }
//! ```
//!
//! The #\[async_trait\] macro is used to define async methods in traits.

use self::models::{group::Group, malware::Malware, tactic::Tactic, technique::Technique};
use crate::{
    error::Result,
    parser::InputData,
    routes::{
        cves::CveQuery, groups::GroupQuery, malware::MalwareQuery, tactics::TacticQuery,
        techniques::TechniqueQuery,
    },
};
use async_trait::async_trait;
use cveparser::objects::cve_item::CveItem;

pub mod models;
pub mod mongo;

/// Trait for database methods that are used by the server
///
/// In order to add a new database, this trait must be implemented
/// for the new database type.
///
#[async_trait]
pub trait DbMethods: Send + Sync + Sized + 'static {
    /// Initialize the database from the STIX data
    async fn init_db_from_data(&mut self) -> Result<()>;

    /// Populate the group techniques from the Mitre ATT&CK data files
    /// located in the data directory
    async fn populate_groups_fields(&self) -> Result<()>;

    /// Populate the tactic techniques from the Mitre ATT&CK data
    async fn populate_tactic_fields(&mut self) -> Result<()>;

    /// Populate the cves collection from NVD data
    async fn init_cves(&mut self) -> Result<()>;

    /// Generate labels for the various data types in the database
    async fn generate_labels(&mut self) -> Result<()>;

    /// Get cves from the database using the query parameters
    async fn get_cves(&self, query: CveQuery) -> Result<Vec<CveItem>>;

    /// Get a cve from the database using the CVE ID
    async fn get_cve(&self, id: &str) -> Result<CveItem>;

    /// Get techniques from the database using the query parameters
    async fn get_techniques(&self, query: TechniqueQuery) -> Result<Vec<Technique>>;

    /// Get a technique from the database using the Mitre ID
    async fn get_technique(&self, id: &str) -> Result<Technique>;

    /// Get groups from the database using the query parameters
    async fn get_groups(&self, query: GroupQuery) -> Result<Vec<Group>>;

    /// Get a group from the database using the Mitre ID
    async fn get_group(&self, id: &str) -> Result<Group>;

    /// Get tactics from the database
    async fn get_tactics(&self, query: TacticQuery) -> Result<Vec<Tactic>>;

    /// Get malware from the database
    async fn get_malware(&self, query: MalwareQuery) -> Result<Vec<Malware>>;

    /// Save an infrastructure file (input data) to the database
    async fn save_input_data(&self, data: InputData) -> Result<String>;

    /// Get an infrastructure file (input data) saved in the database
    async fn get_input_data(&self, id: &str) -> Result<InputData>;

    /// Delete an infrastructure file (input data) from the database
    async fn delete_input_data(&self, id: &str) -> Result<()>;

    /// Delete all data from the database (used for testing)
    async fn delete_all(&self) -> Result<()>;
}
