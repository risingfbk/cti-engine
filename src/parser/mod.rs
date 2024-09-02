//! This is the module that will contain the implementation of the service
//! that parses some infrastructure configuration files and returns the
//! parsed data.
//!
//! TODO: Implement the service that will parse the configuration files
//! - Implement the service that will return the parsed data
//!
//! NOTE: Parsing steps
//! - How to structure the input data?
//!    make it pluggable, so that the service can parse different types of
//!    configuration files.
//!    For example, the service should be able to parse a configuration file
//!    that is in YAML format, and another configuration file from Terraform or
//!    other IaC tools.
//! - How to structure the output data?:
//!    different data structures containing groups, techniques, tactics, etc.
//!    that the infrasturcture could be vulnerable to.
//!     
//!
//!

pub mod analyze;
pub mod custom;
pub mod terraform;

use cveparser::objects::cve_item::CveItem;
use serde::{Deserialize, Serialize};
use strum::EnumIter;
use std::collections::HashMap;

use crate::db::models::{group::Group, technique::Technique};

/// Data type enum
///
/// This enum contains the different types of configuration files that
/// the service can parse.
///
/// If a new configuration file type is added, it should be added to this
/// enum.
#[derive(Debug, Serialize, EnumIter)]
pub enum DataType {
    Custom,
    Terraform,
    SaltStack,
}

/// Input data structure
///
/// This structure is used to have a common structure for the input data
/// that will be used to generate the output data.
///
/// To parse specific configuration files, a custom module should be created
/// that will contain its own data structure that will be converted into
/// this structure.
///
/// From this structure, the output data will be generated.
#[derive(Debug, Serialize, Deserialize)]
pub struct InputData {
    countries: Vec<String>,
    sectors: Vec<String>,
    operating_systems: Vec<String>,
    software: Vec<String>,
    // TODO: Add more fields ...
}

/// Trait for converting the custom data structure into the input data structure
pub trait ToInputData: Send + Sync {
    fn to_input_data(&self) -> InputData;
}

/// Output data structure
///
/// This structure is used to have a common structure for the output data
/// that will be generated from the input data.
///
/// The output data will contain the groups, techniques, tactics, etc.
/// that the infrastructure could be vulnerable to.
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct OutputData {
    groups: GroupResult,
    techniques: Vec<TechniqueCount>,
    tactics: HashMap<String, Vec<Technique>>,
    cves: HashMap<String, Vec<CveItem>>,
    procedures: Vec<String>,
    mitigations: Vec<String>,
    // Additional fields ...
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct GroupResult {
    countries: HashMap<String, Vec<Group>>,
    sectors: HashMap<String, Vec<Group>>,
    keywords: HashMap<String, Vec<Group>>,
}

impl GroupResult {
    pub fn groups(&self) -> Vec<Group> {
        let mut groups = HashMap::<String, Group>::new();

        self.countries.iter().chain(self.sectors.iter()).chain(self.keywords.iter()).for_each(|(_key, value)| {
            value.iter().for_each(|group| {
                groups.insert(group.mid.clone(), group.clone());
            });
        });

        groups.values().cloned().collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct TechniqueCount {
    pub technique: Technique,
    pub count: u32,
}

impl TechniqueCount {
    fn new(technique: Technique, count: u32) -> Self {
        Self { technique, count }
    }
}
