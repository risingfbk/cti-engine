//! # Custom Data
//!
//! This module contains the definition of the custom data structure.
//! This data structure will be used to parse the custom configuration files,
//! and will be converted into [`InputData`] structure.

use crate::error::Result;
use serde::{Deserialize, Serialize};

use super::ToInputData;

#[derive(Debug, Serialize, Deserialize)]
pub struct CustomData {
    countries: Vec<String>,
    sectors: Vec<String>,
    operating_systems: Vec<String>,
    software: Vec<String>,
}

impl CustomData {
    pub fn new(
        countries: Vec<String>,
        sectors: Vec<String>,
        operating_systems: Vec<String>,
        software: Vec<String>,
    ) -> Self {
        Self {
            countries,
            sectors,
            operating_systems,
            software,
        }
    }

    pub fn from_yaml(yaml: &str) -> Result<Self> {
        serde_yaml::from_str(yaml).map_err(|e| e.into())
    }
}

/// Implementing the `ToInputData` trait for the `CustomData` structure.
/// In this case, the fields are the same as the `InputData` structure, since
/// the custom data structure is used mailny for testing purposes.
impl ToInputData for CustomData {
    fn to_input_data(&self) -> super::InputData {
        super::InputData {
            countries: self.countries.clone(),
            sectors: self.sectors.clone(),
            operating_systems: self.operating_systems.clone(),
            software: self.software.clone(),
        }
    }
}
