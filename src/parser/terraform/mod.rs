// #![cfg(feature = "terraform")]
//! # Terraform Data
//!
//! This module contains the definition of the Terraform data structure.

use serde::{Deserialize, Serialize};

use super::ToInputData;
use terraform_parser::state_representation::StateRepresentation;

#[derive(Debug, Serialize, Deserialize)]
pub struct TerraformData {
    pub state: StateRepresentation,
}

impl ToInputData for TerraformData {
    fn to_input_data(&self) -> super::InputData { 
        let mut countries = vec![];
        let mut sectors = vec![];

        if let Some(outputs) = &self.state.values.outputs {
            for (name, output) in outputs {
                if name == "countries" {
                    countries = output.value.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
                } else if name == "sectors" {
                    sectors = output.value.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
                }
            }
        }

        let mut software = vec![];
        for resource in &self.state.values.root_module.resources {
            software.push(resource.name.clone());
        }

        super::InputData {
            countries,
            sectors,
            operating_systems: vec![],
            software,
        }
    }
}

