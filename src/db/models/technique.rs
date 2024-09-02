//! # Technique Model
//!
//! This module contains the model for the technique object in the database, and the
//! implementation for converting the `attck` `AttackPattern` object to the technique object.

use std::collections::{BTreeSet, HashSet};

use attck::{AttackPattern, Node};
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use stix::{ExternalReference, Object};

/// Model for a MITRE ATT&CK technique object
///
/// This model is used to represent a MITRE ATT&CK technique object in the database.
/// It is derived from the `AttackPattern` object in the `attck` crate.
/// It contains all the fields that are relevant to the technique object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Technique {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub mid: String,
    pub name: String,

    pub labels: HashSet<String>,
    pub tactics: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<ExternalReference>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_subtechnique: Option<bool>,

    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub data_sources: BTreeSet<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection: Option<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub effective_permissions: BTreeSet<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub permissions_required: BTreeSet<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub platforms: BTreeSet<String>,

    #[serde(default)]
    #[serde(skip_serializing_if = "BTreeSet::is_empty")]
    pub system_requirements: BTreeSet<String>,
}

impl<'a> From<&Node<'a, AttackPattern>> for Technique {
    fn from(value: &Node<'a, AttackPattern>) -> Self {
        let tactics: Vec<String> = value
            .base
            .kill_chain_phases
            .iter()
            .filter(|p| p.kill_chain_name == "mitre-attack")
            .map(|p| p.phase_name.clone())
            .collect();

        Self {
            id: Some(ObjectId::default()),
            mid: value.mitre_id().unwrap().to_string(),
            name: value.name().to_string(),
            labels: HashSet::default(),
            tactics,
            comment: None,
            description: value.base.description.clone(),
            external_references: value.external_references().to_vec(),
            is_subtechnique: value.mitre.is_subtechnique,
            data_sources: value.mitre.data_sources.clone(),
            detection: value.mitre.detection.clone(),
            effective_permissions: value.mitre.effective_permissions.clone(),
            permissions_required: value.mitre.permissions_required.clone(),
            platforms: value.mitre.platforms.iter().map(
                |p| p.to_lowercase().to_string(),
            ).collect(),
            system_requirements: value.mitre.system_requirements.clone(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GroupTech {
    #[serde(rename = "techniqueID")]
    pub mid: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TechniqueMitreVec {
    pub techniques: Vec<GroupTech>,
}

impl TechniqueMitreVec {
    pub fn from_file(group_id: &str) -> Result<Self, std::io::Error> {
        // TODO: change `unwrap_or` after testing
        let dir = std::env::var("GROUP_TECHNIQUES_DIR").unwrap_or("data/group-techniques".to_string());

        let uri = format!("{}/{}.json", dir, group_id);
        let data = std::fs::read_to_string(uri)?;

        let techniques_vec: Self = serde_json::from_str(&data)?;

        Ok(techniques_vec)
    }
}
