//! # Tactic Model
//!
//! This module contains the model for a MITRE ATT&CK tactic object and the implementation for
//! converting the `attck` `Tactic` object to the tactic object.

use attck::Node;
use mongodb::bson::oid::ObjectId;
use serde::{Deserialize, Serialize};
use stix::{ExternalReference, Object};

/// Model for a MITRE ATT&CK tactic object
///
/// This model is used to represent a MITRE ATT&CK tactic object in the database.
/// It is derived from the `Tactic` object in the `attck` crate.
#[derive(Serialize, Deserialize, stix::TypedObject)]
#[typed_object(name = "x-mitre-tactic")]
pub struct Tactic {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub mid: String,
    pub name: String,

    #[serde(rename = "x_mitre_shortname")]
    pub shortname: String,

    pub technique_refs: Vec<String>,

    #[serde(default)]
    pub description: Option<String>,

    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub external_references: Vec<ExternalReference>,
}

impl<'a> From<&Node<'a, attck::Tactic>> for Tactic {
    fn from(value: &Node<'a, attck::Tactic>) -> Self {
        Self {
            id: Some(ObjectId::default()),
            mid: value.mitre_id().expect("No mitre id found!").to_string(),
            name: value.name.clone(),
            shortname: value.shortname.clone(),
            technique_refs: vec![],
            description: value.description.clone(),
            external_references: value.external_references().to_vec(),
        }
    }
}
