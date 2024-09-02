//! # Group Model
//!
//! This module contains the model for a MITRE ATT&CK group object and the implementation for
//! converting the `attck` `IntrusionSet` object to the group object.

use std::{
    collections::{BTreeSet, HashSet},
    fmt::Debug,
};

use attck::Node;
use chrono::{DateTime, Utc};
use mongodb::{
    bson::{doc, oid::ObjectId, Bson},
    Collection,
};
use serde::{Deserialize, Serialize};
use stix::{
    vocab::{AttackMotivation, AttackResourceLevel},
    ExternalReference, IntrusionSet, Object,
};

use super::technique::{Technique, TechniqueMitreVec};

/// Model for a MITRE ATT&CK group object
///
/// This model is used to represent a MITRE ATT&CK group object in the database.
/// It is derived from the `IntrusionSet` object in the `attck` crate.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Group {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,

    pub mid: String,
    pub name: String,
    pub description: Option<String>,

    pub labels: HashSet<String>,
    pub techniques: Vec<String>,

    #[serde(default)]
    pub sectors: Vec<String>,

    #[serde(default)]
    pub countries: Vec<String>,

    #[serde(default)]
    pub external_references: Vec<ExternalReference>,

    #[serde(default)]
    pub aliases: BTreeSet<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<DateTime<Utc>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,

    pub goals: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_level: Option<AttackResourceLevel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_motivation: Option<AttackMotivation>,

    #[serde(default)]
    pub secondary_motivations: BTreeSet<AttackMotivation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechRef {
    #[serde(rename = "_id", skip_serializing_if = "Option::is_none")]
    pub id: Option<ObjectId>,
    pub mid: String,
}

impl From<TechRef> for Bson {
    fn from(val: TechRef) -> Self {
        Bson::Document(doc! {
            "_id": val.id,
            "mid": val.mid
        })
    }
}

impl Group {
    pub async fn get_techniques(
        mid: &str,
        coll: &Collection<Technique>,
    ) -> crate::error::Result<Vec<String>> {
        let group_techniques = TechniqueMitreVec::from_file(mid)?;
        let mut techniques = Vec::<String>::new();

        for t in group_techniques.techniques {
            let filter = doc! {
                "mid": t.mid
            };
            let tech = coll.find_one(filter, None).await?;

            if let Some(tech) = tech {
                techniques.push(tech.mid);
            }
        }

        Ok(techniques)
    }
}

impl<'a> From<&Node<'a, IntrusionSet>> for Group {
    fn from(intr_set: &Node<'a, IntrusionSet>) -> Self {
        let mitre_id = intr_set
            .external_references()
            .iter()
            .filter(|xr| xr.source_name == "mitre-attack")
            .map(|xr| xr.external_id.clone())
            .next()
            .unwrap();
        Self {
            id: Some(ObjectId::default()),
            mid: mitre_id.expect("No mitre id found!").to_string(),
            name: intr_set.name().to_string(),
            description: intr_set.description().map(|s| s.to_owned()),
            labels: HashSet::default(),
            techniques: vec![],
            sectors: vec![],
            countries: vec![],
            external_references: intr_set.external_references().to_vec(),
            aliases: intr_set.aliases().clone(),
            first_seen: intr_set.first_seen,
            last_seen: intr_set.last_seen,
            goals: intr_set.goals.clone(),
            resource_level: intr_set.resource_level.clone(),
            primary_motivation: intr_set.primary_motivation.clone(),
            secondary_motivations: intr_set.secondary_motivations.clone(),
        }
    }
}
