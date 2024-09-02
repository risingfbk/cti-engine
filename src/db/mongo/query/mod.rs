//! # MongoDb queries
//!
//! This module contains the [`DbQuery`] trait and the implementations for the different models
//! in the database.

use mongodb::bson::{doc, Document};

pub mod cve;
pub mod group;
pub mod malware;
pub mod tactic;
pub mod techniques;

/// Trait for converting query parameters to a MongoDB document,
/// used to query the database
pub trait DbQuery {
    fn to_doc(&self) -> Document;
}

pub fn logic_filter(expressions: &str, key: &str) -> Vec<Document> {
    let mut filters = vec![];
    let mut or_conditions = vec![];
    for exp in expressions.split(',').filter(|t| !t.is_empty()).map(|t| t.to_lowercase()) {
        let mut and_conditions = Vec::new();
        for keyword in exp.split(&['+', ' ']).map(|t| t.to_lowercase()) {
            let keyword = keyword.trim();
            if let Some(excluded) = keyword.strip_prefix('!') {
                and_conditions.push(doc! {key: { "$nin": [excluded] }});
            } else {
                and_conditions.push(doc! {key: keyword });
            }
        }
        or_conditions.push(doc! { "$and": and_conditions });
    }
    if !or_conditions.is_empty() {
        filters.push(doc! { "$or": or_conditions });
    }

    filters
}
