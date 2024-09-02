use super::{logic_filter, DbQuery};
use crate::routes::techniques::TechniqueQuery;
use mongodb::bson::doc;

/// DbQuery implementation for the Technique model
///
/// Techniques can be queried by:
///  - mitre id (mid)
///  - description (matches if the description contains the passed strings)
///  - platforms (platforms): platforms must be separated by commas and any platform must be present in the technique
///  - labels: labels query is a comma separated list of expressions. Each expression is a list of labels separated by '+' or ' '.
///          Each expression is a list of labels that must be present in the technique. If a label is prefixed with '!', it must not be present in the technique.
///          If multiple expressions are present, any of them can match.
///          Example: `labels=windows+!linux,macos` will match techniques that have the label 'windows' and do not have the label 'linux' or have the label 'macos'
/// - tactics: tactics query is a comma separated list of expressions. Each expression is a list of tactics separated by '+' or ' '.
///         Each expression is a list of tactics that must be present in the technique. If a tactic is prefixed with '!', it must not be present in the technique.
///         If multiple expressions are present, any of them can match.
///         Example: `tactics=impact+!defense-evasion` will match techniques that have the tactic 'impact' and do not have the tactic 'defense-evasion'
impl DbQuery for TechniqueQuery {
    fn to_doc(&self) -> mongodb::bson::Document {
        let mut doc = doc! {};
        if let Some(value) = &self.desc {
            let regex = doc! {
            "$regex": value.to_lowercase(),
            "$options": "i"
            };
            doc.insert("description", regex);
        }
        if let Some(id) = &self.mid {
            let regex = doc! {
            "$regex": id,
            "$options": "i"
            };
            doc.insert("mid", regex);
        }
        if let Some(plats) = &self.platforms {
            let platforms: Vec<String> = plats.split(',').map(|p| p.to_string()).collect();
            doc.insert("platforms", doc! {"$in": platforms});
        }
        if let Some(labels) = &self.labels {
            let filters = logic_filter(labels, "labels");
            doc.insert("$and", filters);
        }
        if let Some(tactics) = &self.tactics {
            let filters = logic_filter(tactics, "tactics");
            doc.insert("$and", filters);
        }
        doc
    }
}
