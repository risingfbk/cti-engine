use mongodb::bson::doc;

use crate::routes::tactics::TacticQuery;

use super::{logic_filter, DbQuery};

/// Query parameters for the tactics endpoint
///
/// Tactics can be queried by:
///     - mitre id
///     - techniques (tech): techniques are a comma separated list of expressions. Each expression is a list of techniques separated by '+' or ' '.
///     Each expression is a list of techniques that must be present in the tactic. If a technique is prefixed with '!', it must not be present in the tactic.
///     If multiple expressions are present, any of them can match.
///     Example: `techs=T1003+!T1004,T1005` will match tactics that have the technique 'T1003' AND NOT have the technique 'T1004', OR have the technique 'T1005'
impl DbQuery for TacticQuery {
    fn to_doc(&self) -> mongodb::bson::Document {
        let mut doc = doc! {};
        if let Some(value) = &self.mid {
            let regex = doc! {
            "$regex": value,
            "$options": "i"
            };
            doc.insert("mid", regex);
        }
        if let Some(techs) = &self.techs {
            let filters = logic_filter(techs, "technique_refs");
            doc.insert("$and", filters);
        }
        doc
    }
}
