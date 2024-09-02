use super::{logic_filter, DbQuery};
use crate::routes::groups::GroupQuery;
use mongodb::bson::doc;

/// DbQuery implementation for the Group model
///
/// Groups can be queried by:
///  - mitre id (mid)
///  - description (matches if the description contains the passed strings)
///  - techniques (tech): techniques must be separated by commas and all techniques must be present in the group  
///                     for it to be matched
///  - labels: labels query is a comma separated list of expressions. Each expression is a list of labels separated by '+' or ' '.
///        Each expression is a list of labels that must be present in the group. If a label is prefixed with '!', it must not be present in the group.
///        If multiple expressions are present, any of them can match.
///        Example: `labels=windows+!linux,aws` will match groups that have the label 'windows' AND NOT the label 'linux' OR have the label 'aws'
impl DbQuery for GroupQuery {
    fn to_doc(&self) -> mongodb::bson::Document {
        let mut doc = doc! {};
        if let Some(value) = &self.desc {
            let regex = doc! {
                "$regex": value,
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
        if let Some(techs) = &self.techs {
            let filters = logic_filter(techs, "techniques");
            doc.insert("$and", filters);
        }
        if let Some(labels) = &self.labels {
            let filters = logic_filter(labels, "labels");
            doc.insert("$and", filters);
        }
        if let Some(sectors) = &self.sectors {
            let filters = logic_filter(sectors, "sectors");
            doc.insert("$and", filters);
        }
        if let Some(countries) = &self.countries {
            let filters = logic_filter(countries, "countries");
            doc.insert("$and", filters);
        }
        doc
    }
}
