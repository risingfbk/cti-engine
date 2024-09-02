use super::DbQuery;
use crate::routes::cves::CveQuery;
use mongodb::bson::doc;

impl DbQuery for CveQuery {
    fn to_doc(&self) -> mongodb::bson::Document {
        let mut doc = doc! {};
        if let Some(id) = &self.id {
            let regex = doc! {
                "$regex": id,
                "$options": "i"
            };
            doc.insert("id", regex);
        }
        if let Some(kws) = &self.keywords {
            let regex = doc! {
                "$regex": kws,
                "$options": "i"
            };
            doc.insert("cve.description.description_data.value", regex);
        }
        if let Some(score) = &self.base_score {
            let operator = if score.starts_with('>') {
                "$gt"
            } else if score.starts_with('<') {
                "$lt"
            } else {
                "$eq"
            };

            let score = score.trim_start_matches(|c| c == '<' || c == '>');
            let score = score.parse::<f64>().unwrap_or(0.0);

            doc.insert(
                "impact.baseMetricV3.cvssV3.baseScore",
                doc! { operator: score },
            );
        }

        doc
    }
}
