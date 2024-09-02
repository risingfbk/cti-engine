use std::{collections::HashSet, env};

use async_trait::async_trait;
use keyword_extraction::yake::{Yake, YakeParams};
use mongodb::{bson::doc, Collection};
use rocket::futures::StreamExt;
use yansi::{Color, Paint as _};

use crate::{
    db::models::technique::Technique,
    error::{Error, Result},
};

use super::LabelGenerator;

/// NLP based label generator
///
/// This label generator uses the YAKE keyword extraction algorithm
#[derive(Debug)]
pub struct NlpGenerator {
    pub stop_words: Vec<String>,
}

impl Default for NlpGenerator {
    fn default() -> Self {
        let stop_words = stop_words::get(stop_words::LANGUAGE::English);
        Self { stop_words }
    }
}

impl NlpGenerator {
    pub fn new(additional_stop_words: &[String]) -> Self {
        let mut nlp_generator = NlpGenerator::default();
        nlp_generator
            .stop_words
            .append(&mut additional_stop_words.to_vec());

        nlp_generator
    }
}

#[async_trait]
impl LabelGenerator for NlpGenerator {
    async fn generate_technique_labels(
        &self,
        techniques: &mut Collection<Technique>,
    ) -> Result<()> {
        let mut cursor = techniques.find(doc! {}, None).await?;
        let mut generated_labels = 0;

        let n_keywords = match env::var("NLP_KEYWORD_N") {
            Ok(val) => val.parse::<usize>().unwrap_or(5),
            Err(_) => 5,
        };

        println!(
            "{} Using {} to generate technique-labels",
            "".bold(),
            "NLP".bold().fg(Color::Magenta)
        );

        while let Some(result) = cursor.next().await {
            match result {
                Ok(document) => {
                    let mut labels_set = HashSet::<String>::new();
                    let mut labels_vec = vec![];

                    if let Some(d) = document.description {
                        let yake = Yake::new(YakeParams::WithDefaults(&d, &self.stop_words));
                        labels_vec = yake.get_ranked_terms(n_keywords);
                    }

                    if let Some(d) = document.detection {
                        let yake = Yake::new(YakeParams::WithDefaults(&d, &self.stop_words));
                        labels_vec = yake.get_ranked_terms(n_keywords);
                    }

                    let mut platforms: Vec<String> = document.platforms.iter().cloned().collect();
                    labels_vec.append(&mut platforms);
                    for lab in labels_vec {
                        labels_set.insert(lab.to_lowercase());
                    }
                    generated_labels += labels_set.len();
                    labels_vec = labels_set.iter().cloned().collect();

                    let update = doc! {
                        "$set": {
                            "labels": labels_vec
                        }
                    };

                    techniques
                        .update_one(doc! { "_id": document.id.unwrap() }, update, None)
                        .await?;
                }
                Err(err) => return Err(Error::Db(err)),
            }
        }
        println!(
            "{} {} {} technique-labels",
            "󰸞".bold(),
            "Generated".fg(Color::Red),
            generated_labels.bold()
        );

        Ok(())
    }

    async fn generate_group_labels(
        &self,
        groups: &mut Collection<crate::db::models::group::Group>,
    ) -> Result<()> {
        let mut cursor = groups.find(doc! {}, None).await?;
        let mut generated_labels = 0;

        let n_keywords = match env::var("NLP_KEYWORD_N") {
            Ok(val) => val.parse::<usize>().unwrap_or(5),
            Err(_) => 5,
        };

        println!(
            "{} Using {} to generate group-labels",
            "".bold(),
            "NLP".bold().fg(Color::Magenta)
        );

        while let Some(result) = cursor.next().await {
            match result {
                Ok(group) => {
                    let mut labels_set = HashSet::<String>::new();
                    let mut labels_vec = Vec::<String>::new();

                    if let Some(d) = group.description {
                        let yake = Yake::new(YakeParams::WithDefaults(&d, &self.stop_words));
                        labels_vec.append(&mut yake.get_ranked_terms(n_keywords));
                    }

                    for xr in group.external_references {
                        if let Some(d) = xr.description {
                            let yake = Yake::new(YakeParams::WithDefaults(&d, &self.stop_words));
                            labels_vec.append(&mut yake.get_ranked_terms(n_keywords));
                        }
                    }

                    for lab in labels_vec {
                        labels_set.insert(lab.to_lowercase());
                    }
                    generated_labels += labels_set.len();
                    labels_vec = labels_set.iter().cloned().collect();

                    let update = doc! {
                        "$set": {
                            "labels": labels_vec
                        }
                    };

                    groups
                        .update_one(doc! { "_id": group.id.unwrap() }, update, None)
                        .await?;
                }
                Err(err) => return Err(Error::Db(err)),
            }
        }
        println!(
            "{} {} {} group-labels",
            "󰸞".bold(),
            "Generated".fg(Color::Red),
            generated_labels.bold()
        );
        Ok(())
    }
}
