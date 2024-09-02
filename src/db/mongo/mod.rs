//! # MongoDb Database implementation
//!
//! This module contains the implementation of the MongoDB database.
//! It contains the [`MongoDb`] struct which contains the MongoDB collections
//! for all the models defined in the models module.
//!
//! The [`DbMethods`] trait is implemented for the [`MongoDb`] struct to provide
//! the database methods that are used by the server.
//!
//! The [`query`] module contains the implementation of the [`DbQuery`] trait
//! for the MongoDB database.

use self::query::DbQuery;
use super::{
    models::{group::Group, malware::Malware, tactic::Tactic, technique::Technique},
    DbMethods,
};
use crate::{
    error::{Error, Result},
    labels::LabelGenerator,
    parser::InputData,
    routes::{
        cves::CveQuery, groups::GroupQuery, malware::MalwareQuery, tactics::TacticQuery,
        techniques::TechniqueQuery,
    },
};
use async_trait::async_trait;
use attck::Declaration;
use cveparser::objects::cve_item::CveItem;
use indicatif::{ProgressBar, ProgressStyle};
use mongodb::{
    bson::{doc, oid::ObjectId},
    Client, Collection,
};
use rocket::futures::StreamExt;
use std::{env, str::FromStr, time::Duration};
use yansi::{Color, Paint};

pub mod query;

/// MongoDB database struct
///
/// This struct contains the MongoDB collections for all the models
/// defined in the models module
pub struct MongoDb {
    pub groups: Collection<Group>,
    pub techniques: Collection<Technique>,
    pub tactics: Collection<Tactic>,
    pub malware: Collection<Malware>,

    pub cves: Collection<CveItem>,

    pub input_data: Collection<InputData>,

    pub label_generator: Box<dyn LabelGenerator + Send + Sync>,
}

impl MongoDb {
    pub async fn init(
        from_stix: bool,
        label_generator: Box<dyn LabelGenerator + Send + Sync>,
    ) -> Result<Self> {
        let uri = match env::var("MONGOURI") {
            Ok(val) => val,
            Err(err) => format!("Error loading env var: {}", err),
        };
        let client = Client::with_uri_str(uri).await?;
        let db_name = match env::var("DATABASE") {
            Ok(val) => val,
            Err(err) => format!("Error loading env var: {}", err),
        };
        let db = client.database(&db_name);
        let groups: Collection<Group> = db.collection("group");
        let techniques: Collection<Technique> = db.collection("technique");
        let tactics: Collection<Tactic> = db.collection("tactic");
        let malware: Collection<Malware> = db.collection("malware");
        let input_data: Collection<InputData> = db.collection("input_data");

        let cves: Collection<CveItem> = db.collection("cves");

        let mut db = MongoDb {
            groups,
            techniques,
            tactics,
            malware,
            cves,
            input_data,
            label_generator,
        };
        if from_stix {
            db.delete_all().await?;
            db.init_db_from_data().await?;
        }

        Ok(db)
    }

    pub async fn get_all_groups(&self) -> Result<Vec<Group>> {
        let cursor = self.groups.find(doc! {}, None).await?;
        let groups: Vec<Group> = cursor.map(|doc| doc.unwrap()).collect().await;
        Ok(groups)
    }

    pub async fn get_all_tactics(&self) -> Result<Vec<Tactic>> {
        let cursor = self.tactics.find(doc! {}, None).await?;
        let tactics: Vec<Tactic> = cursor.map(|doc| doc.unwrap()).collect().await;
        Ok(tactics)
    }

    pub async fn get_all_techniques(&self) -> Result<Vec<Technique>> {
        let cursor = self.techniques.find(doc! {}, None).await?;
        let techniques: Vec<Technique> = cursor.map(|doc| doc.unwrap()).collect().await;
        Ok(techniques)
    }

    #[cfg(feature = "latest")]
    pub async fn download_latest_data() -> Result<()> {
        use std::{fs::File, io::Write};

        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_style(
            ProgressStyle::with_template("{spinner:.blue} {msg}")
                .unwrap()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈"),
        );
        pb.set_message(format!(
            "{} {} latest STIX data",
            "".bold(),
            "Downloading".bold().fg(Color::Magenta)
        ));

        let stix_json = reqwest::get("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json")
            .await?
            .text()
            .await?;


        let path = env::var("ENTERPRISE_ATTACK_FILE").unwrap_or_else(|_| "data/enterprise.json".to_string());
        let mut file = File::create(&path)?;
        file.write_all(stix_json.as_bytes())?;

        pb.finish_with_message("Download complete");

        Ok(())
    }
}

#[async_trait]
impl DbMethods for MongoDb {
    async fn init_db_from_data(&mut self) -> Result<()> {
        #[cfg(feature = "latest")]
        MongoDb::download_latest_data().await?;

        let data = attck::enterprise();

        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_style(
            ProgressStyle::with_template("{spinner:.blue} {msg}")
                .unwrap()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈"),
        );
        pb.set_message(format!(
            "{} {}",
            "".bold(),
            "Initializing techniques".bold().fg(Color::Magenta)
        ));
        let techniques: Vec<Technique> = data
            .attack_patterns()
            .map(|t| Technique::from(&t))
            .collect();
        let _created_techniques = self.techniques.insert_many(techniques, None).await?;

        pb.set_message(format!(
            "{} {}",
            "".bold(),
            "Initializing groups".bold().fg(Color::Magenta)
        ));
        let groups: Vec<Group> = data.intrusion_sets().map(|g| Group::from(&g)).collect();
        let _created_groups = self.groups.insert_many(groups, None).await?;

        pb.set_message(format!(
            "{} {}",
            "".bold(),
            "Initializing tactics".bold().fg(Color::Magenta)
        ));
        let tactics: Vec<Tactic> = data.tactics().map(|t| Tactic::from(&t)).collect();
        let _created_tactics = self.tactics.insert_many(tactics, None).await?;

        pb.set_message(format!(
            "{} {}",
            "".bold(),
            "Initializing malware".bold().fg(Color::Magenta)
        ));
        let malware: Vec<Malware> = data.malware().map(|m| Malware::from(&m)).collect();
        let _created_malware = self.malware.insert_many(malware, None).await?;

        pb.finish_with_message("Initialization complete");

        self.populate_groups_fields().await?;
        self.populate_tactic_fields().await?;

        self.init_cves().await?;

        self.generate_labels().await?;

        Ok(())
    }

    async fn populate_groups_fields(&self) -> Result<()> {
        println!(
            "{} {} groups' techniques",
            "".bold(),
            "Populating".bold().fg(Color::Magenta)
        );

        let groups = self.get_all_groups().await?;

        let style = ProgressStyle::with_template("{msg} {prefix:.bold} [{bar:.cyan/blue}] ")
            .unwrap()
            .progress_chars("█▇▆▅▄▃▂▁  ");
        let pb = ProgressBar::new(groups.len() as u64);
        pb.set_style(style);
        let mut curr = 0;
        for mut group in groups {
            let uri = format!("data/group-techniques/{}.json", group.mid);
            let msg = format!(
                "{} {} from: {}",
                "".bold(),
                "Loading techniques".bold().fg(Color::Blue),
                uri.italic().fg(Color::BrightCyan)
            );
            pb.set_message(msg);
            let techniques = Group::get_techniques(&group.mid, &self.techniques).await;
            if let Ok(techniques) = techniques {
                group.techniques.clone_from(&techniques);
                let filter = doc! {
                    "_id": group.id.unwrap()
                };
                let update = doc! {
                    "$set": {
                        "techniques": techniques
                    }
                };
                self.groups.update_one(filter, update, None).await?;
            }
            curr += 1;
            pb.set_position(curr);
        }

        //TODO: change `unwrap_or_else` to `unwrap` after testing
        let threat_actors_filename = env::var("ADDITIONAL_TA_DATA").unwrap_or_else(|_| "data/threat_actors_fbk.csv".to_string());
        let csv_file = std::fs::read_to_string(threat_actors_filename).unwrap();

        for line in csv_file.lines().skip(1) {
            let parts: Vec<&str> = line.split(',').collect();
            let name = parts[0];
            let aliases: Vec<&str> = parts[2].split('|').collect();
            let _sectors: Vec<&str> = parts[3].split('|').collect();
            let _target_countries: Vec<&str> = parts[4].split('|').collect();

            for group in self.get_all_groups().await? {
                if group.name == name || aliases.contains(&group.name.as_str()) {
                    let filter = doc! {
                        "_id": group.id.unwrap()
                    };
                    let sectors: Vec<String> = parts[3].split('|').map(|s| s.to_string()).collect();
                    let target_countries: Vec<String> =
                        parts[4].split('|').map(|s| s.to_string()).collect();
                    let update = doc! {
                        "$set": {
                            "sectors": sectors,
                            "countries": target_countries
                        }
                    };
                    self.groups.update_one(filter, update, None).await?;
                }
            }
        }

        Ok(())
    }

    async fn populate_tactic_fields(&mut self) -> Result<()> {
        println!(
            "{} {} tactics' techniques",
            "".bold(),
            "Populating".bold().fg(Color::Magenta)
        );

        let tactics = self.get_all_tactics().await?;
        let style = ProgressStyle::with_template("{msg} {prefix:.bold} [{bar:.cyan/blue}] ")
            .unwrap()
            .progress_chars("█▇▆▅▄▃▂▁  ");
        let pb = ProgressBar::new(tactics.len() as u64);
        pb.set_style(style);
        let mut curr = 0;

        let techniques = self.get_all_techniques().await?;

        for technique in techniques {
            for tactic in technique.tactics {
                let tactic_id = self
                    .tactics
                    .find_one(doc! { "x_mitre_shortname": tactic }, None)
                    .await?;

                if let Some(tactic_id) = tactic_id {
                    let filter = doc! {
                        "_id": tactic_id.id.unwrap()
                    };
                    let update = doc! {
                        "$push": {
                            "technique_refs": technique.mid.clone()
                        }
                    };
                    self.tactics.update_one(filter, update, None).await?;
                }
            }
            curr += 1;
            pb.set_position(curr);
        }

        Ok(())
    }

    async fn init_cves(&mut self) -> Result<()> {
        let pb = ProgressBar::new_spinner();
        pb.enable_steady_tick(Duration::from_millis(120));
        pb.set_style(
            ProgressStyle::with_template("{spinner:.blue} {msg}")
                .unwrap()
                .tick_chars("⠁⠂⠄⡀⢀⠠⠐⠈"),
        );
        pb.set_message(format!(
            "{} {}",
            "".bold(),
            "Initializing CVEs".bold().fg(Color::Magenta)
        ));

        let cves = cveparser::functions::parse_all_cves();
        let _created_cves = self.cves.insert_many(cves, None).await?;
        Ok(())
    }

    async fn generate_labels(&mut self) -> Result<()> {
        self.label_generator
            .generate_technique_labels(&mut self.techniques)
            .await?;
        self.label_generator
            .generate_group_labels(&mut self.groups)
            .await?;
        Ok(())
    }

    async fn get_cves(&self, query: CveQuery) -> Result<Vec<CveItem>> {
        let cursor = self.cves.find(query.to_doc(), None).await?;
        let cves: Vec<CveItem> = cursor.map(|doc| doc.unwrap()).collect().await;
        Ok(cves)
    }

    async fn get_cve(&self, id: &str) -> Result<CveItem> {
        let filter = doc! { "cve.CVE_data_meta.ID": id };
        let cve = self.cves.find_one(filter, None).await?;
        cve.ok_or_else(|| Error::Other("CVE not found".to_string()))
    }

    async fn get_techniques(&self, query: TechniqueQuery) -> Result<Vec<Technique>> {
        let cursor = self.techniques.find(query.to_doc(), None).await?;
        let techniques: Vec<Technique> = cursor.map(|doc| doc.unwrap()).collect().await;
        Ok(techniques)
    }

    async fn get_technique(&self, id: &str) -> Result<Technique> {
        let filter = doc! { "mid": id };
        let technique = self.techniques.find_one(filter, None).await?;
        technique.ok_or_else(|| Error::Other("Technique not found".to_string()))
    }

    async fn get_groups(&self, query: GroupQuery) -> Result<Vec<Group>> {
        let cursor = self.groups.find(query.to_doc(), None).await?;
        let groups: Vec<Group> = cursor.map(|doc| doc.unwrap()).collect().await;
        Ok(groups)
    }

    async fn get_group(&self, id: &str) -> Result<Group> {
        let filter = doc! { "mid": id };
        let group = self.groups.find_one(filter, None).await?;
        group.ok_or_else(|| Error::Other("Group not found".to_string()))
    }

    async fn get_tactics(&self, query: TacticQuery) -> Result<Vec<Tactic>> {
        let cursor = self.tactics.find(query.to_doc(), None).await?;
        let tactics: Vec<Tactic> = cursor.map(|doc| doc.unwrap()).collect().await;
        Ok(tactics)
    }

    async fn get_malware(&self, query: MalwareQuery) -> Result<Vec<Malware>> {
        let cursor = self.malware.find(query.to_doc(), None).await?;
        let malware: Vec<Malware> = cursor.map(|doc| doc.unwrap()).collect().await;
        Ok(malware)
    }

    async fn save_input_data(&self, data: InputData) -> Result<String> {
        let id = self.input_data.insert_one(data, None).await?;
        Ok(id.inserted_id.to_string())
    }

    async fn delete_input_data(&self, id: &str) -> Result<()> {
        let id = ObjectId::from_str(id).map_err(|_| Error::Other("Invalid ID".to_string()))?;
        let filter = doc! { "_id": id };
        self.input_data.delete_one(filter, None).await?;
        Ok(())
    }

    async fn get_input_data(&self, id: &str) -> Result<InputData> {
        let id = ObjectId::from_str(id).map_err(|_| Error::Other("Invalid ID".to_string()))?;
        let filter = doc! { "_id": id };
        let data = self.input_data.find_one(filter, None).await?;
        data.ok_or_else(|| Error::Other("Input data not found".to_string()))
    }

    async fn delete_all(&self) -> Result<()> {
        self.groups.delete_many(doc! {}, None).await?;
        self.techniques.delete_many(doc! {}, None).await?;
        self.tactics.delete_many(doc! {}, None).await?;
        self.malware.delete_many(doc! {}, None).await?;
        self.cves.delete_many(doc! {}, None).await?;
        Ok(())
    }
}
