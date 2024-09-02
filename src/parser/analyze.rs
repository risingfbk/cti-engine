//! # Transform
//!
//! This module contains the functions to transform the input data into the output data.
//! The input data is the data that is parsed from the configuration files, and the output
//! data contains the attack vectors that the infrastructure could be vulnerable to.
//!
//! TODO: 
//! - more complex analysis
//! - divide it into modules
//! - add possibility to add custom analysis

use std::collections::{HashMap, HashSet};

use cveparser::objects::cve_item::CveItem;
use rocket::State;
use crate::{db::{models::{group::Group, technique::Technique}, mongo::MongoDb, DbMethods}, routes::{cves::CveQuery, techniques::TechniqueQuery}};
use super::{InputData, OutputData, TechniqueCount, GroupResult};

impl InputData {
    pub async fn analyze(&self, db: &State<MongoDb>) -> OutputData {
        let mut techniques_set = HashSet::<String>::new();
        let mut techniques = vec![];

        for os in self.operating_systems.iter() {
            let query = TechniqueQuery {
                platforms: Some(os.clone()),
                ..Default::default()
            };

            let os_techniques = db.get_techniques(query).await.unwrap();
            for technique in os_techniques {
                if !techniques_set.contains(&technique.mid) {
                    techniques_set.insert(technique.mid.clone());
                    techniques.push(technique);
                }
            }
        }

        let groups = self.groups(db).await;
        let techniques = self.techniques(db, &groups.groups()).await;
        let tactics = self.tactics(&techniques);
        let cves = self.cves(db).await;

        OutputData {
            groups,
            techniques,
            tactics,
            cves,
            procedures: vec![],
            mitigations: vec![],
        }
    }

    async fn groups(&self, db: &State<MongoDb>) -> GroupResult {
        let mut countries_groups = HashMap::<String, Vec<Group>>::new();
        let mut sectors_groups = HashMap::<String, Vec<Group>>::new();
        let mut keyowrds_groups = HashMap::<String, Vec<Group>>::new();

        let all_groups = db.get_groups(Default::default()).await.unwrap();

        for group in all_groups.iter() {
            for sector in self.sectors.iter() {
                if group.sectors.contains(sector) {
                    let _tuple = sectors_groups.entry(sector.clone()).and_modify(|v| v.push(group.clone())).or_insert(vec![group.clone()]);
                }
            }

            for country in self.countries.iter() {
                if group.countries.contains(country) {
                    let _tuple = countries_groups.entry(country.clone()).and_modify(|v| v.push(group.clone())).or_insert(vec![group.clone()]);
                }
            }

            for technique_mid in group.techniques.iter() {
                let technique = db.get_technique(technique_mid).await.unwrap();
                for keyword in technique.labels {
                    for software in self.software.iter() {
                        if software.to_lowercase().contains(&keyword) {
                            let _tuple = keyowrds_groups.entry(keyword.clone()).and_modify(|v| v.push(group.clone())).or_insert(vec![group.clone()]);
                        }
                    }
                }
            }

        }

        GroupResult {
            countries: countries_groups,
            sectors: sectors_groups,
            keywords: keyowrds_groups,
        }

        // all_groups.iter().filter(|group| {
        //     group.sectors.iter().any(|sector| self.sectors.contains(sector))
        //     ||
        //     group.countries.iter().any(|country| self.countries.contains(country))
        // }).for_each(|group| {
        //     groups_set.insert(group.mid.clone());
        // });

        // let mut groups = Vec::<Group>::new();
        // for mid in groups_set.iter() {
        //     let group = db.get_group(mid).await.unwrap();
        //     groups.push(group);
        // }
        
        // groups
    }

    async fn techniques(&self, db: &State<MongoDb>, groups: &[Group]) -> Vec<TechniqueCount> {
        let mut techniques_set = HashMap::<String, u32>::new();

        for group in groups.iter() {
            for technique in group.techniques.iter() {
                if !techniques_set.contains_key(technique) {
                    techniques_set.insert(technique.clone(), 1);
                } else {
                    let count = techniques_set.get_mut(technique).unwrap();
                    *count += 1;
                }
            }
        }

        let mut techniques = vec![];

        for (mid, count) in techniques_set.iter() {
            let technique = db.get_technique(mid).await.unwrap();
            techniques.push(TechniqueCount::new(technique, *count));
        }

        // Sort the techniques by the times they appear in the groups
        techniques.sort_by(|a, b| b.count.cmp(&a.count));

        techniques
    }

    fn tactics(&self, techniques: &[TechniqueCount]) -> HashMap<String, Vec<Technique>> {
        let mut tactics_techniques = HashMap::<String, Vec<Technique>>::new();

        for t in techniques.iter() {
            for tactic in t.technique.tactics.iter() {
                let _tuple = tactics_techniques.entry(tactic.clone()).and_modify(|v| v.push(t.technique.clone())).or_insert(vec![t.technique.clone()]);
            }
        }

        tactics_techniques
    }

    async fn cves(&self, db: &State<MongoDb>) -> HashMap<String, Vec<CveItem>> {
        let mut cves = HashMap::<String, Vec<CveItem>>::new();

        for software in self.software.iter() {
            let query = CveQuery {
                keywords: Some(software.clone()),
                ..Default::default()
            };

            let software_cves = db.get_cves(query).await.unwrap();
            for cve in software_cves {
                let _tuple = cves.entry(software.clone()).and_modify(|v| v.push(cve.clone())).or_insert(vec![cve.clone()]);
            }
        }
 
        cves
    }
}
