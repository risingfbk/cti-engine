use cti_engine::parser::custom::CustomData;
use stix::Object;

use crate::{db::mongo::MongoDb, labels::nlp::NlpGenerator, parser::{terraform::TerraformData, ToInputData}};

#[test]
fn groups() {
    let enterprise = attck::enterprise();

    let mut cnt = 0;
    for group in enterprise.intrusion_sets() {
        println!("{:?}", group.name());
        cnt += 1;
    }
    println!("Found {} groups", cnt);
}

#[test]
fn techniques() {
    let enterprise = attck::enterprise();

    for tech in enterprise.attack_patterns() {
        println!("\n\n{:?}", tech.mitre_id());
        println!("{:?}", tech.name());
        println!("{:?}", tech.base.description);
        println!("{:?}", tech.base.kill_chain_phases);
    }
}

#[test]
fn techniques_platforms() {
    let enterprise = attck::enterprise();
    let mut platforms = std::collections::HashSet::new();

    for tech in enterprise.attack_patterns() {
        for platform in tech.mitre.platforms.iter() {
            platforms.insert(platform.clone());
        }
    }

    println!("{:?}", platforms);
}

#[test]
fn tactics() {
    let enterprise = attck::enterprise();

    for tactic in enterprise.tactics() {
        println!("{:?}", tactic.name);
        println!("{:?}", tactic.shortname);
        println!("{:?}", tactic.description);
        println!("{:?}", tactic.labels());
        println!("{:?}", tactic.external_references());

        println!();
    }
}

#[test]
fn relationships() {
    let enterprise = attck::enterprise();

    let mut types = std::collections::HashSet::new();
    for rel in enterprise.relationships() {
        println!("{:?}", rel.source_ref);
        println!("{:?}", rel.target_ref);
        println!("{:?}", rel.relationship_type);
        println!();

        types.insert(rel.relationship_type.clone());
    }

    println!("{:?}", types);
}

#[test]
fn malware() {
    let enterprise = attck::enterprise();

    for (cnt, malware) in enterprise.malware().enumerate() {
        println!("{}: {:?}", cnt, malware.name());
        println!("{:?}", malware.description());
        println!("{:?}", malware.base.external_references());
        println!();
    }
}

#[test]
fn campaigns() {
    let enterprise = attck::enterprise();

    let mut cnt = 0;
    for campaign in enterprise.campaigns() {
        println!("{:?}", campaign.name);
        println!("{:?}", campaign.description);
        println!("{:?}", campaign.objective);
        println!("{:?}", campaign.external_references());
        println!();
        cnt += 1;
    }

    println!("Found {} campaigns", cnt);
}

#[test]
fn custom_data() {
    let countries = vec![
        "United States".to_string(),
        "Italy".to_string(),
        "Germany".to_string(),
    ];

    let sectors = vec!["Public Administration".to_string(), "Finance".to_string()];

    let operating_systems = vec![
        "Windows".to_string(),
        "Linux".to_string(),
        "MacOS".to_string(),
    ];
    let services = vec!["Apache".to_string(), "Nginx".to_string(), "IIS".to_string()];
    let software = vec![
        "Wordpress".to_string(),
        "Joomla".to_string(),
        "Drupal".to_string(),
    ];
    let additional_data = vec!["AWS".to_string(), "Azure".to_string(), "GCP".to_string()];
    let custom_data = CustomData::new(
        countries,
        sectors,
        operating_systems,
        services,
        software,
        additional_data,
    );

    let serialized = serde_yaml::to_string(&custom_data).unwrap();
    println!("{}", serialized);

    let deserialized: CustomData = serde_yaml::from_str(&serialized).unwrap();
    println!("{:?}", deserialized);
}

#[test]
fn fbk_csv() {
    let csv_file = std::fs::read_to_string("data/threat_actors_fbk.csv").unwrap();

    for line in csv_file.lines() {
        let parts: Vec<&str> = line.split(',').collect();
        let sectors: Vec<&str> = parts[3].split('|').collect();
        let target_countries: Vec<&str> = parts[4].split('|').collect();
        println!(
            "Name: {}\nSectors: {:?}\nTarget Countries: {:?}\n",
            parts[0], sectors, target_countries
        );
    }
}

#[tokio::test]
async fn compare_groups() {
    dotenv::dotenv().ok();
    let csv_file = std::fs::read_to_string("data/threat_actors_fbk.csv").unwrap();
    let words = std::fs::read_to_string("data/stop_words.txt").unwrap();
    let additional_stop_words: Vec<String> =
        words.split_whitespace().map(|s| s.to_string()).collect();
    let label_generator = Box::new(NlpGenerator::new(&additional_stop_words));

    let mongo_db = MongoDb::init(false, label_generator).await.unwrap();

    let groups = mongo_db.get_all_groups().await.unwrap();

    let mut found = 0;
    for line in csv_file.lines().skip(1) {
        let parts: Vec<&str> = line.split(',').collect();
        let name = parts[0];
        let aliases: Vec<&str> = parts[2].split('|').collect();
        let _sectors: Vec<&str> = parts[3].split('|').collect();
        let _target_countries: Vec<&str> = parts[4].split('|').collect();

        for group in &groups {
            if group.name == name || aliases.contains(&group.name.as_str()) {
                found += 1;
                println!("{} found", parts[0]);
                break;
            }
        }
    }

    println!("\n\nFound: {}\nNot found {}", found, groups.len() - found);
}

#[test]
fn cves() {
    let file_str = std::fs::read_to_string("data/nvdcve.json").unwrap();
    let json = serde_json::from_str::<serde_json::Value>(&file_str).unwrap();

    println!("{}", json["CVE_Items"]);
}

#[test]
fn terraform_parsing() {
}
