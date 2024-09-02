use clap::Parser;
use cli::Cli;
use db::mongo::MongoDb;
use labels::nlp::NlpGenerator;
use rocket::{config::LogLevel, launch, routes, Config};

pub mod cli;
pub mod db;
pub mod error;
pub mod labels;
pub mod parser;
pub mod routes;

#[cfg(test)]
mod tests;

#[launch]
pub async fn rocket() -> _ {
    dotenv::dotenv().ok();

    let args = Cli::parse();
    let log_level = match args.verbose {
        0 => LogLevel::Critical,
        1 => LogLevel::Normal,
        2 => LogLevel::Debug,
        _ => LogLevel::Normal,
    };

    let conf = Config {
        log_level,
        ..Config::debug_default()
    };

    let words = std::fs::read_to_string("data/stop_words.txt").unwrap();
    let additional_stop_words: Vec<String> =
        words.split_whitespace().map(|s| s.to_string()).collect();
    let label_generator = Box::new(NlpGenerator::new(&additional_stop_words));

    let mongo_db = MongoDb::init(args.init, label_generator).await.unwrap();

    rocket::custom(&conf)
        .mount("/", routes![routes::favicon])
        .mount(
            "/",
            routes![
                routes::cves::get_cves,
                routes::cves::get_cve,
                routes::groups::get_groups,
                routes::groups::get_group,
                routes::techniques::get_techniques,
                routes::tactics::get_tactics,
                routes::malware::get_malware,
                routes::utils::target_countries,
                routes::utils::target_sectors,
            ],
        )
        .mount(
            "/",
            routes![
                routes::file::get_infrastructure,
                routes::file::delete_infrastructure,
                routes::file::get_types,
                routes::file::analyze,

                routes::file::custom::upload_custom,
                routes::file::terraform::upload_terraform,
            ],
        )
        .manage(mongo_db)
}
