use std::collections::HashSet;
use crate::db::DbMethods;

use rocket::{get, http::Status, serde::json::Json, State};

use crate::db::mongo::MongoDb;


#[get("/countries")]
pub async fn target_countries(db: &State<MongoDb>) -> Result<Json<Vec<String>>, Status> {
    let groups = db.get_groups(Default::default()).await.expect("Error in fetching groups");

    let mut countries_set = HashSet::<String>::new();
    groups.iter().for_each(|group| {
        group.countries.iter().for_each(|country| {
            countries_set.insert(country.clone());
        });
    });

    let mut target_countries = countries_set.iter().cloned().collect::<Vec<String>>();
    target_countries.sort();

    Ok(Json(target_countries))
}

#[get("/sectors")]
pub async fn target_sectors(db: &State<MongoDb>) -> Result<Json<Vec<String>>, Status> {
    let groups = db.get_groups(Default::default()).await.expect("Error in fetching groups");

    let mut sectors_set = HashSet::<String>::new();
    groups.iter().for_each(|group| {
        group.sectors.iter().for_each(|sector| {
            sectors_set.insert(sector.clone());
        });
    });

    let mut target_sectors = sectors_set.iter().cloned().collect::<Vec<String>>();
    target_sectors.sort();

    Ok(Json(target_sectors))
}
