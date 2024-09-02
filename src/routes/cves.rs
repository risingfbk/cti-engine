use crate::db::DbMethods;
use cveparser::objects::cve_item::CveItem;
use rocket::{get, http::Status, serde::json::Json, FromForm, State};

use crate::db::mongo::MongoDb;

/// Query parameters for the group endpoint
#[derive(Debug, FromForm, Default)]
pub struct CveQuery {
    pub id: Option<String>,
    pub keywords: Option<String>,
    pub base_score: Option<String>,
}

/// Endpoint to get cves from the database with optional query parameters
#[get("/cves?<query..>")]
pub async fn get_cves(db: &State<MongoDb>, query: CveQuery) -> Result<Json<Vec<CveItem>>, Status> {
    let cves = db.get_cves(query).await.expect("Error in fetching groups");
    Ok(Json(cves))
}

/// Endpoint to get a specific cve from the database by using its `id`
#[get("/cves/<id>")]
pub async fn get_cve(db: &State<MongoDb>, id: &str) -> Result<Json<CveItem>, Status> {
    if id.is_empty() {
        return Err(Status::BadRequest);
    }
    let cve_res = db.get_cve(id).await;
    match cve_res {
        Ok(cve) => Ok(Json(cve)),
        Err(_) => Err(Status::NotFound),
    }
}
