use crate::db::mongo::MongoDb;
use crate::db::DbMethods;
use mongodb::bson::doc;
use rocket::{get, http::Status, serde::json::Json, FromForm, State};

use crate::db::models::technique::Technique;

/// Query parameters for the technique endpoint
#[derive(Debug, FromForm, Default)]
pub struct TechniqueQuery {
    pub mid: Option<String>,
    pub desc: Option<String>,
    pub platforms: Option<String>,
    pub labels: Option<String>,
    pub tactics: Option<String>,
}

/// Endpoint to get techniques from the database with optional query parameters
#[get("/techniques?<query..>")]
pub async fn get_techniques(
    db: &State<MongoDb>,
    query: TechniqueQuery,
) -> Result<Json<Vec<Technique>>, Status> {
    let techniques = db
        .get_techniques(query)
        .await
        .map_err(|_| Status::InternalServerError)?;

    Ok(Json(techniques))
}

#[get("/techniques/<id>")]
pub async fn get_technique(db: &State<MongoDb>, id: &str) -> Result<Json<Technique>, Status> {
    if id.is_empty() {
        return Err(Status::BadRequest);
    }
    let technique_res = db.get_technique(id).await;
    match technique_res {
        Ok(technique) => Ok(Json(technique)),
        Err(_) => Err(Status::NotFound),
    }
}
