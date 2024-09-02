use crate::db::{models::tactic::Tactic, mongo::MongoDb, DbMethods};
use mongodb::bson::doc;
use rocket::{get, http::Status, serde::json::Json, FromForm, State};

/// Query parameters for the tactics endpoint
#[derive(Debug, FromForm)]
pub struct TacticQuery {
    pub mid: Option<String>,
    pub techs: Option<String>,
}

/// Endpoint to get tactics from the database with optional query parameters
#[get("/tactics?<query..>")]
pub async fn get_tactics(
    db: &State<MongoDb>,
    query: TacticQuery,
) -> Result<Json<Vec<Tactic>>, Status> {
    let techniques = db
        .get_tactics(query)
        .await
        .expect("Error in fetching tactics");

    Ok(Json(techniques))
}
