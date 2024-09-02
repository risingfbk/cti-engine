use crate::db::DbMethods;
use rocket::{get, http::Status, serde::json::Json, FromForm, State};

use crate::db::{models::group::Group, mongo::MongoDb};

/// Query parameters for the group endpoint
#[derive(Debug, FromForm, Default)]
pub struct GroupQuery {
    pub mid: Option<String>,
    pub desc: Option<String>,
    pub techs: Option<String>,
    pub labels: Option<String>,
    pub sectors: Option<String>,
    pub countries: Option<String>,
}

/// Endpoint to get groups from the database with optional query parameters
#[get("/groups?<query..>")]
pub async fn get_groups(
    db: &State<MongoDb>,
    query: GroupQuery,
) -> Result<Json<Vec<Group>>, Status> {
    let groups = db
        .get_groups(query)
        .await
        .expect("Error in fetching groups");
    Ok(Json(groups))
}

#[get("/groups/<id>")]
pub async fn get_group(db: &State<MongoDb>, id: &str) -> Result<Json<Group>, Status> {
    if id.is_empty() {
        return Err(Status::BadRequest);
    }
    let group_res = db.get_group(id).await;
    match group_res {
        Ok(group) => Ok(Json(group)),
        Err(_) => Err(Status::NotFound),
    }
}
