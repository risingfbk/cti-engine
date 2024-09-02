use crate::{
    db::mongo::MongoDb,
    parser::{DataType, OutputData},
};
use crate::{db::DbMethods, parser::InputData};
use rocket::{
    data::ToByteUnit,
    delete,
    form::{DataField, Form, FromFormField},
    get,
    http::{ContentType, Status},
    serde::json::Json,
    State,
};
use strum::IntoEnumIterator;

pub mod custom;
pub mod terraform;

/// File structure to hold the uploaded file data
pub struct File<'a> {
    pub filename: Option<&'a str>,
    pub content_type: ContentType,
    pub data: Vec<u8>,
}

#[rocket::async_trait]
impl<'a> FromFormField<'a> for File<'a> {
    async fn from_data(field: DataField<'a, '_>) -> rocket::form::Result<'a, Self> {
        let bytes = field.data.open(u32::MAX.bytes()).into_bytes().await?;
        let data = bytes.into_inner();

        let filename = field.file_name.and_then(|name| name.as_str());

        Ok(File {
            filename,
            content_type: field.content_type,
            data,
        })
    }
}

/// Endpoint to get the types of infrastructure configuration files that can be uploaded
#[get("/file")]
pub async fn get_types() -> Result<Json<Vec<DataType>>, Status> {
    let types: Vec<DataType> = DataType::iter().collect();
    Ok(Json(types))
}

#[get("/file/<id>")]
pub async fn get_infrastructure(
    db: &State<MongoDb>,
    id: String,
) -> Result<Json<InputData>, Status> {
    let input_data = db.get_input_data(&id).await.map_err(|_| Status::NotFound)?;
    Ok(Json(input_data))
}

#[delete("/file/<id>")]
pub async fn delete_infrastructure(db: &State<MongoDb>, id: String) -> Result<(), Status> {
    db.delete_input_data(&id)
        .await
        .map_err(|_| Status::NotFound)?;
    Ok(())
}

/// Endpoint to analyze the uploaded infrastructure file
/// It should return the output data that contains the attack vectors
/// that the infrastructure could be vulnerable to.
#[get("/analyze/<id>")]
pub async fn analyze(db: &State<MongoDb>, id: String) -> Result<Json<OutputData>, Status> {
    format!("Analysis of the file with id: {}", id);
    let input_data = db.get_input_data(&id).await.map_err(|_| Status::NotFound)?;
    let output_data = input_data.analyze(db).await;

    Ok(Json(output_data))
}

