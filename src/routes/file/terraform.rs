use rocket::{http::Status, post};
use terraform_parser::state_representation::StateRepresentation;
use crate::{db::mongo::MongoDb, parser::{terraform::TerraformData, ToInputData}, routes::file::{File, Form, State}};
use crate::db::DbMethods;

impl File<'_> {
    /// Convert the passed file data into the specific input data structure
    pub fn to_terraform_data(&self) -> crate::error::Result<Box<dyn ToInputData>> {
        if let Some(_filename) = self.filename {
            let state = serde_json::from_slice::<StateRepresentation>(&self.data).map_err(|_| crate::error::Error::InvalidInput)?;
            Ok(Box::new(TerraformData { state }))
        } else {
            Err(crate::error::Error::InvalidInput)
        }
    }
}


#[post("/file/terraform", data = "<file>")]
pub async fn upload_terraform(db: &State<MongoDb>, file: Form<File<'_>>) -> Result<String, Status> {
    let data = file.to_terraform_data().map_err(|_| Status::InternalServerError)?;
    let input_data = data.to_input_data();

    let id = db
        .save_input_data(input_data)
        .await
        .map_err(|_| Status::InternalServerError)?;

    Ok(id)
}
