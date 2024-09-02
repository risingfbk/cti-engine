use rocket::{http::Status, post, State};
use crate::db::DbMethods;
use crate::db::mongo::MongoDb;
use crate::parser::custom::CustomData;
use crate::parser::ToInputData;
use crate::routes::file::{File, Form};

impl File<'_> {
    /// Convert the passed file data into the specific input data structure
    pub fn to_custom_data(&self) -> crate::error::Result<Box<dyn ToInputData>> {
        if let Some(_filename) = self.filename {
            match serde_yaml::from_slice::<CustomData>(&self.data) {
                Ok(custom_data) => Ok(Box::new(custom_data)),
                Err(e) => {
                    println!("Error: {:?}", e);
                    Err(crate::error::Error::InvalidInput)
                }
            }
        } else {
            Err(crate::error::Error::InvalidInput)
        }
    }
}

#[post("/file/custom", data = "<file>")]
pub async fn upload_custom(db: &State<MongoDb>, file: Form<File<'_>>) -> Result<String, Status> {
    let data = file.to_custom_data().map_err(|_| Status::InternalServerError)?;
    let input_data = data.to_input_data();

    let id = db
        .save_input_data(input_data)
        .await
        .map_err(|_| Status::InternalServerError)?;

    Ok(id)
}
