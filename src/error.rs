//! # Error handling
//!
//! This module contains the custom error type and result type for the application.
//!
//! The custom error type is used to represent the different types of errors that can occur
//! in the application, such as invalid input, file not found, database errors, etc.
//!
//! The custom result type is used to return the result of a function that can return an error
//! (less verbose)
//!
//! The `From<T>` trait is implemented for the custom error type to convert other error types
//! enabling the use of the `?` operator in functions that return the custom error type.

use rocket::{
    response::{self, status, Responder},
    serde::json::{json, Json},
    Request,
};
use std::{error, fmt};

/// Custom error type for the application
#[derive(Debug)]
pub enum Error {
    InvalidInput,
    FileNotFound,
    Io(std::io::Error),
    Other(String),
    Db(mongodb::error::Error),

    InvalidFileType,

    Yaml(serde_yaml::Error),

    #[cfg(feature = "latest")]
    Reqwest(reqwest::Error),
}

/// Custom result type for the application
pub type Result<T> = std::result::Result<T, Error>;

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::InvalidInput => write!(f, "Invalid input data."),
            Error::FileNotFound => write!(f, "File not found."),
            Error::Db(e) => write!(f, "Database error: {}", e),
            Error::Io(e) => write!(f, "Io error: {}", e),
            Error::Other(ref message) => write!(f, "An error occurred: {}", message),
            Error::Yaml(e) => write!(f, "Yaml error: {}", e),
            Error::InvalidFileType => write!(f, "Invalid file type."),

            #[cfg(feature = "latest")]
            Error::Reqwest(e) => write!(f, "{}", e),
        }
    }
}

impl From<mongodb::error::Error> for Error {
    fn from(val: mongodb::error::Error) -> Self {
        Error::Db(val)
    }
}

impl From<std::io::Error> for Error {
    fn from(val: std::io::Error) -> Self {
        Error::Io(val)
    }
}

impl<'r> Responder<'r, 'static> for Error {
    fn respond_to(self, req: &Request) -> response::Result<'static> {
        let status = match self {
            Error::InvalidInput => rocket::http::Status::BadRequest,
            Error::FileNotFound => rocket::http::Status::NotFound,
            _ => rocket::http::Status::InternalServerError,
        };
        status::Custom(status, Json(json!({ "error": self.to_string() }))).respond_to(req)
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(val: serde_yaml::Error) -> Self {
        Error::Yaml(val)
    }
}

#[cfg(feature = "latest")]
impl From<reqwest::Error> for Error {
    fn from(val: reqwest::Error) -> Self {
        Error::Reqwest(val)
    }
}
