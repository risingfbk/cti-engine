//! # Routes
//! This module contains all the routes for the server.
//!
//! The routes are organized into modules based on the data type they handle.
//! For example, the [`groups`] module contains the routes for handling groups,
//! and the [`techniques`] module contains the routes for handling techniques.
//!

use mongodb::bson::doc;
use rocket::{fs::NamedFile, get};

pub mod cves;
pub mod file;
pub mod groups;
pub mod malware;
pub mod tactics;
pub mod techniques;
pub mod utils;

#[get("/favicon.ico")]
pub async fn favicon() -> Option<NamedFile> {
    NamedFile::open("static/favicon.ico").await.ok()
}
