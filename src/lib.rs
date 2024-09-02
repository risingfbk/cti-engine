//! # Cti Engine
//! Cti engine is a server that provides a *REST API* to query various Cyber Threat Intelligence (CTI) data.  
//! The server is built using the [Rocket](https://rocket.rs/) web framework and uses a [MongoDB](https://www.mongodb.com/) database to store the data.  
//!

pub mod cli;
pub mod db;
pub mod error;
pub mod labels;
pub mod parser;
pub mod routes;
