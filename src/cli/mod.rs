//! # Command line interface
//!
//! This module contains the command line interface for the `db` command.
//! The possible arguments are:
//! - `init`: Initialize the database
//! - `verbose`: Increase verbosity

use clap::Parser;

#[derive(Parser)]
pub struct Cli {
    /// Initialize the database
    #[arg(short, long, default_value_t = false)]
    pub init: bool,

    /// Increase verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}
