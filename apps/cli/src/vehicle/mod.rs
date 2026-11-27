//! `lforge vehicle`: vehicle body discovery and preview rendering.
//!
//! `bodies` scans the unresolved top-level rows of a RPF9 archive for type 3
//! fragments whose headers name a known vehicle, and writes the verified
//! associations as JSON. Nothing is extracted to a directory and the archive is
//! never modified.
//!
//! `previews` renders one primary image and one thumbnail per association and
//! writes the preview manifest the exporter consumes. Rendering is cached by a
//! versioned identity, so an unchanged run reuses every image.

use std::path::PathBuf;

use clap::{Subcommand, ValueEnum};

pub mod bodies;
pub mod cache;
pub mod manifest;
pub mod names;
pub mod previews;

#[derive(Subcommand)]
pub enum Command {
    /// Find vehicle body fragments and write their archive locators
    Bodies {
        /// The RPF9 archive that holds the vehicle archives
        #[arg(long)]
        archive: PathBuf,
        /// The executable that authenticates processed metadata
        #[arg(long)]
        executable: Option<PathBuf>,
        /// A vehicle name list: text lines or JSON with Name or modelName
        #[arg(long)]
        names: PathBuf,
        /// Where to write the association document
        #[arg(long)]
        output: PathBuf,
        /// The smallest candidate fragment considered, in logical bytes
        #[arg(long, default_value_t = 300_000)]
        min_bytes: u64,
        /// The most root rows inspected. Every row is inspected by default
        #[arg(long)]
        max_root_rows: Option<u32>,
        /// Print the machine-readable report instead of a summary
        #[arg(long)]
        json: bool,
    },
    /// Render primary images and thumbnails for the associations
    Previews {
        /// The body association document written by `vehicle bodies`
        #[arg(long)]
        bodies: PathBuf,
        /// Where the images and the manifest are written
        #[arg(long)]
        output: PathBuf,
        /// The archive that holds the bodies. Defaults to the one the association document names
        #[arg(long)]
        archive: Option<PathBuf>,
        /// The executable that authenticates processed metadata
        #[arg(long)]
        executable: Option<PathBuf>,
        /// A texture store root. Repeat to search several
        #[arg(long)]
        textures: Vec<PathBuf>,
        /// A body colour list in the public dump shape
        #[arg(long)]
        colors: Option<PathBuf>,
        /// The primary image edge in pixels
        #[arg(long, default_value_t = 1024)]
        size: u32,
        /// The thumbnail edge in pixels
        #[arg(long, default_value_t = 320)]
        thumb: u32,
        /// Render only this model
        #[arg(long)]
        only: Option<String>,
        /// Render every model, ignoring a valid cache entry
        #[arg(long)]
        force: bool,
        /// Stop after this many models, for a bounded run
        #[arg(long)]
        limit: Option<usize>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
}

pub fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Bodies {
            archive,
            executable,
            names,
            output,
            min_bytes,
            max_root_rows,
            json,
        } => bodies::run(&bodies::Options {
            archive,
            executable,
            names,
            output,
            min_bytes,
            max_root_rows,
            json,
        }),
        Command::Previews {
            bodies,
            output,
            archive,
            executable,
            textures,
            colors,
            size,
            thumb,
            only,
            force,
            limit,
        } => previews::run(&previews::Options {
            bodies,
            output,
            archive,
            executable,
            textures,
            colors,
            size,
            thumb,
            only,
            force,
            limit,
        }),
    }
}
