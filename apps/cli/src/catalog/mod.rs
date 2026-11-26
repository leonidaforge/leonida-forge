//! `lforge catalog`: structured catalog observations and publication package
//! validation.
//!
//! `extract` reads the XML metadata documents stored in RPF9 rows and writes
//! one observation per source item. It does not merge observations or assign
//! catalog identities; that is the exporter's job.
//!
//! `validate` checks a website publication package against the catalog
//! contract. It never extracts the archive to a directory and never writes to
//! the package.

use std::path::PathBuf;

use clap::Subcommand;

pub mod extract;
pub mod json;
pub mod validate;

#[derive(Subcommand)]
pub enum Command {
    /// Extract structured catalog observations from an archive's XML rows
    Extract {
        /// The RPF9 archive to read
        archive: PathBuf,
        /// The executable that authenticates processed metadata
        #[arg(long)]
        executable: Option<PathBuf>,
        /// A stable identifier for this source. Defaults to the archive's file name
        #[arg(long)]
        source_id: Option<String>,
        /// Where to write NDJSON observations. Defaults to standard output
        #[arg(long)]
        output: Option<PathBuf>,
        /// Where to write the JSON extraction report
        #[arg(long)]
        report: Option<PathBuf>,
        /// Only emit observations in this category
        #[arg(long, value_enum, default_value_t = CategoryFilter::All)]
        category: CategoryFilter,
        /// The largest decoded row read into memory
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        max_row_bytes: u64,
        /// Stop after this many rows
        #[arg(long)]
        max_rows: Option<u32>,
    },
    /// Validate a publication package against the catalog contract
    Validate {
        /// The ZIP package to validate
        package: PathBuf,
        /// Print the machine-readable result
        #[arg(long)]
        json: bool,
        /// The largest ZIP file accepted
        #[arg(long, default_value_t = 512 * 1024 * 1024)]
        max_package_bytes: u64,
        /// The largest total decompressed size accepted
        #[arg(long, default_value_t = 128 * 1024 * 1024)]
        max_total_bytes: u64,
        /// The largest decompressed data file accepted
        #[arg(long, default_value_t = 64 * 1024 * 1024)]
        max_data_file_bytes: u64,
        /// The largest decompressed image accepted
        #[arg(long, default_value_t = 8 * 1024 * 1024)]
        max_image_bytes: u64,
        /// The most ZIP entries accepted
        #[arg(long, default_value_t = 256)]
        max_entries: u64,
        /// The largest accepted uncompressed-to-compressed ratio above a 256 KiB floor
        #[arg(long, default_value_t = 100)]
        max_compression_ratio: u64,
        /// The most catalog records accepted across all data files
        #[arg(long, default_value_t = 1_000_000)]
        max_records: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum CategoryFilter {
    All,
    Peds,
    Weapons,
    Vehicles,
    Clothing,
}

impl CategoryFilter {
    pub fn includes(self, category: lforge_rage9::catalog::Category) -> bool {
        use lforge_rage9::catalog::Category;
        match self {
            CategoryFilter::All => true,
            CategoryFilter::Peds => category == Category::Peds,
            CategoryFilter::Weapons => category == Category::Weapons,
            CategoryFilter::Vehicles => category == Category::Vehicles,
            CategoryFilter::Clothing => category == Category::Clothing,
        }
    }
}

pub fn run(command: Command) -> Result<(), String> {
    match command {
        Command::Extract {
            archive,
            executable,
            source_id,
            output,
            report,
            category,
            max_row_bytes,
            max_rows,
        } => extract::run(extract::Options {
            archive,
            executable,
            source_id,
            output,
            report,
            category,
            max_row_bytes,
            max_rows,
        }),
        Command::Validate {
            package,
            json,
            max_package_bytes,
            max_total_bytes,
            max_data_file_bytes,
            max_image_bytes,
            max_entries,
            max_compression_ratio,
            max_records,
        } => validate::run(validate::Options {
            package,
            json,
            max_package_bytes,
            max_total_bytes,
            max_data_file_bytes,
            max_image_bytes,
            max_entries,
            max_compression_ratio,
            max_records,
        }),
    }
}
