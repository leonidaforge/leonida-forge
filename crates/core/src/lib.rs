//! Application information, file identification and format inspection shared
//! by the desktop application and the CLI.

pub mod archive;
pub mod classify;
pub mod dictionary;
pub mod inspect;
pub mod metadata;
pub mod odrp;
pub mod pso;
pub mod rbf0;
pub mod registry;
pub mod resource;
pub mod zip;

use std::path::PathBuf;

use serde::Serialize;

pub const APP_NAME: &str = "Leonida Forge";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BuildInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub os: &'static str,
    pub arch: &'static str,
    pub profile: &'static str,
}

impl BuildInfo {
    pub fn current() -> Self {
        Self {
            name: APP_NAME,
            version: VERSION,
            os: std::env::consts::OS,
            arch: std::env::consts::ARCH,
            profile: if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            },
        }
    }
}

/// `%APPDATA%\Leonida Forge`, the only place the tools write to.
pub fn data_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|app_data| PathBuf::from(app_data).join(APP_NAME))
}
