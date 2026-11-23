//! User preferences, stored as JSON in the per-user roaming app data folder.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fs::Sort;

pub const DEFAULT_TREE_WIDTH: f32 = 240.;
pub const DEFAULT_PREVIEW_WIDTH: f32 = 320.;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ViewMode {
    Icons,
    SmallIcons,
    List,
    #[default]
    Details,
    Tiles,
}

impl ViewMode {
    pub const ALL: [ViewMode; 5] = [
        ViewMode::Icons,
        ViewMode::SmallIcons,
        ViewMode::List,
        ViewMode::Details,
        ViewMode::Tiles,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ViewMode::Icons => "Icons",
            ViewMode::SmallIcons => "Small Icons",
            ViewMode::List => "List",
            ViewMode::Details => "Details",
            ViewMode::Tiles => "Tiles",
        }
    }
}

/// Missing fields fall back to their defaults, so older files keep loading.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub gta_directory: Option<PathBuf>,
    pub folders: Vec<PathBuf>,
    pub view_mode: ViewMode,
    pub sort: Sort,
    pub preview_visible: bool,
    pub tree_width: f32,
    pub preview_width: f32,
    pub last_directory: Option<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            gta_directory: None,
            folders: Vec::new(),
            view_mode: ViewMode::default(),
            sort: Sort::default(),
            preview_visible: true,
            tree_width: DEFAULT_TREE_WIDTH,
            preview_width: DEFAULT_PREVIEW_WIDTH,
            last_directory: None,
        }
    }
}

/// `%APPDATA%\Leonida Forge\settings.json`.
pub fn default_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|app_data| {
        PathBuf::from(app_data)
            .join("Leonida Forge")
            .join("settings.json")
    })
}

impl Settings {
    /// Loads settings, falling back to defaults if the file is missing or invalid.
    pub fn load(path: &Path) -> Self {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Self::default(),
            Err(err) => {
                log::warn!("cannot read {}: {err}", path.display());
                return Self::default();
            }
        };
        match serde_json::from_slice::<Self>(&bytes) {
            Ok(settings) => settings,
            Err(err) => {
                log::warn!("ignoring invalid settings in {}: {err}", path.display());
                Self::default()
            }
        }
    }

    /// Writes to a temporary file first so a crash cannot leave a partial file.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_vec_pretty(self).map_err(io::Error::other)?;
        let temp = path.with_extension("json.tmp");
        fs::write(&temp, json)?;
        fs::rename(&temp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fs::SortKey;

    #[test]
    fn missing_file_gives_defaults() {
        let temp = tempfile::tempdir().unwrap();
        let settings = Settings::load(&temp.path().join("settings.json"));
        assert_eq!(settings, Settings::default());
        assert!(settings.preview_visible);
        assert_eq!(settings.view_mode, ViewMode::Details);
    }

    #[test]
    fn round_trips_through_a_new_directory() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("Leonida Forge").join("settings.json");
        let settings = Settings {
            gta_directory: Some(PathBuf::from(r"D:\Spiele\GTA VI")),
            folders: vec![PathBuf::from(r"E:\Mods ä"), PathBuf::from(r"E:\研究")],
            view_mode: ViewMode::Tiles,
            sort: Sort {
                key: SortKey::Size,
                descending: true,
            },
            preview_visible: false,
            tree_width: 300.,
            preview_width: 260.,
            last_directory: Some(PathBuf::from(r"E:\Mods ä\cars")),
        };
        settings.save(&path).unwrap();
        assert_eq!(Settings::load(&path), settings);
        assert!(!path.with_extension("json.tmp").exists());
    }

    #[test]
    fn malformed_file_gives_defaults() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings.json");
        fs::write(&path, "{ not json").unwrap();
        assert_eq!(Settings::load(&path), Settings::default());
    }

    #[test]
    fn partial_and_unknown_fields_are_tolerated() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("settings.json");
        fs::write(&path, r#"{ "view_mode": "List", "removed_option": 1 }"#).unwrap();
        let settings = Settings::load(&path);
        assert_eq!(settings.view_mode, ViewMode::List);
        assert!(settings.preview_visible);
        assert_eq!(settings.tree_width, DEFAULT_TREE_WIDTH);
    }
}
