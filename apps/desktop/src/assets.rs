use std::borrow::Cow;

use gpui::{AssetSource, Result, SharedString};

macro_rules! icons {
    ($($variant:ident => $file:literal,)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Icon {
            $($variant,)*
        }

        impl Icon {
            pub fn path(self) -> &'static str {
                match self {
                    $(Icon::$variant => concat!("icons/", $file, ".svg"),)*
                }
            }
        }

        const ICONS: &[(&str, &[u8])] = &[
            $((concat!("icons/", $file, ".svg"), include_bytes!(concat!("../assets/icons/", $file, ".svg"))),)*
        ];
    };
}

icons! {
    ArrowDown => "arrow-down",
    ArrowLeft => "arrow-left",
    ArrowRight => "arrow-right",
    ArrowUp => "arrow-up",
    Check => "check",
    ChevronDown => "chevron-down",
    ChevronRight => "chevron-right",
    File => "file",
    FileImage => "file-image",
    FileMissing => "file-missing",
    Folder => "folder",
    Gamepad => "gamepad",
    PanelRight => "panel-right",
    ViewDetails => "view-details",
    ViewIcons => "view-icons",
    ViewList => "view-list",
    ViewSmallIcons => "view-small-icons",
    ViewTiles => "view-tiles",
}

/// Serves the icons compiled into the binary.
pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        Ok(ICONS
            .iter()
            .find(|(icon, _)| *icon == path)
            .map(|(_, bytes)| Cow::Borrowed(*bytes)))
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        Ok(ICONS
            .iter()
            .filter(|(icon, _)| icon.starts_with(path))
            .map(|(icon, _)| (*icon).into())
            .collect())
    }
}
