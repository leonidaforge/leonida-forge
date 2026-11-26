//! Texture viewers: one image, or a dictionary with a list and a preview.

mod dictionary;
mod preview;
mod single;

use std::path::{Path, PathBuf};
use std::sync::Arc;

use gpui::{
    App, Bounds, Pixels, SharedString, Size, TitlebarOptions, Window, WindowBounds, WindowOptions,
    div, prelude::*, px, rgb, size,
};
use lforge_texture::{DictionaryStore, Store, TextureInfo, TextureStore};

pub use dictionary::TextureDictionaryViewer;
pub use preview::ImagePreview;
pub use single::TextureViewer;

use crate::files::{self, Access};
use crate::ui;
use crate::ui::theme;

/// Longest side of a dictionary thumbnail.
pub const THUMBNAIL_SIZE: u32 = 96;
/// Decoded previews kept for the selected texture and recent ones.
pub const PREVIEW_CACHE_BYTES: usize = 96 * 1024 * 1024;

pub fn open(path: PathBuf, access: Access, cx: &mut App) {
    open_loaded(path, access, false, cx);
}

/// Opens a type-5 resource as a texture dictionary, falling back to the Binary
/// Inspector when it is not one. This is the default double-click behaviour.
pub fn open_resource(path: PathBuf, access: Access, cx: &mut App) {
    open_loaded(path, access, true, cx);
}

/// Opens a type-5 resource as a texture dictionary and reports why it cannot
/// be opened. This is the explicit **Open as Texture** action, which must not
/// silently substitute a different viewer.
pub fn open_resource_explicit(path: PathBuf, access: Access, cx: &mut App) {
    open_loaded(path, access, false, cx);
}

fn open_loaded(path: PathBuf, access: Access, fallback_inspector: bool, cx: &mut App) {
    let load_path = path.clone();
    let load_access = access.clone();
    let load = cx
        .background_spawn(async move { load_store(&load_path, &load_access, fallback_inspector) });
    cx.spawn(async move |cx| {
        let result = load.await;
        cx.update(|cx| match result {
            Ok(store) if store.len() == 1 => open_single(store, path, 0, cx),
            Ok(store) => open_dictionary(store, path, cx),
            Err(LoadError::NotTexture) if fallback_inspector => {
                crate::explorer::open_binary_inspector(path, access, cx)
            }
            Err(LoadError::NotTexture) => open_failed(
                path,
                "this file is not a texture store or a RAGE texture dictionary".to_string(),
                cx,
            ),
            Err(LoadError::Message(err)) => open_failed(path, err, cx),
        });
    })
    .detach();
}

/// Opens one entry of an already parsed store in the single-image viewer.
pub fn open_entry(store: TextureStore, index: u32, path: PathBuf, cx: &mut App) {
    let title = format!("{} - Texture", file_name(&path));
    let options = window_options(title, size(px(960.), px(720.)), cx);
    if let Err(err) = cx.open_window(options, |window, cx| {
        ui::close_through_gpui(window, cx);
        let viewer = cx.new(|cx| TextureViewer::new(store, index, path, window, cx));
        viewer.read(cx).focus_handle().clone().focus(window, cx);
        viewer
    }) {
        log::error!("failed to open texture viewer: {err:#}");
    }
}

fn open_single(store: TextureStore, path: PathBuf, index: u32, cx: &mut App) {
    open_entry(store, index, path, cx);
}

fn open_dictionary(store: TextureStore, path: PathBuf, cx: &mut App) {
    let title = format!("{} - Texture Dictionary", file_name(&path));
    let options = window_options(title, size(px(1180.), px(760.)), cx);
    if let Err(err) = cx.open_window(options, |window, cx| {
        ui::close_through_gpui(window, cx);
        let viewer = cx.new(|cx| TextureDictionaryViewer::new(store, path, window, cx));
        viewer.read(cx).focus_handle().clone().focus(window, cx);
        viewer
    }) {
        log::error!("failed to open texture dictionary viewer: {err:#}");
    }
}

fn open_failed(path: PathBuf, message: String, cx: &mut App) {
    let title = format!("{} - Texture", file_name(&path));
    let options = window_options(title, size(px(720.), px(480.)), cx);
    if let Err(err) = cx.open_window(options, |window, cx| {
        ui::close_through_gpui(window, cx);
        let viewer = cx.new(|cx| TextureViewer::failed(path, message, window, cx));
        viewer.read(cx).focus_handle().clone().focus(window, cx);
        viewer
    }) {
        log::error!("failed to open texture error viewer: {err:#}");
    }
}

enum LoadError {
    NotTexture,
    Message(String),
}

fn load_store(
    path: &Path,
    access: &Access,
    fallback_inspector: bool,
) -> Result<TextureStore, LoadError> {
    let file =
        files::open_binary_with(path, access).map_err(|err| LoadError::Message(err.to_string()))?;
    let head = lforge_binary::read_at(&mut file.source.clone(), 0, 16).unwrap_or_default();
    if lforge_texture::is_store(&head) {
        return Store::open(file.source)
            .map(TextureStore::Rds5)
            .map_err(|err| LoadError::Message(err.to_string()));
    }
    let split = match files::resource_split_with(path, access, &file.source) {
        Ok(Some(split)) => split,
        Ok(None) => return Err(LoadError::NotTexture),
        Err(_) if fallback_inspector => return Err(LoadError::NotTexture),
        Err(err) => {
            return Err(LoadError::Message(format!(
                "the resource page split could not be established: {err}"
            )));
        }
    };
    match DictionaryStore::open(file.source, split.system_len) {
        Ok(store) => Ok(TextureStore::Dictionary(store)),
        Err(lforge_texture::Error::NotDictionary(_)) if fallback_inspector => {
            Err(LoadError::NotTexture)
        }
        Err(lforge_texture::Error::NotDictionary(reason)) => Err(LoadError::Message(format!(
            "the system segment is not a texture dictionary: {reason}"
        ))),
        Err(err) => Err(LoadError::Message(err.to_string())),
    }
}

pub(crate) fn render_image(
    image: lforge_texture::Image,
) -> Result<(Arc<gpui::RenderImage>, u32, u32), String> {
    let (width, height) = (image.width, image.height);
    let image = files::images::render_rgba(image.rgba, width, height)?;
    Ok((image, width, height))
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

pub(crate) fn window_options(title: String, window_size: Size<Pixels>, cx: &App) -> WindowOptions {
    let display = cx.primary_display();
    let target = match display.as_ref().map(|display| display.visible_bounds()) {
        Some(visible) => {
            let max_width = (f32::from(visible.size.width) - 24.).max(200.);
            let max_height = (f32::from(visible.size.height) - 48.).max(200.);
            size(
                px(f32::from(window_size.width).min(max_width)),
                px(f32::from(window_size.height).min(max_height)),
            )
        }
        None => window_size,
    };
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            display.as_ref().map(|display| display.id()),
            target,
            cx,
        ))),
        titlebar: Some(TitlebarOptions {
            title: Some(title.into()),
            ..Default::default()
        }),
        window_min_size: Some(size(px(420.), px(320.))),
        ..Default::default()
    }
}

pub(crate) fn metadata_rows(
    info: &TextureInfo,
    viewer_status: Option<&str>,
) -> Vec<(&'static str, SharedString)> {
    let mut rows = vec![
        ("Name", SharedString::from(info.name())),
        ("Container", SharedString::from(info.container)),
        ("Key", SharedString::from(format!("0x{:016X}", info.key))),
        ("Dimensions", SharedString::from(info.dimensions())),
        (
            "Format",
            SharedString::from(format!("{} (id {})", info.format.name, info.format.id)),
        ),
        ("Format evidence", SharedString::from(info.format_basis)),
        (
            "Kind / array",
            SharedString::from(format!("kind {}, array {}", info.kind, info.array_size)),
        ),
        (
            "Mip field",
            SharedString::from(format!(
                "{} (level meaning not established)",
                info.mip_field
            )),
        ),
        (
            "Decoded levels",
            SharedString::from(info.levels.len().to_string()),
        ),
        (
            "Level 0 size",
            SharedString::from(
                info.level0_len
                    .map(files::format_bytes_exact)
                    .unwrap_or_else(|| "-".to_string()),
            ),
        ),
        (
            "Encoded range",
            SharedString::from(files::format_bytes_exact(info.encoded_len)),
        ),
        (
            "Tile mode / flags",
            SharedString::from(format!("{}, {}", info.tile_mode, info.flags)),
        ),
    ];
    let status = viewer_status
        .map(str::to_string)
        .or_else(|| info.status.reason().map(str::to_string))
        .unwrap_or_else(|| "Decoded".to_string());
    rows.push(("Status", SharedString::from(status)));
    rows
}

pub(crate) fn metadata_panel(
    info: Option<&TextureInfo>,
    status: Option<String>,
) -> impl IntoElement {
    let rows = match info {
        Some(info) => metadata_rows(info, status.as_deref()),
        None => Vec::new(),
    };
    div()
        .flex()
        .flex_col()
        .flex_none()
        .gap_1()
        .p_3()
        .border_t_1()
        .border_color(rgb(theme::BORDER))
        .bg(rgb(theme::PANEL))
        .text_xs()
        .child(
            div().flex().items_center().gap_3().child(
                div()
                    .font_weight(gpui::FontWeight::SEMIBOLD)
                    .child("Texture metadata"),
            ),
        )
        .children(rows.into_iter().map(|(label, value)| {
            div()
                .flex()
                .gap_2()
                .child(
                    div()
                        .flex_none()
                        .w(px(120.))
                        .text_color(rgb(theme::TEXT_MUTED))
                        .child(label),
                )
                .child(div().flex_1().min_w_0().truncate().child(value))
        }))
}

pub(crate) fn initial_window_size(info: &TextureInfo, window: &Window) -> Size<Pixels> {
    let scale = window.scale_factor().max(0.1);
    let width = (info.width as f32 / scale + 120.).clamp(640., 1400.);
    let height = (info.height as f32 / scale + 340.).clamp(560., 800.);
    size(px(width), px(height))
}

pub(crate) fn texture_context_label(info: &TextureInfo) -> String {
    format!(
        "{}  ·  {}  ·  {} (id {})",
        info.name(),
        info.dimensions(),
        info.format.name,
        info.format.id
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use lforge_texture::StoreSet;

    /// Manual census over the real `.ttpf` stores below a game installation.
    /// The baseline is the recorded 912-descriptor store. The test reads only
    /// caller-supplied paths and is ignored by default.
    #[test]
    #[ignore = "requires LF_TEST_GAME_ROOT"]
    fn rds5_census_matches_the_recorded_baseline() {
        let root = std::env::var("LF_TEST_GAME_ROOT").expect("LF_TEST_GAME_ROOT");
        let ttdb = Path::new(&root).join("data").join("ttdb");
        let set = StoreSet::scan(&ttdb).expect("scan the texture stores");
        let cancel = std::sync::atomic::AtomicBool::new(false);
        let mut found = None;
        for store_index in 0..set.len() {
            let store = set.open(store_index).expect("open a store");
            if store.textures().len() != 912 {
                continue;
            }
            let mut decodable = 0usize;
            let mut decoded = 0usize;
            for (index, info) in store.textures().iter().enumerate() {
                if !info.status.is_decodable() {
                    continue;
                }
                decodable += 1;
                if store.level(index as u32, 0, &cancel).is_ok() {
                    decoded += 1;
                }
            }
            found = Some((decodable, decoded));
            break;
        }
        let (decodable, decoded) = found.expect("the 912-descriptor store");
        eprintln!("total=912 decodable={decodable} decoded={decoded}");
        assert_eq!(decodable, 886);
        assert_eq!(decoded, 872);
    }
}
