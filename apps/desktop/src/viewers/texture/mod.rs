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
use lforge_texture::{Store, TextureInfo};

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
    let load_path = path.clone();
    let load_access = access.clone();
    let load = cx.background_spawn(async move { load_store(&load_path, &load_access) });
    cx.spawn(async move |cx| {
        let result = load.await;
        cx.update(|cx| match result {
            Ok(store) if store.len() == 1 => open_single(store, path, 0, cx),
            Ok(store) => open_dictionary(store, path, cx),
            Err(err) => open_failed(path, err, cx),
        });
    })
    .detach();
}

/// Opens one entry of an already parsed store in the single-image viewer.
pub fn open_entry(store: Store, index: u32, path: PathBuf, cx: &mut App) {
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

fn open_single(store: Store, path: PathBuf, index: u32, cx: &mut App) {
    open_entry(store, index, path, cx);
}

fn open_dictionary(store: Store, path: PathBuf, cx: &mut App) {
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

fn load_store(path: &Path, access: &Access) -> Result<Store, String> {
    let file = files::open_binary_with(path, access).map_err(|err| err.to_string())?;
    Store::open(file.source).map_err(|err| err.to_string())
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
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            window_size,
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
        ("Key", SharedString::from(format!("0x{:016X}", info.key))),
        ("Dimensions", SharedString::from(info.dimensions())),
        (
            "Format",
            SharedString::from(format!("{} (id {})", info.format.name, info.format.id)),
        ),
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
    let height = (info.height as f32 / scale + 340.).clamp(560., 1000.);
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
