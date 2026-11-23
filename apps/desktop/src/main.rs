#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod explorer;
mod files;
mod settings;
mod ui;
mod viewers;

use gpui::{App, Bounds, TitlebarOptions, WindowBounds, WindowOptions, prelude::*, px, size};
use lforge_core::APP_NAME;

use crate::explorer::Explorer;
use crate::settings::Settings;
use crate::ui::assets::Assets;

fn main() {
    env_logger::init();
    let settings_path = settings::default_path();
    let settings = match &settings_path {
        Some(path) => Settings::load(path),
        None => {
            log::warn!("APPDATA is not set; settings will not be saved");
            Settings::default()
        }
    };

    gpui_platform::application()
        .with_assets(Assets)
        .run(move |cx: &mut App| {
            explorer::bind_keys(cx);
            let options = WindowOptions {
                window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                    None,
                    size(px(1400.), px(860.)),
                    cx,
                ))),
                titlebar: Some(TitlebarOptions {
                    title: Some(APP_NAME.into()),
                    ..Default::default()
                }),
                window_min_size: Some(size(px(900.), px(540.))),
                ..Default::default()
            };
            let window = cx.open_window(options, |window, cx| {
                ui::close_through_gpui(window, cx);
                let explorer = cx.new(|cx| Explorer::new(settings, settings_path, cx));
                let focus_handle = explorer.read(cx).focus_handle().clone();
                focus_handle.focus(window, cx);
                explorer
            });
            let main_window = match window {
                Ok(window) => window.window_id(),
                Err(err) => {
                    log::error!("failed to open window: {err:#}");
                    cx.quit();
                    return;
                }
            };

            // Viewer windows do not keep the application alive.
            cx.on_window_closed(move |cx, closed| {
                if closed == main_window || cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
            cx.activate(true);
        });
}
