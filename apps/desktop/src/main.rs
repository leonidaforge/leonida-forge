#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod theme;
mod viewport;
mod workspace;

use gpui::{App, Bounds, TitlebarOptions, WindowBounds, WindowOptions, prelude::*, px, size};
use lforge_core::APP_NAME;

use crate::workspace::Workspace;

fn main() {
    env_logger::init();
    gpui_platform::application().run(|cx: &mut App| {
        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();

        let options = WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
                None,
                size(px(1280.), px(800.)),
                cx,
            ))),
            titlebar: Some(TitlebarOptions {
                title: Some(APP_NAME.into()),
                ..Default::default()
            }),
            window_min_size: Some(size(px(800.), px(480.))),
            ..Default::default()
        };
        if let Err(err) = cx.open_window(options, |_, cx| cx.new(Workspace::new)) {
            log::error!("failed to open window: {err:#}");
            cx.quit();
            return;
        }
        cx.activate(true);
    });
}
