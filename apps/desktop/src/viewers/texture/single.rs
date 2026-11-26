//! One texture in its own window.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use gpui::{
    Context, Entity, FocusHandle, KeyDownEvent, Render, Task, Window, div, prelude::*, px, rgb,
};

use lforge_texture::Store;

use super::{
    ImagePreview, file_name, initial_window_size, metadata_panel, render_image,
    texture_context_label,
};
use crate::ui;
use crate::ui::theme;

const TOOLBAR_HEIGHT: f32 = 40.;
const STATUS_BAR_HEIGHT: f32 = 24.;
const METADATA_HEIGHT: f32 = 210.;

pub struct TextureViewer {
    path: PathBuf,
    store: Option<Store>,
    info: Option<lforge_texture::TextureInfo>,
    index: u32,
    level: u32,
    preview: Entity<ImagePreview>,
    focus_handle: FocusHandle,
    generation: u64,
    cancel: Option<Arc<AtomicBool>>,
    _decode: Option<Task<()>>,
    resized: bool,
}

impl TextureViewer {
    pub fn new(
        store: Store,
        index: u32,
        path: PathBuf,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let info = store.textures().get(index as usize).cloned();
        let preview = cx.new(|_| ImagePreview::new());
        let mut viewer = Self {
            path,
            store: Some(store),
            info,
            index,
            level: 0,
            preview,
            focus_handle: cx.focus_handle(),
            generation: 0,
            cancel: None,
            _decode: None,
            resized: false,
        };
        if viewer.info.is_none() {
            viewer.preview.update(cx, |preview, cx| {
                preview.set_error("The store holds no texture.".to_string(), cx)
            });
        } else {
            viewer.start_decode(cx);
        }
        viewer
    }

    pub fn failed(
        path: PathBuf,
        message: String,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let preview = cx.new(|_| ImagePreview::new());
        preview.update(cx, |preview, cx| preview.set_error(message, cx));
        Self {
            path,
            store: None,
            info: None,
            index: 0,
            level: 0,
            preview,
            focus_handle: cx.focus_handle(),
            generation: 0,
            cancel: None,
            _decode: None,
            resized: true,
        }
    }

    pub fn focus_handle(&self) -> &FocusHandle {
        &self.focus_handle
    }

    fn start_decode(&mut self, cx: &mut Context<Self>) {
        let Some(store) = self.store.clone() else {
            return;
        };
        if let Some(previous) = self.cancel.take() {
            previous.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        self.generation += 1;
        let generation = self.generation;
        let index = self.index;
        let level = self.level;
        self.preview
            .update(cx, |preview, cx| preview.set_loading(cx));
        let task = cx.spawn(async move |this, cx| {
            let decoded = cx
                .background_spawn(async move {
                    match store.decode(index, level, &cancel) {
                        Ok(image) => render_image(image).map(Some),
                        Err(lforge_texture::Error::Cancelled) => Ok(None),
                        Err(err) => Err(err.to_string()),
                    }
                })
                .await;
            this.update(cx, |this, cx| {
                if this.generation != generation {
                    return;
                }
                match decoded {
                    Ok(Some(image)) => {
                        this.preview.update(cx, |preview, cx| {
                            preview.set_image(image.0, image.1, image.2, cx)
                        });
                    }
                    Ok(None) => {}
                    Err(err) => {
                        this.preview
                            .update(cx, |preview, cx| preview.set_error(err, cx));
                    }
                }
            })
            .ok();
        });
        self._decode = Some(task);
    }

    fn set_level(&mut self, level: u32, cx: &mut Context<Self>) {
        if self.level == level {
            return;
        }
        self.level = level;
        self.start_decode(cx);
        cx.notify();
    }

    fn available_size(&self, window: &Window) -> (f32, f32) {
        let viewport = window.viewport_size();
        (
            (f32::from(viewport.width) - 32.).max(80.),
            (f32::from(viewport.height)
                - TOOLBAR_HEIGHT
                - STATUS_BAR_HEIGHT
                - METADATA_HEIGHT
                - 16.)
                .max(80.),
        )
    }

    fn key_down(&mut self, event: &KeyDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        match event.keystroke.key.as_str() {
            "f" => self.preview.update(cx, |preview, cx| preview.fit(cx)),
            "0" => {
                self.preview.update(cx, |preview, cx| {
                    preview.fit(cx);
                });
            }
            "=" | "+" => self.zoom(true, window, cx),
            "-" => self.zoom(false, window, cx),
            _ => {}
        }
    }

    fn zoom(&mut self, zoom_in: bool, _window: &mut Window, cx: &mut Context<Self>) {
        let factor = if zoom_in { 1.25 } else { 1. / 1.25 };
        self.preview
            .update(cx, |preview, cx| preview.step_zoom_public(factor, cx));
    }

    fn toolbar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let zoom = self.preview.read(cx).zoom_label();
        let levels = self
            .info
            .as_ref()
            .map(|info| info.levels.len())
            .unwrap_or(0);
        div()
            .flex()
            .flex_none()
            .items_center()
            .gap_1p5()
            .h(px(TOOLBAR_HEIGHT))
            .px_2()
            .border_b_1()
            .border_color(rgb(theme::BORDER))
            .child(
                ui::button("texture-fit", "Fit").on_click(cx.listener(|this, _, _, cx| {
                    this.preview.update(cx, |preview, cx| preview.fit(cx));
                })),
            )
            .child(
                ui::button("texture-zoom-out", "-")
                    .on_click(cx.listener(|this, _, window, cx| this.zoom(false, window, cx))),
            )
            .child(
                div()
                    .w(px(58.))
                    .text_center()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(zoom),
            )
            .child(
                ui::button("texture-zoom-in", "+")
                    .on_click(cx.listener(|this, _, window, cx| this.zoom(true, window, cx))),
            )
            .child(ui::button("texture-zoom-one", "100%").on_click(cx.listener(
                |this, _, _, cx| {
                    this.preview.update(cx, |preview, cx| {
                        preview.set_zoom_public(1., cx);
                    });
                },
            )))
            .when(levels > 1, |el| {
                el.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_1()
                        .child(div().text_color(rgb(theme::TEXT_MUTED)).child("Mip"))
                        .children((0..levels as u32).map(|level| {
                            ui::button(("mip", level as usize), format!("{level}")).on_click(
                                cx.listener(move |this, _, _, cx| this.set_level(level, cx)),
                            )
                        })),
                )
            })
            .child(div().flex_1())
            .when_some(self.info.as_ref(), |el, info| {
                el.child(
                    div()
                        .min_w_0()
                        .truncate()
                        .text_color(rgb(theme::TEXT_MUTED))
                        .child(texture_context_label(info)),
                )
            })
    }
}

impl Render for TextureViewer {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if !self.resized
            && let Some(info) = &self.info
        {
            window.resize(initial_window_size(info, window));
            self.resized = true;
        }
        let (width, height) = self.available_size(window);
        self.preview
            .update(cx, |preview, _| preview.set_available(width, height));

        let status = self
            .info
            .as_ref()
            .map(|info| {
                format!(
                    "{}  ·  {}  ·  {} bytes in range",
                    info.dimensions(),
                    info.format.name,
                    info.encoded_len
                )
            })
            .unwrap_or_default();
        let file = file_name(&self.path);

        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme::BACKGROUND))
            .text_color(rgb(theme::TEXT))
            .font_family(theme::UI_FONT)
            .text_sm()
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(Self::key_down))
            .child(self.toolbar(cx))
            .child(div().flex_1().min_h_0().child(self.preview.clone()))
            .child(metadata_panel(self.info.as_ref(), None))
            .child(
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .justify_between()
                    .h(px(STATUS_BAR_HEIGHT))
                    .px_3()
                    .border_t_1()
                    .border_color(rgb(theme::BORDER))
                    .text_xs()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(file)
                    .child(status),
            )
    }
}
