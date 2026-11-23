use std::path::PathBuf;

use gpui::{Context, ScrollEvent, Task, Window, div, img, prelude::*, px, rgb};

use crate::files::images::{self, DecodedImage};
use crate::ui;
use crate::ui::theme;

const TOOLBAR_HEIGHT: f32 = 40.;
const STATUS_BAR_HEIGHT: f32 = 26.;
const PADDING: f32 = 16.;
const ZOOM_STEPS: [f32; 13] = [0.05, 0.1, 0.25, 0.5, 0.75, 1., 1.5, 2., 3., 4., 6., 8., 16.];

enum State {
    Loading,
    Ready(DecodedImage),
    Failed(String),
}

pub struct ImageViewer {
    format: String,
    state: State,
    /// `None` fits the image to the window.
    zoom: Option<f32>,
    _load: Task<()>,
}

impl ImageViewer {
    pub fn new(path: PathBuf, _window: &mut Window, cx: &mut Context<Self>) -> Self {
        let format = path
            .extension()
            .map(|ext| ext.to_string_lossy().to_uppercase())
            .unwrap_or_default();
        let decode = cx.background_spawn(async move { images::load(&path) });
        let load = cx.spawn(async move |this, cx| {
            let result = decode.await;
            this.update(cx, |this, cx| {
                this.state = match result {
                    Ok(decoded) => State::Ready(decoded),
                    Err(err) => State::Failed(err),
                };
                cx.notify();
            })
            .ok();
        });
        Self {
            format,
            state: State::Loading,
            zoom: None,
            _load: load,
        }
    }

    /// Image pixels per device pixel that fit the image into the viewport,
    /// without enlarging small images.
    fn fit_zoom(&self, window: &Window) -> f32 {
        let State::Ready(image) = &self.state else {
            return 1.;
        };
        let viewport = window.viewport_size();
        let scale = window.scale_factor();
        let width = (f32::from(viewport.width) - 2. * PADDING) * scale;
        let height =
            (f32::from(viewport.height) - TOOLBAR_HEIGHT - STATUS_BAR_HEIGHT - 2. * PADDING)
                * scale;
        (width / image.width as f32)
            .min(height / image.height as f32)
            .clamp(ZOOM_STEPS[0], 1.)
    }

    fn zoom(&self, window: &Window) -> f32 {
        self.zoom.unwrap_or_else(|| self.fit_zoom(window))
    }

    fn step_zoom(&mut self, zoom_in: bool, window: &Window, cx: &mut Context<Self>) {
        let current = self.zoom(window);
        let next = if zoom_in {
            ZOOM_STEPS.iter().find(|step| **step > current * 1.001)
        } else {
            ZOOM_STEPS
                .iter()
                .rev()
                .find(|step| **step < current * 0.999)
        };
        if let Some(next) = next {
            self.zoom = Some(*next);
            cx.notify();
        }
    }

    fn scroll(&mut self, event: &ScrollEvent, window: &mut Window, cx: &mut Context<Self>) {
        if !event.modifiers.control {
            return;
        }
        let delta = event.delta.pixel_delta(window.line_height()).y;
        if delta != px(0.) {
            self.step_zoom(delta > px(0.), window, cx);
            cx.stop_propagation();
        }
    }
}

impl Render for ImageViewer {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let zoom = self.zoom(window);
        let zoom_label = format!("{:.0}%", zoom * 100.);
        let ready = matches!(self.state, State::Ready(_));

        let content = match &self.state {
            State::Loading => ui::centered_message("Loading…", None),
            State::Failed(err) => {
                ui::centered_message("This image cannot be opened.", Some(err.clone()))
            }
            State::Ready(image) => {
                let scale = window.scale_factor();
                let width = image.width as f32 * zoom / scale;
                let height = image.height as f32 * zoom / scale;
                div()
                    .id("image-scroll")
                    .size_full()
                    .overflow_scroll()
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_center()
                            .min_w_full()
                            .min_h_full()
                            .p(px(PADDING))
                            .child(
                                img(image.image.clone())
                                    .flex_none()
                                    .w(px(width))
                                    .h(px(height)),
                            ),
                    )
                    .into_any_element()
            }
        };

        let status = match &self.state {
            State::Ready(image) => {
                format!("{}  │  {} × {}", self.format, image.width, image.height)
            }
            _ => self.format.clone(),
        };

        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme::BACKGROUND))
            .text_color(rgb(theme::TEXT))
            .font_family(theme::UI_FONT)
            .text_sm()
            .child(
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
                        ui::button("fit", "Fit to Window")
                            .when(self.zoom.is_none(), |el| {
                                el.bg(rgb(theme::SELECTION))
                                    .border_color(rgb(theme::SELECTION_BORDER))
                            })
                            .on_click(cx.listener(|this, _, _, cx| {
                                this.zoom = None;
                                cx.notify();
                            })),
                    )
                    .child(div().w(px(1.)).h(px(18.)).mx_1().bg(rgb(theme::BORDER)))
                    .child(ui::button("zoom-out", "−").on_click(
                        cx.listener(|this, _, window, cx| this.step_zoom(false, window, cx)),
                    ))
                    .child(
                        div()
                            .w(px(56.))
                            .text_center()
                            .when(!ready, |el| el.text_color(rgb(theme::TEXT_MUTED)))
                            .child(zoom_label.clone()),
                    )
                    .child(ui::button("zoom-in", "+").on_click(
                        cx.listener(|this, _, window, cx| this.step_zoom(true, window, cx)),
                    ))
                    .child(ui::button("actual-size", "100%").on_click(cx.listener(
                        |this, _, _, cx| {
                            this.zoom = Some(1.);
                            cx.notify();
                        },
                    ))),
            )
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .bg(rgb(theme::VIEWPORT))
                    .on_scroll(
                        cx.listener(|this, event, window, cx| this.scroll(event, window, cx)),
                    )
                    .child(content),
            )
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
                    .child(status)
                    .child(format!("Zoom: {zoom_label}")),
            )
    }
}
