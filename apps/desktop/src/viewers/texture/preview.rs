//! A reusable image preview with fit, zoom, pan and a transparency grid.
//!
//! It owns no decoder. Callers hand it a `RenderImage` and reset it when the
//! image changes, so the texture viewers and any future image source share the
//! same interaction code.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;

use gpui::{
    Bounds, Context, DispatchPhase, MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent,
    Pixels, Point, Render, RenderImage, ScrollEvent, Size, Window, canvas, div, fill, img,
    prelude::*, px, rgb, size,
};

use crate::ui::theme;

const MIN_ZOOM: f32 = 0.02;
const MAX_ZOOM: f32 = 32.;
const MAX_FIT_ZOOM: f32 = 8.;
const FIT_PADDING: f32 = 8.;
const CHECKER_SIZE: f32 = 16.;
const CHECKER_DARK: u32 = 0x15151c;
const CHECKER_LIGHT: u32 = 0x20202a;

pub enum PreviewState {
    Empty,
    Loading,
    Ready {
        image: Arc<RenderImage>,
        width: u32,
        height: u32,
    },
    Error(String),
}

pub struct ImagePreview {
    state: PreviewState,
    /// `None` fits the image to the available area.
    zoom: Option<f32>,
    pan: Point<Pixels>,
    drag: Option<Point<Pixels>>,
    available: Size<Pixels>,
    bounds: Rc<Cell<Bounds<Pixels>>>,
}

impl ImagePreview {
    pub fn new() -> Self {
        Self {
            state: PreviewState::Loading,
            zoom: None,
            pan: Point::default(),
            drag: None,
            available: size(px(0.), px(0.)),
            bounds: Rc::new(Cell::new(Bounds::new(
                Point::default(),
                size(px(0.), px(0.)),
            ))),
        }
    }

    pub fn set_loading(&mut self, cx: &mut Context<Self>) {
        self.state = PreviewState::Loading;
        self.zoom = None;
        self.pan = Point::default();
        self.drag = None;
        cx.notify();
    }

    pub fn set_error(&mut self, message: String, cx: &mut Context<Self>) {
        self.state = PreviewState::Error(message);
        self.zoom = None;
        self.pan = Point::default();
        self.drag = None;
        cx.notify();
    }

    pub fn set_image(
        &mut self,
        image: Arc<RenderImage>,
        width: u32,
        height: u32,
        cx: &mut Context<Self>,
    ) {
        self.state = PreviewState::Ready {
            image,
            width,
            height,
        };
        self.zoom = None;
        self.pan = Point::default();
        self.drag = None;
        cx.notify();
    }

    pub fn clear(&mut self, cx: &mut Context<Self>) {
        self.state = PreviewState::Empty;
        self.zoom = None;
        self.pan = Point::default();
        self.drag = None;
        cx.notify();
    }

    pub fn set_available(&mut self, width: f32, height: f32) {
        let next = size(px(width.max(1.)), px(height.max(1.)));
        if self.available != next {
            self.available = next;
            self.clamp_pan();
        }
    }

    pub fn fit(&mut self, cx: &mut Context<Self>) {
        self.zoom = None;
        self.pan = Point::default();
        self.clamp_pan();
        cx.notify();
    }

    /// Steps the zoom from a toolbar button, keeping the image centred.
    pub fn step_zoom_public(&mut self, factor: f32, cx: &mut Context<Self>) {
        self.step_zoom(factor, None, cx);
    }

    /// Sets an absolute zoom and centres the image.
    pub fn set_zoom_public(&mut self, zoom: f32, cx: &mut Context<Self>) {
        if self.image_size().is_none() {
            return;
        }
        self.zoom = Some(zoom.clamp(MIN_ZOOM, MAX_ZOOM));
        self.pan = Point::default();
        self.clamp_pan();
        cx.notify();
    }

    pub fn zoom_percent(&self) -> f32 {
        self.effective_zoom() * 100.
    }

    pub fn zoom_label(&self) -> String {
        if self.image_size().is_none() {
            "-".to_string()
        } else {
            format!("{:.0}%", self.zoom_percent())
        }
    }

    fn image_size(&self) -> Option<(u32, u32)> {
        match &self.state {
            PreviewState::Ready { width, height, .. } => Some((*width, *height)),
            _ => None,
        }
    }

    fn fit_zoom(&self) -> f32 {
        let Some((width, height)) = self.image_size() else {
            return 1.;
        };
        let available_width = (f32::from(self.available.width) - 2. * FIT_PADDING).max(1.);
        let available_height = (f32::from(self.available.height) - 2. * FIT_PADDING).max(1.);
        (available_width / width.max(1) as f32)
            .min(available_height / height.max(1) as f32)
            .clamp(MIN_ZOOM, MAX_FIT_ZOOM)
    }

    fn effective_zoom(&self) -> f32 {
        self.zoom.unwrap_or_else(|| self.fit_zoom())
    }

    fn step_zoom(&mut self, factor: f32, cursor: Option<Point<Pixels>>, cx: &mut Context<Self>) {
        if self.image_size().is_none() {
            return;
        }
        let old = self.effective_zoom();
        let new = (old * factor).clamp(MIN_ZOOM, MAX_ZOOM);
        if (new - old).abs() < f32::EPSILON {
            return;
        }
        let viewport = self.available;
        let center = Point::new(viewport.width / 2., viewport.height / 2.);
        let cursor = cursor.unwrap_or(center);
        let origin = self.bounds.get().origin;
        let local = Point::new(cursor.x - origin.x, cursor.y - origin.y);
        let before = Point::new(
            (local.x - center.x - self.pan.x) / old,
            (local.y - center.y - self.pan.y) / old,
        );
        self.pan = Point::new(
            local.x - center.x - before.x * new,
            local.y - center.y - before.y * new,
        );
        self.zoom = Some(new);
        self.clamp_pan();
        cx.notify();
    }

    fn scroll(&mut self, event: &ScrollEvent, window: &mut Window, cx: &mut Context<Self>) {
        let delta = event.delta.pixel_delta(window.line_height()).y;
        if delta == px(0.) {
            return;
        }
        let factor = if delta > px(0.) { 1.15 } else { 1. / 1.15 };
        self.step_zoom(factor, Some(event.position), cx);
        cx.stop_propagation();
    }

    fn begin_drag(&mut self, event: &MouseDownEvent, _window: &mut Window, cx: &mut Context<Self>) {
        if event.button != MouseButton::Left || self.image_size().is_none() {
            return;
        }
        self.drag = Some(event.position);
        cx.stop_propagation();
    }

    fn drag_to(&mut self, position: Point<Pixels>, cx: &mut Context<Self>) {
        let Some(last) = self.drag else {
            return;
        };
        let delta = position - last;
        self.pan = Point::new(self.pan.x + delta.x, self.pan.y + delta.y);
        self.drag = Some(position);
        self.clamp_pan();
        cx.notify();
    }

    fn end_drag(&mut self, cx: &mut Context<Self>) {
        if self.drag.take().is_some() {
            cx.notify();
        }
    }

    fn clamp_pan(&mut self) {
        let Some((width, height)) = self.image_size() else {
            self.pan = Point::default();
            return;
        };
        let zoom = self.effective_zoom();
        let image = Size::new(px(width as f32 * zoom), px(height as f32 * zoom));
        let max_x = ((image.width - self.available.width) / 2.).max(px(0.));
        let max_y = ((image.height - self.available.height) / 2.).max(px(0.));
        self.pan = Point::new(
            self.pan.x.clamp(-max_x, max_x),
            self.pan.y.clamp(-max_y, max_y),
        );
    }

    fn pan_tracker(entity: gpui::Entity<Self>) -> impl IntoElement {
        canvas(
            |_, _, _| {},
            move |_: Bounds<Pixels>, (), window, _| {
                let move_entity = entity.clone();
                window.on_mouse_event(move |event: &MouseMoveEvent, phase, _, cx| {
                    if phase == DispatchPhase::Bubble {
                        move_entity.update(cx, |this, cx| this.drag_to(event.position, cx));
                    }
                });
                let up_entity = entity.clone();
                window.on_mouse_event(move |event: &MouseUpEvent, phase, _, cx| {
                    if phase == DispatchPhase::Bubble && event.button == MouseButton::Left {
                        up_entity.update(cx, |this, cx| this.end_drag(cx));
                    }
                });
            },
        )
        .absolute()
        .size_0()
    }
}

impl Render for ImagePreview {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let available = self.available;
        let zoom = self.effective_zoom();
        let measured = self.bounds.clone();
        let state = match &self.state {
            PreviewState::Empty => "Empty",
            PreviewState::Loading => "Loading",
            PreviewState::Ready { .. } => "Ready",
            PreviewState::Error(_) => "Error",
        };

        let content = match &self.state {
            PreviewState::Empty => div()
                .flex()
                .size_full()
                .items_center()
                .justify_center()
                .text_color(rgb(theme::TEXT_MUTED))
                .child("No texture selected")
                .into_any_element(),
            PreviewState::Loading => div()
                .flex()
                .size_full()
                .items_center()
                .justify_center()
                .text_color(rgb(theme::TEXT_MUTED))
                .child("Decoding.")
                .into_any_element(),
            PreviewState::Error(message) => div()
                .flex()
                .flex_col()
                .size_full()
                .items_center()
                .justify_center()
                .gap_2()
                .p_6()
                .text_center()
                .child(
                    div()
                        .text_color(rgb(theme::ERROR))
                        .child("This texture cannot be decoded."),
                )
                .child(
                    div()
                        .max_w(px(520.))
                        .text_xs()
                        .text_color(rgb(theme::TEXT_MUTED))
                        .child(message.clone()),
                )
                .into_any_element(),
            PreviewState::Ready {
                image,
                width,
                height,
            } => {
                let scaled_width = (*width as f32 * zoom).max(1.);
                let scaled_height = (*height as f32 * zoom).max(1.);
                let left = (f32::from(available.width) - scaled_width) / 2. + f32::from(self.pan.x);
                let top =
                    (f32::from(available.height) - scaled_height) / 2. + f32::from(self.pan.y);
                div()
                    .absolute()
                    .left(px(left))
                    .top(px(top))
                    .w(px(scaled_width))
                    .h(px(scaled_height))
                    .child(img(image.clone()).size_full())
                    .into_any_element()
            }
        };

        div()
            .relative()
            .size_full()
            .overflow_hidden()
            .bg(rgb(theme::VIEWPORT))
            .on_scroll(cx.listener(Self::scroll))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::begin_drag))
            .on_mouse_move(
                cx.listener(|this, event: &MouseMoveEvent, _, cx| this.drag_to(event.position, cx)),
            )
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _, _, cx| this.end_drag(cx)),
            )
            .child(
                canvas(
                    move |bounds, _, _| {
                        measured.set(bounds);
                        bounds
                    },
                    move |bounds, _, window, _| {
                        let width = f32::from(bounds.size.width);
                        let height = f32::from(bounds.size.height);
                        let cols = (width / CHECKER_SIZE).ceil() as usize + 1;
                        let rows = (height / CHECKER_SIZE).ceil() as usize + 1;
                        for row in 0..rows {
                            for col in 0..cols {
                                let color = if (row + col) % 2 == 0 {
                                    CHECKER_DARK
                                } else {
                                    CHECKER_LIGHT
                                };
                                let tile = Bounds::new(
                                    Point::new(
                                        bounds.left() + px(col as f32 * CHECKER_SIZE),
                                        bounds.top() + px(row as f32 * CHECKER_SIZE),
                                    ),
                                    size(px(CHECKER_SIZE), px(CHECKER_SIZE)),
                                );
                                window.paint_quad(fill(tile, rgb(color)));
                            }
                        }
                    },
                )
                .absolute()
                .inset_0(),
            )
            .child(content)
            .child(Self::pan_tracker(cx.entity()))
            .child(
                div()
                    .absolute()
                    .left(px(8.))
                    .bottom(px(8.))
                    .px_1p5()
                    .py_0p5()
                    .rounded_sm()
                    .bg(rgb(theme::SURFACE))
                    .text_xs()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(format!("{state}  {:.0}%", zoom * 100.)),
            )
    }
}
