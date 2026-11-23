//! Development window for the Phase 0 cube renderer.

use gpui::{Context, Div, Entity, FontWeight, SharedString, Window, div, prelude::*, px, rgb};
use lforge_core::VERSION;

use crate::theme;
use crate::ui;
use crate::viewport::{RendererStatus, Viewport};

pub struct RendererDemo {
    viewport: Entity<Viewport>,
}

impl RendererDemo {
    pub fn new(cx: &mut Context<Self>) -> Self {
        let viewport = cx.new(Viewport::new);
        cx.observe(&viewport, |_, _, cx| cx.notify()).detach();
        Self { viewport }
    }

    fn properties(&self, cx: &Context<Self>) -> impl IntoElement {
        let viewport = self.viewport.read(cx);
        let camera = viewport.camera;
        let (adapter, backend) = match &viewport.status {
            RendererStatus::Ready { adapter, backend } => (adapter.clone(), backend.clone()),
            _ => ("—".to_string(), "—".to_string()),
        };
        let rotate_label = if viewport.auto_rotate {
            "Stop rotation"
        } else {
            "Auto-rotate"
        };

        panel("Properties")
            .w(px(280.))
            .border_l_1()
            .child(section("Camera"))
            .child(property("Yaw", format!("{:.1}°", camera.yaw.to_degrees())))
            .child(property(
                "Pitch",
                format!("{:.1}°", camera.pitch.to_degrees()),
            ))
            .child(property("Distance", format!("{:.2}", camera.distance)))
            .child(
                div()
                    .flex()
                    .gap_2()
                    .px_3()
                    .py_2()
                    .child(
                        ui::button("auto-rotate", rotate_label).on_click(cx.listener(
                            |this, _, _, cx| {
                                this.viewport
                                    .update(cx, |viewport, cx| viewport.toggle_auto_rotate(cx));
                            },
                        )),
                    )
                    .child(
                        ui::button("reset-camera", "Reset view").on_click(cx.listener(
                            |this, _, _, cx| {
                                this.viewport
                                    .update(cx, |viewport, cx| viewport.reset_camera(cx));
                            },
                        )),
                    ),
            )
            .child(section("Renderer"))
            .child(property("Adapter", adapter))
            .child(property("Backend", backend))
            .child(property(
                "Viewport",
                format!("{} × {} px", viewport.size.width.0, viewport.size.height.0),
            ))
    }

    fn status_bar(&self, cx: &Context<Self>) -> impl IntoElement {
        let (status, color): (SharedString, _) = match &self.viewport.read(cx).status {
            RendererStatus::Starting => ("Initializing renderer…".into(), theme::TEXT_MUTED),
            RendererStatus::Ready { adapter, backend } => {
                (format!("{adapter} ({backend})").into(), theme::TEXT_MUTED)
            }
            RendererStatus::Failed(message) => {
                (format!("Renderer error: {message}").into(), theme::ERROR)
            }
        };

        div()
            .flex()
            .flex_none()
            .items_center()
            .justify_between()
            .gap_3()
            .h(px(24.))
            .px_3()
            .bg(rgb(theme::PANEL))
            .border_t_1()
            .border_color(rgb(theme::BORDER))
            .text_xs()
            .child(
                div()
                    .min_w_0()
                    .truncate()
                    .text_color(rgb(color))
                    .child(status),
            )
            .child(
                div()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(format!("v{VERSION}")),
            )
    }
}

impl Render for RendererDemo {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
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
                    .flex_1()
                    .min_h_0()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .child(self.viewport.clone()),
                    )
                    .child(self.properties(cx)),
            )
            .child(self.status_bar(cx))
    }
}

fn panel(title: &'static str) -> Div {
    div()
        .flex()
        .flex_col()
        .flex_none()
        .h_full()
        .overflow_hidden()
        .bg(rgb(theme::PANEL))
        .border_color(rgb(theme::BORDER))
        .child(
            div()
                .px_3()
                .py_2()
                .text_xs()
                .font_weight(FontWeight::SEMIBOLD)
                .text_color(rgb(theme::TEXT_MUTED))
                .child(title.to_uppercase()),
        )
}

fn section(title: &'static str) -> impl IntoElement {
    div()
        .mt_2()
        .px_3()
        .pt_2()
        .pb_1()
        .border_t_1()
        .border_color(rgb(theme::BORDER))
        .font_weight(FontWeight::SEMIBOLD)
        .child(title)
}

fn property(label: &'static str, value: impl Into<SharedString>) -> impl IntoElement {
    div()
        .flex()
        .justify_between()
        .gap_3()
        .px_3()
        .py(px(3.))
        .child(
            div()
                .flex_none()
                .text_color(rgb(theme::TEXT_MUTED))
                .child(label),
        )
        .child(
            div()
                .min_w_0()
                .truncate()
                .font_family(theme::MONO_FONT)
                .child(value.into()),
        )
}
