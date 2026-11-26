//! Independent window showing one decoded model resource.

use std::path::PathBuf;
use std::sync::Arc;

use gpui::{Context, Entity, FontWeight, Task, Window, div, prelude::*, px, rgb};

use super::viewport::{RendererStatus, Viewport};
use crate::files::{Access, model};
use crate::ui;
use crate::ui::theme;

const TOOLBAR_HEIGHT: f32 = 40.;
const STATUS_BAR_HEIGHT: f32 = 26.;
const DIAGNOSTICS_WIDTH: f32 = 360.;

struct Summary {
    meshes: usize,
    materials: usize,
    textures: usize,
    vertices: usize,
    triangles: usize,
}

enum State {
    Loading,
    Ready {
        viewport: Entity<Viewport>,
        summary: Summary,
        diagnostics: Vec<String>,
    },
    Failed(String),
}

pub struct ModelViewer {
    name: String,
    state: State,
    _load: Task<()>,
}

impl ModelViewer {
    pub fn new(
        path: PathBuf,
        access: Access,
        gta_root: Option<PathBuf>,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "Model".to_string());
        let load =
            cx.background_spawn(async move { model::load(&path, &access, gta_root.as_deref()) });
        let task = cx.spawn(async move |this, cx| {
            let result = load.await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(loaded) => {
                        let scene = Arc::new(loaded.scene);
                        let viewport = cx.new(|cx| Viewport::new(scene.clone(), cx));
                        cx.observe(&viewport, |_, _, cx| cx.notify()).detach();
                        let summary = Summary {
                            meshes: scene.meshes.len(),
                            materials: scene.materials.len(),
                            textures: scene.textures.len(),
                            vertices: scene.vertex_count(),
                            triangles: scene.triangle_count(),
                        };
                        let diagnostics = scene
                            .diagnostics
                            .iter()
                            .map(|diagnostic| {
                                let mut line = String::new();
                                if let Some(mesh) = &diagnostic.mesh {
                                    line.push_str(mesh);
                                    line.push_str(": ");
                                }
                                if let Some(material) = &diagnostic.material {
                                    line.push_str(material);
                                    line.push_str(": ");
                                }
                                if let Some(reference) = &diagnostic.reference {
                                    line.push_str(reference);
                                    line.push_str(": ");
                                }
                                line.push_str(&diagnostic.reason);
                                line
                            })
                            .collect();
                        this.name = loaded.name;
                        this.state = State::Ready {
                            viewport,
                            summary,
                            diagnostics,
                        };
                    }
                    Err(err) => this.state = State::Failed(err),
                }
                cx.notify();
            })
            .ok();
        });
        Self {
            name,
            state: State::Loading,
            _load: task,
        }
    }

    fn toolbar(&self, cx: &Context<Self>) -> impl IntoElement {
        let ready = matches!(self.state, State::Ready { .. });
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
                ui::button("reset-view", "Reset View")
                    .when(!ready, |el| el.text_color(rgb(theme::TEXT_DISABLED)))
                    .on_click(cx.listener(|this, _, _, cx| {
                        if let State::Ready { viewport, .. } = &this.state {
                            viewport
                                .clone()
                                .update(cx, |viewport, cx| viewport.reset_camera(cx));
                        }
                    })),
            )
            .child(div().w(px(1.)).h(px(18.)).mx_1().bg(rgb(theme::BORDER)))
            .child(
                div()
                    .min_w_0()
                    .flex_1()
                    .truncate()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(self.name.clone()),
            )
    }

    fn content(&self, _cx: &Context<Self>) -> gpui::AnyElement {
        match &self.state {
            State::Loading => ui::centered_message("Loading model.", None).into_any_element(),
            State::Failed(err) => {
                ui::centered_message("This model cannot be opened.", Some(err.clone()))
                    .into_any_element()
            }
            State::Ready {
                viewport,
                diagnostics,
                ..
            } => {
                let viewport_element = div()
                    .flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .child(viewport.clone());
                if diagnostics.is_empty() {
                    return viewport_element.into_any_element();
                }
                viewport_element
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_none()
                            .w(px(DIAGNOSTICS_WIDTH))
                            .h_full()
                            .overflow_hidden()
                            .bg(rgb(theme::PANEL))
                            .border_l_1()
                            .border_color(rgb(theme::BORDER))
                            .child(
                                div()
                                    .px_3()
                                    .py_2()
                                    .text_xs()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(theme::TEXT_MUTED))
                                    .child("DIAGNOSTICS"),
                            )
                            .child(
                                div()
                                    .id("model-diagnostics")
                                    .flex_1()
                                    .min_h_0()
                                    .overflow_y_scroll()
                                    .px_3()
                                    .pb_2()
                                    .flex()
                                    .flex_col()
                                    .gap_1()
                                    .children(diagnostics.iter().map(|line| {
                                        div()
                                            .text_xs()
                                            .text_color(rgb(theme::TEXT_MUTED))
                                            .child(line.clone())
                                    })),
                            ),
                    )
                    .into_any_element()
            }
        }
    }

    fn status_bar(&self, cx: &Context<Self>) -> impl IntoElement {
        let (left, right) = match &self.state {
            State::Loading => ("Loading model.".to_string(), String::new()),
            State::Failed(err) => (format!("Error: {err}"), String::new()),
            State::Ready {
                viewport, summary, ..
            } => {
                let viewport = viewport.read(cx);
                let renderer = match &viewport.status {
                    RendererStatus::Starting => "Renderer starting".to_string(),
                    RendererStatus::Ready { adapter, backend } => {
                        format!("{adapter} ({backend})")
                    }
                    RendererStatus::Failed(err) => format!("Renderer error: {err}"),
                };
                let left = format!(
                    "{} meshes  ·  {} materials  ·  {} textures  ·  {} vertices  ·  {} triangles",
                    summary.meshes,
                    summary.materials,
                    summary.textures,
                    format_count(summary.vertices),
                    format_count(summary.triangles)
                );
                (left, renderer)
            }
        };
        div()
            .flex()
            .flex_none()
            .items_center()
            .justify_between()
            .gap_3()
            .h(px(STATUS_BAR_HEIGHT))
            .px_3()
            .bg(rgb(theme::PANEL))
            .border_t_1()
            .border_color(rgb(theme::BORDER))
            .text_xs()
            .child(
                div()
                    .min_w_0()
                    .truncate()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(left),
            )
            .child(
                div()
                    .flex_none()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(right),
            )
    }
}

impl Render for ModelViewer {
    fn render(&mut self, _window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme::BACKGROUND))
            .text_color(rgb(theme::TEXT))
            .font_family(theme::UI_FONT)
            .text_sm()
            .child(self.toolbar(cx))
            .child(div().flex().flex_1().min_h_0().child(self.content(cx)))
            .child(self.status_bar(cx))
    }
}

fn format_count(value: usize) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, character) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(character);
    }
    out
}
