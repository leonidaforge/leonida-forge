//! Independent window showing one decoded model resource.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use gpui::{Context, Entity, FontWeight, Task, Window, div, prelude::*, px, rgb};

use super::BonePanel;
use super::viewport::{RendererStatus, Viewport};
use crate::files::{Access, model};
use crate::ui;
use crate::ui::theme;

const TOOLBAR_HEIGHT: f32 = 40.;
const STATUS_BAR_HEIGHT: f32 = 26.;
const DIAGNOSTICS_WIDTH: f32 = 360.;
/// Largest number of hierarchy rows built in one frame. A filter narrows a
/// larger skeleton; the decoded bones themselves stay in the scene.
const MAX_BONE_ROWS: usize = 600;

struct Summary {
    meshes: usize,
    materials: usize,
    textures: usize,
    vertices: usize,
    triangles: usize,
    completeness: lforge_model::ModelCompleteness,
    exact_layout: bool,
}

enum State {
    Loading,
    Ready {
        viewport: Entity<Viewport>,
        summary: Box<Summary>,
        fragment: Option<Box<model::FragmentSummary>>,
        diagnostics: Vec<String>,
    },
    Failed(String),
}

pub struct ModelViewer {
    name: String,
    state: State,
    cancel: Arc<AtomicBool>,
    /// Collapse state and bone selection of this window only.
    bones: BonePanel,
    bone_filter: Entity<ui::text_field::TextField>,
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
        let cancel = Arc::new(AtomicBool::new(false));
        let load_cancel = cancel.clone();
        let bone_filter =
            cx.new(|cx| ui::text_field::TextField::new("Filter bones, indices, keys", cx));
        cx.observe(&bone_filter, |_, _, cx| cx.notify()).detach();
        let load = cx.background_spawn(async move {
            model::load_with_cancel(&path, &access, gta_root.as_deref(), &load_cancel)
        });
        let task = cx.spawn(async move |this, cx| {
            let result = load.await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(loaded) => {
                        let scene = Arc::new(loaded.scene);
                        let viewport = cx.new(|cx| Viewport::new(scene.clone(), cx));
                        cx.observe(&viewport, |_, _, cx| cx.notify()).detach();
                        let summary = Box::new(Summary {
                            meshes: scene.meshes.len(),
                            materials: scene.materials.len(),
                            textures: scene.textures.len(),
                            vertices: scene.vertex_count(),
                            triangles: scene.triangle_count(),
                            completeness: loaded.completeness.clone(),
                            exact_layout: loaded.exact_layout,
                        });
                        let mut lines: Vec<String> = loaded.completeness.notes.to_vec();
                        if let lforge_model::GeometryCompleteness::Partial { reason } =
                            &loaded.completeness.geometry
                        {
                            lines.push(format!("Partial geometry: {reason}"));
                        }
                        if let lforge_model::TextureCompleteness::Partial { missing } =
                            loaded.completeness.textures
                        {
                            lines.push(format!(
                                "Partial textures: {missing} material(s) use a fallback"
                            ));
                        }
                        let unresolved = loaded
                            .texture_bindings
                            .iter()
                            .filter(|binding| binding.texture.is_none())
                            .count();
                        if unresolved > 0 {
                            lines.push(format!(
                                "{unresolved} of {} texture binding(s) are unresolved",
                                loaded.texture_bindings.len()
                            ));
                        }
                        if !loaded.exact_layout {
                            lines.push(
                                "The system/graphics boundary was inferred; no native page metadata was available."
                                    .into(),
                            );
                        }
                        lines.extend(scene.diagnostics.iter().map(|diagnostic| {
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
                        }));
                        if let Some(fragment) = &loaded.fragment {
                            lines.push(format!(
                                "Fragment: {}; root counts at +0x30 {:?}; {} root pointer(s) reach unidentified records",
                                match fragment.components.len() {
                                    1 => "one component, the member drawable".to_string(),
                                    count => format!("{count} components"),
                                },
                                fragment.counts,
                                fragment.unexplained
                            ));
                            match &fragment.completeness {
                                lforge_model::FragmentCompleteness::SinglePrimaryDrawable => {
                                    lines.push(
                                        "Fragment completeness: one member drawable, fully decoded"
                                            .into(),
                                    );
                                }
                                lforge_model::FragmentCompleteness::Partial { reason } => {
                                    lines.push(format!("Partial fragment: {reason}"));
                                }
                                lforge_model::FragmentCompleteness::Unsupported { reason } => {
                                    lines.push(format!("Unsupported fragment: {reason}"));
                                }
                            }
                            let unsupported = fragment
                                .components
                                .iter()
                                .filter(|component| component.status != "decoded")
                                .count();
                            if unsupported > 0 {
                                lines.push(format!(
                                    "{unsupported} of {} component(s) are not fully decoded",
                                    fragment.components.len()
                                ));
                            }
                        }
                        match &loaded.completeness.skeleton {
                            lforge_model::SkeletonCompleteness::NotPresent => {
                                lines.push(
                                    "Skeleton: none; the drawable is complete as a static model"
                                        .into(),
                                );
                            }
                            lforge_model::SkeletonCompleteness::Complete => lines.push(format!(
                                "Skeleton: complete ({} bones)",
                                scene.skeleton.as_ref().map_or(0, |skeleton| skeleton.bones.len())
                            )),
                            lforge_model::SkeletonCompleteness::Partial { reason } => {
                                lines.push(format!("Partial skeleton: {reason}"));
                            }
                            lforge_model::SkeletonCompleteness::Unsupported { reason } => {
                                lines.push(format!("Unsupported skeleton: {reason}"));
                            }
                        }
                        match &loaded.completeness.associations {
                            lforge_model::AssociationCompleteness::NotReferenced => {}
                            lforge_model::AssociationCompleteness::Complete => lines.push(format!(
                                "Geometry bone associations: complete ({} primitive(s))",
                                scene.associations.len()
                            )),
                            lforge_model::AssociationCompleteness::Partial { reason } => {
                                lines.push(format!("Partial bone associations: {reason}"));
                            }
                            lforge_model::AssociationCompleteness::Unsupported { reason } => {
                                lines.push(format!("Unsupported bone associations: {reason}"));
                            }
                        }
                        match &loaded.completeness.placement {
                            lforge_model::PlacementCompleteness::NotRequired => {}

                            lforge_model::PlacementCompleteness::Unverified { reason } => {
                                lines.push(format!("Static placement unverified: {reason}"));
                            }
                            lforge_model::PlacementCompleteness::Applied { reason } => {
                                lines.push(format!("Static placement applied: {reason}"));
                            }
                        }
                        this.bones.reset();
                        let diagnostics = lines;
                        this.name = loaded.name;
                        this.state = State::Ready {
                            viewport,
                            summary,
                            fragment: loaded.fragment.map(Box::new),
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
            cancel,
            bones: BonePanel::new(),
            bone_filter,
            _load: task,
        }
    }

    fn toolbar(&self, cx: &Context<Self>) -> impl IntoElement {
        let ready = matches!(self.state, State::Ready { .. });
        let (has_skeleton, skeleton_visible, any_mesh) = match &self.state {
            State::Ready { viewport, .. } => {
                let viewport = viewport.read(cx);
                (
                    viewport.has_skeleton(),
                    viewport.skeleton_visible(),
                    viewport.any_mesh_visible(),
                )
            }
            _ => (false, false, true),
        };
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
            .child(
                ui::button(
                    "skeleton-toggle",
                    if skeleton_visible {
                        "Hide Skeleton"
                    } else {
                        "Show Skeleton"
                    },
                )
                .when(!has_skeleton, |el| el.text_color(rgb(theme::TEXT_DISABLED)))
                .when(has_skeleton, |el| {
                    el.on_click(cx.listener(|this, _, _, cx| {
                        if let State::Ready { viewport, .. } = &this.state {
                            viewport
                                .clone()
                                .update(cx, |viewport, cx| viewport.toggle_skeleton(cx));
                        }
                    }))
                }),
            )
            .child(
                ui::button(
                    "mesh-toggle",
                    if any_mesh { "Hide Mesh" } else { "Show Mesh" },
                )
                .when(!ready, |el| el.text_color(rgb(theme::TEXT_DISABLED)))
                .when(ready, |el| {
                    el.on_click(cx.listener(|this, _, _, cx| {
                        if let State::Ready { viewport, .. } = &this.state {
                            let visible = !{
                                let viewport = viewport.read(cx);
                                viewport.any_mesh_visible()
                            };
                            viewport.clone().update(cx, |viewport, cx| {
                                viewport.set_all_meshes_visible(visible, cx);
                            });
                        }
                    }))
                }),
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

    fn content(&self, cx: &Context<Self>) -> gpui::AnyElement {
        match &self.state {
            State::Loading => ui::centered_message("Loading model.", None).into_any_element(),
            State::Failed(err) => {
                ui::centered_message("This model cannot be opened.", Some(err.clone()))
                    .into_any_element()
            }
            State::Ready {
                viewport,
                fragment,
                diagnostics,
                ..
            } => {
                let viewport_element = div()
                    .flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .child(viewport.clone());
                if fragment.is_none() && diagnostics.is_empty() && !viewport.read(cx).has_skeleton()
                {
                    return viewport_element.into_any_element();
                }
                let mut panel = div()
                    .flex()
                    .flex_col()
                    .flex_none()
                    .w(px(DIAGNOSTICS_WIDTH))
                    .h_full()
                    .overflow_hidden()
                    .bg(rgb(theme::PANEL))
                    .border_l_1()
                    .border_color(rgb(theme::BORDER));
                panel = panel.child(self.skeleton_section(viewport, cx));
                if let Some(fragment) = fragment {
                    panel = panel.child(components_section(viewport, fragment, cx));
                }
                if !diagnostics.is_empty() {
                    panel = panel.child(
                        div()
                            .px_3()
                            .py_2()
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(theme::TEXT_MUTED))
                            .child("DIAGNOSTICS"),
                    );
                    panel = panel.child(
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
                    );
                }
                viewport_element.child(panel).into_any_element()
            }
        }
    }

    /// The skeleton section: visibility, filter, hierarchy and the selected
    /// bone's metadata. It reads the decoded skeleton from the viewport's
    /// scene, so expanding a row never decodes or reloads anything.
    fn skeleton_section(
        &self,
        viewport: &Entity<Viewport>,
        cx: &Context<Self>,
    ) -> gpui::AnyElement {
        let viewport_state = viewport.read(cx);
        let Some(skeleton) = viewport_state.skeleton() else {
            return div().into_any_element();
        };
        let bones = skeleton.bones.len();
        let roots = skeleton.roots.len();
        let depth = skeleton.max_depth;
        let selected = self.bones.selected();
        let filter = self.bone_filter.read(cx).text().to_string();
        let rows = self.bones.rows(skeleton, &filter);
        let shown = rows.len();
        let mut metadata = Vec::new();
        if let Some(index) = selected {
            metadata = self.bones.metadata(skeleton, viewport_state.associations());
            let _ = index;
        }
        let _ = viewport_state;

        let mut list = div()
            .id("bone-hierarchy")
            .min_h_0()
            .flex_1()
            .overflow_y_scroll()
            .pb_1();
        for row in rows.into_iter().take(MAX_BONE_ROWS) {
            let index = row.index;
            let is_selected = selected == Some(index);
            let chevron = if row.has_children {
                if row.collapsed {
                    "\u{25B8}"
                } else {
                    "\u{25BE}"
                }
            } else {
                "\u{00B7}"
            };
            let toggle = div()
                .id(("bone-toggle", index))
                .w(px(14.))
                .flex_none()
                .text_xs()
                .text_color(rgb(theme::TEXT_MUTED))
                .cursor_pointer()
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.bones.toggle(index);
                    cx.notify();
                }))
                .child(chevron);
            let label = div()
                .id(("bone-row", index))
                .flex_1()
                .min_w_0()
                .cursor_pointer()
                .on_click(cx.listener(move |this, _, _, cx| {
                    this.bones.select(Some(index));
                    if let State::Ready { viewport, .. } = &this.state {
                        viewport
                            .clone()
                            .update(cx, |viewport, cx| viewport.select_bone(Some(index), cx));
                    }
                    cx.notify();
                }))
                .child(
                    div()
                        .text_xs()
                        .truncate()
                        .child(format!("{} {}", row.label, row.detail)),
                );
            list = list.child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .pr_3()
                    .py_0p5()
                    .pl(px(8.0 + row.depth as f32 * 10.0))
                    .when(is_selected, |el| el.bg(rgb(theme::SELECTION)))
                    .hover(|style| style.bg(rgb(theme::HOVER)))
                    .child(toggle)
                    .child(label),
            );
        }

        let mut section = div()
            .flex()
            .flex_col()
            .flex_none()
            .max_h(px(360.))
            .border_b_1()
            .border_color(rgb(theme::BORDER))
            .child(
                div()
                    .flex()
                    .items_center()
                    .justify_between()
                    .px_3()
                    .py_2()
                    .child(
                        div()
                            .text_xs()
                            .font_weight(FontWeight::SEMIBOLD)
                            .text_color(rgb(theme::TEXT_MUTED))
                            .child(format!(
                                "SKELETON \u{00B7} {bones} BONE(S) \u{00B7} {roots} ROOT(S) \u{00B7} DEPTH {depth}"
                            )),
                    )
                    .child(
                        ui::button(
                            "bones-toggle-overlay",
                            if viewport.read(cx).skeleton_visible() {
                                "Hide"
                            } else {
                                "Show"
                            },
                        )
                        .on_click(cx.listener(|this, _, _, cx| {
                            if let State::Ready { viewport, .. } = &this.state {
                                viewport
                                    .clone()
                                    .update(cx, |viewport, cx| viewport.toggle_skeleton(cx));
                            }
                        })),
                    ),
            )
            .child(
                div()
                    .px_3()
                    .py_1()
                    .child(self.bone_filter.clone()),
            );
        if !metadata.is_empty() {
            section = section.child(
                div()
                    .id("bone-metadata")
                    .flex()
                    .flex_col()
                    .gap_0p5()
                    .px_3()
                    .pb_1()
                    .children(metadata.into_iter().map(|(key, value)| {
                        div()
                            .flex()
                            .gap_1()
                            .text_xs()
                            .child(
                                div()
                                    .w(px(96.))
                                    .flex_none()
                                    .text_color(rgb(theme::TEXT_MUTED))
                                    .child(key),
                            )
                            .child(div().min_w_0().truncate().child(value))
                    })),
            );
        }
        if shown > MAX_BONE_ROWS {
            section = section.child(
                div()
                    .px_3()
                    .py_1()
                    .text_xs()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(format!(
                        "Showing the first {MAX_BONE_ROWS} of {shown} rows; filter to narrow them."
                    )),
            );
        }
        section.child(list).into_any_element()
    }

    fn status_bar(&self, cx: &Context<Self>) -> impl IntoElement {
        let (left, right) = match &self.state {
            State::Loading => ("Loading model.".to_string(), String::new()),
            State::Failed(err) => (format!("Error: {err}"), String::new()),
            State::Ready {
                viewport,
                summary,
                fragment,
                ..
            } => {
                let viewport = viewport.read(cx);
                let renderer = match &viewport.status {
                    RendererStatus::Starting => "Renderer starting".to_string(),
                    RendererStatus::Ready { adapter, backend } => {
                        format!("{adapter} ({backend})")
                    }
                    RendererStatus::Failed(err) => format!("Renderer error: {err}"),
                };
                let geometry = match &summary.completeness.geometry {
                    lforge_model::GeometryCompleteness::Complete => "complete selected LOD",
                    lforge_model::GeometryCompleteness::Partial { .. } => "partial selected LOD",
                    lforge_model::GeometryCompleteness::Unsupported { .. } => {
                        "unsupported geometry"
                    }
                };
                let layout = if summary.exact_layout {
                    "native page layout"
                } else {
                    "inferred boundary"
                };
                let textures = match &summary.completeness.textures {
                    lforge_model::TextureCompleteness::Complete => "complete textures",
                    lforge_model::TextureCompleteness::Partial { .. } => "partial textures",
                    lforge_model::TextureCompleteness::NotReferenced => "no texture references",
                };
                let left = format!(
                    "{}{geometry}  \u{00B7}  {textures}  \u{00B7}  {layout}  \u{00B7}  {} meshes  \u{00B7}  {} materials  \u{00B7}  {} textures  \u{00B7}  {} vertices  \u{00B7}  {} triangles",
                    if fragment.is_some() {
                        "fragment  \u{00B7}  "
                    } else {
                        ""
                    },
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

impl Drop for ModelViewer {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
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

/// The drawable contents of a fragment.
///
/// Two structural levels are listed separately because they are different
/// things: a component is one member drawable, and its meshes are that
/// drawable's models. A component row toggles every mesh it owns; a mesh row
/// toggles one model. Visibility is applied to the uploaded scene, so nothing
/// is re-read or re-decoded and no completeness verdict changes.
fn components_section(
    viewport: &Entity<Viewport>,
    fragment: &model::FragmentSummary,
    cx: &Context<ModelViewer>,
) -> impl IntoElement {
    let viewport_state = viewport.read(cx);
    let mesh_total = viewport_state.mesh_count();
    let visible: Vec<bool> = fragment
        .components
        .iter()
        .map(|component| viewport_state.component_visible(component.meshes.clone()))
        .collect();
    let mesh_rows: Vec<(usize, String, usize, bool)> = fragment
        .components
        .iter()
        .flat_map(|component| {
            component.meshes.clone().map(|mesh| {
                (
                    mesh,
                    viewport_state
                        .mesh_name(mesh)
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("mesh {mesh}")),
                    viewport_state.mesh_primitives(mesh),
                    viewport_state.mesh_visible(mesh),
                )
            })
        })
        .collect();
    let _ = viewport_state;
    let rows = fragment
        .components
        .iter()
        .zip(visible)
        .flat_map(|(component, shown)| {
            let meshes = component.meshes.clone();
            let label = format!(
                "{} {}",
                if shown { "\u{25CF}" } else { "\u{25CB}" },
                component.name
            );
            let detail = format!(
                "component #{}  lod {}  {} primitive(s)  {} vertices  {} triangles  {}  \u{00B7}  drawable +{:#x}",
                component.index,
                component
                    .lod
                    .map_or_else(|| "-".to_string(), |lod| lod.to_string()),
                component.primitives,
                format_count(component.vertices),
                format_count(component.triangles),
                component.status,
                component.drawable_at
            );
            let component_row = div()
                .id(("component", component.index))
                .flex()
                .flex_col()
                .gap_0p5()
                .px_3()
                .py_1()
                .rounded_sm()
                .cursor_pointer()
                .hover(|style| style.bg(rgb(theme::HOVER)))
                .on_click(cx.listener(move |this, _, _, cx| {
                    let State::Ready { viewport, .. } = &this.state else {
                        return;
                    };
                    let viewport = viewport.clone();
                    let meshes = meshes.clone();
                    viewport.update(cx, |viewport, cx| {
                        viewport.set_meshes_visible(meshes, !shown, cx);
                    });
                }))
                .child(div().text_xs().child(label))
                .child(
                    div()
                        .text_xs()
                        .text_color(rgb(theme::TEXT_MUTED))
                        .child(detail),
                );
            let mesh_rows = mesh_rows
                .iter()
                .filter(|(mesh, ..)| component.meshes.contains(mesh))
                .map(|(mesh, name, primitives, shown)| {
                    let mesh = *mesh;
                    let shown = *shown;
                    div()
                        .id(("mesh", mesh))
                        .flex()
                        .items_center()
                        .gap_1()
                        .pl_6()
                        .pr_3()
                        .py_0p5()
                        .rounded_sm()
                        .cursor_pointer()
                        .hover(|style| style.bg(rgb(theme::HOVER)))
                        .on_click(cx.listener(move |this, _, _, cx| {
                            let State::Ready { viewport, .. } = &this.state else {
                                return;
                            };
                            let viewport = viewport.clone();
                            viewport.update(cx, |viewport, cx| {
                                viewport.set_mesh_visible(mesh, !shown, cx);
                            });
                        }))
                        .child(
                            div()
                                .text_xs()
                                .text_color(rgb(theme::TEXT_MUTED))
                                .child(format!("{} mesh {}", if shown { "\u{25CF}" } else { "\u{25CB}" }, mesh)),
                        )
                        .child(
                            div()
                                .text_xs()
                                .text_color(rgb(theme::TEXT_MUTED))
                                .child(format!("{name}  \u{00B7}  {primitives} primitive(s)")),
                        )
                });
            std::iter::once(component_row.into_any_element())
                .chain(mesh_rows.map(|row| row.into_any_element()))
        });
    div()
        .flex()
        .flex_col()
        .flex_none()
        .border_b_1()
        .border_color(rgb(theme::BORDER))
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .px_3()
                .py_2()
                .child(
                    div()
                        .text_xs()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(theme::TEXT_MUTED))
                        .child(format!(
                            "DRAWABLE CONTENTS \u{00B7} {} COMPONENT(S) \u{00B7} {} MESH(ES)",
                            fragment.components.len(),
                            mesh_total
                        )),
                )
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_1()
                        .child(
                            ui::button("components-show-all", "Show All").on_click(cx.listener(
                                |this, _, _, cx| {
                                    let State::Ready { viewport, .. } = &this.state else {
                                        return;
                                    };
                                    viewport.clone().update(cx, |viewport, cx| {
                                        viewport.show_all_components(cx);
                                    });
                                },
                            )),
                        )
                        .child(ui::button("components-reset", "Reset Visibility").on_click(
                            cx.listener(|this, _, _, cx| {
                                let State::Ready { viewport, .. } = &this.state else {
                                    return;
                                };
                                viewport.clone().update(cx, |viewport, cx| {
                                    viewport.restore_default_visibility(cx);
                                });
                            }),
                        )),
                ),
        )
        .child(
            div()
                .id("model-components")
                .flex()
                .flex_col()
                .gap_0p5()
                .px_1()
                .py_1()
                .children(rows),
        )
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
