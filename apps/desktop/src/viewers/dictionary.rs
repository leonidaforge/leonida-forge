//! Independent window listing a drawable dictionary and one selected member.
//!
//! Enumeration and member decoding are separate: opening the window reads the
//! resource once and releases it, and each member selection reads it again
//! through the shared loader. An idle window therefore holds no model source
//! memory, and a slow selection cannot replace a newer one because results are
//! matched against the selection generation.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use gpui::{
    Context, Entity, FontWeight, Task, UniformListScrollHandle, Window, div, prelude::*, px, rgb,
    uniform_list,
};

use super::viewport::{RendererStatus, Viewport};
use crate::files::{Access, model};
use crate::ui;
use crate::ui::theme;

const TOOLBAR_HEIGHT: f32 = 40.;
const STATUS_BAR_HEIGHT: f32 = 26.;
const MEMBER_PANEL_WIDTH: f32 = 340.;
const DIAGNOSTICS_WIDTH: f32 = 320.;

/// A decoded member as the viewer presents it.
struct MemberSummary {
    name: String,
    index: usize,
    hash: u32,
    lod: usize,
    meshes: usize,
    primitives: usize,
    vertices: usize,
    triangles: usize,
    materials: usize,
    textures: usize,
    completeness: lforge_model::ModelCompleteness,
    exact_layout: bool,
    unresolved_bindings: usize,
    bindings: usize,
}

enum State {
    Loading,
    Ready {
        info: Arc<lforge_model::DictionaryInfo>,
        diagnostics: Vec<String>,
    },
    Failed(String),
}

/// The selected member's load state. A superseded result is dropped because
/// the viewer only applies a result whose generation is still current.
enum MemberLoad {
    None,
    Loading,
    Ready {
        viewport: Entity<Viewport>,
        summary: Box<MemberSummary>,
        diagnostics: Vec<String>,
    },
    Failed(String),
}

pub struct DictionaryViewer {
    name: String,
    state: State,
    member: MemberLoad,
    selected: usize,
    generation: u64,
    search: Entity<ui::text_field::TextField>,
    list_scroll: UniformListScrollHandle,
    path: PathBuf,
    access: Access,
    gta_root: Option<PathBuf>,
    cancel: Arc<AtomicBool>,
    _load: Task<()>,
    _member_task: Option<Task<()>>,
}

impl DictionaryViewer {
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
            .unwrap_or_else(|| "Dictionary".to_string());
        let cancel = Arc::new(AtomicBool::new(false));
        let load_cancel = cancel.clone();
        let load_path = path.clone();
        let load_access = access.clone();
        let load = cx.background_spawn(async move {
            model::enumerate_dictionary(&load_path, &load_access, &load_cancel)
        });
        let search =
            cx.new(|cx| ui::text_field::TextField::new("Filter members, hashes, indices", cx));
        cx.observe(&search, |_, _, cx| cx.notify()).detach();
        let task = cx.spawn(async move |this, cx| {
            let result = load.await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(resource) => {
                        this.name = resource.name;
                        let info = resource.info;
                        let first = info.drawable_members().next().map(|member| member.index);
                        let diagnostics = dictionary_diagnostics(&info, resource.exact_layout);
                        this.state = State::Ready {
                            info: Arc::new(info),
                            diagnostics,
                        };
                        if let Some(first) = first {
                            this.load_member(first, cx);
                        }
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
            member: MemberLoad::None,
            selected: 0,
            generation: 0,
            search,
            list_scroll: UniformListScrollHandle::new(),
            path,
            access,
            gta_root,
            cancel,
            _load: task,
            _member_task: None,
        }
    }

    /// Selects one member. A newer selection supersedes the pending one: the
    /// previous task is dropped and its result, should it still arrive, is
    /// rejected by generation.
    fn load_member(&mut self, index: usize, cx: &mut Context<Self>) {
        self.generation = self.generation.wrapping_add(1);
        let generation = self.generation;
        self.selected = index;
        self.member = MemberLoad::Loading;
        cx.notify();
        let path = self.path.clone();
        let access = self.access.clone();
        let gta_root = self.gta_root.clone();
        let cancel = self.cancel.clone();
        let task = cx.spawn(async move |this, cx| {
            let loaded = cx
                .background_spawn(async move {
                    model::load_dictionary_member(
                        &path,
                        &access,
                        gta_root.as_deref(),
                        index,
                        &cancel,
                    )
                })
                .await;
            this.update(cx, |this, cx| {
                this.apply_member(generation, index, loaded, cx)
            })
            .ok();
        });
        self._member_task = Some(task);
    }

    fn apply_member(
        &mut self,
        generation: u64,
        index: usize,
        loaded: Result<model::LoadedMember, String>,
        cx: &mut Context<Self>,
    ) {
        if generation != self.generation {
            // A newer selection is already pending; this result is obsolete.
            return;
        }
        match loaded {
            Ok(loaded) => {
                let scene = Arc::new(loaded.scene);
                let viewport = cx.new(|cx| Viewport::new(scene.clone(), cx));
                cx.observe(&viewport, |_, _, cx| cx.notify()).detach();
                let summary = Box::new(MemberSummary {
                    name: loaded.name,
                    index,
                    hash: loaded.member.hash,
                    lod: loaded.lod,
                    meshes: scene.meshes.len(),
                    primitives: scene.meshes.iter().map(|mesh| mesh.primitives.len()).sum(),
                    vertices: scene.vertex_count(),
                    triangles: scene.triangle_count(),
                    materials: scene.materials.len(),
                    textures: scene.textures.len(),
                    completeness: loaded.completeness,
                    exact_layout: loaded.exact_layout,
                    unresolved_bindings: loaded
                        .texture_bindings
                        .iter()
                        .filter(|binding| binding.texture.is_none())
                        .count(),
                    bindings: loaded.texture_bindings.len(),
                });
                let complete =
                    summary.completeness.geometry == lforge_model::GeometryCompleteness::Complete;
                let mut diagnostics = vec![
                    format!("member {} name hash {:#010x}", summary.index, summary.hash),
                    format!(
                        "LOD {} {}, {} primitive(s), {} texture(s)",
                        summary.lod,
                        if complete { "complete" } else { "partial" },
                        summary.primitives,
                        summary.textures
                    ),
                ];
                if let lforge_model::GeometryCompleteness::Partial { reason } =
                    &summary.completeness.geometry
                {
                    diagnostics.push(format!("Partial geometry: {reason}"));
                }
                if let lforge_model::TextureCompleteness::Partial { missing } =
                    summary.completeness.textures
                {
                    diagnostics.push(format!(
                        "Partial textures: {missing} material(s) use a fallback"
                    ));
                }
                if summary.unresolved_bindings > 0 {
                    diagnostics.push(format!(
                        "{} of {} texture binding(s) are unresolved",
                        summary.unresolved_bindings, summary.bindings
                    ));
                }
                if !summary.exact_layout {
                    diagnostics.push(
                        "The system/graphics boundary was inferred; no native page metadata was available."
                            .into(),
                    );
                }
                diagnostics.extend(scene.diagnostics.iter().map(|diagnostic| {
                    let mut line = String::new();
                    if let Some(mesh) = &diagnostic.mesh {
                        line.push_str(mesh);
                        line.push_str(": ");
                    }
                    if let Some(material) = &diagnostic.material {
                        line.push_str(material);
                        line.push_str(": ");
                    }
                    line.push_str(&diagnostic.reason);
                    line
                }));
                self.member = MemberLoad::Ready {
                    viewport,
                    summary,
                    diagnostics,
                };
            }
            Err(reason) => {
                self.member = MemberLoad::Failed(reason);
            }
        }
        cx.notify();
    }

    /// The member indices the filter leaves visible.
    fn visible_members(&self, cx: &Context<Self>) -> Vec<usize> {
        let State::Ready { info, .. } = &self.state else {
            return Vec::new();
        };
        let filter = self.search.read(cx).text().trim().to_ascii_lowercase();
        if filter.is_empty() {
            return (0..info.members.len()).collect();
        }
        info.members
            .iter()
            .enumerate()
            .filter(|(index, member)| {
                let name = member.name.as_deref().unwrap_or("");
                name.to_ascii_lowercase().contains(&filter)
                    || format!("{:08x}", member.hash).contains(&filter)
                    || index.to_string() == filter
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn toolbar(&self, cx: &Context<Self>) -> impl IntoElement {
        let ready = matches!(&self.member, MemberLoad::Ready { .. });
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
                ui::button("dictionary-reset-view", "Reset View")
                    .when(!ready, |el| el.text_color(rgb(theme::TEXT_DISABLED)))
                    .on_click(cx.listener(|this, _, _, cx| {
                        if let MemberLoad::Ready { viewport, .. } = &this.member {
                            viewport
                                .clone()
                                .update(cx, |viewport, cx| viewport.reset_camera(cx));
                        }
                    })),
            )
            .child(
                ui::button("dictionary-auto-rotate", "Auto-rotate").on_click(cx.listener(
                    |this, _, _, cx| {
                        if let MemberLoad::Ready { viewport, .. } = &this.member {
                            viewport
                                .clone()
                                .update(cx, |viewport, cx| viewport.toggle_auto_rotate(cx));
                        }
                    },
                )),
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

    fn member_rows(
        &self,
        range: std::ops::Range<usize>,
        cx: &Context<Self>,
    ) -> Vec<gpui::AnyElement> {
        let visible = self.visible_members(cx);
        range
            .map(|row| match visible.get(row).copied() {
                Some(index) => self.member_row(index, cx),
                None => div().into_any_element(),
            })
            .collect()
    }

    fn member_row(&self, index: usize, cx: &Context<Self>) -> gpui::AnyElement {
        let State::Ready { info, .. } = &self.state else {
            return div().into_any_element();
        };
        let Some(member) = info.members.get(index) else {
            return div().into_any_element();
        };
        let selected = index == self.selected;
        let label = member
            .name
            .clone()
            .unwrap_or_else(|| format!("member {index}"));
        let detail = format!(
            "{}  \u{00B7}  hash {:08x}  \u{00B7}  {}",
            index,
            member.hash,
            member.state.name()
        );
        div()
            .id(("dictionary-member", index))
            .flex()
            .flex_col()
            .gap_0p5()
            .mx_1()
            .my_0p5()
            .px_2()
            .py_1()
            .rounded_sm()
            .cursor_pointer()
            .when(selected, |el| el.bg(rgb(theme::SELECTION)))
            .hover(|style| style.bg(rgb(theme::HOVER)))
            .on_click(cx.listener(move |this, _, _, cx| this.load_member(index, cx)))
            .child(div().text_xs().truncate().child(label))
            .child(
                div()
                    .text_xs()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(detail),
            )
            .into_any_element()
    }

    fn member_panel(&self, cx: &Context<Self>) -> gpui::AnyElement {
        match &self.state {
            State::Loading => div()
                .flex()
                .flex_none()
                .w(px(MEMBER_PANEL_WIDTH))
                .h_full()
                .p_3()
                .bg(rgb(theme::PANEL))
                .text_xs()
                .text_color(rgb(theme::TEXT_MUTED))
                .child("Reading the dictionary.")
                .into_any_element(),
            State::Failed(err) => div()
                .flex()
                .flex_none()
                .w(px(MEMBER_PANEL_WIDTH))
                .h_full()
                .p_3()
                .bg(rgb(theme::PANEL))
                .text_xs()
                .text_color(rgb(theme::ERROR))
                .child(err.clone())
                .into_any_element(),
            State::Ready { info, .. } => {
                let visible = self.visible_members(cx);
                let empty = info.members.is_empty();
                let heading = if visible.len() == info.members.len() {
                    format!("MEMBERS ({})", info.count)
                } else {
                    format!("MEMBERS ({}) - showing {}", info.count, visible.len())
                };
                let list = uniform_list(
                    "dictionary-members",
                    visible.len(),
                    cx.processor(move |this, range, _window, cx| this.member_rows(range, cx)),
                )
                .track_scroll(&self.list_scroll)
                .flex_1()
                .min_h_0();
                div()
                    .flex()
                    .flex_col()
                    .flex_none()
                    .w(px(MEMBER_PANEL_WIDTH))
                    .h_full()
                    .overflow_hidden()
                    .bg(rgb(theme::PANEL))
                    .border_r_1()
                    .border_color(rgb(theme::BORDER))
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .justify_between()
                            .gap_2()
                            .px_3()
                            .py_2()
                            .child(
                                div()
                                    .text_xs()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .text_color(rgb(theme::TEXT_MUTED))
                                    .child(heading),
                            )
                            .child(div().w(px(150.)).child(self.search.clone())),
                    )
                    .when(empty, |el| {
                        el.child(
                            div()
                                .px_3()
                                .py_2()
                                .text_xs()
                                .text_color(rgb(theme::TEXT_MUTED))
                                .child("This dictionary holds no members."),
                        )
                    })
                    .child(list)
                    .into_any_element()
            }
        }
    }

    fn viewport_area(&self) -> gpui::AnyElement {
        match &self.member {
            MemberLoad::Loading => ui::centered_message("Loading member.", None).into_any_element(),
            MemberLoad::Failed(reason) => {
                ui::centered_message("This member cannot be decoded.", Some(reason.clone()))
                    .into_any_element()
            }
            MemberLoad::Ready { viewport, .. } => div()
                .flex()
                .flex_1()
                .min_w_0()
                .h_full()
                .child(viewport.clone())
                .into_any_element(),
            MemberLoad::None => {
                ui::centered_message("No member is selected.", None).into_any_element()
            }
        }
    }

    fn diagnostics_panel(&self) -> gpui::AnyElement {
        let lines = match &self.state {
            State::Ready { diagnostics, .. } => {
                let mut lines = diagnostics.clone();
                if let MemberLoad::Ready {
                    diagnostics: member,
                    ..
                } = &self.member
                {
                    lines.push(String::new());
                    lines.extend(member.iter().cloned());
                }
                lines
            }
            State::Failed(err) => vec![err.clone()],
            State::Loading => vec!["Reading the dictionary.".to_string()],
        };
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
                    .child("DICTIONARY"),
            )
            .child(
                div()
                    .id("dictionary-diagnostics")
                    .flex_1()
                    .min_h_0()
                    .overflow_y_scroll()
                    .px_3()
                    .pb_2()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .children(lines.into_iter().map(|line| {
                        div()
                            .text_xs()
                            .text_color(rgb(theme::TEXT_MUTED))
                            .child(line)
                    })),
            )
            .into_any_element()
    }

    fn status_bar(&self, cx: &Context<Self>) -> impl IntoElement {
        let (left, right) = match &self.member {
            MemberLoad::Ready {
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
                let geometry = match &summary.completeness.geometry {
                    lforge_model::GeometryCompleteness::Complete => "complete selected LOD",
                    lforge_model::GeometryCompleteness::Partial { .. } => "partial selected LOD",
                    lforge_model::GeometryCompleteness::Unsupported { .. } => {
                        "unsupported geometry"
                    }
                };
                let textures = match &summary.completeness.textures {
                    lforge_model::TextureCompleteness::Complete => "complete textures",
                    lforge_model::TextureCompleteness::Partial { .. } => "partial textures",
                    lforge_model::TextureCompleteness::NotReferenced => "no texture references",
                };
                let layout = if summary.exact_layout {
                    "native page layout"
                } else {
                    "inferred boundary"
                };
                let left = format!(
                    "member {} {}  \u{00B7}  {geometry}  \u{00B7}  {textures}  \u{00B7}  {layout}  \u{00B7}  {} meshes  \u{00B7}  {} materials  \u{00B7}  {} vertices  \u{00B7}  {} triangles",
                    summary.index,
                    summary.name,
                    summary.meshes,
                    summary.materials,
                    format_count(summary.vertices),
                    format_count(summary.triangles)
                );
                (left, renderer)
            }
            MemberLoad::Loading => ("Loading member.".to_string(), String::new()),
            MemberLoad::Failed(reason) => (format!("Error: {reason}"), String::new()),
            MemberLoad::None => ("No member selected.".to_string(), String::new()),
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

impl Drop for DictionaryViewer {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl Render for DictionaryViewer {
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
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(self.member_panel(cx))
                    .child(self.viewport_area())
                    .child(self.diagnostics_panel()),
            )
            .child(self.status_bar(cx))
    }
}

/// The dictionary lines shown before any member is selected.
fn dictionary_diagnostics(info: &lforge_model::DictionaryInfo, exact_layout: bool) -> Vec<String> {
    let mut lines = vec![
        format!(
            "{} member(s), capacity {}, page map {:#x}",
            info.count, info.capacity, info.page_map
        ),
        format!(
            "root words +0x10 {:#x}, +0x18 {:#x}",
            info.word_10, info.word_18
        ),
        format!(
            "{} member(s) resolve to a drawable",
            info.drawable_members().count()
        ),
    ];
    if info.empty {
        lines.push("This dictionary holds no members.".to_string());
    }
    if !info.hash_sorted {
        lines.push("The hash array is not ascending and duplicate-free.".to_string());
    }
    lines.extend(info.issues.iter().cloned());
    if !exact_layout {
        lines.push(
            "The system/graphics boundary was inferred; no native page metadata was available."
                .to_string(),
        );
    }
    lines
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
