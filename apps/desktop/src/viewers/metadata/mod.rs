//! A read-only view of a decoded metadata document.
//!
//! Both encodings the census found open here: a `PSIN` container (its schema
//! and instance blocks) and an `RBF0` payload (its name table and element
//! tree). The rows are a pre-order walk of the decoded document, built by
//! [`tree`] on a background thread so the window never stalls on a large one. A
//! row expands and collapses, a filter keeps the rows that match and the
//! ancestors that hold them, and a row can be copied as text.
//!
//! A `PSIN` container keeps its stored hashes as the identity: a name the name
//! table reproduces is shown beside its hash, never in place of it. An `RBF0`
//! payload stores its names, and they are shown as they are.

mod tree;

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gpui::{
    AnyElement, App, Context, Entity, FocusHandle, KeyDownEvent, MouseButton, ScrollStrategy, Task,
    UniformListScrollHandle, Window, div, prelude::*, px, rgb, uniform_list,
};
use lforge_core::resource::ResourcePath;
use lforge_rage9::psin::pso::names::Names;
use lforge_rage9::rpf::names::{Builtin, StringTable};

use crate::files::Access;
use crate::ui;
use crate::ui::theme;

const TOOLBAR_HEIGHT: f32 = 40.;
const STATUS_BAR_HEIGHT: f32 = 26.;
const ROW_HEIGHT: f32 = 22.;
const INDENT: f32 = 14.;
const CANDIDATES_WIDTH: f32 = 240.;

/// What the window shows.
enum State {
    Loading,
    Failed(String),
    Ready(Box<Ready>),
}

struct Ready {
    tree: tree::Tree,
    /// The path the container was read from, for the status bar.
    source: String,
    /// What naming the document offers: the hashes a name table resolves, or
    /// the names the payload itself defines.
    names: String,
}

/// A window over one metadata container.
pub struct MetadataViewer {
    title: String,
    state: State,
    /// Indices of the rows the user collapsed.
    collapsed: HashSet<usize>,
    /// The index of the selected row in the visible list.
    selected: usize,
    filter: Entity<ui::text_field::TextField>,
    scroll: UniformListScrollHandle,
    focus: FocusHandle,
    _load: Task<()>,
}

impl MetadataViewer {
    pub fn new(
        path: PathBuf,
        resource: Option<Arc<ResourcePath>>,
        access: Access,
        _window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let title = identity(&path, resource.as_deref());
        let filter =
            cx.new(|cx| ui::text_field::TextField::new("Filter structures, fields, values", cx));
        let decode = cx.background_spawn({
            let path = path.clone();
            async move { decode(&path, &access) }
        });
        let load = cx.spawn(async move |this, cx| {
            let result = decode.await;
            this.update(cx, |this, cx| {
                this.state = match result {
                    Ok((tree, names)) => {
                        let source = this.title.clone();
                        State::Ready(Box::new(Ready {
                            tree,
                            source,
                            names,
                        }))
                    }
                    Err(err) => State::Failed(err),
                };
                this.selected = 0;
                cx.notify();
            })
            .ok();
        });
        Self {
            title,
            state: State::Loading,
            collapsed: HashSet::new(),
            selected: 0,
            filter,
            scroll: UniformListScrollHandle::new(),
            focus: cx.focus_handle(),
            _load: load,
        }
    }

    fn ready(&self) -> Option<&Ready> {
        match &self.state {
            State::Ready(ready) => Some(ready),
            _ => None,
        }
    }

    fn visible(&self, cx: &Context<Self>) -> Vec<usize> {
        let Some(ready) = self.ready() else {
            return Vec::new();
        };
        let filter = self.filter.read(cx).text().to_string();
        ready.tree.visible(&self.collapsed, &filter)
    }

    fn toggle(&mut self, row: usize) {
        let Some(ready) = self.ready() else {
            return;
        };
        if !ready.tree.rows.get(row).is_some_and(|row| row.expandable) {
            return;
        }
        if !self.collapsed.remove(&row) {
            self.collapsed.insert(row);
        }
    }

    fn copy_row(&mut self, cx: &mut Context<Self>) {
        let visible = self.visible(cx);
        let Some(&row) = visible.get(self.selected) else {
            return;
        };
        let Some(item) = self.ready().and_then(|ready| ready.tree.rows.get(row)) else {
            return;
        };
        cx.write_to_clipboard(gpui::ClipboardItem::new_string(item.copy.clone()));
    }

    fn select(&mut self, index: usize, cx: &mut Context<Self>) {
        let visible = self.visible(cx);
        if visible.is_empty() {
            return;
        }
        self.selected = index.min(visible.len() - 1);
        self.scroll
            .scroll_to_item(self.selected, ScrollStrategy::Center);
        cx.notify();
    }

    fn move_by(&mut self, delta: isize, cx: &mut Context<Self>) {
        let visible = self.visible(cx);
        if visible.is_empty() {
            return;
        }
        let next = (self.selected as isize + delta).clamp(0, visible.len() as isize - 1) as usize;
        self.select(next, cx);
    }

    fn collapse_selected(&mut self, cx: &mut Context<Self>) {
        let visible = self.visible(cx);
        let Some(&row) = visible.get(self.selected) else {
            return;
        };
        if self.ready().is_some_and(|ready| {
            ready
                .tree
                .rows
                .get(row)
                .is_some_and(|entry| entry.expandable)
        }) && !self.collapsed.contains(&row)
        {
            self.collapsed.insert(row);
            cx.notify();
            return;
        }
        // Already collapsed or a leaf: step to the row that holds it.
        if let Some(parent) = self.ready().and_then(|ready| ready.tree.parent(row))
            && let Some(position) = visible.iter().position(|index| *index == parent)
        {
            self.select(position, cx);
        }
    }

    fn expand_selected(&mut self, cx: &mut Context<Self>) {
        let visible = self.visible(cx);
        let Some(&row) = visible.get(self.selected) else {
            return;
        };
        if self.collapsed.remove(&row) {
            cx.notify();
        }
    }

    fn key_down(&mut self, event: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        let keystroke = &event.keystroke;
        let shortcut = keystroke.modifiers.control || keystroke.modifiers.platform;
        match keystroke.key.as_str() {
            "down" => self.move_by(1, cx),
            "up" => self.move_by(-1, cx),
            "left" => self.collapse_selected(cx),
            "right" => self.expand_selected(cx),
            "home" => self.select(0, cx),
            "end" => {
                let last = self.visible(cx).len().saturating_sub(1);
                self.select(last, cx);
            }
            "enter" | "space" => {
                let visible = self.visible(cx);
                if let Some(&row) = visible.get(self.selected) {
                    self.toggle(row);
                    cx.notify();
                }
            }
            "c" if shortcut => self.copy_row(cx),
            _ => return,
        }
        cx.stop_propagation();
    }

    fn rows(
        &self,
        range: std::ops::Range<usize>,
        visible: &[usize],
        cx: &Context<Self>,
    ) -> Vec<AnyElement> {
        let Some(ready) = self.ready() else {
            return Vec::new();
        };
        range
            .map(|position| match visible.get(position) {
                Some(&index) => match ready.tree.rows.get(index) {
                    Some(row) => self.row(position, index, row, &ready.tree, cx),
                    None => div().into_any_element(),
                },
                None => div().into_any_element(),
            })
            .collect()
    }

    fn row(
        &self,
        position: usize,
        index: usize,
        row: &tree::Row,
        whole: &tree::Tree,
        cx: &Context<Self>,
    ) -> AnyElement {
        let selected = position == self.selected;
        let collapsed = self.collapsed.contains(&index);
        let color = match row.tone {
            tree::Tone::Normal => theme::TEXT,
            tree::Tone::Muted => theme::TEXT_MUTED,
            tree::Tone::Accent => theme::ACCENT,
            tree::Tone::Warning => theme::ERROR,
        };
        let chevron = if row.expandable {
            if collapsed { "▸" } else { "▾" }
        } else {
            " "
        };
        let below = whole.descendants(index);
        div()
            .id(("metadata-row", index))
            .flex()
            .items_center()
            .gap_1()
            .h(px(ROW_HEIGHT))
            .pl(px(8. + row.depth as f32 * INDENT))
            .pr_2()
            .whitespace_nowrap()
            .overflow_hidden()
            .rounded_sm()
            .cursor_pointer()
            .when(selected, |el| el.bg(rgb(theme::SELECTION)))
            .hover(|style| style.bg(rgb(theme::HOVER)))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, window, cx| {
                    cx.stop_propagation();
                    this.focus.focus(window, cx);
                    this.selected = position;
                    // A row that holds others folds and unfolds on a click,
                    // which is what a read-only tree is expected to do.
                    this.toggle(index);
                    cx.notify();
                }),
            )
            .child(
                div()
                    .w(px(12.))
                    .flex_none()
                    .text_xs()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(chevron),
            )
            .child(
                div()
                    .flex_none()
                    .font_family(theme::MONO_FONT)
                    .text_color(rgb(color))
                    .child(row.label.clone()),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .truncate()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(row.detail.clone()),
            )
            .children((row.expandable && below > 0).then(|| {
                div()
                    .flex_none()
                    .text_xs()
                    .text_color(rgb(theme::TEXT_DISABLED))
                    .child(format!("{below} below"))
            }))
            .into_any_element()
    }
}

impl Render for MetadataViewer {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let focused = self.focus.is_focused(window);
        let visible = self.visible(cx);
        let (status, summary, source, names) = match &self.state {
            State::Loading => (
                "loading",
                "Reading the document…".to_string(),
                String::new(),
                String::new(),
            ),
            State::Failed(err) => ("failed", err.clone(), String::new(), String::new()),
            State::Ready(ready) => (
                ready.tree.status,
                ready.tree.summary.clone(),
                ready.source.clone(),
                ready.names.clone(),
            ),
        };
        let issues = self.ready().map_or(0, |ready| ready.tree.issues.len());
        let truncated = self.ready().is_some_and(|ready| ready.tree.truncated);
        let row_count = self.ready().map_or(0, |ready| ready.tree.rows.len());

        let content: AnyElement = match content_area(&self.state, visible.len()) {
            ContentArea::Rows => uniform_list(
                "metadata-rows",
                visible.len(),
                cx.processor(move |this, range, _window, cx| {
                    let visible = this.visible(cx);
                    this.rows(range, &visible, cx)
                }),
            )
            .track_scroll(&self.scroll)
            .flex_1()
            .min_h_0()
            .into_any_element(),
            ContentArea::Message { title, detail } => ui::centered_message(title, detail),
        };

        div()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme::BACKGROUND))
            .text_color(rgb(theme::TEXT))
            .font_family(theme::UI_FONT)
            .text_sm()
            .track_focus(&self.focus)
            .on_key_down(cx.listener(Self::key_down))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, window, cx| {
                    this.focus.focus(window, cx);
                }),
            )
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
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .whitespace_nowrap()
                            .text_color(rgb(theme::TEXT_MUTED))
                            .child(summary.clone()),
                    )
                    .child(div().w(px(CANDIDATES_WIDTH)).child(self.filter.clone()))
                    .child(ui::button("meta-expand", "Expand").on_click(cx.listener(
                        |this, _, _, cx| {
                            this.collapsed.clear();
                            cx.notify();
                        },
                    )))
                    .child(
                        ui::button("meta-collapse", "Collapse").on_click(cx.listener(
                            |this, _, _, cx| {
                                let Some(ready) = this.ready() else {
                                    return;
                                };
                                this.collapsed = ready
                                    .tree
                                    .rows
                                    .iter()
                                    .enumerate()
                                    .filter(|(_, row)| row.expandable)
                                    .map(|(index, _)| index)
                                    .collect();
                                cx.notify();
                            },
                        )),
                    )
                    .child(
                        ui::button("meta-copy", "Copy Row")
                            .on_click(cx.listener(|this, _, _, cx| this.copy_row(cx))),
                    ),
            )
            .child(
                // The list is a flex item that takes the height left between
                // the toolbar and the status bar. It must sit in a flex column:
                // in a block box its `flex_1` means nothing, it measures its
                // own intrinsic height and paints nothing.
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_h_0()
                    .overflow_hidden()
                    .bg(rgb(theme::PANEL))
                    .child(content),
            )
            .child(
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .justify_between()
                    .gap_3()
                    .h(px(STATUS_BAR_HEIGHT))
                    .px_3()
                    .border_t_1()
                    .border_color(rgb(theme::BORDER))
                    .text_xs()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .truncate()
                            .child(if source.is_empty() {
                                self.title.clone()
                            } else {
                                source
                            }),
                    )
                    .child(format!(
                        "{status}  \u{00B7}  {row_count} rows  \u{00B7}  {names}{}{}{}",
                        if issues > 0 {
                            format!("  \u{00B7}  {issues} issues")
                        } else {
                            String::new()
                        },
                        if truncated {
                            "  \u{00B7}  row limit reached"
                        } else {
                            ""
                        },
                        if focused {
                            ""
                        } else {
                            "  \u{00B7}  click to use the keyboard"
                        },
                    )),
            )
    }
}

/// Opens the metadata viewer on `path`, described by its canonical resource
/// path when the entry came from an archive.
pub(crate) fn open(
    path: PathBuf,
    resource: Option<Arc<ResourcePath>>,
    access: Access,
    cx: &mut App,
) {
    let title = identity(&path, resource.as_deref());
    let options = gpui::WindowOptions {
        window_bounds: Some(gpui::WindowBounds::Windowed(gpui::Bounds::centered(
            None,
            gpui::size(px(1100.), px(760.)),
            cx,
        ))),
        titlebar: Some(gpui::TitlebarOptions {
            title: Some(format!("{title} — Leonida Forge").into()),
            ..Default::default()
        }),
        window_min_size: Some(gpui::size(px(720.), px(420.))),
        ..Default::default()
    };
    if let Err(err) = cx.open_window(options, |window, cx| {
        ui::close_through_gpui(window, cx);
        let viewer = cx.new(|cx| MetadataViewer::new(path, resource, access, window, cx));
        let focus = viewer.read(cx).focus.clone();
        focus.focus(window, cx);
        viewer
    }) {
        log::error!("failed to open metadata viewer: {err:#}");
    }
}

/// The detail line a document with no rows reports, so the reason is visible
/// rather than implied.
fn empty_document_detail(tree: &tree::Tree) -> String {
    if !tree.issues.is_empty() {
        return tree.issues.join("; ");
    }
    "the document carries no elements, fields, attributes or text".to_string()
}

/// What the area between the toolbar and the status bar shows.
///
/// A decoded document with rows is a list. Everything else is a message, so a
/// viewer never presents an unexplained blank area: a document with no rows, a
/// filter that matches nothing and a failed decode each say what they are.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ContentArea {
    Rows,
    Message {
        title: &'static str,
        detail: Option<String>,
    },
}

fn content_area(state: &State, visible: usize) -> ContentArea {
    match state {
        State::Loading => ContentArea::Message {
            title: "Reading the metadata document.",
            detail: None,
        },
        State::Failed(err) => ContentArea::Message {
            title: "This metadata document cannot be decoded.",
            detail: Some(err.clone()),
        },
        State::Ready(ready) if ready.tree.rows.is_empty() => ContentArea::Message {
            title: "This metadata document has no rows to show.",
            detail: Some(empty_document_detail(&ready.tree)),
        },
        State::Ready(_) if visible == 0 => ContentArea::Message {
            title: "No row matches the filter.",
            detail: Some("Clear the filter to see the whole document.".to_string()),
        },
        State::Ready(_) => ContentArea::Rows,
    }
}

/// Reads and decodes `path`.
///
/// The format comes from the payload's own signature: a `PSIN` container is
/// decoded by its schema, an `RBF0` payload by its grammar, and both become the
/// same rows. What names the document is what its status line reports.
fn decode(path: &Path, access: &Access) -> Result<(tree::Tree, String), String> {
    let bytes = crate::files::read_with(path, access).map_err(|err| err.to_string())?;
    let document = lforge_core::metadata::decode(&bytes).map_err(|err| err.to_string())?;
    let names = names_for(path);
    match &document {
        lforge_core::metadata::Document::Pso(document) => Ok((
            tree::build(document, &names),
            format!("{} hashes named", names.len()),
        )),
        lforge_core::metadata::Document::Rbf0(document) => Ok((
            tree::build_rbf0(document),
            format!("{} names in the document", document.names.len()),
        )),
    }
}

/// How the viewer names what it shows: the canonical resource path when the
/// entry came from an archive, else the file name. A payload read through a
/// temporary spool file is never named by that file.
fn identity(path: &Path, resource: Option<&ResourcePath>) -> String {
    match resource {
        Some(resource) => resource.display(),
        None => path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
    }
}

/// The name table of the archive holding `path`, then the built-in tables.
fn names_for(path: &Path) -> Names {
    let mut table = StringTable::default();
    if let Some((archive, _)) = crate::files::split_location(path) {
        let mut name = archive.file_name().unwrap_or_default().to_os_string();
        name.push(".names.txt");
        let file = archive.with_file_name(name);
        if file.is_file()
            && let Ok(bytes) = std::fs::read(&file)
        {
            table.merge(StringTable::parse(&bytes, false));
        }
    }
    table.merge(Builtin::beside_executable().table().clone());
    if table.entries().is_empty() {
        return Names::empty();
    }
    Names::from_table(&table)
}

#[cfg(test)]
mod tests {
    use lforge_core::resource::{EntryId, ResourcePath};
    use lforge_rage9::rpf::names::Key;

    use super::{ContentArea, Ready, State, content_area, identity};

    fn named(key: u64, name: &'static str, type_id: u8) -> EntryId {
        EntryId::new(
            Some(Key::Hash64(key)),
            Some(type_id),
            Some(name.to_string()),
        )
    }

    #[test]
    fn a_window_names_the_row_by_its_canonical_path() {
        let path = ResourcePath::root("data.rpf")
            .push(named(0x11, "packs/camera.rpf", 0))
            .with_entry(named(0x22, "packs/camera/cam.zmt", 11));
        assert_eq!(
            identity(std::path::Path::new("/tmp/spool-1234"), Some(&path)),
            "data.rpf!packs/camera.rpf!packs/camera/cam.zmt"
        );
    }

    #[test]
    fn a_payload_without_a_resource_path_is_named_by_its_file() {
        assert_eq!(
            identity(std::path::Path::new("C:/game/data/thing.zmt"), None),
            "thing.zmt"
        );
    }

    fn ready(rows: usize, issues: &[&str]) -> State {
        State::Ready(Box::new(Ready {
            tree: super::tree::Tree {
                rows: (0..rows)
                    .map(|index| super::tree::Row {
                        depth: 0,
                        label: format!("row {index}"),
                        detail: String::new(),
                        copy: String::new(),
                        expandable: false,
                        tone: super::tree::Tone::Normal,
                    })
                    .collect(),
                status: "decoded",
                summary: String::new(),
                issues: issues.iter().map(|issue| issue.to_string()).collect(),
                truncated: false,
            },
            source: String::new(),
            names: String::new(),
        }))
    }

    #[test]
    fn a_decoded_document_with_rows_is_a_list() {
        assert_eq!(content_area(&ready(3, &[]), 3), ContentArea::Rows);
        // A filtered list still has rows to draw.
        assert_eq!(content_area(&ready(3, &[]), 1), ContentArea::Rows);
    }

    #[test]
    fn a_document_with_no_rows_says_so() {
        match content_area(&ready(0, &[]), 0) {
            ContentArea::Message { title, detail } => {
                assert!(title.contains("no rows"), "{title}");
                let detail = detail.unwrap_or_default();
                assert!(detail.contains("no elements"), "{detail}");
            }
            ContentArea::Rows => panic!("an empty document must not be drawn as an empty list"),
        }
    }

    #[test]
    fn a_document_with_no_rows_reports_why() {
        match content_area(&ready(0, &["the parse stopped: Unterminated"]), 0) {
            ContentArea::Message { detail, .. } => assert_eq!(
                detail.as_deref(),
                Some("the parse stopped: Unterminated"),
                "the reason the document is empty is shown, not implied"
            ),
            ContentArea::Rows => panic!("an empty document must not be drawn as an empty list"),
        }
    }

    #[test]
    fn a_filter_that_matches_nothing_says_so() {
        match content_area(&ready(4, &[]), 0) {
            ContentArea::Message { title, .. } => {
                assert!(title.contains("No row matches"), "{title}");
            }
            ContentArea::Rows => panic!("no visible row must not be a blank list"),
        }
    }

    #[test]
    fn a_failed_decode_shows_the_reason() {
        match content_area(&State::Failed("not a PSIN or RBF0 document".to_string()), 0) {
            ContentArea::Message { detail, .. } => {
                assert_eq!(detail.as_deref(), Some("not a PSIN or RBF0 document"));
            }
            ContentArea::Rows => panic!("a failed decode is not a list"),
        }
    }

    #[test]
    fn the_loading_state_says_it_is_reading() {
        match content_area(&State::Loading, 0) {
            ContentArea::Message { title, detail } => {
                assert!(title.contains("Reading"), "{title}");
                assert!(detail.is_none());
            }
            ContentArea::Rows => panic!("nothing is decoded yet"),
        }
    }
}
