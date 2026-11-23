use std::path::{Path, PathBuf};
use std::rc::Rc;

use gpui::{
    Context, MouseButton, MouseDownEvent, ScrollStrategy, div, prelude::*, px, rgb, uniform_list,
};

use super::navigation::GTA_ROOT_LABEL;
use super::{Explorer, Listing, Menu};
use crate::files::Entry;
use crate::ui;
use crate::ui::assets::Icon;
use crate::ui::theme;

const ROW_HEIGHT: f32 = 24.;
const INDENT: f32 = 14.;

enum RowKind {
    /// The GTA VI root before a folder is configured.
    UnconfiguredGta,
    Root {
        gta: bool,
        path: PathBuf,
    },
    Entry(Entry),
    Message(&'static str),
}

struct TreeRow {
    depth: usize,
    kind: RowKind,
    expanded: bool,
}

impl TreeRow {
    fn path(&self) -> Option<&Path> {
        match &self.kind {
            RowKind::Root { path, .. } => Some(path),
            RowKind::Entry(entry) => Some(&entry.path),
            RowKind::UnconfiguredGta | RowKind::Message(_) => None,
        }
    }

    fn is_container(&self) -> bool {
        matches!(self.kind, RowKind::Root { .. } | RowKind::Entry(_))
    }
}

impl Explorer {
    fn tree_rows(&self) -> Vec<TreeRow> {
        let mut rows = Vec::new();
        match &self.workspace.gta {
            Some(path) => self.push_root(&mut rows, path, true),
            None => rows.push(TreeRow {
                depth: 0,
                kind: RowKind::UnconfiguredGta,
                expanded: false,
            }),
        }
        for folder in &self.workspace.folders {
            self.push_root(&mut rows, folder, false);
        }
        rows
    }

    fn push_root(&self, rows: &mut Vec<TreeRow>, path: &Path, gta: bool) {
        let expanded = self.expanded.contains(path);
        rows.push(TreeRow {
            depth: 0,
            kind: RowKind::Root {
                gta,
                path: path.to_path_buf(),
            },
            expanded,
        });
        // An unavailable root says so on its own row.
        let failed = matches!(self.listings.get(path), Some(Listing::Failed(_)));
        if expanded && !failed {
            self.push_children(rows, path, 1);
        }
    }

    /// Lists folders and archives only. Only containers the user expanded are
    /// visited, so junction loops cannot cause runaway recursion.
    fn push_children(&self, rows: &mut Vec<TreeRow>, dir: &Path, depth: usize) {
        match self.listings.get(dir) {
            Some(Listing::Loaded(entries)) => {
                for entry in entries.iter().filter(|entry| entry.is_container()) {
                    let expanded = self.expanded.contains(&entry.path);
                    rows.push(TreeRow {
                        depth,
                        kind: RowKind::Entry(entry.clone()),
                        expanded,
                    });
                    if expanded {
                        self.push_children(rows, &entry.path, depth + 1);
                    }
                }
            }
            Some(Listing::Loading) | None => rows.push(TreeRow {
                depth,
                kind: RowKind::Message("Loading…"),
                expanded: false,
            }),
            Some(Listing::Indexing(_)) => rows.push(TreeRow {
                depth,
                kind: RowKind::Message("Indexing…"),
                expanded: false,
            }),
            Some(Listing::Failed(_)) => rows.push(TreeRow {
                depth,
                kind: RowKind::Message("Cannot open folder"),
                expanded: false,
            }),
        }
    }

    pub(super) fn render_tree(
        &self,
        width: f32,
        reveal: Option<&Path>,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let rows = Rc::new(self.tree_rows());
        if let Some(reveal) = reveal
            && let Some(ix) = rows.iter().position(|row| row.path() == Some(reveal))
        {
            self.tree_scroll.scroll_to_item(ix, ScrollStrategy::Nearest);
        }

        div()
            .flex()
            .flex_col()
            .flex_none()
            .w(px(width))
            .h_full()
            .bg(rgb(theme::PANEL))
            .child(
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .h(px(32.))
                    .px_3()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child("Workspaces"),
            )
            .child(
                uniform_list(
                    "tree",
                    rows.len(),
                    cx.processor(move |this, range: std::ops::Range<usize>, _, cx| {
                        range
                            .map(|ix| this.render_tree_row(ix, &rows[ix], cx).into_any_element())
                            .collect::<Vec<_>>()
                    }),
                )
                .track_scroll(&self.tree_scroll)
                .flex_1()
                .px_1p5()
                .pb_2(),
            )
    }

    fn render_tree_row(&self, ix: usize, row: &TreeRow, cx: &Context<Self>) -> impl IntoElement {
        let path = row.path().map(Path::to_path_buf);
        let current = path.is_some() && path.as_deref() == self.current_dir();
        // Until a container is listed, assume it has subfolders.
        let expandable = row.is_container()
            && path
                .as_ref()
                .and_then(|path| match self.listings.get(path) {
                    Some(Listing::Loaded(entries)) => {
                        Some(entries.iter().any(|entry| entry.is_container()))
                    }
                    _ => None,
                })
                .unwrap_or(true);
        let root_unavailable = matches!(row.kind, RowKind::Root { .. })
            && path
                .as_ref()
                .is_some_and(|path| matches!(self.listings.get(path), Some(Listing::Failed(_))));

        let icon = match &row.kind {
            RowKind::UnconfiguredGta | RowKind::Root { gta: true, .. } => {
                Some(ui::icon(Icon::Gamepad, px(16.), theme::ACCENT).into_any_element())
            }
            RowKind::Root { gta: false, .. } => {
                Some(ui::icon(Icon::Folder, px(16.), theme::FOLDER).into_any_element())
            }
            RowKind::Entry(entry) => Some(self.entry_icon(entry, px(16.))),
            RowKind::Message(_) => None,
        };
        let (label, note) = match &row.kind {
            RowKind::UnconfiguredGta => (GTA_ROOT_LABEL.to_string(), Some("Set folder…")),
            RowKind::Root { path, .. } => (
                self.workspace.root_label(path),
                root_unavailable.then_some("Unavailable"),
            ),
            RowKind::Entry(entry) => (entry.name.clone(), None),
            RowKind::Message(message) => (message.to_string(), None),
        };
        let is_message = matches!(row.kind, RowKind::Message(_));

        let chevron = div()
            .id(("chevron", ix))
            .flex()
            .flex_none()
            .items_center()
            .justify_center()
            .size(px(16.))
            .rounded_sm()
            .when(expandable, |el| {
                let dir = path.clone();
                el.hover(|s| s.bg(rgb(theme::HOVER)))
                    .child(ui::icon(
                        if row.expanded {
                            Icon::ChevronDown
                        } else {
                            Icon::ChevronRight
                        },
                        px(12.),
                        theme::TEXT_MUTED,
                    ))
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(move |this, _, _, cx| {
                            cx.stop_propagation();
                            if let Some(dir) = dir.clone() {
                                this.toggle_expanded(dir, cx);
                            }
                        }),
                    )
            });

        div()
            .id(("tree-row", ix))
            .flex()
            .items_center()
            .w_full()
            .gap_1()
            .h(px(ROW_HEIGHT))
            .pl(px(4. + row.depth as f32 * INDENT))
            .pr_2()
            .rounded_sm()
            .border_1()
            .border_color(gpui::transparent_black())
            .when(current, |el| {
                el.bg(rgb(theme::SELECTION))
                    .border_color(rgb(theme::SELECTION_BORDER))
            })
            .when(!current && !is_message, |el| {
                el.hover(|s| s.bg(rgb(theme::HOVER)))
            })
            .child(chevron)
            .children(icon)
            .child(
                div()
                    .min_w_0()
                    .truncate()
                    .when(is_message || root_unavailable, |el| {
                        el.text_color(rgb(theme::TEXT_MUTED))
                    })
                    .child(label),
            )
            .children(note.map(|note| {
                div()
                    .flex_none()
                    .text_xs()
                    .text_color(rgb(if root_unavailable {
                        theme::ERROR
                    } else {
                        theme::TEXT_MUTED
                    }))
                    .child(note)
            }))
            .when(!is_message, |el| {
                let target = path.clone();
                el.on_click(cx.listener(move |this, _, _, cx| match &target {
                    Some(dir) => this.navigate(dir.clone(), cx),
                    None => this.choose_gta_folder(cx),
                }))
            })
            .when_some(
                match &row.kind {
                    RowKind::Root { path, .. } => Some(path.clone()),
                    _ => None,
                },
                |el, root| {
                    el.on_mouse_down(
                        MouseButton::Right,
                        cx.listener(move |this, event: &MouseDownEvent, _, cx| {
                            this.open_menu = Some(Menu::Root {
                                root: root.clone(),
                                position: event.position,
                            });
                            cx.notify();
                        }),
                    )
                },
            )
    }
}
