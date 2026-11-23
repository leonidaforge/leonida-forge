use std::path::{Path, PathBuf};
use std::rc::Rc;

use gpui::{
    ClickEvent, Context, MouseButton, MouseDownEvent, ScrollStrategy, div, prelude::*, px, rgb,
    uniform_list,
};

use super::{Explorer, Listing, Menu, browser::entry_icon};
use crate::assets::Icon;
use crate::fs::Entry;
use crate::navigation::GTA_ROOT_LABEL;
use crate::theme;
use crate::ui;

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

    fn expandable(&self) -> bool {
        match &self.kind {
            RowKind::Root { .. } => true,
            RowKind::Entry(entry) => entry.is_dir(),
            RowKind::UnconfiguredGta | RowKind::Message(_) => false,
        }
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

    /// Only directories the user expanded are visited, so junction loops
    /// cannot cause runaway recursion.
    fn push_children(&self, rows: &mut Vec<TreeRow>, dir: &Path, depth: usize) {
        match self.listings.get(dir) {
            Some(Listing::Loaded(entries)) => {
                for entry in entries.iter() {
                    let expanded = entry.is_dir() && self.expanded.contains(&entry.path);
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
        let selected = path.is_some() && path == self.selected;
        // The current folder is filled unless one of its items is selected.
        let highlighted = selected || (current && self.selected.is_none());
        let root_unavailable = matches!(row.kind, RowKind::Root { .. })
            && path
                .as_ref()
                .is_some_and(|path| matches!(self.listings.get(path), Some(Listing::Failed(_))));

        let (glyph, color) = match &row.kind {
            RowKind::UnconfiguredGta | RowKind::Root { gta: true, .. } => {
                (Some(Icon::Gamepad), theme::ACCENT)
            }
            RowKind::Root { gta: false, .. } => (Some(Icon::Folder), theme::FOLDER),
            RowKind::Entry(entry) => {
                let (glyph, color) = entry_icon(entry);
                (Some(glyph), color)
            }
            RowKind::Message(_) => (None, theme::TEXT_MUTED),
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
            .when(row.expandable(), |el| {
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
            .when(highlighted, |el| {
                el.bg(rgb(theme::SELECTION))
                    .border_color(rgb(theme::SELECTION_BORDER))
            })
            .when(current && !highlighted, |el| el.bg(rgb(theme::HOVER)))
            .when(!highlighted && !is_message, |el| {
                el.hover(|s| s.bg(rgb(theme::HOVER)))
            })
            .child(chevron)
            .children(glyph.map(|glyph| ui::icon(glyph, px(16.), color)))
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
                let kind_click = match &row.kind {
                    RowKind::UnconfiguredGta => None,
                    RowKind::Root { path, .. } => Some((path.clone(), None)),
                    RowKind::Entry(entry) => Some((entry.path.clone(), Some(entry.clone()))),
                    RowKind::Message(_) => None,
                };
                el.on_click(cx.listener(move |this, event: &ClickEvent, window, cx| {
                    match &kind_click {
                        None => this.choose_gta_folder(cx),
                        Some((dir, None)) => this.navigate(dir.clone(), cx),
                        Some((_, Some(entry))) if entry.is_dir() => {
                            this.navigate(entry.path.clone(), cx)
                        }
                        Some((_, Some(entry))) => {
                            if event.click_count() >= 2 {
                                this.open_entry(entry, window, cx);
                            } else {
                                this.reveal_file(entry.path.clone(), cx);
                            }
                        }
                    }
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
