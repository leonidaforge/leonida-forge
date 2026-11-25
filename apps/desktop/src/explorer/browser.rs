use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gpui::{
    Anchor, AnyElement, ClickEvent, Context, Div, FontWeight, MouseButton, MouseDownEvent, Pixels,
    Point, ScrollStrategy, Stateful, anchored, deferred, div, img, prelude::*, px, rgb,
    uniform_list,
};

use super::{Axis, BROWSER_HEADER_HEIGHT, Explorer, Layout, Listing, Menu};
use crate::files::archive::Stage;
use crate::files::{self, Entry, EntryKind, ListingLayout, SortKey};
use crate::settings::ViewMode;
use crate::ui;
use crate::ui::assets::Icon;
use crate::ui::theme;

const PADDING: f32 = 8.;
const GAP: f32 = 4.;
const DETAILS_ROW_HEIGHT: f32 = 26.;
const LIST_ROW_HEIGHT: f32 = 22.;
const LIST_COLUMN_WIDTH: f32 = 240.;
const LIST_COLUMN_GAP: f32 = 4.;
const NOTE_HEIGHT: f32 = 44.;
const PROGRESS_WIDTH: f32 = 280.;
const INDEXING_NOTE: &str = "Archives stored in other archives are decompressed to a temporary \
     file first. RPF9 entries are recovered by scanning the archive data, without names or \
     folders. The result is kept until the archive changes.";
const AUTHENTICATING_NOTE: &str = "The archive's table of contents is processed before use. It is \
     read only when the signature verifies against the selected executable. This can take a \
     moment on a large executable.";
const NEEDS_EXECUTABLE_NOTE: &str = "Selecting a compatible local game executable lets the \
     archive's own table of contents be read and authenticated, with entry names as hashes, sizes \
     and types. Recovering by scanning reads the archive data instead and lists entries by kind \
     and offset. The two are never mixed.";
const IMAGE_ICON_COLOR: u32 = 0x7fb4ff;
const DETAILS_NAME_MIN_WIDTH: f32 = 110.;

fn grid_cell(mode: ViewMode) -> Option<(f32, f32)> {
    match mode {
        ViewMode::Icons => Some((104., 100.)),
        ViewMode::SmallIcons => Some((210., 26.)),
        ViewMode::Tiles => Some((270., 60.)),
        ViewMode::List | ViewMode::Details => None,
    }
}

/// The built-in icon for types Windows does not know.
fn fallback_icon(entry: &Entry) -> (Icon, u32) {
    match entry.kind {
        EntryKind::Directory => (Icon::Folder, theme::FOLDER),
        EntryKind::Unavailable => (Icon::FileMissing, theme::TEXT_MUTED),
        EntryKind::File if entry.is_supported_image() => (Icon::FileImage, IMAGE_ICON_COLOR),
        EntryKind::Archive | EntryKind::File => (Icon::File, theme::TEXT_MUTED),
    }
}

impl Explorer {
    /// The icon Windows shows for the entry's type, or a built-in one.
    /// Folders always use the built-in icon so they match the theme.
    pub(super) fn entry_icon(&self, entry: &Entry, size: Pixels) -> AnyElement {
        let icons = entry
            .extension()
            .and_then(|extension| self.file_icons.get(&extension))
            .and_then(Option::as_ref);
        match icons {
            Some(icons) if !entry.is_dir() => {
                let image = if size > px(24.) {
                    icons.large.clone()
                } else {
                    icons.small.clone()
                };
                img(image).flex_none().size(size).into_any_element()
            }
            _ => {
                let (glyph, color) = fallback_icon(entry);
                ui::icon(glyph, size, color).into_any_element()
            }
        }
    }

    pub(super) fn render_browser(
        &self,
        layout: &Layout,
        reveal: Option<&Path>,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .h_full()
            .bg(rgb(theme::PANEL))
            .child(self.render_browser_header(layout.center, cx))
            .child(
                div()
                    .id("browser")
                    .flex_1()
                    .min_h_0()
                    .on_click(cx.listener(|this, _, _, cx| this.select(None, cx)))
                    .child(self.render_browser_body(layout, reveal, cx)),
            )
    }

    fn render_browser_header(&self, width: f32, cx: &Context<Self>) -> impl IntoElement {
        let show_labels = width >= 640.;
        let sort_open = self.open_menu == Some(Menu::Sort);
        div()
            .flex()
            .flex_none()
            .items_center()
            .gap_2()
            .h(px(BROWSER_HEADER_HEIGHT))
            .px_2()
            .child(
                div()
                    .flex()
                    .gap_0p5()
                    .p_0p5()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(theme::BORDER))
                    .bg(rgb(theme::BACKGROUND))
                    .children(ViewMode::ALL.into_iter().map(|mode| {
                        let active = self.view_mode == mode;
                        div()
                            .id(mode.label())
                            .flex()
                            .items_center()
                            .gap_1p5()
                            .h(px(26.))
                            .px_2()
                            .rounded_sm()
                            .border_1()
                            .border_color(gpui::transparent_black())
                            .when(active, |el| {
                                el.bg(rgb(theme::SELECTION))
                                    .border_color(rgb(theme::SELECTION_BORDER))
                            })
                            .when(!active, |el| el.hover(|s| s.bg(rgb(theme::HOVER))))
                            .child(ui::icon(view_mode_icon(mode), px(14.), theme::TEXT))
                            .when(show_labels, |el| el.child(mode.label()))
                            .on_click(
                                cx.listener(move |this, _, _, cx| this.set_view_mode(mode, cx)),
                            )
                    })),
            )
            .child(
                div()
                    .flex()
                    .gap_0p5()
                    .p_0p5()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(theme::BORDER))
                    .bg(rgb(theme::BACKGROUND))
                    .children(ListingLayout::ALL.into_iter().map(|layout| {
                        let active = self.layout == layout;
                        div()
                            .id(layout.label())
                            .flex()
                            .items_center()
                            .h(px(26.))
                            .px_2()
                            .rounded_sm()
                            .border_1()
                            .border_color(gpui::transparent_black())
                            .when(active, |el| {
                                el.bg(rgb(theme::SELECTION))
                                    .border_color(rgb(theme::SELECTION_BORDER))
                            })
                            .when(!active, |el| el.hover(|s| s.bg(rgb(theme::HOVER))))
                            .when(show_labels, |el| el.child(layout.label()))
                            .on_click(
                                cx.listener(move |this, _, _, cx| this.set_layout(layout, cx)),
                            )
                    })),
            )
            .child(div().flex_1())
            .when_some(self.search.clone(), |el, search| {
                let empty = search.read(cx).text().is_empty();
                el.child(div().w(px(220.)).child(search))
                    .when(!empty, |el| {
                        el.child(ui::button("clear-filter", "Clear").on_click(cx.listener(
                            move |this, _, _, cx| {
                                cx.stop_propagation();
                                if let Some(search) = &this.search {
                                    search.update(cx, |field, cx| field.clear(cx));
                                }
                                cx.notify();
                            },
                        )))
                    })
            })
            .child(div().text_color(rgb(theme::TEXT_MUTED)).child("Sort:"))
            .child(
                div()
                    .id("sort")
                    .relative()
                    .flex()
                    .items_center()
                    .gap_2()
                    .h(px(28.))
                    .px_2()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(theme::BORDER))
                    .bg(rgb(theme::BACKGROUND))
                    .hover(|s| s.bg(rgb(theme::HOVER)))
                    .child(self.sort_label())
                    .child(ui::icon(Icon::ChevronDown, px(12.), theme::TEXT_MUTED))
                    .on_mouse_down(
                        MouseButton::Left,
                        cx.listener(|this, _, _, cx| {
                            this.open_menu = Some(Menu::Sort);
                            cx.notify();
                        }),
                    )
                    .when(sort_open, |el| {
                        el.child(
                            div().absolute().top_full().right_0().child(
                                deferred(
                                    anchored()
                                        .anchor(Anchor::TopRight)
                                        .snap_to_window_with_margin(px(4.))
                                        .child(self.render_menu_items(&Menu::Sort, cx)),
                                )
                                .priority(2),
                            ),
                        )
                    }),
            )
    }

    fn sort_label(&self) -> String {
        let descending = self.sort.descending;
        match self.sort.key {
            SortKey::Name if descending => "Name (Z–A)",
            SortKey::Name => "Name (A–Z)",
            SortKey::Type if descending => "Type (Z–A)",
            SortKey::Type => "Type (A–Z)",
            SortKey::Size if descending => "Size (largest)",
            SortKey::Size => "Size (smallest)",
            SortKey::Modified if descending => "Modified (newest)",
            SortKey::Modified => "Modified (oldest)",
        }
        .to_string()
    }

    /// The listing plus its scrollbar. The bar sits beside or below the
    /// content, according to the direction that can actually scroll.
    fn render_browser_body(
        &self,
        layout: &Layout,
        reveal: Option<&Path>,
        cx: &Context<Self>,
    ) -> AnyElement {
        let content = self.render_browser_content(layout, reveal, cx);
        let (handle, axis) = match self.view_mode {
            ViewMode::List => (self.list_scroll.clone(), Axis::Horizontal),
            ViewMode::Details | ViewMode::Icons | ViewMode::SmallIcons | ViewMode::Tiles => (
                self.browser_scroll.0.borrow().base_handle.clone(),
                Axis::Vertical,
            ),
        };
        match axis {
            Axis::Vertical => div()
                .flex()
                .size_full()
                .min_h_0()
                .child(div().flex_1().min_w_0().min_h_0().child(content))
                .child(self.render_scrollbar(handle, axis, "browser-scrollbar", cx))
                .into_any_element(),
            Axis::Horizontal => div()
                .flex()
                .flex_col()
                .size_full()
                .min_h_0()
                .child(div().flex_1().min_h_0().child(content))
                .child(self.render_scrollbar(handle, axis, "browser-scrollbar", cx))
                .into_any_element(),
        }
    }

    fn render_browser_content(
        &self,
        layout: &Layout,
        reveal: Option<&Path>,
        cx: &Context<Self>,
    ) -> AnyElement {
        let Some(dir) = self.current_dir() else {
            return self.render_start(cx).into_any_element();
        };
        let entries = match self.listings.get(dir) {
            Some(Listing::Loaded(entries)) => entries.clone(),
            Some(Listing::Loading) | None => return ui::centered_message("Loading…", None),
            Some(Listing::Indexing(archive)) => {
                return self.render_indexing(archive.clone(), cx).into_any_element();
            }
            Some(Listing::NeedsExecutable { archive, reason }) => {
                return self
                    .render_needs_executable(archive.clone(), reason.clone(), false, cx)
                    .into_any_element();
            }
            Some(Listing::AuthenticationFailed { archive, message }) => {
                return self
                    .render_needs_executable(archive.clone(), message.clone(), true, cx)
                    .into_any_element();
            }
            Some(Listing::Failed(err)) => {
                return ui::centered_message("This folder cannot be opened.", Some(err.clone()));
            }
        };
        let note = self.notes.get(dir);
        let needle = self
            .search
            .as_ref()
            .map(|search| search.read(cx).text().trim().to_ascii_lowercase())
            .unwrap_or_default();
        let entries = if needle.is_empty() {
            entries
        } else {
            Arc::new(
                entries
                    .iter()
                    .filter(|entry| matches_filter(entry, &needle))
                    .cloned()
                    .collect::<Vec<Entry>>(),
            )
        };
        if entries.is_empty() {
            return match (note, needle.is_empty()) {
                // The note explains why nothing is listed; "empty" could be wrong.
                (Some(note), true) => div()
                    .flex()
                    .size_full()
                    .items_center()
                    .justify_center()
                    .p_4()
                    .child(
                        div()
                            .max_w(px(520.))
                            .text_center()
                            .text_color(rgb(theme::TEXT_MUTED))
                            .child(note.clone()),
                    )
                    .into_any_element(),
                (_, false) => ui::centered_message("No entries match the filter.", None),
                (None, true) => ui::centered_message("This folder is empty.", None),
            };
        }
        let list_height = layout.center_height - if note.is_some() { NOTE_HEIGHT } else { 0. };

        let reveal_ix = reveal.map(|reveal| entries.iter().position(|e| e.path == reveal));
        let content = match self.view_mode {
            ViewMode::Details => {
                if let Some(ix) = reveal_ix {
                    self.browser_scroll.scroll_to_item(
                        ix.unwrap_or(0),
                        if ix.is_some() {
                            ScrollStrategy::Nearest
                        } else {
                            ScrollStrategy::Top
                        },
                    );
                }
                self.render_details(entries, cx).into_any_element()
            }
            ViewMode::List => {
                if reveal_ix.is_some() {
                    self.list_scroll.set_offset(Point::default());
                }
                self.render_list(&entries, layout.center, list_height, cx)
                    .into_any_element()
            }
            ViewMode::Icons | ViewMode::SmallIcons | ViewMode::Tiles => {
                let (cell_width, _) = grid_cell(self.view_mode).expect("grid mode");
                let columns =
                    (((layout.center - 2. * PADDING) / (cell_width + GAP)) as usize).max(1);
                if let Some(ix) = reveal_ix {
                    self.browser_scroll.scroll_to_item(
                        ix.map_or(0, |ix| ix / columns),
                        if ix.is_some() {
                            ScrollStrategy::Nearest
                        } else {
                            ScrollStrategy::Top
                        },
                    );
                }
                self.render_grid(entries, columns, cx).into_any_element()
            }
        };
        match note {
            Some(note) => div()
                .flex()
                .flex_col()
                .size_full()
                .child(
                    div()
                        .flex()
                        .flex_none()
                        .items_center()
                        .h(px(NOTE_HEIGHT - 8.))
                        .mx(px(PADDING))
                        .mb_2()
                        .px_2()
                        .rounded_md()
                        .border_1()
                        .border_color(rgb(theme::BORDER))
                        .bg(rgb(theme::SURFACE))
                        .text_xs()
                        .text_color(rgb(theme::TEXT_MUTED))
                        .child(div().line_clamp(2).child(note.clone())),
                )
                .child(div().flex_1().min_h_0().child(content))
                .into_any_element(),
            None => content,
        }
    }

    /// Shown while an archive is decompressed, authenticated or scanned before
    /// its contents can be listed.
    fn render_indexing(&self, archive: PathBuf, cx: &Context<Self>) -> impl IntoElement {
        let state = self.indexing_state(&archive);
        let running = state.is_some();
        let (fraction, stage, cancelling) = state.unwrap_or((None, Stage::OPENING, false));
        let headline = match stage {
            Stage::VERIFYING => "Authenticating the table of contents…",
            Stage::SCANNING => "Recovering entries by scanning…",
            _ => match fraction {
                Some(_) => "Indexing archive…",
                None => "Opening archive…",
            },
        };
        let note = match stage {
            Stage::VERIFYING => AUTHENTICATING_NOTE,
            Stage::SCANNING => INDEXING_NOTE,
            _ => INDEXING_NOTE,
        };
        div()
            .flex()
            .flex_col()
            .size_full()
            .items_center()
            .justify_center()
            .gap_3()
            .p_4()
            .text_color(rgb(theme::TEXT_MUTED))
            .child(div().text_color(rgb(theme::TEXT)).child(headline))
            .child(
                div()
                    .w(px(PROGRESS_WIDTH))
                    .h(px(6.))
                    .rounded_full()
                    .bg(rgb(theme::SURFACE))
                    .child(
                        div()
                            .h_full()
                            .rounded_full()
                            .bg(rgb(theme::ACCENT))
                            .w(px(PROGRESS_WIDTH * fraction.unwrap_or(0.))),
                    ),
            )
            .child(div().text_xs().child(match fraction {
                Some(fraction) => format!("{:.0}%", fraction * 100.),
                None => "Starting…".to_string(),
            }))
            .child(div().max_w(px(460.)).text_xs().text_center().child(note))
            .when(running && !cancelling, |el| {
                el.child(
                    ui::button("cancel-indexing", "Cancel").on_click(cx.listener(
                        move |this, _, _, cx| {
                            cx.stop_propagation();
                            this.cancel_indexing(&archive, cx)
                        },
                    )),
                )
            })
            .when(cancelling, |el| {
                el.child(div().text_xs().child("Cancelling…"))
            })
    }

    /// Shown when an archive's stored metadata needs an executable, or did not
    /// authenticate with the selected one. The user either selects an
    /// executable or chooses to scan the archive data. Native entries are
    /// never listed unauthenticated.
    fn render_needs_executable(
        &self,
        archive: PathBuf,
        message: String,
        failed: bool,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let headline = if failed {
            "The table of contents was not authenticated."
        } else {
            "The table of contents needs a local executable."
        };
        let executable = match &self.executable {
            super::ExecutableState::Checking => {
                Some("Checking the selected executable…".to_string())
            }
            super::ExecutableState::Failed(reason) => {
                Some(format!("The selected executable cannot be used: {reason}"))
            }
            super::ExecutableState::Ready(_) | super::ExecutableState::Unset => None,
        };
        div()
            .flex()
            .flex_col()
            .size_full()
            .items_center()
            .justify_center()
            .gap_3()
            .p_4()
            .child(div().text_color(rgb(theme::TEXT)).child(headline))
            .child(
                div()
                    .max_w(px(560.))
                    .text_xs()
                    .text_center()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(message),
            )
            .when_some(executable, |el, executable| {
                el.child(
                    div()
                        .max_w(px(560.))
                        .text_xs()
                        .text_center()
                        .text_color(rgb(theme::ERROR))
                        .child(executable),
                )
            })
            .child(
                div()
                    .max_w(px(560.))
                    .text_xs()
                    .text_center()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(NEEDS_EXECUTABLE_NOTE),
            )
            .child(
                div()
                    .flex()
                    .gap_2()
                    .child(
                        ui::button("choose-executable", "Select Game Executable…").on_click(
                            cx.listener(|this, _, _, cx| {
                                cx.stop_propagation();
                                this.choose_executable(cx)
                            }),
                        ),
                    )
                    .child(ui::button("scan-instead", "Recover by Scanning").on_click(
                        cx.listener(move |this, _, _, cx| {
                            cx.stop_propagation();
                            this.scan_instead(archive.clone(), cx)
                        }),
                    )),
            )
    }

    /// Shown when no directory is open.
    fn render_start(&self, cx: &Context<Self>) -> impl IntoElement {
        let message = if self.workspace.gta.is_none() {
            "Set the GTA VI folder or open another folder to start browsing."
        } else {
            "Select a folder in the tree."
        };
        div()
            .flex()
            .flex_col()
            .size_full()
            .items_center()
            .justify_center()
            .gap_3()
            .text_color(rgb(theme::TEXT_MUTED))
            .child(message)
            .child(
                div()
                    .flex()
                    .gap_2()
                    .when(self.workspace.gta.is_none(), |el| {
                        el.child(
                            ui::button("start-set-gta", "Set GTA VI Folder…")
                                .on_click(cx.listener(|this, _, _, cx| this.choose_gta_folder(cx))),
                        )
                    })
                    .child(
                        ui::button("start-open-folder", "Open Folder…")
                            .on_click(cx.listener(|this, _, _, cx| this.choose_folder_to_open(cx))),
                    ),
            )
    }

    fn render_details(&self, entries: Arc<Vec<Entry>>, cx: &Context<Self>) -> impl IntoElement {
        let header_cell = |key: SortKey, label: &'static str| {
            let active = self.sort.key == key;
            div()
                .id(label)
                .flex()
                .items_center()
                .gap_1()
                .h_full()
                .px_2()
                .when(key == SortKey::Size, |el| el.justify_end())
                .hover(|s| s.bg(rgb(theme::HOVER)))
                .child(label)
                .when(active, |el| {
                    el.child(ui::icon(
                        if self.sort.descending {
                            Icon::ArrowDown
                        } else {
                            Icon::ArrowUp
                        },
                        px(12.),
                        theme::TEXT_MUTED,
                    ))
                })
                .on_click(cx.listener(move |this, _, _, cx| {
                    cx.stop_propagation();
                    this.sort_by_column(key, cx)
                }))
        };

        div()
            .flex()
            .flex_col()
            .size_full()
            .child(
                div()
                    .flex()
                    .flex_none()
                    .h(px(28.))
                    .mx(px(PADDING))
                    .px_px()
                    .rounded_t_md()
                    .bg(rgb(theme::SURFACE))
                    .border_b_1()
                    .border_color(rgb(theme::BORDER))
                    .font_weight(FontWeight::MEDIUM)
                    .child(
                        header_cell(SortKey::Name, "Name")
                            .flex_1()
                            .min_w(px(DETAILS_NAME_MIN_WIDTH)),
                    )
                    .child(
                        header_cell(SortKey::Type, "Type")
                            .relative()
                            .w(px(self.details_widths[0]))
                            .child(self.column_grip(0, cx)),
                    )
                    .child(
                        header_cell(SortKey::Size, "Size")
                            .relative()
                            .w(px(self.details_widths[1]))
                            .child(self.column_grip(1, cx)),
                    )
                    .child(
                        header_cell(SortKey::Modified, "Modified")
                            .relative()
                            .w(px(self.details_widths[2]))
                            .child(self.column_grip(2, cx)),
                    ),
            )
            .child(
                uniform_list(
                    "details",
                    entries.len(),
                    cx.processor(move |this, range: Range<usize>, _, cx| {
                        range
                            .map(|ix| {
                                this.render_details_row(ix, &entries[ix], cx)
                                    .into_any_element()
                            })
                            .collect::<Vec<_>>()
                    }),
                )
                .track_scroll(&self.browser_scroll)
                .flex_1()
                .px(px(PADDING))
                .pt_1(),
            )
    }

    fn render_details_row(&self, ix: usize, entry: &Entry, cx: &Context<Self>) -> impl IntoElement {
        let cell = || div().px_2().truncate();
        self.browser_item(ix, entry, cx)
            .flex()
            .items_center()
            .w_full()
            .h(px(DETAILS_ROW_HEIGHT))
            .child(
                cell()
                    .flex()
                    .items_center()
                    .gap_2()
                    .flex_1()
                    .min_w(px(DETAILS_NAME_MIN_WIDTH))
                    .child(self.entry_icon(entry, px(16.)))
                    .child(div().min_w_0().truncate().child(entry.name.clone())),
            )
            .child(
                cell()
                    .w(px(self.details_widths[0]))
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(entry.type_name.clone()),
            )
            .child(
                cell()
                    .w(px(self.details_widths[1]))
                    .flex()
                    .justify_end()
                    .child(entry.size.map(files::format_size).unwrap_or_default()),
            )
            .child(
                cell()
                    .w(px(self.details_widths[2]))
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(
                        entry
                            .modified
                            .map(files::format_modified)
                            .unwrap_or_default(),
                    ),
            )
    }

    /// Items flow top to bottom in columns, scrolling horizontally. Only the
    /// columns in view are built, so large folders stay responsive.
    fn render_list(
        &self,
        entries: &[Entry],
        width: f32,
        height: f32,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let rows = (((height - 2. * PADDING) / LIST_ROW_HEIGHT) as usize).max(1);
        let columns = entries.len().div_ceil(rows);
        let stride = LIST_COLUMN_WIDTH + LIST_COLUMN_GAP;
        let scrolled = (-f32::from(self.list_scroll.offset().x)).max(0.);
        let first = ((scrolled / stride) as usize).min(columns);
        let visible = ((width / stride).ceil() as usize + 1).min(columns - first);
        div()
            .id("list")
            .size_full()
            .overflow_x_scroll()
            .track_scroll(&self.list_scroll)
            .p(px(PADDING))
            .child(
                div()
                    .flex()
                    .flex_none()
                    .h_full()
                    .w(px(columns as f32 * stride))
                    .pl(px(first as f32 * stride))
                    .gap(px(LIST_COLUMN_GAP))
                    .children(
                        entries
                            .chunks(rows)
                            .enumerate()
                            .skip(first)
                            .take(visible)
                            .map(|(column, chunk)| {
                                div()
                                    .flex()
                                    .flex_col()
                                    .flex_none()
                                    .w(px(LIST_COLUMN_WIDTH))
                                    .children(chunk.iter().enumerate().map(|(row, entry)| {
                                        self.browser_item(column * rows + row, entry, cx)
                                            .flex()
                                            .items_center()
                                            .gap_1p5()
                                            .h(px(LIST_ROW_HEIGHT))
                                            .px_1p5()
                                            .child(self.entry_icon(entry, px(16.)))
                                            .child(
                                                div()
                                                    .min_w_0()
                                                    .truncate()
                                                    .child(entry.name.clone()),
                                            )
                                    }))
                            }),
                    ),
            )
    }

    fn render_grid(
        &self,
        entries: Arc<Vec<Entry>>,
        columns: usize,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let mode = self.view_mode;
        let (cell_width, cell_height) = grid_cell(mode).expect("grid mode");
        let rows = entries.len().div_ceil(columns);
        uniform_list(
            "grid",
            rows,
            cx.processor(move |this, range: Range<usize>, _, cx| {
                range
                    .map(|row| {
                        let start = row * columns;
                        let end = (start + columns).min(entries.len());
                        div()
                            .flex()
                            .gap(px(GAP))
                            .pb(px(GAP))
                            .children((start..end).map(|ix| {
                                this.render_grid_item(ix, &entries[ix], mode, cx)
                                    .w(px(cell_width))
                                    .h(px(cell_height))
                            }))
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .track_scroll(&self.browser_scroll)
        .size_full()
        .p(px(PADDING))
    }

    fn render_grid_item(
        &self,
        ix: usize,
        entry: &Entry,
        mode: ViewMode,
        cx: &Context<Self>,
    ) -> Stateful<Div> {
        let item = self
            .browser_item(ix, entry, cx)
            .flex_none()
            .overflow_hidden();
        match mode {
            ViewMode::Icons => item
                .flex()
                .flex_col()
                .items_center()
                .gap_1()
                .pt_2()
                .px_1()
                .child(self.entry_icon(entry, px(48.)))
                .child(
                    div()
                        .w_full()
                        .text_xs()
                        .text_center()
                        .line_clamp(2)
                        .child(entry.name.clone()),
                ),
            ViewMode::Tiles => item
                .flex()
                .items_center()
                .gap_2()
                .px_2()
                .child(self.entry_icon(entry, px(36.)))
                .child(
                    div()
                        .flex()
                        .flex_col()
                        .min_w_0()
                        .child(div().truncate().child(entry.name.clone()))
                        .child(
                            div()
                                .text_xs()
                                .text_color(rgb(theme::TEXT_MUTED))
                                .truncate()
                                .child(entry.type_name.clone()),
                        )
                        .children(entry.size.map(|size| {
                            div()
                                .text_xs()
                                .text_color(rgb(theme::TEXT_MUTED))
                                .child(files::format_size(size))
                        })),
                ),
            _ => item
                .flex()
                .items_center()
                .gap_2()
                .px_1p5()
                .child(self.entry_icon(entry, px(20.)))
                .child(div().min_w_0().truncate().child(entry.name.clone())),
        }
    }

    /// A selectable item. Double-clicking opens it; right-clicking a file
    /// opens its context menu.
    fn browser_item(&self, ix: usize, entry: &Entry, cx: &Context<Self>) -> Stateful<Div> {
        let selected = self.selected.as_ref() == Some(&entry.path);
        let item = div()
            .id(("entry", ix))
            .rounded_sm()
            .border_1()
            .border_color(gpui::transparent_black())
            .when(selected, |el| {
                el.bg(rgb(theme::SELECTION))
                    .border_color(rgb(theme::SELECTION_BORDER))
            })
            .when(!selected, |el| el.hover(|s| s.bg(rgb(theme::HOVER))))
            .when(entry.is_inspectable(), |el| {
                let entry = entry.clone();
                el.on_mouse_down(
                    MouseButton::Right,
                    cx.listener(move |this, event: &MouseDownEvent, _, cx| {
                        cx.stop_propagation();
                        this.select(Some(entry.path.clone()), cx);
                        this.open_menu = Some(Menu::Entry {
                            entry: entry.clone(),
                            position: event.position,
                        });
                    }),
                )
            });
        let entry = entry.clone();
        item.on_click(cx.listener(move |this, event: &ClickEvent, _, cx| {
            cx.stop_propagation();
            if event.click_count() >= 2 {
                this.open_entry(&entry, cx);
            } else {
                this.select(Some(entry.path.clone()), cx);
            }
        }))
    }
}

fn view_mode_icon(mode: ViewMode) -> Icon {
    match mode {
        ViewMode::Icons => Icon::ViewIcons,
        ViewMode::SmallIcons => Icon::ViewSmallIcons,
        ViewMode::List => Icon::ViewList,
        ViewMode::Details => Icon::ViewDetails,
        ViewMode::Tiles => Icon::ViewTiles,
    }
}

/// Whether the entry matches a lower-case filter: its visible label, its
/// stored name key or hash, and its type. Matching is a bounded substring
/// test on the values the entry already carries, not an index.
fn matches_filter(entry: &Entry, needle: &str) -> bool {
    entry.name.to_ascii_lowercase().contains(needle)
        || entry.type_name.to_ascii_lowercase().contains(needle)
        || entry.details.iter().any(|(label, value)| {
            matches!(*label, "Name hash" | "Name key" | "Type ID" | "Names")
                && value.to_ascii_lowercase().contains(needle)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::files::Entry;

    fn rpf_entry() -> Entry {
        let mut entry = Entry::new(
            "props/crate.rpf".to_string(),
            PathBuf::from(r"pack.rpf\props\Row 00001"),
            EntryKind::File,
            Some(12),
            None,
        );
        entry.type_name = "RPF9 entry, type 0 (rpf)".to_string();
        entry.details = vec![
            ("Name hash", "0xABCDEF0123456789".to_string()),
            ("Name key", "0x1234ABCD".to_string()),
            ("Type ID", "0 (meaning not established)".to_string()),
            ("Names", "props/crate.rpf".to_string()),
        ];
        entry
    }

    #[test]
    fn filter_matches_labels_hashes_types_and_candidates() {
        let entry = rpf_entry();
        for needle in [
            "crate",
            "abcdef0123456789",
            "1234abcd",
            "type 0",
            "0 (meaning",
            "props/crate",
        ] {
            assert!(matches_filter(&entry, needle), "{needle}");
        }
        assert!(!matches_filter(&entry, "crates"));
        assert!(!matches_filter(&entry, "0x9999"));
    }

    #[test]
    fn filter_is_case_insensitive_through_the_caller_lower_case() {
        let entry = rpf_entry();
        // The caller lower-cases the needle; values are lowered here.
        assert!(matches_filter(
            &entry,
            "props/CRATE.rpf".to_ascii_lowercase().as_str()
        ));
        assert!(!matches_filter(&entry, "Props/crate.rpf"));
    }
}
