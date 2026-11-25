//! The binary inspector: a read-only hex view with a data inspector.
//!
//! Only the rows on screen and a margin around them are held in memory. Reads,
//! searches and hashing run on background threads against clones of one
//! [`Source`], so files of any size open without loading them.

mod render;

use std::io;
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use gpui::{
    App, ClipboardItem, Context, Entity, FocusHandle, KeyBinding, KeyDownEvent, Pixels, Point,
    ScrollEvent, SharedString, Subscription, Task, Window, actions, prelude::*, px,
};
use lforge_binary::{Endian, Source};

use crate::files;
use crate::ui::text_field::{TextField, TextFieldEvent};

actions!(
    binary_inspector,
    [
        GoToOffset,
        Find,
        FindNext,
        FindPrevious,
        CopyHex,
        Escape,
        CloseWindow
    ]
);

const KEY_CONTEXT: &str = "BinaryInspector";
/// Bytes kept around the visible rows, so small scrolls need no read.
const PAGE_MARGIN: u64 = 32 * 1024;
/// Bytes decoded by the data inspector; enough for every type and a text preview.
const INSPECT_LEN: u64 = 32;
const SIGNATURE_LEN: usize = 16;
/// Selections up to this size can be copied to the clipboard.
const MAX_COPY: u64 = 16 * 1024 * 1024;

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("ctrl-g", GoToOffset, Some(KEY_CONTEXT)),
        KeyBinding::new("ctrl-f", Find, Some(KEY_CONTEXT)),
        KeyBinding::new("f3", FindNext, Some(KEY_CONTEXT)),
        KeyBinding::new("shift-f3", FindPrevious, Some(KEY_CONTEXT)),
        KeyBinding::new("ctrl-c", CopyHex, Some(KEY_CONTEXT)),
        KeyBinding::new("escape", Escape, Some(KEY_CONTEXT)),
        KeyBinding::new("ctrl-w", CloseWindow, Some(KEY_CONTEXT)),
    ]);
}

struct OpenFile {
    source: Source,
    modified: Option<SystemTime>,
    signature: Vec<u8>,
}

enum State {
    Opening,
    Failed(String),
    Ready(OpenFile),
}

/// Bytes read from the file, starting at `start`.
struct Page {
    start: u64,
    bytes: Vec<u8>,
}

impl Page {
    fn covers(&self, range: &Range<u64>) -> bool {
        range.start >= self.start && range.end <= self.start + self.bytes.len() as u64
    }

    fn get(&self, range: Range<u64>) -> Option<&[u8]> {
        if !self.covers(&range) {
            return None;
        }
        let start = (range.start - self.start) as usize;
        let end = (range.end - self.start) as usize;
        Some(&self.bytes[start..end])
    }
}

/// A read in flight, or one that failed and is not retried for the same range.
struct Request {
    range: Range<u64>,
    _task: Option<Task<()>>,
}

#[derive(Clone, Copy, PartialEq)]
enum SearchMode {
    Hex,
    Text,
}

struct Search {
    cancel: Arc<AtomicBool>,
    _task: Task<()>,
}

enum Hash {
    Idle,
    Running {
        cancel: Arc<AtomicBool>,
        _task: Task<()>,
    },
    Done(String),
    Failed(String),
}

#[derive(Clone, Copy, PartialEq)]
enum Menu {
    File,
    View,
    Search,
}

#[derive(Clone, Copy, PartialEq)]
enum Drag {
    Selection,
    /// Holds where the thumb was grabbed, relative to its top.
    Scrollbar(f32),
    Panel,
}

struct Notice {
    text: SharedString,
    error: bool,
}

pub struct BinaryInspector {
    path: PathBuf,
    name: String,
    state: State,
    bytes_per_row: u64,
    endian: Endian,
    /// First row on screen.
    top_row: u64,
    /// Rows that fit on screen, updated on every render.
    visible_rows: u64,
    scroll_remainder: f32,
    cursor: u64,
    /// The other end of the selection, which always includes the cursor.
    anchor: u64,
    page: Option<Page>,
    page_request: Option<Request>,
    inspect: Option<Page>,
    inspect_request: Option<Request>,
    search_mode: SearchMode,
    search: Option<Search>,
    last_match: Option<Range<u64>>,
    hash: Hash,
    notice: Option<Notice>,
    panel_visible: bool,
    panel_width: f32,
    drag: Option<Drag>,
    open_menu: Option<Menu>,
    offset_field: Entity<TextField>,
    search_field: Entity<TextField>,
    focus_handle: FocusHandle,
    _open: Task<()>,
    _subscriptions: Vec<Subscription>,
}

impl BinaryInspector {
    pub fn new(
        path: PathBuf,
        access: crate::files::Access,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string());
        let open = cx.background_spawn({
            let path = path.clone();
            async move {
                let mut file = files::open_binary_with(&path, &access)?;
                let signature = lforge_binary::read_at(&mut file.source, 0, SIGNATURE_LEN)?;
                io::Result::Ok(OpenFile {
                    source: file.source,
                    modified: file.modified,
                    signature,
                })
            }
        });
        let open = cx.spawn(async move |this, cx| {
            let result = open.await;
            this.update(cx, |this, cx| {
                this.state = match result {
                    Ok(file) => State::Ready(file),
                    Err(err) => State::Failed(err.to_string()),
                };
                cx.notify();
            })
            .ok();
        });

        let offset_field = cx.new(|cx| TextField::new("0x0", cx));
        let search_field = cx.new(|cx| TextField::new("Hex bytes, e.g. 52 50 46 37", cx));
        let subscriptions = vec![
            cx.subscribe_in(
                &offset_field,
                window,
                |this, _, _: &TextFieldEvent, window, cx| this.go_to_entered_offset(window, cx),
            ),
            cx.subscribe_in(
                &search_field,
                window,
                |this, _, event: &TextFieldEvent, _, cx| {
                    let TextFieldEvent::Submit { shift } = event;
                    this.find(*shift, cx)
                },
            ),
        ];

        Self {
            path,
            name,
            state: State::Opening,
            bytes_per_row: 16,
            endian: Endian::Little,
            top_row: 0,
            visible_rows: 1,
            scroll_remainder: 0.,
            cursor: 0,
            anchor: 0,
            page: None,
            page_request: None,
            inspect: None,
            inspect_request: None,
            search_mode: SearchMode::Hex,
            search: None,
            last_match: None,
            hash: Hash::Idle,
            notice: None,
            panel_visible: true,
            panel_width: render::DEFAULT_PANEL_WIDTH,
            drag: None,
            open_menu: None,
            offset_field,
            search_field,
            focus_handle: cx.focus_handle(),
            _open: open,
            _subscriptions: subscriptions,
        }
    }

    pub fn focus_handle(&self) -> &FocusHandle {
        &self.focus_handle
    }

    fn file(&self) -> Option<&OpenFile> {
        match &self.state {
            State::Ready(file) => Some(file),
            State::Opening | State::Failed(_) => None,
        }
    }

    fn len(&self) -> u64 {
        self.file().map_or(0, |file| file.source.len())
    }

    fn total_rows(&self) -> u64 {
        self.len().div_ceil(self.bytes_per_row)
    }

    fn max_top_row(&self) -> u64 {
        self.total_rows().saturating_sub(self.visible_rows)
    }

    /// The selected bytes; empty only for an empty file.
    fn selection(&self) -> Range<u64> {
        if self.len() == 0 {
            return 0..0;
        }
        self.cursor.min(self.anchor)..self.cursor.max(self.anchor) + 1
    }

    fn notify_notice(&mut self, text: impl Into<SharedString>, error: bool) {
        self.notice = Some(Notice {
            text: text.into(),
            error,
        });
    }

    /// The bytes at `range` if they have been read.
    fn bytes(&self, range: Range<u64>) -> Option<&[u8]> {
        self.page
            .as_ref()
            .and_then(|page| page.get(range.clone()))
            .or_else(|| self.inspect.as_ref().and_then(|page| page.get(range)))
    }

    fn view_range(&self) -> Range<u64> {
        let start = self
            .top_row
            .saturating_mul(self.bytes_per_row)
            .min(self.len());
        let end = start
            .saturating_add(self.visible_rows.saturating_mul(self.bytes_per_row))
            .min(self.len());
        start..end
    }

    fn inspect_range(&self) -> Range<u64> {
        let len = self.len();
        self.cursor.min(len)..self.cursor.saturating_add(INSPECT_LEN).min(len)
    }

    /// Starts background reads for the visible rows and the bytes at the
    /// cursor when they are not in memory yet.
    fn request_data(&mut self, cx: &mut Context<Self>) {
        let Some(file) = self.file() else {
            return;
        };
        let source = file.source.clone();
        let len = source.len();
        let view = self.view_range();
        let pending = |request: &Option<Request>, range: &Range<u64>| {
            request.as_ref().is_some_and(|request| {
                range.start >= request.range.start && range.end <= request.range.end
            })
        };
        if !self.page.as_ref().is_some_and(|page| page.covers(&view))
            && !pending(&self.page_request, &view)
        {
            let range = view.start.saturating_sub(PAGE_MARGIN)
                ..view.end.saturating_add(PAGE_MARGIN).min(len);
            let task = self.read(source.clone(), range.clone(), false, cx);
            self.page_request = Some(Request {
                range,
                _task: Some(task),
            });
        }

        let inspect = self.inspect_range();
        if self.bytes(inspect.clone()).is_none()
            && !pending(&self.page_request, &inspect)
            && !pending(&self.inspect_request, &inspect)
        {
            let task = self.read(source, inspect.clone(), true, cx);
            self.inspect_request = Some(Request {
                range: inspect,
                _task: Some(task),
            });
        }
    }

    fn read(
        &self,
        mut source: Source,
        range: Range<u64>,
        inspect: bool,
        cx: &mut Context<Self>,
    ) -> Task<()> {
        let start = range.start;
        let count = (range.end - range.start) as usize;
        let read =
            cx.background_spawn(async move { lforge_binary::read_at(&mut source, start, count) });
        cx.spawn(async move |this, cx| {
            let result = read.await;
            this.update(cx, |this, cx| {
                let request = if inspect {
                    &mut this.inspect_request
                } else {
                    &mut this.page_request
                };
                match result {
                    Ok(bytes) => {
                        *request = None;
                        let page = Some(Page { start, bytes });
                        if inspect {
                            this.inspect = page;
                        } else {
                            this.page = page;
                        }
                    }
                    Err(err) => {
                        // Keep the finished request so the range is not retried every frame.
                        if let Some(request) = request {
                            request._task = None;
                        }
                        this.notify_notice(format!("Read failed: {err}"), true);
                    }
                }
                cx.notify();
            })
            .ok();
        })
    }

    fn set_top_row(&mut self, row: u64, cx: &mut Context<Self>) {
        let row = row.min(self.max_top_row());
        if row != self.top_row {
            self.top_row = row;
            cx.notify();
        }
    }

    fn scroll_to_cursor(&mut self) {
        let row = self.cursor / self.bytes_per_row;
        if row < self.top_row {
            self.top_row = row;
        } else if row >= self.top_row + self.visible_rows {
            self.top_row = row + 1 - self.visible_rows;
        }
    }

    fn set_cursor(&mut self, offset: u64, extend: bool, cx: &mut Context<Self>) {
        let len = self.len();
        if len == 0 {
            return;
        }
        self.cursor = offset.min(len - 1);
        if !extend {
            self.anchor = self.cursor;
        }
        self.scroll_to_cursor();
        cx.notify();
    }

    fn select(&mut self, range: Range<u64>, cx: &mut Context<Self>) {
        self.anchor = range.end - 1;
        self.set_cursor(range.start, true, cx);
    }

    fn hex_key_down(&mut self, event: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        let len = self.len();
        if len == 0 {
            return;
        }
        let keystroke = &event.keystroke;
        let control = keystroke.modifiers.control;
        let bpr = self.bytes_per_row;
        let page = self.visible_rows * bpr;
        let cursor = self.cursor;
        let row_start = cursor - cursor % bpr;
        let target = match keystroke.key.as_str() {
            "left" => cursor.saturating_sub(1),
            "right" => cursor + 1,
            "up" if cursor >= bpr => cursor - bpr,
            "down" if row_start / bpr < (len - 1) / bpr => cursor.saturating_add(bpr),
            "up" | "down" => cursor,
            "pageup" => {
                self.top_row = self.top_row.saturating_sub(self.visible_rows);
                cursor.saturating_sub(page)
            }
            "pagedown" => {
                self.top_row = (self.top_row + self.visible_rows).min(self.max_top_row());
                cursor.saturating_add(page)
            }
            "home" if control => 0,
            "end" if control => len - 1,
            "home" => row_start,
            "end" => row_start.saturating_add(bpr - 1),
            _ => return,
        };
        self.set_cursor(target, keystroke.modifiers.shift, cx);
        cx.stop_propagation();
    }

    fn scroll(&mut self, event: &ScrollEvent, _: &mut Window, cx: &mut Context<Self>) {
        let delta = event.delta.pixel_delta(px(render::ROW_HEIGHT)).y;
        self.scroll_remainder -= f32::from(delta) / render::ROW_HEIGHT;
        let rows = self.scroll_remainder.trunc();
        self.scroll_remainder -= rows;
        let top = if rows < 0. {
            self.top_row.saturating_sub(-rows as u64)
        } else {
            self.top_row.saturating_add(rows as u64)
        };
        self.set_top_row(top, cx);
        cx.stop_propagation();
    }

    fn press_byte(
        &mut self,
        offset: u64,
        shift: bool,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.focus_handle.focus(window, cx);
        self.drag = Some(Drag::Selection);
        self.set_cursor(offset, shift, cx);
    }

    fn drag_to(&mut self, position: Point<Pixels>, window: &Window, cx: &mut Context<Self>) {
        match self.drag {
            Some(Drag::Scrollbar(grab)) => {
                let (track_top, track_height) = render::scrollbar_track(window);
                let thumb = render::thumb_height(self, track_height);
                let free = (track_height - thumb).max(1.);
                let fraction = ((f32::from(position.y) - track_top - grab) / free).clamp(0., 1.);
                let row = (fraction as f64 * self.max_top_row() as f64).round() as u64;
                self.set_top_row(row, cx);
            }
            Some(Drag::Panel) => {
                let width = f32::from(window.viewport_size().width);
                self.panel_width = render::clamp_panel_width(width - f32::from(position.x), width);
                cx.notify();
            }
            Some(Drag::Selection) | None => {}
        }
    }

    fn set_bytes_per_row(&mut self, bytes: u64, cx: &mut Context<Self>) {
        self.bytes_per_row = bytes;
        self.top_row = self.top_row.min(self.max_top_row());
        self.scroll_to_cursor();
        cx.notify();
    }

    fn set_endian(&mut self, endian: Endian, cx: &mut Context<Self>) {
        self.endian = endian;
        cx.notify();
    }

    fn set_search_mode(&mut self, mode: SearchMode, cx: &mut Context<Self>) {
        self.search_mode = mode;
        let placeholder = match mode {
            SearchMode::Hex => "Hex bytes, e.g. 52 50 46 37",
            SearchMode::Text => "Text, searched as UTF-8",
        };
        self.search_field
            .update(cx, |field, _| field.set_placeholder(placeholder));
        cx.notify();
    }

    fn focus_offset_field(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let current = format!("{:#x}", self.cursor);
        self.offset_field.update(cx, |field, cx| {
            field.set_placeholder(current);
            field.clear(cx);
            field.focus(window, cx);
        });
    }

    fn go_to_entered_offset(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.offset_field.read(cx).text().to_string();
        let len = self.len();
        match lforge_binary::parse_offset(&text) {
            Ok(offset) if offset < len => {
                self.set_cursor(offset, false, cx);
                // Show the target in the top half rather than at the bottom edge.
                let row = offset / self.bytes_per_row;
                self.set_top_row(row.saturating_sub(self.visible_rows / 3), cx);
                self.notice = None;
                // The field has no selection, so start the next entry empty.
                self.offset_field.update(cx, |field, cx| {
                    field.set_placeholder(format!("{offset:#x}"));
                    field.clear(cx);
                });
                self.focus_handle.focus(window, cx);
            }
            Ok(offset) => self.notify_notice(
                format!("Offset {offset:#x} is beyond the end of the file ({len:#x} bytes)"),
                true,
            ),
            Err(err) => self.notify_notice(err, true),
        }
        cx.notify();
    }

    fn focus_search_field(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.search_field
            .update(cx, |field, cx| field.focus(window, cx));
    }

    fn pattern(&self, cx: &App) -> Result<Vec<u8>, String> {
        let text = self.search_field.read(cx).text();
        match self.search_mode {
            SearchMode::Hex => lforge_binary::parse_hex_pattern(text),
            SearchMode::Text if text.is_empty() => Err("the pattern is empty".to_string()),
            SearchMode::Text => Ok(text.as_bytes().to_vec()),
        }
    }

    /// Searches from the cursor. A repeated search skips the match it found last.
    fn find(&mut self, backward: bool, cx: &mut Context<Self>) {
        let Some(mut source) = self.file().map(|file| file.source.clone()) else {
            return;
        };
        let pattern = match self.pattern(cx) {
            Ok(pattern) => pattern,
            Err(err) => {
                self.notify_notice(format!("Invalid pattern: {err}"), true);
                cx.notify();
                return;
            }
        };
        self.cancel_search();
        let selection = self.selection();
        let from = if self.last_match.as_ref() == Some(&selection) {
            selection.start + 1
        } else {
            self.cursor
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let search = cx.background_spawn({
            let cancel = cancel.clone();
            let pattern = pattern.clone();
            async move {
                if backward {
                    lforge_binary::find_previous(&mut source, &pattern, selection.start, &cancel)
                } else {
                    lforge_binary::find_next(&mut source, &pattern, from, &cancel)
                }
            }
        });
        let task = cx.spawn(async move |this, cx| {
            let result = search.await;
            this.update(cx, |this, cx| {
                this.search = None;
                match result {
                    Ok(Some(at)) => {
                        let found = at..at + pattern.len() as u64;
                        this.last_match = Some(found.clone());
                        this.select(found, cx);
                        this.notify_notice(format!("Match at {at:#x}"), false);
                    }
                    Ok(None) if backward => this.notify_notice("No earlier match", false),
                    Ok(None) => this.notify_notice("No further match", false),
                    Err(lforge_binary::Error::Cancelled) => {
                        this.notify_notice("Search cancelled", false)
                    }
                    Err(err) => this.notify_notice(format!("Search failed: {err}"), true),
                }
                cx.notify();
            })
            .ok();
        });
        self.search = Some(Search {
            cancel,
            _task: task,
        });
        self.notice = None;
        cx.notify();
    }

    fn cancel_search(&mut self) {
        if let Some(search) = self.search.take() {
            search.cancel.store(true, Ordering::Relaxed);
        }
    }

    fn compute_hash(&mut self, cx: &mut Context<Self>) {
        let Some(file) = self.file() else {
            return;
        };
        if matches!(self.hash, Hash::Running { .. }) {
            return;
        }
        let mut source = file.source.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let hash = cx.background_spawn({
            let cancel = cancel.clone();
            async move { lforge_binary::sha256(&mut source, &cancel) }
        });
        let task = cx.spawn(async move |this, cx| {
            let result = hash.await;
            this.update(cx, |this, cx| {
                this.hash = match result {
                    Ok(digest) => Hash::Done(lforge_binary::hex_digest(&digest)),
                    Err(lforge_binary::Error::Cancelled) => Hash::Idle,
                    Err(err) => Hash::Failed(err.to_string()),
                };
                cx.notify();
            })
            .ok();
        });
        self.hash = Hash::Running {
            cancel,
            _task: task,
        };
        cx.notify();
    }

    fn cancel_hash(&mut self, cx: &mut Context<Self>) {
        if let Hash::Running { cancel, .. } = &self.hash {
            cancel.store(true, Ordering::Relaxed);
            self.hash = Hash::Idle;
            cx.notify();
        }
    }

    /// Copies the selection as hex, or as text when it is valid UTF-8.
    fn copy(&mut self, as_text: bool, cx: &mut Context<Self>) {
        let Some(file) = self.file() else {
            return;
        };
        let selection = self.selection();
        let count = selection.end - selection.start;
        if count == 0 {
            return;
        }
        if count > MAX_COPY {
            self.notify_notice(
                format!(
                    "Selections over {} cannot be copied",
                    files::format_size(MAX_COPY)
                ),
                true,
            );
            cx.notify();
            return;
        }
        let mut source = file.source.clone();
        let read = cx.background_spawn(async move {
            lforge_binary::read_at(&mut source, selection.start, count as usize)
        });
        cx.spawn(async move |this, cx| {
            let result = read.await;
            this.update(cx, |this, cx| {
                let text = match result {
                    Ok(bytes) if as_text => match String::from_utf8(bytes) {
                        Ok(text)
                            if !text
                                .chars()
                                .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r')) =>
                        {
                            Ok(text)
                        }
                        Ok(_) => Err("The selection contains control characters".to_string()),
                        Err(_) => Err("The selection is not valid UTF-8 text".to_string()),
                    },
                    Ok(bytes) => Ok(lforge_binary::hex_bytes(&bytes)),
                    Err(err) => Err(format!("Read failed: {err}")),
                };
                match text {
                    Ok(text) => {
                        cx.write_to_clipboard(ClipboardItem::new_string(text));
                        let what = if as_text { "text" } else { "hex" };
                        let bytes = if count == 1 { "byte" } else { "bytes" };
                        this.notify_notice(format!("Copied {count} {bytes} as {what}"), false);
                    }
                    Err(err) => this.notify_notice(err, true),
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn escape(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.open_menu.is_some() {
            self.open_menu = None;
        } else if self.search.is_some() {
            self.cancel_search();
            self.notify_notice("Search cancelled", false);
        } else {
            self.focus_handle.focus(window, cx);
        }
        cx.notify();
    }
}

impl Drop for BinaryInspector {
    /// Stops background work that would otherwise run until it finishes.
    fn drop(&mut self) {
        self.cancel_search();
        if let Hash::Running { cancel, .. } = &self.hash {
            cancel.store(true, Ordering::Relaxed);
        }
    }
}
