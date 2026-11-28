//! The text viewer: a read-only window over a textual payload.
//!
//! The payload is indexed on a background thread and only the lines on screen
//! are decoded. Search, rewrap and reopening with another encoding also run in
//! the background, so the window stays responsive on payloads of any size.
//!
//! Nothing here writes: the viewer has no editing state, and every read goes
//! through the archive path the other viewers use.

mod render;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use gpui::{
    App, ClipboardItem, Context, Entity, FocusHandle, KeyBinding, KeyDownEvent, Pixels, Point,
    ScrollEvent, SharedString, Subscription, Task, Window, actions, prelude::*,
};
use lforge_text::document::{self, TAB_WIDTH};
use lforge_text::syntax::{self, Span};
use lforge_text::{Detection, Document, Encoding, Language, Match};

use crate::files::{self, Access};
use crate::ui::text_field::{TextField, TextFieldEvent};

actions!(
    text_viewer,
    [
        Find,
        FindNext,
        FindPrevious,
        GoToLine,
        Copy,
        SelectAll,
        ToggleWrap,
        Escape,
        CloseWindow
    ]
);

const KEY_CONTEXT: &str = "TextViewer";
/// Lines decoded before and after the visible ones.
const PAGE_MARGIN: usize = 200;
/// Columns above which a line is shown without highlighting.
const HIGHLIGHT_LIMIT: u32 = 20_000;
/// Selections up to this size can be copied to the clipboard.
const MAX_COPY: usize = 32 * 1024 * 1024;
/// Matches highlighted on a line at once.
const MAX_LINE_MATCHES: usize = 200;
/// Bytes read to decide whether a payload is text.
const SAMPLE: u64 = 64 * 1024;

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("ctrl-f", Find, Some(KEY_CONTEXT)),
        KeyBinding::new("f3", FindNext, Some(KEY_CONTEXT)),
        KeyBinding::new("shift-f3", FindPrevious, Some(KEY_CONTEXT)),
        KeyBinding::new("ctrl-g", GoToLine, Some(KEY_CONTEXT)),
        KeyBinding::new("ctrl-c", Copy, Some(KEY_CONTEXT)),
        KeyBinding::new("ctrl-a", SelectAll, Some(KEY_CONTEXT)),
        KeyBinding::new("alt-z", ToggleWrap, Some(KEY_CONTEXT)),
        KeyBinding::new("escape", Escape, Some(KEY_CONTEXT)),
        KeyBinding::new("ctrl-w", CloseWindow, Some(KEY_CONTEXT)),
    ]);
}

/// A caret position: a line, and a display column within it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Position {
    pub line: usize,
    pub col: u32,
}

/// Bytes read by the indexing pass, for the loading message.
#[derive(Default)]
pub struct Progress {
    read: AtomicU64,
    total: AtomicU64,
}

/// What the viewer starts with, established before the window opens.
pub struct Prepared {
    pub encoding: Encoding,
    pub language: Language,
    pub extension: Option<String>,
    /// Why the payload was opened as text although the check did not accept
    /// it, shown once the window is up.
    pub notice: Option<String>,
}

/// One decoded line, ready to draw. Spans are in display columns.
struct PageLine {
    text: SharedString,
    columns: u32,
    spans: Vec<ColoredSpan>,
}

/// A highlighted display-column range of one line.
struct ColoredSpan {
    start: u32,
    end: u32,
    token: syntax::Token,
}

/// Lines decoded together, around the visible ones.
struct Page {
    first: usize,
    lines: Vec<PageLine>,
}

impl Page {
    fn contains(&self, lines: std::ops::Range<usize>) -> bool {
        !lines.is_empty() && lines.start >= self.first && lines.end <= self.first + self.lines.len()
    }

    fn get(&self, line: usize) -> Option<&PageLine> {
        self.lines.get(line.checked_sub(self.first)?)
    }
}

struct Request {
    first: usize,
    count: usize,
    _task: Option<Task<()>>,
}

struct Load {
    cancel: Arc<AtomicBool>,
    progress: Arc<Progress>,
    _task: Task<()>,
}

/// Where each line starts in wrapped rows.
struct Wrap {
    /// Columns a row showed when the index was built.
    columns: u32,
    /// `starts[line]` is the first row of that line; the last entry is the row
    /// count.
    starts: Arc<Vec<u64>>,
    rows: u64,
}

struct Open {
    document: Arc<Document>,
    language: Language,
    extension: Option<String>,
    wrap: Option<Wrap>,
    wrap_task: Option<Task<()>>,
    wrap_generation: u64,
}

enum State {
    Loading,
    Failed(String),
    Ready(Open),
}

enum SearchState {
    Idle,
    Running {
        cancel: Arc<AtomicBool>,
        _task: Task<()>,
    },
    Done {
        results: lforge_text::Results,
        current: Option<usize>,
        /// The needle and case mode the results were found with.
        needle: String,
        match_case: bool,
    },
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
    Scrollbar(f32),
    Horizontal(f32),
}

pub(super) struct Notice {
    pub text: SharedString,
    pub error: bool,
}
pub struct TextViewer {
    path: PathBuf,
    /// The entry's visible name: a resolved name, or the stored hash. Never the
    /// archive's internal row number.
    name: String,
    /// The archive file the payload is stored in, and its virtual folders.
    location: Option<String>,
    access: Access,
    encoding: Encoding,
    bom: bool,
    state: State,
    load: Option<Load>,
    /// Bumped by every load, so a superseded pass cannot replace a newer one.
    load_generation: u64,
    page: Option<Page>,
    page_request: Option<Request>,
    /// Bumped by every page request, for the same reason.
    page_generation: u64,
    top_row: u64,
    visible_rows: u64,
    /// Columns the viewport shows, updated on every render.
    columns: u32,
    /// Width of one monospace character, updated on every render.
    advance: f32,
    /// Width of the line-number gutter, updated on every render.
    gutter: f32,
    scroll_x: u32,
    scroll_remainder: f32,
    h_scroll_remainder: f32,
    anchor: Position,
    cursor: Position,
    wrap: bool,
    search: SearchState,
    match_case: bool,
    notice: Option<Notice>,
    find_field: Entity<TextField>,
    goto_field: Entity<TextField>,
    open_menu: Option<Menu>,
    drag: Option<Drag>,
    focus_handle: FocusHandle,
    _subscriptions: Vec<Subscription>,
}

/// Opens a payload found by content, falling back to the Binary Inspector when
/// the bytes turn out not to be text.
pub fn open(path: PathBuf, name: Option<String>, access: Access, cx: &mut App) {
    prepare_and_open(path, name, access, false, cx);
}

/// Opens a payload because the user asked for it, whatever the check says, and
/// explains a decode that is only a guess.
pub fn open_as_text(path: PathBuf, name: Option<String>, access: Access, cx: &mut App) {
    prepare_and_open(path, name, access, true, cx);
}

fn prepare_and_open(
    path: PathBuf,
    name: Option<String>,
    access: Access,
    explicit: bool,
    cx: &mut App,
) {
    let head = cx.background_spawn({
        let (path, access) = (path.clone(), access.clone());
        async move { files::read_head_with(&path, &access, SAMPLE) }
    });
    cx.spawn(async move |cx| {
        let head = match head.await {
            Ok(head) => head,
            Err(err) => {
                cx.update(|cx| open_failed(path, err.to_string(), cx));
                return;
            }
        };
        let extension = path
            .extension()
            .map(|extension| extension.to_string_lossy().to_ascii_lowercase());
        let detection = lforge_text::detect(&head, extension.as_deref());
        let prepared = match detection {
            Detection::Text(info) => Some(Prepared {
                encoding: info.encoding,
                language: info.language,
                extension,
                notice: None,
            }),
            Detection::Binary(reason) if explicit => {
                let (encoding, _) = lforge_text::guess_encoding(&head);
                Some(Prepared {
                    encoding,
                    language: extension
                        .as_deref()
                        .and_then(Language::from_extension)
                        .unwrap_or(Language::Plain),
                    extension,
                    notice: Some(format!(
                        "This payload is not text ({}). It is shown with an explicit encoding, \
                         and invalid sequences appear as replacement characters.",
                        reason.text()
                    )),
                })
            }
            Detection::Binary(_) => None,
        };
        cx.update(|cx| match prepared {
            Some(prepared) => open_window(path, name, access, prepared, cx),
            None => crate::explorer::open_binary_inspector(path, access, cx),
        });
    })
    .detach();
}

fn open_window(
    path: PathBuf,
    name: Option<String>,
    access: Access,
    prepared: Prepared,
    cx: &mut App,
) {
    let title = display_name(&path, name.as_deref());
    let mut options =
        crate::explorer::window_options(&title, gpui::size(gpui::px(1100.), gpui::px(760.)), cx);
    options.window_min_size = Some(gpui::size(gpui::px(480.), gpui::px(320.)));
    if let Err(err) = cx.open_window(options, |window, cx| {
        crate::ui::close_through_gpui(window, cx);
        let viewer = cx.new(|cx| TextViewer::new(path, name, access, prepared, window, cx));
        let focus_handle = viewer.read(cx).focus_handle().clone();
        focus_handle.focus(window, cx);
        viewer
    }) {
        log::error!("failed to open text viewer: {err:#}");
    }
}

fn open_failed(path: PathBuf, reason: String, cx: &mut App) {
    let title = display_name(&path, None);
    let mut options =
        crate::explorer::window_options(&title, gpui::size(gpui::px(640.), gpui::px(320.)), cx);
    options.window_min_size = Some(gpui::size(gpui::px(400.), gpui::px(240.)));
    if let Err(err) = cx.open_window(options, |window, cx| {
        crate::ui::close_through_gpui(window, cx);
        cx.new(|_| FailedView { reason })
    }) {
        log::error!("failed to open text viewer: {err:#}");
    }
}

/// The name a payload is identified by: the entry's resolved name or stored
/// hash, and never an internal row number.
fn display_name(path: &Path, name: Option<&str>) -> String {
    if let Some(name) = name.filter(|name| !name.is_empty()) {
        return name.to_string();
    }
    let last = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    if is_row_label(&last) {
        // Without a name the row cannot be identified better than by the
        // archive it is stored in.
        return files::split_location(path)
            .and_then(|(file, _)| {
                file.file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .unwrap_or(last);
    }
    last
}

/// Whether a path component is the archive's own `Row 00042` identity.
fn is_row_label(component: &str) -> bool {
    component
        .strip_prefix("Row ")
        .is_some_and(|row| !row.is_empty() && row.bytes().all(|byte| byte.is_ascii_digit()))
}

/// The archive and virtual folders the payload is stored under, with the row
/// labels of nested archives left out: a row number is not a path.
fn location(path: &Path) -> Option<String> {
    let (file, inner) = files::split_location(path)?;
    let mut parts: Vec<String> = Vec::new();
    if let Some(name) = file.file_name() {
        parts.push(name.to_string_lossy().into_owned());
    }
    let mut folders: Vec<String> = inner
        .parent()
        .map(|parent| {
            parent
                .iter()
                .map(|part| part.to_string_lossy().into_owned())
                .filter(|part| !is_row_label(part))
                .collect()
        })
        .unwrap_or_default();
    parts.append(&mut folders);
    Some(parts.join(" / "))
}

/// A window that only says why nothing could be read.
struct FailedView {
    reason: String,
}

impl Render for FailedView {
    fn render(&mut self, _: &mut Window, _: &mut Context<Self>) -> impl IntoElement {
        crate::ui::centered_message(
            "This file cannot be opened as text.",
            Some(self.reason.clone()),
        )
    }
}

impl TextViewer {
    fn new(
        path: PathBuf,
        name: Option<String>,
        access: Access,
        prepared: Prepared,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> Self {
        let name = display_name(&path, name.as_deref());
        let location = location(&path);
        let find_field = cx.new(|cx| TextField::new("Find", cx));
        let goto_field = cx.new(|cx| TextField::new("Line", cx));
        let subscriptions = vec![
            cx.subscribe_in(
                &find_field,
                window,
                |this, _, event: &TextFieldEvent, _, cx| {
                    let TextFieldEvent::Submit { shift } = event;
                    this.submit_find(*shift, cx)
                },
            ),
            cx.subscribe_in(
                &goto_field,
                window,
                |this, _, event: &TextFieldEvent, window, cx| {
                    let TextFieldEvent::Submit { .. } = event;
                    this.submit_goto(window, cx)
                },
            ),
        ];
        let mut viewer = Self {
            path,
            name,
            location,
            access,
            encoding: prepared.encoding,
            bom: false,
            state: State::Loading,
            load: None,
            load_generation: 0,
            page: None,
            page_request: None,
            page_generation: 0,
            top_row: 0,
            visible_rows: 1,
            columns: 80,
            advance: 8.,
            gutter: 48.,
            scroll_x: 0,
            scroll_remainder: 0.,
            h_scroll_remainder: 0.,
            anchor: Position::default(),
            cursor: Position::default(),
            wrap: false,
            search: SearchState::Idle,
            match_case: false,
            notice: None,
            find_field,
            goto_field,
            open_menu: None,
            drag: None,
            focus_handle: cx.focus_handle(),
            _subscriptions: subscriptions,
        };
        viewer.start_load(prepared, cx);
        viewer
    }

    pub fn focus_handle(&self) -> &FocusHandle {
        &self.focus_handle
    }

    fn open(&self) -> Option<&Open> {
        match &self.state {
            State::Ready(open) => Some(open),
            State::Loading | State::Failed(_) => None,
        }
    }

    /// Indexes the payload with the chosen encoding, replacing any pass in
    /// flight.
    fn start_load(&mut self, prepared: Prepared, cx: &mut Context<Self>) {
        if let Some(load) = self.load.take() {
            load.cancel.store(true, Ordering::Relaxed);
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let progress = Arc::new(Progress::default());
        self.load_generation += 1;
        let generation = self.load_generation;
        self.encoding = prepared.encoding;
        self.bom = false;
        self.state = State::Loading;
        self.page = None;
        self.page_request = None;
        self.top_row = 0;
        self.scroll_x = 0;
        self.anchor = Position::default();
        self.cursor = Position::default();
        self.search = SearchState::Idle;
        self.notice = prepared.notice.as_deref().map(|text| Notice {
            text: text.into(),
            error: false,
        });

        let encoding = prepared.encoding;
        let language = prepared.language;
        let extension = prepared.extension.clone();
        let path = self.path.clone();
        let access = self.access.clone();
        let work = cx.background_spawn({
            let cancel = cancel.clone();
            let progress = progress.clone();
            async move {
                let file =
                    files::open_binary_with(&path, &access).map_err(|err| err.to_string())?;
                let document = Document::load(file.source, encoding, &cancel, |read, total| {
                    progress.read.store(read, Ordering::Relaxed);
                    progress.total.store(total, Ordering::Relaxed);
                })
                .map_err(|err| err.to_string())?;
                // An extension names the language; content only fills a gap.
                let language = match extension.as_deref().and_then(Language::from_extension) {
                    Some(named) => named,
                    None => match document.read_lines(0, 80) {
                        Ok(lines) => Language::sniff(&lines.join("\n")).unwrap_or(language),
                        Err(_) => language,
                    },
                };
                Ok::<_, String>((document, language, extension))
            }
        });
        let task = cx.spawn(async move |this, cx| {
            let result = work.await;
            this.update(cx, |this, cx| {
                if this.load_generation != generation {
                    return;
                }
                match result {
                    Ok((document, language, extension)) => {
                        this.bom = document.bom_len() > 0;
                        this.state = State::Ready(Open {
                            document: Arc::new(document),
                            language,
                            extension,
                            wrap: None,
                            wrap_task: None,
                            wrap_generation: 0,
                        });
                        this.page = None;
                        this.page_request = None;
                        this.page_generation += 1;
                        if this.wrap {
                            this.rebuild_wrap(cx);
                        }
                    }
                    Err(err) => this.state = State::Failed(err),
                }
                cx.notify();
            })
            .ok();
        });
        self.load = Some(Load {
            cancel,
            progress,
            _task: task,
        });
        // Repaints while the pass runs, so the number of bytes read moves.
        cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(Duration::from_millis(200))
                    .await;
                let loading = this
                    .update(cx, |this, cx| {
                        if matches!(this.state, State::Loading) {
                            cx.notify();
                            true
                        } else {
                            false
                        }
                    })
                    .unwrap_or(false);
                if !loading {
                    break;
                }
            }
        })
        .detach();
        cx.notify();
    }

    /// Reloads the payload with an encoding the user chose.
    fn set_encoding(&mut self, encoding: Encoding, cx: &mut Context<Self>) {
        let extension = self
            .open()
            .and_then(|open| open.extension.clone())
            .or_else(|| {
                self.path
                    .extension()
                    .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
            });
        let prepared = Prepared {
            encoding,
            language: extension
                .as_deref()
                .and_then(Language::from_extension)
                .unwrap_or(Language::Plain),
            extension,
            notice: None,
        };
        self.start_load(prepared, cx);
    }

    fn open_mut(&mut self) -> Option<&mut Open> {
        match &mut self.state {
            State::Ready(open) => Some(open),
            State::Loading | State::Failed(_) => None,
        }
    }

    fn row_count(&self) -> u64 {
        let Some(open) = self.open() else {
            return 0;
        };
        match &open.wrap {
            Some(wrap) if self.wrap => wrap.rows,
            _ => open.document.line_count() as u64,
        }
    }

    fn max_top_row(&self) -> u64 {
        self.row_count().saturating_sub(self.visible_rows)
    }

    /// The line and wrapped segment a row belongs to.
    fn line_of_row(&self, row: u64) -> (usize, u64) {
        let Some(open) = self.open() else {
            return (0, 0);
        };
        match &open.wrap {
            Some(wrap) if self.wrap => {
                let starts = &wrap.starts;
                let line = starts
                    .partition_point(|start| *start <= row)
                    .saturating_sub(1);
                (
                    line,
                    row.saturating_sub(starts.get(line).copied().unwrap_or(0)),
                )
            }
            _ => (usize::try_from(row).unwrap_or(usize::MAX), 0),
        }
    }

    /// The row a caret is on.
    fn row_of(&self, position: Position) -> u64 {
        let Some(open) = self.open() else {
            return 0;
        };
        match &open.wrap {
            Some(wrap) if self.wrap => {
                let start = wrap.starts.get(position.line).copied().unwrap_or(0);
                let segment = u64::from(position.col / self.columns.max(1));
                start + segment
            }
            _ => position.line as u64,
        }
    }

    fn line_columns(&self, line: usize) -> u32 {
        self.open()
            .map(|open| open.document.line_columns(line))
            .unwrap_or(0)
    }

    fn clamp(&self, position: Position) -> Position {
        let Some(open) = self.open() else {
            return Position::default();
        };
        let lines = open.document.line_count();
        if lines == 0 {
            return Position::default();
        }
        let line = position.line.min(lines - 1);
        Position {
            line,
            col: position.col.min(open.document.line_columns(line)),
        }
    }

    fn set_cursor(&mut self, position: Position, extend: bool, cx: &mut Context<Self>) {
        let position = self.clamp(position);
        self.cursor = position;
        if !extend {
            self.anchor = position;
        }
        self.scroll_to_cursor();
        self.request_page(cx);
        cx.notify();
    }

    fn scroll_to_cursor(&mut self) {
        let row = self.row_of(self.cursor);
        if row < self.top_row {
            self.top_row = row;
        } else if row >= self.top_row + self.visible_rows {
            self.top_row = row + 1 - self.visible_rows;
        }
        if !self.wrap {
            let columns = self.columns.max(1);
            if self.cursor.col < self.scroll_x {
                self.scroll_x = self.cursor.col;
            } else if self.cursor.col >= self.scroll_x + columns {
                self.scroll_x = self.cursor.col + 1 - columns;
            }
        }
    }

    fn set_top_row(&mut self, row: u64, cx: &mut Context<Self>) {
        let row = row.min(self.max_top_row());
        if row != self.top_row {
            self.top_row = row;
            cx.notify();
        }
    }

    /// The ordered selection, or `None` when the caret is a point.
    fn selection(&self) -> Option<(Position, Position)> {
        if self.anchor == self.cursor {
            return None;
        }
        Some(if self.anchor < self.cursor {
            (self.anchor, self.cursor)
        } else {
            (self.cursor, self.anchor)
        })
    }

    fn select_all(&mut self, cx: &mut Context<Self>) {
        let Some(open) = self.open() else {
            return;
        };
        let lines = open.document.line_count();
        if lines == 0 {
            return;
        }
        let last = Position {
            line: lines - 1,
            col: open.document.line_columns(lines - 1),
        };
        self.anchor = Position::default();
        self.cursor = last;
        self.scroll_to_cursor();
        self.request_page(cx);
        cx.notify();
    }

    /// The visible lines, which are the ones the page must hold.
    fn visible_lines(&self) -> std::ops::Range<usize> {
        if self.row_count() == 0 {
            return 0..0;
        }
        let first = self.line_of_row(self.top_row).0;
        let last_row = (self.top_row + self.visible_rows - 1).min(self.row_count() - 1);
        let last = self.line_of_row(last_row).0;
        first..last + 1
    }

    /// Starts decoding the visible lines, with a margin, when the page does not
    /// already hold them.
    fn request_page(&mut self, cx: &mut Context<Self>) {
        let Some(open) = self.open() else {
            return;
        };
        let lines = open.document.line_count();
        let visible = self.visible_lines();
        if lines == 0 || visible.is_empty() {
            return;
        }
        if self
            .page
            .as_ref()
            .is_some_and(|page| page.contains(visible.clone()))
        {
            return;
        }
        if let Some(request) = &self.page_request
            && request.first <= visible.start
            && visible.end <= request.first + request.count
        {
            return;
        }
        let first = visible.start.saturating_sub(PAGE_MARGIN);
        let last = (visible.end + PAGE_MARGIN).min(lines);
        let count = last - first;
        let document = Arc::clone(&open.document);
        let language = open.language;
        self.page_generation += 1;
        let generation = self.page_generation;
        let load = cx.background_spawn(async move {
            let lines = document.read_lines(first, count)?;
            let page_lines = lines
                .into_iter()
                .map(|raw| page_line(&raw, language))
                .collect();
            Ok::<_, document::Error>(Page {
                first,
                lines: page_lines,
            })
        });
        let task = cx.spawn(async move |this, cx| {
            let result = load.await;
            this.update(cx, |this, cx| {
                if this.page_generation != generation {
                    return;
                }
                this.page_request = None;
                match result {
                    Ok(page) => {
                        // Keep the caret's line available if the page does not
                        // hold it.
                        this.page = Some(page);
                    }
                    Err(err) => this.notify(format!("Could not read the lines: {err}"), true),
                }
                cx.notify();
            })
            .ok();
        });
        self.page_request = Some(Request {
            first,
            count,
            _task: Some(task),
        });
    }

    /// Builds the row index wrapping needs, after the payload is indexed or the
    /// window width changes.
    fn rebuild_wrap(&mut self, cx: &mut Context<Self>) {
        let Some(open) = self.open() else {
            return;
        };
        if !self.wrap || self.columns == 0 {
            return;
        }
        let columns = self.columns;
        if open
            .wrap
            .as_ref()
            .is_some_and(|wrap| wrap.columns == columns)
        {
            return;
        }
        let document = Arc::clone(&open.document);
        let Some(open) = self.open_mut() else {
            return;
        };
        open.wrap_generation += 1;
        let generation = open.wrap_generation;
        // A short delay keeps a resize from rebuilding the index per frame.
        let task = cx.spawn(async move |this, cx| {
            cx.background_executor()
                .timer(Duration::from_millis(120))
                .await;
            let build = cx.background_spawn(async move {
                let lines = document.line_count();
                let mut starts = Vec::with_capacity(lines + 1);
                let mut rows = 0u64;
                for line in 0..lines {
                    starts.push(rows);
                    rows += u64::from(document.line_columns(line).div_ceil(columns).max(1));
                }
                starts.push(rows);
                Wrap {
                    columns,
                    starts: Arc::new(starts),
                    rows,
                }
            });
            let wrap = build.await;
            this.update(cx, |this, cx| {
                let caret = this.cursor;
                let Some(open) = this.open_mut() else {
                    return;
                };
                if open.wrap_generation != generation {
                    return;
                }
                open.wrap = Some(wrap);
                this.top_row = this.row_of(caret).saturating_sub(this.visible_rows / 4);
                this.top_row = this.top_row.min(this.max_top_row());
                this.request_page(cx);
                cx.notify();
            })
            .ok();
        });
        if let Some(open) = self.open_mut() {
            open.wrap_task = Some(task);
        }
        cx.notify();
    }

    fn toggle_wrap(&mut self, cx: &mut Context<Self>) {
        self.wrap = !self.wrap;
        if self.wrap {
            self.scroll_x = 0;
            self.rebuild_wrap(cx);
        } else {
            let line = self.line_of_row(self.top_row).0;
            self.top_row = (line as u64).min(self.max_top_row());
        }
        self.scroll_to_cursor();
        self.request_page(cx);
        cx.notify();
    }

    fn scroll(&mut self, event: &ScrollEvent, _: &mut Window, cx: &mut Context<Self>) {
        if event.modifiers.shift && !self.wrap {
            let delta = event.delta.pixel_delta(render::row_height()).y;
            self.scroll_x_by(-f32::from(delta), cx);
            cx.stop_propagation();
            return;
        }
        let delta = f32::from(event.delta.pixel_delta(render::row_height()).y);
        self.scroll_remainder -= delta / render::ROW_HEIGHT;
        let rows = self.scroll_remainder.trunc();
        self.scroll_remainder -= rows;
        let top = if rows < 0. {
            self.top_row.saturating_sub(-rows as u64)
        } else {
            self.top_row.saturating_add(rows as u64)
        };
        self.set_top_row(top, cx);
        self.request_page(cx);
        cx.stop_propagation();
    }

    fn scroll_x_by(&mut self, pixels: f32, cx: &mut Context<Self>) {
        self.h_scroll_remainder += pixels / self.advance.max(1.);
        let step = self.h_scroll_remainder.trunc() as i32;
        self.h_scroll_remainder -= step as f32;
        self.set_scroll_x(self.scroll_x.saturating_add_signed(step), cx);
    }

    fn set_scroll_x(&mut self, columns: u32, cx: &mut Context<Self>) {
        let columns = columns.min(self.max_scroll_x());
        if columns != self.scroll_x {
            self.scroll_x = columns;
            cx.notify();
        }
    }

    fn max_scroll_x(&self) -> u32 {
        self.open()
            .map_or(0, |open| open.document.max_columns())
            .saturating_sub(self.columns)
    }

    fn key_down(&mut self, event: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        let Some(open) = self.open() else {
            return;
        };
        let lines = open.document.line_count();
        if lines == 0 {
            return;
        }
        let keystroke = &event.keystroke;
        let modifiers = keystroke.modifiers;
        let page = self.visible_rows as usize;
        let cursor = self.cursor;
        let line_end = self.line_columns(cursor.line);
        let target = match keystroke.key.as_str() {
            "left" if cursor.col > 0 => Position {
                col: cursor.col - 1,
                ..cursor
            },
            "left" if cursor.line > 0 => Position {
                line: cursor.line - 1,
                col: self.line_columns(cursor.line - 1),
            },
            "right" if cursor.col < line_end => Position {
                col: cursor.col + 1,
                ..cursor
            },
            "right" if cursor.line + 1 < lines => Position {
                line: cursor.line + 1,
                col: 0,
            },
            "up" if cursor.line > 0 => Position {
                line: cursor.line - 1,
                ..cursor
            },
            "down" if cursor.line + 1 < lines => Position {
                line: cursor.line + 1,
                ..cursor
            },
            "up" | "down" => cursor,
            "pageup" => Position {
                line: cursor.line.saturating_sub(page),
                ..cursor
            },
            "pagedown" => Position {
                line: (cursor.line + page).min(lines - 1),
                ..cursor
            },
            "home" if modifiers.control => Position::default(),
            "end" if modifiers.control => Position {
                line: lines - 1,
                col: self.line_columns(lines - 1),
            },
            "home" => Position { col: 0, ..cursor },
            "end" => Position {
                col: line_end,
                ..cursor
            },
            _ => return,
        };
        self.set_cursor(target, modifiers.shift, cx);
        cx.stop_propagation();
    }

    fn press(&mut self, position: Position, shift: bool, cx: &mut Context<Self>) {
        self.drag = Some(Drag::Selection);
        self.set_cursor(position, shift, cx);
    }

    fn drag_to(&mut self, point: Point<Pixels>, window: &Window, cx: &mut Context<Self>) {
        match self.drag {
            Some(Drag::Scrollbar(grab)) => {
                let (track_top, track_height) = render::track(window, !self.wrap);
                let thumb = render::thumb_height(self, track_height);
                let free = (track_height - thumb).max(1.);
                let fraction = ((f32::from(point.y) - track_top - grab) / free).clamp(0., 1.);
                let row = (fraction as f64 * self.max_top_row() as f64).round() as u64;
                self.set_top_row(row, cx);
                self.request_page(cx);
            }
            Some(Drag::Horizontal(grab)) => {
                let (track_left, track_width) = render::horizontal_track(window);
                let thumb = render::horizontal_thumb(self, track_width);
                let free = (track_width - thumb).max(1.);
                let fraction = ((f32::from(point.x) - track_left - grab) / free).clamp(0., 1.);
                let columns = (fraction as f64 * self.max_scroll_x() as f64).round() as u32;
                self.set_scroll_x(columns, cx);
            }
            Some(Drag::Selection) | None => {}
        }
    }

    /// The caret a click at `point` lands on.
    fn caret_at(&self, point: Point<Pixels>, window: &Window) -> Position {
        let (left, top) = render::text_origin(self, window);
        let row = self.top_row
            + ((f32::from(point.y) - top) / render::ROW_HEIGHT)
                .floor()
                .max(0.) as u64;
        let row = row.min(self.row_count().saturating_sub(1));
        let (line, segment) = self.line_of_row(row);
        let start_col = if self.wrap {
            u32::try_from(segment).unwrap_or(u32::MAX) * self.columns.max(1)
        } else {
            self.scroll_x
        };
        let column = ((f32::from(point.x) - left) / self.advance.max(1.)).max(0.);
        let col = start_col.saturating_add(column.round() as u32);
        Position {
            line,
            col: col.min(self.line_columns(line)),
        }
    }

    fn focus_find(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.find_field
            .update(cx, |field, cx| field.focus(window, cx));
    }

    fn focus_goto(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.goto_field.update(cx, |field, cx| {
            field.clear(cx);
            field.focus(window, cx);
        });
    }

    fn submit_goto(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.goto_field.read(cx).text().trim().to_string();
        let lines = self.open().map_or(0, |open| open.document.line_count());
        match text.parse::<usize>() {
            Ok(line) if (1..=lines).contains(&line) => {
                self.set_cursor(
                    Position {
                        line: line - 1,
                        col: 0,
                    },
                    false,
                    cx,
                );
                self.notice = None;
                self.focus_handle.focus(window, cx);
            }
            Ok(line) => self.notify(
                format!("Line {line} is outside this file (1–{lines})"),
                true,
            ),
            Err(_) => self.notify("Enter a line number".to_string(), true),
        }
        cx.notify();
    }

    fn submit_find(&mut self, backward: bool, cx: &mut Context<Self>) {
        let needle = self.find_field.read(cx).text().to_string();
        let unchanged = matches!(
            &self.search,
            SearchState::Done { needle: searched, match_case, .. }
                if *searched == needle && *match_case == self.match_case
        );
        if unchanged {
            self.step_match(backward, cx);
        } else {
            self.start_search(cx);
        }
    }

    fn start_search(&mut self, cx: &mut Context<Self>) {
        let Some(open) = self.open() else {
            return;
        };
        let needle = self.find_field.read(cx).text().to_string();
        if needle.is_empty() {
            self.notify("Enter text to find".to_string(), true);
            cx.notify();
            return;
        }
        if let SearchState::Running { cancel, .. } = &self.search {
            cancel.store(true, Ordering::Relaxed);
        }
        let document = Arc::clone(&open.document);
        let match_case = self.match_case;
        let cancel = Arc::new(AtomicBool::new(false));
        let work = cx.background_spawn({
            let cancel = cancel.clone();
            let needle = needle.clone();
            async move { lforge_text::find(&document, &needle, match_case, &cancel) }
        });
        let task = cx.spawn(async move |this, cx| {
            let result = work.await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(results) => {
                        let current = this.match_at_cursor(&results);
                        this.search = SearchState::Done {
                            results,
                            current,
                            needle,
                            match_case,
                        };
                        this.jump_to_match(cx);
                        this.update_match_notice();
                    }
                    Err(document::Error::Cancelled) => {
                        this.search = SearchState::Idle;
                        this.notify("Search cancelled".to_string(), false);
                    }
                    Err(err) => {
                        this.search = SearchState::Idle;
                        this.notify(format!("Search failed: {err}"), true);
                    }
                }
                cx.notify();
            })
            .ok();
        });
        self.search = SearchState::Running {
            cancel,
            _task: task,
        };
        self.notice = None;
        cx.notify();
    }

    /// The first match at or after the caret.
    fn match_at_cursor(&self, results: &lforge_text::Results) -> Option<usize> {
        let cursor = self.cursor;
        results
            .matches
            .iter()
            .position(|found| (found.line as usize, found.start) >= (cursor.line, cursor.col))
    }

    fn step_match(&mut self, backward: bool, cx: &mut Context<Self>) {
        let next = match &self.search {
            SearchState::Done {
                results, current, ..
            } => {
                if results.is_empty() {
                    None
                } else {
                    let count = results.matches.len();
                    match (*current, backward) {
                        (Some(index), false) => Some((index + 1) % count),
                        (None, false) => self.match_at_cursor(results),
                        (Some(0), true) => Some(count - 1),
                        (Some(index), true) => Some(index - 1),
                        (None, true) => self
                            .match_at_cursor(results)
                            .and_then(|index| index.checked_sub(1))
                            .or(Some(count - 1)),
                    }
                }
            }
            SearchState::Idle | SearchState::Running { .. } => {
                self.start_search(cx);
                return;
            }
        };
        if let SearchState::Done {
            results, current, ..
        } = &mut self.search
        {
            if results.is_empty() {
                self.notify("No matches".to_string(), false);
                cx.notify();
                return;
            }
            *current = next;
        }
        self.jump_to_match(cx);
        self.update_match_notice();
        cx.notify();
    }

    fn jump_to_match(&mut self, cx: &mut Context<Self>) {
        let SearchState::Done {
            results, current, ..
        } = &self.search
        else {
            return;
        };
        let Some(found) = current.and_then(|index| results.matches.get(index)) else {
            return;
        };
        let position = Position {
            line: found.line as usize,
            col: found.start,
        };
        self.cursor = position;
        self.anchor = position;
        self.scroll_to_cursor();
        self.request_page(cx);
    }

    fn update_match_notice(&mut self) {
        let SearchState::Done {
            results, current, ..
        } = &self.search
        else {
            return;
        };
        let text = if results.is_empty() {
            "No matches".to_string()
        } else {
            let shown = current.map_or(0, |index| index + 1);
            let more = if results.capped { "+" } else { "" };
            format!("{shown} of {}{more} matches", results.total)
        };
        self.notice = Some(Notice {
            text: text.into(),
            error: results.is_empty(),
        });
    }

    /// Every match on one line, for highlighting.
    fn line_matches(&self, line: usize) -> Vec<Match> {
        let SearchState::Done { results, .. } = &self.search else {
            return Vec::new();
        };
        let matches = &results.matches;
        let first = matches.partition_point(|found| (found.line as usize) < line);
        matches[first..]
            .iter()
            .take_while(|found| found.line as usize == line)
            .take(MAX_LINE_MATCHES)
            .copied()
            .collect()
    }

    fn current_match(&self) -> Option<Match> {
        let SearchState::Done {
            results, current, ..
        } = &self.search
        else {
            return None;
        };
        current
            .and_then(|index| results.matches.get(index))
            .copied()
    }

    fn copy(&mut self, cx: &mut Context<Self>) {
        let Some(open) = self.open() else {
            return;
        };
        let Some((start, end)) = self.selection() else {
            self.notify("Select text to copy".to_string(), false);
            cx.notify();
            return;
        };
        let document = Arc::clone(&open.document);
        let read = cx.background_spawn(async move {
            let mut text = String::new();
            for line in start.line..=end.line {
                let content = document.read_line(line)?;
                let from = if line == start.line {
                    document::byte_index_at_column(&content, start.col, TAB_WIDTH)
                } else {
                    0
                };
                let to = if line == end.line {
                    document::byte_index_at_column(&content, end.col, TAB_WIDTH)
                } else {
                    content.len()
                };
                if line > start.line {
                    text.push('\n');
                }
                if from < to {
                    text.push_str(&content[from..to]);
                }
                if text.len() > MAX_COPY {
                    return Ok::<_, document::Error>(None);
                }
            }
            Ok(Some(text))
        });
        cx.spawn(async move |this, cx| {
            let result = read.await;
            this.update(cx, |this, cx| match result {
                Ok(Some(text)) => {
                    let bytes = text.len();
                    cx.write_to_clipboard(ClipboardItem::new_string(text));
                    this.notify(format!("Copied {bytes} bytes"), false);
                }
                Ok(None) => this.notify(
                    format!(
                        "Selections over {} cannot be copied",
                        files::format_size(MAX_COPY as u64)
                    ),
                    true,
                ),
                Err(err) => this.notify(format!("Could not read the selection: {err}"), true),
            })
            .ok();
        })
        .detach();
    }

    fn notify(&mut self, text: String, error: bool) {
        self.notice = Some(Notice {
            text: text.into(),
            error,
        });
    }

    fn escape(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.open_menu.is_some() {
            self.open_menu = None;
        } else if let SearchState::Running { cancel, .. } = &self.search {
            cancel.store(true, Ordering::Relaxed);
            self.search = SearchState::Idle;
        } else {
            self.focus_handle.focus(window, cx);
        }
        cx.notify();
    }
}

impl Drop for TextViewer {
    fn drop(&mut self) {
        if let Some(load) = self.load.take() {
            load.cancel.store(true, Ordering::Relaxed);
        }
        if let SearchState::Running { cancel, .. } = &self.search {
            cancel.store(true, Ordering::Relaxed);
        }
    }
}

/// A decoded line as it is drawn: tabs expanded, and highlighted when it is
/// short enough that highlighting stays cheap.
fn page_line(raw: &str, language: Language) -> PageLine {
    let text = document::expand_tabs(raw, TAB_WIDTH);
    let columns = text.chars().count() as u32;
    let spans = if columns > HIGHLIGHT_LIMIT {
        Vec::new()
    } else {
        spans_to_columns(&text, syntax::highlight(language, &text))
    };
    PageLine {
        text: text.into(),
        columns,
        spans,
    }
}

/// Converts the highlighter's byte ranges into display columns in one pass.
fn spans_to_columns(text: &str, spans: Vec<Span>) -> Vec<ColoredSpan> {
    let mut columns = Vec::with_capacity(spans.len());
    let mut chars = text.char_indices().peekable();
    let mut column = 0usize;
    for span in spans {
        while chars.peek().is_some_and(|(at, _)| *at < span.start) {
            chars.next();
            column += 1;
        }
        let start = column;
        while chars.peek().is_some_and(|(at, _)| *at < span.end) {
            chars.next();
            column += 1;
        }
        columns.push(ColoredSpan {
            start: u32::try_from(start).unwrap_or(u32::MAX),
            end: u32::try_from(column).unwrap_or(u32::MAX),
            token: span.token,
        });
    }
    columns
}

#[cfg(test)]
mod tests;
