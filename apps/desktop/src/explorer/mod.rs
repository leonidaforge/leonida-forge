//! The main window: directory tree, file browser and preview pane.
//!
//! All three panels read one navigation state: the current directory comes
//! from `history`, and directory contents come from the shared `listings` cache.

mod browser;
mod menu;
mod navigation;
mod preview;
mod tree;

use std::collections::{HashMap, HashSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use gpui::{
    AnyElement, App, Bounds, Context, DispatchPhase, Div, Entity, FocusHandle, FontWeight,
    KeyBinding, MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent, PathPromptOptions,
    Pixels, Point, RenderImage, ScrollHandle, Stateful, Subscription, Task, TitlebarOptions,
    UniformListScrollHandle, Window, WindowBounds, WindowHandle, WindowOptions, actions, canvas,
    div, fill, prelude::*, px, rgb, size,
};

use lforge_rage9::rpf::Progress;

use crate::files::archive::{Identified, Stage};
use crate::files::shell::ShellWorker;
use crate::files::{
    self, Access, Entry, EntryKind, Executable, ListingLayout, Sort, SortKey, images,
};
use crate::settings::{Settings, ViewMode};
use crate::ui;
use crate::ui::assets::Icon;
use crate::ui::theme;
use crate::viewers::{BinaryInspector, ImageViewer, ModelViewer, RendererDemo};
use navigation::{History, Workspace};

use preview::Thumbnail;

actions!(explorer, [GoBack, GoForward, GoUp, Refresh, CloseMenu]);

const KEY_CONTEXT: &str = "Explorer";
const MENU_BAR_HEIGHT: f32 = 30.;
const TOOLBAR_HEIGHT: f32 = 44.;
const BROWSER_HEADER_HEIGHT: f32 = 44.;
const STATUS_BAR_HEIGHT: f32 = 26.;
const DIVIDER_WIDTH: f32 = 5.;
const MIN_TREE_WIDTH: f32 = 160.;
const MAX_TREE_WIDTH: f32 = 480.;
const MIN_PREVIEW_WIDTH: f32 = 220.;
const MAX_PREVIEW_WIDTH: f32 = 560.;
const MIN_CENTER_WIDTH: f32 = 440.;
const MIN_DETAILS_COLUMN: f32 = 60.;
const MAX_DETAILS_COLUMN: f32 = 420.;
const MIN_DETAILS_NAME: f32 = 120.;
const MAX_DETAILS_NAME: f32 = 640.;
const SCROLLBAR_WIDTH: f32 = 10.;
const MIN_SCROLLBAR_THUMB: f32 = 24.;

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("alt-left", GoBack, Some(KEY_CONTEXT)),
        KeyBinding::new("alt-right", GoForward, Some(KEY_CONTEXT)),
        KeyBinding::new("alt-up", GoUp, Some(KEY_CONTEXT)),
        KeyBinding::new("f5", Refresh, Some(KEY_CONTEXT)),
        KeyBinding::new("escape", CloseMenu, Some(KEY_CONTEXT)),
    ]);
}

#[derive(Clone)]
enum Listing {
    Loading,
    /// Waiting for the archive at this path to be decompressed or indexed.
    Indexing(PathBuf),
    /// The archive's stored metadata needs processing, and no executable that
    /// can authenticate it is selected.
    NeedsExecutable {
        archive: PathBuf,
        reason: String,
    },
    /// The stored metadata did not authenticate with the selected executable.
    AuthenticationFailed {
        archive: PathBuf,
        message: String,
    },
    Loaded(Arc<Vec<Entry>>),
    Failed(String),
}

/// The result of listing a directory in the background.
enum Loaded {
    Entries(Vec<Entry>, Option<String>),
    NeedsIndex(PathBuf),
    Failed(String),
}

/// A background scan of one archive.
struct IndexJob {
    progress: Arc<Progress>,
    stage: Arc<files::archive::Stage>,
    cancel: Arc<AtomicBool>,
    _work: Task<()>,
    _ticker: Task<()>,
}

/// The local executable used to authenticate RPF9 metadata, and whether it
/// could be opened.
#[derive(Default)]
enum ExecutableState {
    /// No executable is configured.
    #[default]
    Unset,
    /// Configured and being checked in the background.
    Checking,
    Ready(Arc<Executable>),
    /// Configured but unusable, with the reason.
    Failed(String),
}

#[derive(Clone, PartialEq)]
enum Menu {
    File,
    View,
    Tools,
    Sort,
    Root {
        root: PathBuf,
        position: Point<Pixels>,
    },
    Entry {
        entry: Entry,
        position: Point<Pixels>,
    },
}

#[derive(Clone, Copy, PartialEq)]
enum Divider {
    Tree,
    Preview,
}

/// A details column being resized by dragging its right edge.
#[derive(Clone, Copy)]
struct ColumnDrag {
    column: usize,
    start_x: f32,
    start_width: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Axis {
    Vertical,
    Horizontal,
}

/// A scrollbar thumb being dragged, with the pointer's offset inside it.
#[derive(Clone)]
struct ScrollDrag {
    handle: ScrollHandle,
    axis: Axis,
    grab: f32,
}

fn clamp_details_column(width: f32) -> f32 {
    width.clamp(MIN_DETAILS_COLUMN, MAX_DETAILS_COLUMN)
}

fn clamp_details_name(width: f32) -> f32 {
    width.clamp(MIN_DETAILS_NAME, MAX_DETAILS_NAME)
}

/// The thumb length and its position along the track. `offset` is the
/// positive distance scrolled, `max` the remaining scrollable distance and
/// `viewport` the track length.
fn scrollbar_geometry(offset: f32, max: f32, viewport: f32) -> (f32, f32) {
    if max <= 0.5 || viewport <= 0. {
        return (0., 0.);
    }
    let thumb = (viewport * viewport / (viewport + max))
        .max(MIN_SCROLLBAR_THUMB)
        .min(viewport);
    let position = (offset / max).clamp(0., 1.) * (viewport - thumb);
    (thumb, position)
}

/// A running or finished export of one file to a chosen destination.
struct Export {
    /// Distinguishes this export from a later one, so a stale callback does
    /// not touch the current state.
    generation: u64,
    label: String,
    cancel: Arc<AtomicBool>,
    state: ExportState,
    _task: Task<()>,
}

enum ExportState {
    Running,
    Done(String),
    Failed(String),
}

/// The single export slot. A save dialog holds it while it is open, so a
/// second request can neither open another dialog nor start an export. The
/// generation identifies the request whose dialog is open.
#[derive(Default)]
struct ExportRequests {
    next_generation: u64,
    pending: Option<u64>,
}

impl ExportRequests {
    /// Takes the slot for a save dialog, or refuses when an export is running
    /// or another dialog is still open.
    fn begin(&mut self, current: Option<&ExportState>) -> Option<u64> {
        if self.pending.is_some() || !can_start_export(current) {
            return None;
        }
        self.next_generation += 1;
        self.pending = Some(self.next_generation);
        Some(self.next_generation)
    }

    /// Whether a new export is blocked, either by a running export or by an
    /// open save dialog.
    fn busy(&self, current: Option<&ExportState>) -> bool {
        self.pending.is_some() || !can_start_export(current)
    }

    /// Releases the slot for the dialog of `generation` and says whether its
    /// export may start. A late result for a cancelled or replaced request
    /// starts nothing, so no destination is written for it.
    fn finish(&mut self, generation: u64, current: Option<&ExportState>) -> bool {
        if self.pending != Some(generation) {
            return false;
        }
        self.pending = None;
        can_start_export(current)
    }

    /// Releases the slot when a dialog returns without a destination.
    fn cancel(&mut self, generation: u64) {
        if self.pending == Some(generation) {
            self.pending = None;
        }
    }
}

/// What to show when an export ends. Separated from the UI so the decision is
/// testable.
enum ExportOutcome {
    Done(String),
    Failed(String),
    Cancelled,
}

/// The icons Windows shows for one file type.
struct FileIcons {
    small: Arc<RenderImage>,
    large: Arc<RenderImage>,
}

/// Panel widths after fitting the stored widths into the window.
struct Layout {
    tree: f32,
    preview: f32,
    center: f32,
    center_height: f32,
}

pub struct Explorer {
    workspace: Workspace,
    listings: HashMap<PathBuf, Listing>,
    /// Explanations shown above a listing, see [`files::describe`].
    notes: HashMap<PathBuf, String>,
    /// Per folder: the number of the latest listing request, so results for
    /// older requests are dropped.
    load_generations: HashMap<PathBuf, u64>,
    indexing: HashMap<PathBuf, IndexJob>,
    expanded: HashSet<PathBuf>,
    history: History,
    selected: Option<PathBuf>,
    sort: Sort,
    view_mode: ViewMode,
    layout: ListingLayout,
    preview_visible: bool,
    tree_width: f32,
    preview_width: f32,
    open_menu: Option<Menu>,
    resizing: Option<Divider>,
    column_drag: Option<ColumnDrag>,
    scroll_drag: Option<ScrollDrag>,
    details_name_width: f32,
    details_widths: [f32; 3],
    export: Option<Export>,
    export_requests: ExportRequests,
    thumbnail: Option<Thumbnail>,
    shell: Option<ShellWorker>,
    /// Keyed by lowercase extension. `None` while loading, or when Windows
    /// does not know the type.
    file_icons: HashMap<String, Option<FileIcons>>,
    stale_images: Vec<Arc<RenderImage>>,
    /// Set by navigation so the next frame scrolls the tree and browser to it.
    reveal: Option<PathBuf>,
    tree_scroll: UniformListScrollHandle,
    browser_scroll: UniformListScrollHandle,
    list_scroll: ScrollHandle,
    preview_scroll: ScrollHandle,
    /// Filters the visible listing by resolved name, stored key or type.
    search: Option<Entity<ui::text_field::TextField>>,
    focus_handle: FocusHandle,
    settings_path: Option<PathBuf>,
    save_task: Option<Task<()>>,
    /// The configured executable, its validation state, and the generation of
    /// the latest check so a late result cannot replace a newer one.
    configured_executable: Option<PathBuf>,
    executable: ExecutableState,
    executable_generation: u64,
    renderer_demo: Option<WindowHandle<RendererDemo>>,
    _quit_subscription: Subscription,
}

impl Explorer {
    pub fn new(settings: Settings, settings_path: Option<PathBuf>, cx: &mut Context<Self>) -> Self {
        let mut this = Self {
            workspace: Workspace {
                gta: settings.gta_directory,
                folders: settings.folders,
            },
            listings: HashMap::new(),
            notes: HashMap::new(),
            load_generations: HashMap::new(),
            indexing: HashMap::new(),
            expanded: HashSet::new(),
            history: History::default(),
            selected: None,
            sort: settings.sort,
            view_mode: settings.view_mode,
            layout: settings.layout,
            preview_visible: settings.preview_visible,
            tree_width: settings.tree_width,
            preview_width: settings.preview_width,
            open_menu: None,
            resizing: None,
            column_drag: None,
            scroll_drag: None,
            details_name_width: clamp_details_name(settings.details_name_width),
            details_widths: settings.details_widths.map(clamp_details_column),
            export: None,
            export_requests: ExportRequests::default(),
            thumbnail: None,
            shell: ShellWorker::start()
                .inspect_err(|err| log::error!("failed to start shell thread: {err}"))
                .ok(),
            file_icons: HashMap::new(),
            stale_images: Vec::new(),
            reveal: None,
            tree_scroll: UniformListScrollHandle::new(),
            browser_scroll: UniformListScrollHandle::new(),
            list_scroll: ScrollHandle::new(),
            preview_scroll: ScrollHandle::new(),
            search: Some(
                cx.new(|cx| ui::text_field::TextField::new("Filter names, hashes, types", cx)),
            ),
            focus_handle: cx.focus_handle(),
            settings_path,
            save_task: None,
            configured_executable: settings.executable.clone(),
            executable: ExecutableState::Unset,
            executable_generation: 0,
            renderer_demo: None,
            _quit_subscription: cx.on_app_quit(|this, _| {
                this.save_task = None;
                this.save_now();
                async {}
            }),
        };

        if let Some(executable) = settings.executable {
            this.check_executable(executable, cx);
        }

        let roots: Vec<PathBuf> = this.workspace.root_paths().map(Path::to_path_buf).collect();
        for root in roots {
            this.load(root, cx);
        }
        if let Some(gta) = this.workspace.gta.clone() {
            this.expanded.insert(gta);
        }
        this.restore_directory(settings.last_directory, cx);
        this
    }

    pub fn focus_handle(&self) -> &FocusHandle {
        &self.focus_handle
    }

    /// The executable that may authenticate stored metadata, or none, with the
    /// listing layout the user selected.
    fn access(&self) -> Access {
        let access = match &self.executable {
            ExecutableState::Ready(executable) => Access::with(executable.clone()),
            ExecutableState::Unset | ExecutableState::Checking | ExecutableState::Failed(_) => {
                Access::none()
            }
        };
        access.with_layout(self.layout)
    }

    /// The configured executable's path, if any.
    fn executable_path(&self) -> Option<PathBuf> {
        self.configured_executable.clone()
    }

    /// Reopens the last directory if it still exists, otherwise the GTA VI root.
    fn restore_directory(&mut self, last: Option<PathBuf>, cx: &mut Context<Self>) {
        let last = last.filter(|dir| self.workspace.root_of(dir).is_some());
        let fallback = self.workspace.gta.clone();
        let access = self.access();
        let exists = cx.background_spawn({
            let last = last.clone();
            async move {
                last.is_some_and(|dir| match files::list_with(&dir, &access) {
                    Ok(_) => true,
                    // Opening it again starts indexing.
                    Err(err) => files::archive::prepare_required(&err).is_some(),
                })
            }
        });
        cx.spawn(async move |this, cx| {
            let target = if exists.await { last } else { fallback };
            if let Some(dir) = target {
                this.update(cx, |this, cx| this.navigate(dir, cx)).ok();
            }
        })
        .detach();
    }

    fn current_dir(&self) -> Option<&Path> {
        self.history.current()
    }

    fn current_listing(&self) -> Option<&Listing> {
        self.current_dir().and_then(|dir| self.listings.get(dir))
    }

    fn current_entries(&self) -> Option<&Arc<Vec<Entry>>> {
        match self.current_listing()? {
            Listing::Loaded(entries) => Some(entries),
            Listing::Loading
            | Listing::Indexing(_)
            | Listing::NeedsExecutable { .. }
            | Listing::AuthenticationFailed { .. }
            | Listing::Failed(_) => None,
        }
    }

    fn selected_entry(&self) -> Option<&Entry> {
        let selected = self.selected.as_deref()?;
        // A flat listing shows rows whose path points into a virtual folder,
        // so the current listing is searched before the row's own folder.
        if let Some(entries) = self.current_entries()
            && let Some(entry) = entries.iter().find(|entry| entry.path == selected)
        {
            return Some(entry);
        }
        self.selected_entry_in(selected)
    }

    fn selected_entry_in(&self, selected: &Path) -> Option<&Entry> {
        let parent = selected.parent()?;
        match self.listings.get(parent)? {
            Listing::Loaded(entries) => entries.iter().find(|entry| entry.path == selected),
            Listing::Loading
            | Listing::Indexing(_)
            | Listing::NeedsExecutable { .. }
            | Listing::AuthenticationFailed { .. }
            | Listing::Failed(_) => None,
        }
    }

    /// Lists `dir` in the background. Cached contents stay visible until the
    /// new listing arrives. A result for an older request for the same folder
    /// is dropped, so a slow listing made with an executable that has since
    /// been replaced cannot overwrite a newer one.
    fn load(&mut self, dir: PathBuf, cx: &mut Context<Self>) {
        let generation = {
            let generation = self.load_generations.entry(dir.clone()).or_default();
            *generation += 1;
            *generation
        };
        self.listings.entry(dir.clone()).or_insert(Listing::Loading);
        let sort = self.sort;
        let access = self.access();
        let task = cx.background_spawn({
            let dir = dir.clone();
            async move {
                match files::list_with(&dir, &access) {
                    Ok(mut entries) => {
                        files::sort_entries(&mut entries, sort);
                        Loaded::Entries(entries, files::describe_with(&dir, &access))
                    }
                    Err(err) => match files::archive::prepare_required(&err) {
                        Some(archive) => Loaded::NeedsIndex(archive.to_path_buf()),
                        None => Loaded::Failed(err.to_string()),
                    },
                }
            }
        });
        cx.spawn(async move |this, cx| {
            let result = task.await;
            this.update(cx, |this, cx| {
                if this.load_generations.get(&dir) != Some(&generation) {
                    return;
                }
                let listing = match result {
                    Loaded::Entries(mut entries, note) => {
                        if this.sort != sort {
                            files::sort_entries(&mut entries, this.sort);
                        }
                        this.request_icons(&entries, cx);
                        match note {
                            Some(note) => this.notes.insert(dir.clone(), note),
                            None => this.notes.remove(&dir),
                        };
                        Listing::Loaded(Arc::new(entries))
                    }
                    Loaded::NeedsIndex(archive) => {
                        this.start_indexing(archive.clone(), false, cx);
                        Listing::Indexing(archive)
                    }
                    Loaded::Failed(err) => Listing::Failed(err),
                };
                this.listings.insert(dir, listing);
                this.update_thumbnail(cx);
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    /// Opens an archive in the background: decompresses it from the archive
    /// it is stored in, authenticates its table of contents where possible and
    /// scans it, as needed. Listings waiting for it are loaded again when the
    /// scan ends.
    fn start_indexing(&mut self, archive: PathBuf, allow_scan: bool, cx: &mut Context<Self>) {
        if self.indexing.contains_key(&archive) {
            return;
        }
        let progress = Arc::new(Progress::default());
        let stage = Arc::new(files::archive::Stage::default());
        let cancel = Arc::new(AtomicBool::new(false));
        let access = self.access();
        let work = cx.background_spawn({
            let (archive, progress, stage, cancel) = (
                archive.clone(),
                progress.clone(),
                stage.clone(),
                cancel.clone(),
            );
            async move {
                files::archive::prepare_with(
                    &archive, &access, allow_scan, &stage, &progress, &cancel,
                )
            }
        });
        let work = cx.spawn({
            let archive = archive.clone();
            async move |this, cx| {
                let result = work.await;
                this.update(cx, |this, cx| this.finish_indexing(&archive, result, cx))
                    .ok();
            }
        });
        // Repaints while the archive is opened, so the progress moves.
        let ticker = cx.spawn({
            let archive = archive.clone();
            async move |this, cx| {
                loop {
                    cx.background_executor()
                        .timer(Duration::from_millis(250))
                        .await;
                    let running = this
                        .update(cx, |this, cx| {
                            cx.notify();
                            this.indexing.contains_key(&archive)
                        })
                        .unwrap_or(false);
                    if !running {
                        break;
                    }
                }
            }
        });
        self.indexing.insert(
            archive,
            IndexJob {
                progress,
                stage,
                cancel,
                _work: work,
                _ticker: ticker,
            },
        );
    }

    fn finish_indexing(&mut self, archive: &Path, result: io::Result<()>, cx: &mut Context<Self>) {
        self.indexing.remove(archive);
        let waiting: Vec<PathBuf> = self
            .listings
            .iter()
            .filter(|(_, listing)| matches!(listing, Listing::Indexing(a) if a == archive))
            .map(|(dir, _)| dir.clone())
            .collect();
        match result {
            Ok(()) => {
                for dir in waiting {
                    self.load(dir, cx);
                }
            }
            Err(err) => {
                let listing =
                    if let Some((archive, reason)) = files::archive::executable_required(&err) {
                        Listing::NeedsExecutable {
                            archive: archive.to_path_buf(),
                            reason: reason.to_string(),
                        }
                    } else if let Some((archive, message)) =
                        files::archive::authentication_failure(&err)
                    {
                        Listing::AuthenticationFailed {
                            archive: archive.to_path_buf(),
                            message: message.to_string(),
                        }
                    } else if err.kind() == io::ErrorKind::Interrupted {
                        Listing::Failed(
                            "Opening the archive was cancelled. Press F5 to open it.".to_string(),
                        )
                    } else {
                        Listing::Failed(format!("The archive could not be opened: {err}"))
                    };
                for dir in waiting {
                    self.listings.insert(dir, listing.clone());
                }
            }
        }
        cx.notify();
    }

    fn cancel_indexing(&mut self, archive: &Path, cx: &mut Context<Self>) {
        if let Some(job) = self.indexing.get(archive) {
            job.cancel.store(true, Ordering::Relaxed);
            cx.notify();
        }
    }

    /// The running preparation of `archive`: its scan progress, if known yet,
    /// the step it is in, and whether it was asked to stop.
    fn indexing_state(&self, archive: &Path) -> Option<(Option<f32>, u8, bool)> {
        let job = self.indexing.get(archive)?;
        Some((
            job.progress.fraction(),
            job.stage.get(),
            job.cancel.load(Ordering::Relaxed),
        ))
    }

    /// Asks Windows for the icons of file types not seen before.
    fn request_icons(&mut self, entries: &[Entry], cx: &mut Context<Self>) {
        let Some(shell) = &self.shell else {
            return;
        };
        let new: HashSet<String> = entries
            .iter()
            .filter_map(Entry::extension)
            .filter(|extension| !self.file_icons.contains_key(extension))
            .collect();
        for extension in new {
            let icon = shell.icon(extension.clone());
            self.file_icons.insert(extension.clone(), None);
            cx.spawn(async move |this, cx| {
                let Ok(Some(icon)) = icon.await else {
                    return;
                };
                this.update(cx, |this, cx| {
                    let icons = FileIcons {
                        small: images::bitmap_to_render_image(icon.small),
                        large: images::bitmap_to_render_image(icon.large),
                    };
                    this.file_icons.insert(extension, Some(icons));
                    cx.notify();
                })
                .ok();
            })
            .detach();
        }
    }

    pub fn navigate(&mut self, dir: PathBuf, cx: &mut Context<Self>) {
        self.history.push(dir);
        self.enter_current(None, cx);
    }

    /// Shows the current history entry, optionally selecting one of its items.
    fn enter_current(&mut self, select: Option<PathBuf>, cx: &mut Context<Self>) {
        if let Some(dir) = self.current_dir().map(Path::to_path_buf) {
            for ancestor in self.workspace.ancestors_within_root(&dir) {
                self.expanded.insert(ancestor.clone());
                if ancestor != dir && !self.listings.contains_key(&ancestor) {
                    self.load(ancestor, cx);
                }
            }
            self.load(dir.clone(), cx);
            self.reveal = Some(select.clone().unwrap_or(dir));
        }
        self.select(select, cx);
        self.schedule_save(cx);
    }

    fn go_back(&mut self, cx: &mut Context<Self>) {
        if self.history.back().is_some() {
            self.enter_current(None, cx);
        }
    }

    fn go_forward(&mut self, cx: &mut Context<Self>) {
        if self.history.forward().is_some() {
            self.enter_current(None, cx);
        }
    }

    fn go_up(&mut self, cx: &mut Context<Self>) {
        let Some(dir) = self.current_dir().map(Path::to_path_buf) else {
            return;
        };
        if let Some(parent) = self.workspace.parent_within_root(&dir) {
            self.history.push(parent);
            self.enter_current(Some(dir), cx);
        }
    }

    fn refresh(&mut self, cx: &mut Context<Self>) {
        let dirs: Vec<PathBuf> = self.listings.keys().cloned().collect();
        for dir in dirs {
            self.load(dir, cx);
        }
    }

    /// Validates a configured executable in the background: it is opened
    /// read-only and parsed as a PE image. A result for an older selection is
    /// dropped, so a slow check cannot replace a newer one.
    fn check_executable(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        self.executable_generation += 1;
        let generation = self.executable_generation;
        self.executable = ExecutableState::Checking;
        cx.notify();
        let opened = cx.background_spawn({
            let path = path.clone();
            async move { Executable::open(&path) }
        });
        cx.spawn(async move |this, cx| {
            let result = opened.await;
            this.update(cx, |this, cx| {
                if this.executable_generation != generation {
                    return;
                }
                this.executable = match result {
                    Ok(executable) => ExecutableState::Ready(Arc::new(executable)),
                    // The reason is shown where the archive needs it. The
                    // path stays out of the log.
                    Err(err) => ExecutableState::Failed(err.to_string()),
                };
                // Listings read before this selection may have been recovered
                // instead; they are listed again with the new context.
                this.refresh(cx);
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    /// Lists again the folders that wait for an executable, so an archive that
    /// was listed from recovered data is re-read with the new context.
    fn reload_waiting_listings(&mut self, cx: &mut Context<Self>) {
        let dirs: Vec<PathBuf> = self
            .listings
            .iter()
            .filter(|(_, listing)| {
                matches!(
                    listing,
                    Listing::NeedsExecutable { .. } | Listing::AuthenticationFailed { .. }
                )
            })
            .map(|(dir, _)| dir.clone())
            .collect();
        for dir in dirs {
            self.load(dir, cx);
        }
    }

    fn choose_executable(&mut self, cx: &mut Context<Self>) {
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Select the GTA VI executable".into()),
        });
        cx.spawn(async move |this, cx| match paths.await {
            Ok(Ok(Some(mut paths))) => {
                if let Some(path) = paths.pop() {
                    this.update(cx, |this, cx| this.set_executable(path, cx))
                        .ok();
                }
            }
            Ok(Ok(None)) | Err(_) => {}
            Ok(Err(err)) => log::error!("executable picker failed: {err:#}"),
        })
        .detach();
    }

    /// Stores a selection and validates it. Only the path is stored; no key
    /// state, IV or executable bytes are kept anywhere.
    fn set_executable(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        self.configured_executable = Some(path.clone());
        self.schedule_save(cx);
        self.check_executable(path, cx);
    }

    fn clear_executable(&mut self, cx: &mut Context<Self>) {
        if self.configured_executable.take().is_none() {
            return;
        }
        self.executable_generation += 1;
        self.executable = ExecutableState::Unset;
        self.schedule_save(cx);
        self.reload_waiting_listings(cx);
        cx.notify();
    }

    /// Recovers the archive's entries by scanning its own data, instead of
    /// authenticating its table of contents. The user chooses this when no
    /// executable matches. Recovered entries are kept apart from native ones.
    fn scan_instead(&mut self, archive: PathBuf, cx: &mut Context<Self>) {
        for listing in self.listings.values_mut() {
            let waiting = match listing {
                Listing::NeedsExecutable { archive: a, .. }
                | Listing::AuthenticationFailed { archive: a, .. } => *a == archive,
                _ => false,
            };
            if waiting {
                *listing = Listing::Indexing(archive.clone());
            }
        }
        self.start_indexing(archive, true, cx);
        cx.notify();
    }

    fn select(&mut self, path: Option<PathBuf>, cx: &mut Context<Self>) {
        self.selected = path;
        self.update_thumbnail(cx);
        cx.notify();
    }

    /// Opens archives as folders, whatever their name, and other files in
    /// their viewer. Files are identified by their contents in the
    /// background first.
    fn open_entry(&mut self, entry: &Entry, cx: &mut Context<Self>) {
        if entry.is_container() {
            self.navigate(entry.path.clone(), cx);
            return;
        }
        if entry.kind != EntryKind::File {
            return;
        }
        let path = entry.path.clone();
        let image = entry.is_supported_image();
        let texture = entry
            .extension()
            .is_some_and(|extension| extension == "ttpf");
        // A type-5 resource may be a texture dictionary. Opening it as one
        // falls back to the Binary Inspector when it is not.
        let resource = entry.resource_type == Some(5);
        let access = self.access();
        let gta_root = self.workspace.gta.clone();
        match model_entry_kind(entry) {
            Some(ModelEntryKind::Direct) => {
                open_model_viewer(path, access, gta_root, cx);
                return;
            }
            Some(ModelEntryKind::Sniff) => {}
            None => {}
        }
        let sniff = model_entry_kind(entry).is_some();
        let identified = cx.background_spawn({
            let (path, access) = (path.clone(), access.clone());
            async move { files::identify_with(&path, &access) }
        });
        cx.spawn(async move |this, cx| {
            let identified = identified.await;
            let model = if sniff && matches!(&identified, Ok(Identified::Unknown)) {
                let (path, access) = (path.clone(), access.clone());
                cx.background_spawn(
                    async move { files::model::is_drawable_resource(&path, &access) },
                )
                .await
            } else {
                false
            };
            this.update(cx, |this, cx| match identified {
                Ok(Identified::Archive(_)) => {
                    this.mark_archive(&path);
                    this.navigate(path, cx);
                }
                // Opening it explains why it is not a valid archive.
                Ok(Identified::Invalid { .. }) => this.navigate(path, cx),
                Ok(Identified::Unknown) if model => open_model_viewer(path, access, gta_root, cx),
                Ok(Identified::Unknown) if texture => {
                    crate::viewers::texture::open(path, access, cx)
                }
                Ok(Identified::Unknown) if resource => {
                    crate::viewers::texture::open_resource(path, access, cx)
                }
                Ok(Identified::Unknown) if image => open_image_viewer(path, access, cx),
                Ok(Identified::Unknown) => open_binary_inspector(path, access, cx),
                Err(err) => {
                    log::warn!("could not identify {}: {err}", path.display());
                    open_binary_inspector(path, access, cx);
                }
            })
            .ok();
        })
        .detach();
    }

    /// Shows a file found to be an archive as one, also in the tree.
    fn mark_archive(&mut self, path: &Path) {
        let Some(Listing::Loaded(entries)) =
            path.parent().and_then(|dir| self.listings.get_mut(dir))
        else {
            return;
        };
        if let Some(entry) = Arc::make_mut(entries)
            .iter_mut()
            .find(|entry| entry.path == path)
        {
            entry.kind = EntryKind::Archive;
        }
    }

    fn toggle_expanded(&mut self, dir: PathBuf, cx: &mut Context<Self>) {
        if !self.expanded.remove(&dir) {
            if !self.listings.contains_key(&dir) {
                self.load(dir.clone(), cx);
            }
            self.expanded.insert(dir);
        }
        cx.notify();
    }

    fn set_sort(&mut self, sort: Sort, cx: &mut Context<Self>) {
        self.sort = sort;
        for listing in self.listings.values_mut() {
            if let Listing::Loaded(entries) = listing {
                let entries: &mut Vec<Entry> = Arc::make_mut(entries);
                files::sort_entries(entries, sort);
            }
        }
        self.schedule_save(cx);
        cx.notify();
    }

    fn sort_by_column(&mut self, key: SortKey, cx: &mut Context<Self>) {
        let descending = self.sort.key == key && !self.sort.descending;
        self.set_sort(Sort { key, descending }, cx);
    }

    fn set_view_mode(&mut self, mode: ViewMode, cx: &mut Context<Self>) {
        self.view_mode = mode;
        self.reveal = self.selected.clone();
        self.schedule_save(cx);
        cx.notify();
    }

    /// Switches between the folder view and one flat list. The archive is not
    /// reopened: only the listings are built again from the table of contents
    /// that is already in memory.
    fn set_layout(&mut self, layout: ListingLayout, cx: &mut Context<Self>) {
        if self.layout == layout {
            return;
        }
        self.layout = layout;
        self.refresh(cx);
        self.reveal = self.selected.clone();
        self.schedule_save(cx);
        cx.notify();
    }

    fn toggle_preview(&mut self, cx: &mut Context<Self>) {
        self.preview_visible = !self.preview_visible;
        self.schedule_save(cx);
        cx.notify();
    }

    fn pick_folder(
        &mut self,
        prompt: &'static str,
        on_pick: fn(&mut Self, PathBuf, &mut Context<Self>),
        cx: &mut Context<Self>,
    ) {
        let paths = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some(prompt.into()),
        });
        cx.spawn(async move |this, cx| match paths.await {
            Ok(Ok(Some(mut paths))) => {
                if let Some(path) = paths.pop() {
                    this.update(cx, |this, cx| on_pick(this, path, cx)).ok();
                }
            }
            Ok(Ok(None)) | Err(_) => {}
            Ok(Err(err)) => log::error!("folder picker failed: {err:#}"),
        })
        .detach();
    }

    fn choose_gta_folder(&mut self, cx: &mut Context<Self>) {
        self.pick_folder("Select GTA VI folder", Self::set_gta_folder, cx);
    }

    fn choose_folder_to_open(&mut self, cx: &mut Context<Self>) {
        self.pick_folder("Open folder", Self::add_folder, cx);
    }

    fn set_gta_folder(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        self.workspace.folders.retain(|folder| *folder != path);
        self.workspace.gta = Some(path.clone());
        self.forget_paths_outside_workspace();
        self.load(path.clone(), cx);
        self.navigate(path, cx);
    }

    fn add_folder(&mut self, path: PathBuf, cx: &mut Context<Self>) {
        if self.workspace.add_folder(path.clone()) {
            self.load(path.clone(), cx);
        }
        self.navigate(path, cx);
    }

    fn remove_folder(&mut self, root: PathBuf, cx: &mut Context<Self>) {
        self.workspace.remove_folder(&root);
        self.forget_paths_outside_workspace();
        self.enter_current(None, cx);
    }

    fn forget_paths_outside_workspace(&mut self) {
        let workspace = self.workspace.clone();
        let inside = |path: &Path| workspace.root_of(path).is_some();
        self.history.retain(inside);
        self.listings.retain(|path, _| inside(path));
        self.notes.retain(|path, _| inside(path));
        self.expanded.retain(|path| inside(path));
    }

    /// The folder root that contains the current directory, if any.
    fn current_folder_root(&self) -> Option<PathBuf> {
        let root = self.workspace.root_of(self.current_dir()?)?;
        self.workspace
            .is_folder_root(root)
            .then(|| root.to_path_buf())
    }

    fn open_renderer_demo(&mut self, cx: &mut Context<Self>) {
        if let Some(handle) = self.renderer_demo
            && handle
                .update(cx, |_, window, _| window.activate_window())
                .is_ok()
        {
            return;
        }
        let options = window_options("Renderer Demo", size(px(1100.), px(720.)), cx);
        match cx.open_window(options, |window, cx| {
            ui::close_through_gpui(window, cx);
            cx.new(RendererDemo::new)
        }) {
            Ok(handle) => self.renderer_demo = Some(handle),
            Err(err) => log::error!("failed to open renderer demo: {err:#}"),
        }
    }

    fn settings(&self) -> Settings {
        Settings {
            gta_directory: self.workspace.gta.clone(),
            folders: self.workspace.folders.clone(),
            view_mode: self.view_mode,
            sort: self.sort,
            layout: self.layout,
            details_widths: self.details_widths,
            details_name_width: self.details_name_width,
            preview_visible: self.preview_visible,
            tree_width: self.tree_width,
            preview_width: self.preview_width,
            last_directory: self.current_dir().map(Path::to_path_buf),
            executable: self.configured_executable.clone(),
        }
    }

    /// Saves shortly after the last change, so dragging a divider writes once.
    fn schedule_save(&mut self, cx: &mut Context<Self>) {
        let Some(path) = self.settings_path.clone() else {
            return;
        };
        let settings = self.settings();
        self.save_task = Some(cx.spawn(async move |_, cx| {
            cx.background_executor()
                .timer(Duration::from_millis(500))
                .await;
            let result = cx
                .background_spawn(async move { settings.save(&path) })
                .await;
            if let Err(err) = result {
                log::error!("failed to save settings: {err}");
            }
        }));
    }

    fn save_now(&self) {
        if let Some(path) = &self.settings_path
            && let Err(err) = self.settings().save(path)
        {
            log::error!("failed to save settings: {err}");
        }
    }

    fn layout(&self, window: &Window) -> Layout {
        let viewport = window.viewport_size();
        let width = f32::from(viewport.width);
        let mut tree = self.tree_width.clamp(MIN_TREE_WIDTH, MAX_TREE_WIDTH);
        let mut preview = if self.preview_visible {
            self.preview_width
                .clamp(MIN_PREVIEW_WIDTH, MAX_PREVIEW_WIDTH)
        } else {
            0.
        };
        let dividers = if self.preview_visible {
            2. * DIVIDER_WIDTH
        } else {
            DIVIDER_WIDTH
        };
        // Give the center its minimum width by shrinking the side panels.
        let mut excess = tree + preview + dividers + MIN_CENTER_WIDTH - width;
        if excess > 0. && self.preview_visible {
            let cut = excess.min(preview - MIN_PREVIEW_WIDTH);
            preview -= cut;
            excess -= cut;
        }
        if excess > 0. {
            tree -= excess.min(tree - MIN_TREE_WIDTH);
        }
        Layout {
            tree,
            preview,
            center: (width - tree - preview - dividers).max(0.),
            center_height: (f32::from(viewport.height)
                - MENU_BAR_HEIGHT
                - TOOLBAR_HEIGHT
                - BROWSER_HEADER_HEIGHT
                - STATUS_BAR_HEIGHT)
                .max(0.),
        }
    }

    fn resize_to(&mut self, position: Point<Pixels>, window: &Window, cx: &mut Context<Self>) {
        let x = f32::from(position.x);
        match self.resizing {
            Some(Divider::Tree) => self.tree_width = x - DIVIDER_WIDTH / 2.,
            Some(Divider::Preview) => {
                let width = f32::from(window.viewport_size().width);
                self.preview_width = width - x - DIVIDER_WIDTH / 2.;
            }
            None => return,
        }
        // Store what the layout actually shows, so a later drag starts from it.
        let layout = self.layout(window);
        self.tree_width = layout.tree;
        if self.preview_visible {
            self.preview_width = layout.preview;
        }
        cx.notify();
    }

    fn close_menu(&mut self, cx: &mut Context<Self>) {
        if self.open_menu.take().is_some() {
            cx.notify();
        }
    }

    /// Whether an export is running or its save dialog is open. Only one
    /// runs at a time, so the Save As actions are disabled while either is
    /// pending (see [`ExportRequests`]).
    fn exporting(&self) -> bool {
        self.export_requests
            .busy(self.export.as_ref().map(|export| &export.state))
    }

    /// Asks where to save `entry`, then exports it in the background. Only
    /// regular files are exportable; directories and archives open as folders.
    /// The request takes the single export slot before the dialog opens, so a
    /// second Save As is refused while a dialog or an export is pending.
    fn start_export(&mut self, entry: &Entry, cx: &mut Context<Self>) {
        if entry.kind != EntryKind::File {
            return;
        }
        let current = self.export.as_ref().map(|export| &export.state);
        let Some(generation) = self.export_requests.begin(current) else {
            return;
        };
        let source = entry.path.clone();
        let label = entry.name.clone();
        let caveat = export_caveat(entry);
        let dir = initial_export_dir(&source);
        // Generated names for recovered and native RPF9 entries; a ZIP entry's
        // own name otherwise. Only a suggestion: the dialog returns the
        // destination, and no entry name is joined to a path.
        let prompt = cx.prompt_for_new_path(&dir, Some(entry.name.as_str()));
        cx.spawn(async move |this, cx| {
            let dest = match prompt.await {
                Ok(Ok(Some(dest))) => dest,
                Ok(Ok(None)) | Err(_) => {
                    this.update(cx, |this, cx| {
                        this.export_requests.cancel(generation);
                        cx.notify();
                    })
                    .ok();
                    return;
                }
                Ok(Err(err)) => {
                    log::error!("save dialog failed: {err:#}");
                    this.update(cx, |this, cx| {
                        this.export_requests.cancel(generation);
                        cx.notify();
                    })
                    .ok();
                    return;
                }
            };
            this.update(cx, |this, cx| {
                this.run_export(generation, source, label, caveat, dest, cx)
            })
            .ok();
        })
        .detach();
    }

    /// Starts the export for the dialog request `generation`. Rechecks the
    /// invariant at the actual start, so a request that lost the slot while
    /// its dialog was delayed cannot replace the running export or write its
    /// destination.
    fn run_export(
        &mut self,
        generation: u64,
        source: PathBuf,
        label: String,
        caveat: Option<String>,
        dest: PathBuf,
        cx: &mut Context<Self>,
    ) {
        let current = self.export.as_ref().map(|export| &export.state);
        if !self.export_requests.finish(generation, current) {
            log::warn!(
                "an export request lost its slot before it started; its destination was not written"
            );
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let access = self.access();
        let task = cx.spawn({
            let cancel = cancel.clone();
            async move |this, cx| {
                let result = cx
                    .background_spawn({
                        let (source, dest) = (source, dest.clone());
                        async move { files::export_with(&source, &dest, &access, &cancel) }
                    })
                    .await;
                this.update(cx, |this, cx| {
                    this.finish_export(generation, &dest, caveat.as_deref(), result, cx)
                })
                .ok();
            }
        });
        self.export = Some(Export {
            generation,
            label,
            cancel,
            state: ExportState::Running,
            _task: task,
        });
        cx.notify();
    }

    fn finish_export(
        &mut self,
        generation: u64,
        dest: &Path,
        caveat: Option<&str>,
        result: io::Result<u64>,
        cx: &mut Context<Self>,
    ) {
        if self.export.as_ref().map(|export| export.generation) != Some(generation) {
            return;
        }
        match export_outcome(result, caveat, dest) {
            ExportOutcome::Cancelled => self.export = None,
            ExportOutcome::Done(message) => {
                if let Some(export) = &mut self.export {
                    export.state = ExportState::Done(message);
                }
                // A result that needs no action clears itself after a moment.
                self.dismiss_export_later(generation, cx);
            }
            ExportOutcome::Failed(message) => {
                if let Some(export) = &mut self.export {
                    export.state = ExportState::Failed(message);
                }
            }
        }
        cx.notify();
    }

    fn dismiss_export_later(&self, generation: u64, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(Duration::from_secs(6)).await;
            this.update(cx, |this, cx| {
                if this
                    .export
                    .as_ref()
                    .is_some_and(|e| e.generation == generation)
                {
                    this.export = None;
                    cx.notify();
                }
            })
            .ok();
        })
        .detach();
    }

    fn cancel_export(&mut self, cx: &mut Context<Self>) {
        if let Some(export) = &self.export {
            export.cancel.store(true, Ordering::Relaxed);
            cx.notify();
        }
    }

    fn dismiss_export(&mut self, cx: &mut Context<Self>) {
        if self.export.take().is_some() {
            cx.notify();
        }
    }
}

impl Render for Explorer {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        for image in self.stale_images.drain(..) {
            if let Err(err) = window.drop_image(image) {
                log::error!("failed to release preview image: {err}");
            }
        }
        let layout = self.layout(window);
        // Keep the reveal request until the current listing can satisfy it.
        let reveal = if self.current_entries().is_some() {
            self.reveal.take()
        } else {
            None
        };
        let reveal = reveal.as_deref();

        div()
            .id("explorer")
            .key_context(KEY_CONTEXT)
            .track_focus(&self.focus_handle)
            .on_action(cx.listener(|this, _: &GoBack, _, cx| this.go_back(cx)))
            .on_action(cx.listener(|this, _: &GoForward, _, cx| this.go_forward(cx)))
            .on_action(cx.listener(|this, _: &GoUp, _, cx| this.go_up(cx)))
            .on_action(cx.listener(|this, _: &Refresh, _, cx| this.refresh(cx)))
            .on_action(cx.listener(|this, _: &CloseMenu, _, cx| this.close_menu(cx)))
            .relative()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme::BACKGROUND))
            .text_color(rgb(theme::TEXT))
            .font_family(theme::UI_FONT)
            .text_sm()
            .child(self.render_menu_bar(cx))
            .child(self.render_toolbar(cx))
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(self.render_tree(layout.tree, reveal, cx))
                    .child(self.render_divider(Divider::Tree, cx))
                    .child(self.render_browser(&layout, reveal, cx))
                    .when(self.preview_visible, |el| {
                        el.child(self.render_divider(Divider::Preview, cx))
                            .child(self.render_preview(layout.preview, cx))
                    }),
            )
            .child(self.render_status_bar())
            .child(self.render_resize_tracker(cx))
            .when(self.export.is_some(), |el| {
                el.child(self.render_export_toast(cx))
            })
            .when_some(self.open_menu.clone(), |el, menu| {
                el.child(self.render_menu_overlay(&menu, cx))
            })
    }
}

impl Explorer {
    fn render_toolbar(&self, cx: &Context<Self>) -> impl IntoElement {
        let can_go_up = self
            .current_dir()
            .is_some_and(|dir| self.workspace.parent_within_root(dir).is_some());
        let crumbs = self
            .current_dir()
            .map(|dir| self.workspace.breadcrumbs(dir))
            .unwrap_or_default();
        let crumb_count = crumbs.len();

        let nav_button = |id: &'static str,
                          glyph: Icon,
                          enabled: bool,
                          action: fn(&mut Self, &mut Context<Self>)| {
            ui::icon_button(id, glyph, enabled, false).when(enabled, |el| {
                el.on_click(cx.listener(move |this, _, _, cx| action(this, cx)))
            })
        };

        div()
            .flex()
            .flex_none()
            .items_center()
            .gap_1()
            .h(px(TOOLBAR_HEIGHT))
            .px_2()
            .bg(rgb(theme::BACKGROUND))
            .border_b_1()
            .border_color(rgb(theme::BORDER))
            .child(nav_button(
                "back",
                Icon::ArrowLeft,
                self.history.can_go_back(),
                Self::go_back,
            ))
            .child(nav_button(
                "forward",
                Icon::ArrowRight,
                self.history.can_go_forward(),
                Self::go_forward,
            ))
            .child(nav_button("up", Icon::ArrowUp, can_go_up, Self::go_up))
            .child(
                div()
                    .id("breadcrumbs")
                    .flex()
                    .flex_1()
                    .min_w_0()
                    .items_center()
                    .gap_0p5()
                    .h(px(30.))
                    .mx_1()
                    .px_2()
                    .overflow_x_hidden()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(theme::BORDER))
                    .bg(rgb(theme::PANEL))
                    .child(ui::icon(Icon::Folder, px(16.), theme::TEXT_MUTED).mr_1())
                    .children(crumbs.into_iter().enumerate().map(|(ix, (label, path))| {
                        div()
                            .flex()
                            .flex_none()
                            .items_center()
                            .gap_0p5()
                            .when(ix > 0, |el| {
                                el.child(ui::icon(Icon::ChevronRight, px(12.), theme::TEXT_MUTED))
                            })
                            .child(
                                div()
                                    .id(("crumb", ix))
                                    .px_1p5()
                                    .py_0p5()
                                    .rounded_sm()
                                    .whitespace_nowrap()
                                    .when(ix + 1 == crumb_count, |el| {
                                        el.text_color(rgb(theme::TEXT))
                                    })
                                    .when(ix + 1 < crumb_count, |el| {
                                        el.text_color(rgb(theme::TEXT_MUTED))
                                    })
                                    .hover(|s| s.bg(rgb(theme::HOVER)))
                                    .child(label)
                                    .on_click(cx.listener(move |this, _, _, cx| {
                                        this.navigate(path.clone(), cx)
                                    })),
                            )
                    })),
            )
            .child(
                ui::icon_button(
                    "toggle-preview",
                    Icon::PanelRight,
                    true,
                    self.preview_visible,
                )
                .on_click(cx.listener(|this, _, _, cx| this.toggle_preview(cx))),
            )
    }

    /// A visible scrollbar for a scroll handle. `axis` selects a vertical bar
    /// on the right or a horizontal bar at the bottom. The bar occupies its own
    /// layout space, so it never covers the content. The thumb is painted after
    /// layout, because a scroll handle only knows its range once its content
    /// has been laid out.
    fn render_scrollbar(
        &self,
        handle: ScrollHandle,
        axis: Axis,
        id: &'static str,
        cx: &Context<Self>,
    ) -> AnyElement {
        let active = self
            .scroll_drag
            .as_ref()
            .is_some_and(|drag| drag.axis == axis);
        let thumb_color = if active {
            theme::ACCENT
        } else {
            theme::TEXT_DISABLED
        };
        let click_handle = handle.clone();
        let paint_handle = handle;
        div()
            .id(id)
            .relative()
            .flex_none()
            .when(axis == Axis::Vertical, |el| {
                el.w(px(SCROLLBAR_WIDTH)).h_full()
            })
            .when(axis == Axis::Horizontal, |el| {
                el.h(px(SCROLLBAR_WIDTH)).w_full()
            })
            .bg(rgb(theme::BACKGROUND))
            .child(
                canvas(
                    |_, _, _| {},
                    move |bounds, _, window, _| {
                        let (offset, max, viewport) = match axis {
                            Axis::Vertical => (
                                -f32::from(paint_handle.offset().y),
                                f32::from(paint_handle.max_offset().y),
                                f32::from(bounds.size.height),
                            ),
                            Axis::Horizontal => (
                                -f32::from(paint_handle.offset().x),
                                f32::from(paint_handle.max_offset().x),
                                f32::from(bounds.size.width),
                            ),
                        };
                        let (thumb, position) = scrollbar_geometry(offset, max, viewport);
                        if thumb <= 0. {
                            return;
                        }
                        let thumb_bounds = match axis {
                            Axis::Vertical => Bounds::new(
                                Point {
                                    x: bounds.left() + px(2.),
                                    y: bounds.top() + px(position),
                                },
                                size(px(SCROLLBAR_WIDTH - 4.), px(thumb)),
                            ),
                            Axis::Horizontal => Bounds::new(
                                Point {
                                    x: bounds.left() + px(position),
                                    y: bounds.top() + px(2.),
                                },
                                size(px(thumb), px(SCROLLBAR_WIDTH - 4.)),
                            ),
                        };
                        window.paint_quad(fill(thumb_bounds, rgb(thumb_color)));
                    },
                )
                .absolute()
                .inset_0(),
            )
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, event: &MouseDownEvent, _, cx| {
                    this.begin_scroll_drag(click_handle.clone(), axis, event.position, cx);
                    cx.stop_propagation();
                }),
            )
            .into_any_element()
    }

    /// Starts dragging a scrollbar thumb at `position`. A click outside the
    /// thumb centres it there first.
    fn begin_scroll_drag(
        &mut self,
        handle: ScrollHandle,
        axis: Axis,
        position: Point<Pixels>,
        cx: &mut Context<Self>,
    ) {
        let bounds = handle.bounds();
        let (local, offset, max, viewport) = match axis {
            Axis::Vertical => (
                f32::from(position.y) - f32::from(bounds.top()),
                -f32::from(handle.offset().y),
                f32::from(handle.max_offset().y),
                f32::from(bounds.size.height),
            ),
            Axis::Horizontal => (
                f32::from(position.x) - f32::from(bounds.left()),
                -f32::from(handle.offset().x),
                f32::from(handle.max_offset().x),
                f32::from(bounds.size.width),
            ),
        };
        if max <= 0.5 || viewport <= 0. {
            return;
        }
        let (thumb, thumb_position) = scrollbar_geometry(offset, max, viewport);
        let grab = if (thumb_position..thumb_position + thumb).contains(&local) {
            local - thumb_position
        } else {
            thumb / 2.
        };
        self.scroll_drag = Some(ScrollDrag { handle, axis, grab });
        self.scroll_drag_to(position, cx);
    }

    /// Moves the active scrollbar to follow the pointer.
    fn scroll_drag_to(&mut self, position: Point<Pixels>, cx: &mut Context<Self>) {
        let Some(drag) = &self.scroll_drag else {
            return;
        };
        let bounds = drag.handle.bounds();
        let (local, max, viewport) = match drag.axis {
            Axis::Vertical => (
                f32::from(position.y) - f32::from(bounds.top()),
                f32::from(drag.handle.max_offset().y),
                f32::from(bounds.size.height),
            ),
            Axis::Horizontal => (
                f32::from(position.x) - f32::from(bounds.left()),
                f32::from(drag.handle.max_offset().x),
                f32::from(bounds.size.width),
            ),
        };
        if max <= 0.5 || viewport <= 0. {
            return;
        }
        let (thumb, _) = scrollbar_geometry(0., max, viewport);
        let travel = (viewport - thumb).max(0.);
        let fraction = if travel > 0. {
            ((local - drag.grab) / travel).clamp(0., 1.)
        } else {
            0.
        };
        let mut offset = drag.handle.offset();
        match drag.axis {
            Axis::Vertical => offset.y = px(-fraction * max),
            Axis::Horizontal => offset.x = px(-fraction * max),
        }
        drag.handle.set_offset(offset);
        cx.notify();
    }

    fn resize_column(&mut self, x: f32, cx: &mut Context<Self>) {
        let Some(drag) = self.column_drag else {
            return;
        };
        let width = drag.start_width + (x - drag.start_x);
        self.set_column_width(drag.column, width);
        cx.notify();
    }

    fn column_width(&self, column: usize) -> Option<f32> {
        match column {
            0 => Some(self.details_name_width),
            n => self.details_widths.get(n - 1).copied(),
        }
    }

    fn set_column_width(&mut self, column: usize, width: f32) {
        match column {
            0 => self.details_name_width = clamp_details_name(width),
            n => {
                if let Some(slot) = self.details_widths.get_mut(n - 1) {
                    *slot = clamp_details_column(width);
                }
            }
        }
    }

    /// The draggable right edge of a details header column. Columns are
    /// numbered Name, Type, Size, Modified.
    fn column_grip(&self, column: usize, cx: &Context<Self>) -> Stateful<Div> {
        let active = self.column_drag.is_some_and(|drag| drag.column == column);
        div()
            .id(("column-grip", column))
            .flex_none()
            .w(px(6.))
            .h_full()
            .cursor_col_resize()
            .hover(|s| s.bg(rgb(theme::HOVER)))
            .child(div().m_auto().w(px(1.)).h_full().bg(rgb(if active {
                theme::SELECTION_BORDER
            } else {
                theme::BORDER
            })))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, event: &MouseDownEvent, _, cx| {
                    let Some(width) = this.column_width(column) else {
                        return;
                    };
                    this.column_drag = Some(ColumnDrag {
                        column,
                        start_x: f32::from(event.position.x),
                        start_width: width,
                    });
                    cx.notify();
                    cx.stop_propagation();
                }),
            )
    }

    fn render_divider(&self, divider: Divider, cx: &Context<Self>) -> impl IntoElement {
        let active = self.resizing == Some(divider);
        div()
            .id(match divider {
                Divider::Tree => "tree-divider",
                Divider::Preview => "preview-divider",
            })
            .relative()
            .flex_none()
            .w(px(DIVIDER_WIDTH))
            .h_full()
            .cursor_col_resize()
            .child(
                div()
                    .absolute()
                    .left(px(2.))
                    .w(px(1.))
                    .h_full()
                    .bg(rgb(if active {
                        theme::SELECTION_BORDER
                    } else {
                        theme::BORDER
                    })),
            )
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    this.resizing = Some(divider);
                    cx.notify();
                }),
            )
    }

    /// Window-level listeners keep a divider drag going when the cursor moves
    /// faster than the divider.
    fn render_resize_tracker(&self, cx: &Context<Self>) -> impl IntoElement {
        let this: Entity<Self> = cx.entity();
        canvas(
            |_, _, _| {},
            move |_: Bounds<Pixels>, (), window, _| {
                let move_target = this.clone();
                window.on_mouse_event(move |event: &MouseMoveEvent, phase, window, cx| {
                    if phase == DispatchPhase::Bubble {
                        move_target.update(cx, |this, cx| {
                            if this.resizing.is_some() {
                                this.resize_to(event.position, window, cx);
                            }
                            if this.column_drag.is_some() {
                                this.resize_column(f32::from(event.position.x), cx);
                            }
                            if this.scroll_drag.is_some() {
                                this.scroll_drag_to(event.position, cx);
                            }
                        });
                    }
                });
                window.on_mouse_event(move |event: &MouseUpEvent, phase, _, cx| {
                    if phase == DispatchPhase::Bubble && event.button == MouseButton::Left {
                        this.update(cx, |this, cx| {
                            if this.scroll_drag.take().is_some() {
                                cx.notify();
                            }
                            if this.column_drag.take().is_some() {
                                this.schedule_save(cx);
                                cx.notify();
                            }
                            if this.resizing.take().is_some() {
                                this.schedule_save(cx);
                                cx.notify();
                            }
                        });
                    }
                });
            },
        )
        .absolute()
        .size_0()
    }

    fn render_status_bar(&self) -> impl IntoElement {
        let items = match self.current_listing() {
            Some(Listing::Loaded(entries)) => match entries.len() {
                1 => "1 item".to_string(),
                n => format!("{n} items"),
            },
            Some(Listing::Loading) => "Loading…".to_string(),
            Some(Listing::Indexing(archive)) => match self.indexing_state(archive) {
                Some((Some(fraction), stage, _)) => {
                    format!("{} {:.0}%", stage_label(stage), fraction * 100.0)
                }
                _ => "Opening archive…".to_string(),
            },
            Some(Listing::NeedsExecutable { .. }) => "Executable needed".to_string(),
            Some(Listing::AuthenticationFailed { .. }) => "Not authenticated".to_string(),
            Some(Listing::Failed(_)) => "Folder unavailable".to_string(),
            None => String::new(),
        };
        let executable = match &self.executable {
            ExecutableState::Unset => None,
            ExecutableState::Checking => Some("Checking executable…".to_string()),
            ExecutableState::Ready(executable) => {
                Some(format!("Executable ready: {}", executable.name()))
            }
            ExecutableState::Failed(_) => Some("Executable unusable".to_string()),
        };
        let selection = self.selected_entry().map(|entry| match entry.size {
            Some(size) => format!("1 item selected ({})", files::format_size(size)),
            None => "1 item selected".to_string(),
        });
        let location = self.current_dir().and_then(|dir| {
            let root = self.workspace.root_of(dir)?;
            let relative = dir.strip_prefix(root).ok()?.display().to_string();
            let glyph = if self.workspace.is_folder_root(root) {
                Icon::Folder
            } else {
                Icon::Gamepad
            };
            Some((glyph, self.workspace.root_label(root), relative))
        });

        let separator = || div().w(px(1.)).h(px(12.)).bg(rgb(theme::BORDER));

        div()
            .flex()
            .flex_none()
            .items_center()
            .gap_3()
            .h(px(STATUS_BAR_HEIGHT))
            .px_3()
            .bg(rgb(theme::BACKGROUND))
            .border_t_1()
            .border_color(rgb(theme::BORDER))
            .text_xs()
            .text_color(rgb(theme::TEXT_MUTED))
            .child(items)
            .when_some(selection, |el, selection| {
                el.child(separator()).child(selection)
            })
            .when_some(executable, |el, executable| {
                el.child(separator())
                    .child(div().max_w(px(280.)).truncate().child(executable))
            })
            .child(div().flex_1())
            .when_some(location, |el, (glyph, root, relative)| {
                el.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_1p5()
                        .child(ui::icon(glyph, px(14.), theme::ACCENT))
                        .child(root),
                )
                .when(!relative.is_empty(), |el| {
                    el.child(separator())
                        .child(div().max_w(px(360.)).truncate().child(relative))
                })
                .child(separator())
            })
            .child(format!("{} view", self.view_mode.label()))
    }

    /// A small card in the corner showing an export's progress or result. It
    /// floats over the layout, so it never shifts the panels.
    fn render_export_toast(&self, cx: &Context<Self>) -> impl IntoElement {
        let export = self.export.as_ref();
        let running = matches!(export.map(|e| &e.state), Some(ExportState::Running));
        let cancelling = export.is_some_and(|e| e.cancel.load(Ordering::Relaxed));
        let failed = matches!(export.map(|e| &e.state), Some(ExportState::Failed(_)));
        let lines: Vec<String> = match export.map(|e| &e.state) {
            Some(ExportState::Running) if cancelling => vec!["Cancelling…".to_string()],
            Some(ExportState::Running) => {
                vec![format!(
                    "Saving {}…",
                    export.map(|e| e.label.as_str()).unwrap_or_default()
                )]
            }
            Some(ExportState::Done(message)) | Some(ExportState::Failed(message)) => {
                message.lines().map(str::to_string).collect()
            }
            None => Vec::new(),
        };
        let heading_color = if failed { theme::ERROR } else { theme::TEXT };

        div()
            .absolute()
            .right(px(16.))
            .bottom(px(STATUS_BAR_HEIGHT + 12.))
            .flex()
            .flex_col()
            .gap_2()
            .w(px(360.))
            .p_3()
            .rounded_md()
            .border_1()
            .border_color(rgb(theme::BORDER))
            .bg(rgb(theme::SURFACE))
            .shadow_lg()
            .text_sm()
            .children(lines.into_iter().enumerate().map(|(ix, line)| {
                if ix == 0 {
                    div()
                        .font_weight(FontWeight::MEDIUM)
                        .text_color(rgb(heading_color))
                        .child(line)
                } else {
                    div()
                        .text_xs()
                        .text_color(rgb(theme::TEXT_MUTED))
                        .child(line)
                }
            }))
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap_2()
                    .when(running && !cancelling, |el| {
                        el.child(ui::button("export-cancel", "Cancel").on_click(cx.listener(
                            |this, _, _, cx| {
                                cx.stop_propagation();
                                this.cancel_export(cx);
                            },
                        )))
                    })
                    .when(!running, |el| {
                        el.child(
                            ui::button("export-dismiss", "Dismiss").on_click(cx.listener(
                                |this, _, _, cx| {
                                    cx.stop_propagation();
                                    this.dismiss_export(cx);
                                },
                            )),
                        )
                    }),
            )
    }
}

fn window_options(title: &str, window_size: gpui::Size<Pixels>, cx: &App) -> WindowOptions {
    WindowOptions {
        window_bounds: Some(WindowBounds::Windowed(Bounds::centered(
            None,
            window_size,
            cx,
        ))),
        titlebar: Some(TitlebarOptions {
            title: Some(format!("{title} — Leonida Forge").into()),
            ..Default::default()
        }),
        window_min_size: Some(size(px(400.), px(300.))),
        ..Default::default()
    }
}

fn window_title(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// Short text for the step an archive preparation is in.
fn stage_label(stage: u8) -> &'static str {
    match stage {
        Stage::VERIFYING => "Authenticating…",
        Stage::SCANNING => "Scanning…",
        _ => "Indexing archive…",
    }
}

/// The directory the save dialog opens in: the folder holding the archive the
/// entry comes from, or the entry's own folder for a file on disk.
fn initial_export_dir(source: &Path) -> PathBuf {
    let on_disk = files::split_location(source)
        .map(|(file, _)| file)
        .unwrap_or(source);
    on_disk.parent().map(Path::to_path_buf).unwrap_or_default()
}

/// A caveat for the recovery status of `entry`, or `None` when its status is
/// not in doubt. Reuses the status text shown in the preview, so an exported
/// partial or unverified entry is not presented as a whole, verified file.
fn export_caveat(entry: &Entry) -> Option<String> {
    let (_, status) = entry.details.iter().find(|(label, _)| *label == "Status")?;
    (!status.starts_with("Complete")).then(|| status.clone())
}

/// Whether a new export may begin. Only one export runs at a time: a new one
/// is refused while another is still writing, so a second Save As cannot take
/// over or cancel an export already in progress. A finished result waiting to
/// be dismissed does not block a new export.
fn can_start_export(current: Option<&ExportState>) -> bool {
    !matches!(current, Some(ExportState::Running))
}

/// Builds the result shown when an export ends. The success message is
/// deliberately neutral: it never implies the saved bytes are a verified or
/// byte-identical original file. Any recovery caveat is appended.
fn export_outcome(result: io::Result<u64>, caveat: Option<&str>, dest: &Path) -> ExportOutcome {
    let name = window_title(dest);
    match result {
        Ok(bytes) => {
            let mut message = format!(
                "Saved {} bytes to {name}.",
                files::format_bytes_exact(bytes)
            );
            if let Some(caveat) = caveat {
                message.push('\n');
                message.push_str(caveat);
            }
            ExportOutcome::Done(message)
        }
        Err(err) if err.kind() == io::ErrorKind::Interrupted => ExportOutcome::Cancelled,
        Err(err) => ExportOutcome::Failed(format!("Could not save {name}: {err}")),
    }
}

/// Opens any regular file, including archive entries and images, as bytes.
pub(crate) fn open_binary_inspector(path: PathBuf, access: Access, cx: &mut App) {
    let mut options = window_options(&window_title(&path), size(px(1200.), px(760.)), cx);
    options.window_min_size = Some(size(px(720.), px(420.)));
    if let Err(err) = cx.open_window(options, |window, cx| {
        ui::close_through_gpui(window, cx);
        let inspector = cx.new(|cx| BinaryInspector::new(path, access, window, cx));
        let focus_handle = inspector.read(cx).focus_handle().clone();
        focus_handle.focus(window, cx);
        inspector
    }) {
        log::error!("failed to open binary inspector: {err:#}");
    }
}

fn open_image_viewer(path: PathBuf, access: Access, cx: &mut App) {
    let options = window_options(&window_title(&path), size(px(960.), px(720.)), cx);
    if let Err(err) = cx.open_window(options, |window, cx| {
        ui::close_through_gpui(window, cx);
        cx.new(|cx| ImageViewer::new(path, access, window, cx))
    }) {
        log::error!("failed to open image viewer: {err:#}");
    }
}

/// How an entry is recognised as a model. Native type 2 and type 3 rows are
/// model resources; a recovered resource needs a content check first because
/// the recovery tree also holds texture dictionaries and other resources.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ModelEntryKind {
    Direct,
    Sniff,
}

fn model_entry_kind(entry: &Entry) -> Option<ModelEntryKind> {
    if entry.type_name.starts_with("RPF9 entry, type 2")
        || entry.type_name.starts_with("RPF9 entry, type 3")
    {
        return Some(ModelEntryKind::Direct);
    }
    if entry.type_name == "RAGE resource" {
        return Some(ModelEntryKind::Sniff);
    }
    // A directly accessible decoded resource has no type metadata. Sniff it
    // by content, with a bound so opening an arbitrary large file stays cheap.
    (entry.kind == EntryKind::File
        && !entry.is_supported_image()
        && entry.size.is_some_and(|size| size <= 64 << 20))
    .then_some(ModelEntryKind::Sniff)
}

fn open_model_viewer(path: PathBuf, access: Access, gta_root: Option<PathBuf>, cx: &mut App) {
    let mut options = window_options(&window_title(&path), size(px(1200.), px(800.)), cx);
    options.window_min_size = Some(size(px(640.), px(420.)));
    if let Err(err) = cx.open_window(options, |window, cx| {
        ui::close_through_gpui(window, cx);
        cx.new(|cx| ModelViewer::new(path, access, gta_root, window, cx))
    }) {
        log::error!("failed to open model viewer: {err:#}");
    }
}

#[cfg(test)]
mod export_tests {
    use super::*;

    fn file_entry(name: &str, details: Vec<(&'static str, String)>) -> Entry {
        let mut entry = Entry::new(
            name.to_string(),
            PathBuf::from(name),
            EntryKind::File,
            Some(10),
            None,
        );
        entry.details = details;
        entry
    }

    #[test]
    fn details_columns_clamp_to_their_limits() {
        assert_eq!(clamp_details_column(10.), MIN_DETAILS_COLUMN);
        assert_eq!(clamp_details_column(1000.), MAX_DETAILS_COLUMN);
        assert_eq!(clamp_details_column(150.), 150.);
    }

    #[test]
    fn scrollbar_thumb_shows_the_visible_fraction() {
        // Nothing to scroll: no thumb.
        assert_eq!(scrollbar_geometry(0., 0., 100.), (0., 0.));
        // Half the content visible: half-height thumb at the top.
        assert_eq!(scrollbar_geometry(0., 100., 100.), (50., 0.));
        // Half way through: the thumb has travelled half the free track.
        let (thumb, position) = scrollbar_geometry(50., 100., 100.);
        assert_eq!(thumb, 50.);
        assert_eq!(position, 25.);
        // A very long list keeps a usable minimum thumb.
        let (thumb, _) = scrollbar_geometry(0., 1_000_000., 100.);
        assert_eq!(thumb, MIN_SCROLLBAR_THUMB);
    }

    #[test]
    fn caveat_is_added_only_for_uncertain_status() {
        let complete = file_entry("0x0000000100.dds", vec![("Status", "Complete: …".into())]);
        assert!(export_caveat(&complete).is_none());

        let unverified = file_entry(
            "0x0000000100.bin",
            vec![("Status", "Unverified: no known file signature".into())],
        );
        assert_eq!(
            export_caveat(&unverified).as_deref(),
            Some("Unverified: no known file signature")
        );

        // A native entry has no recovery status, so no caveat.
        let native = file_entry("Row 00000", vec![("Offset", "0x100".into())]);
        assert!(export_caveat(&native).is_none());
    }

    #[test]
    fn outcome_messages_are_neutral_and_honest() {
        let dest = Path::new("out").join("texture.dds");
        match export_outcome(Ok(2048), None, &dest) {
            ExportOutcome::Done(message) => {
                assert!(
                    message.contains("Saved 2,048 bytes to texture.dds."),
                    "{message}"
                );
                assert!(!message.to_lowercase().contains("original"), "{message}");
            }
            _ => panic!("expected a completed export"),
        }
        match export_outcome(Ok(2048), Some("Unverified: may be partial"), &dest) {
            ExportOutcome::Done(message) => {
                assert!(message.contains("Unverified: may be partial"), "{message}");
            }
            _ => panic!("expected a completed export"),
        }
        let cancelled = io::Error::new(io::ErrorKind::Interrupted, "cancelled");
        assert!(matches!(
            export_outcome(Err(cancelled), None, &dest),
            ExportOutcome::Cancelled
        ));
        let failed = io::Error::other("disk full");
        match export_outcome(Err(failed), None, &dest) {
            ExportOutcome::Failed(message) => {
                assert!(message.contains("Could not save texture.dds"), "{message}");
                assert!(message.contains("disk full"), "{message}");
            }
            _ => panic!("expected a failed export"),
        }
    }

    #[test]
    fn a_new_export_waits_for_the_running_one() {
        // No export, or a finished one awaiting dismissal, never blocks.
        assert!(can_start_export(None));
        assert!(can_start_export(Some(&ExportState::Done("saved".into()))));
        assert!(can_start_export(Some(&ExportState::Failed("error".into()))));
        // A running export owns the single slot until it finishes.
        assert!(!can_start_export(Some(&ExportState::Running)));
    }

    #[test]
    fn overlapping_save_dialogs_share_one_slot() {
        let mut requests = ExportRequests::default();
        let first = requests.begin(None).unwrap();
        // The first dialog still holds the slot, so a second request is
        // refused and never opens a second dialog.
        assert!(requests.busy(None));
        assert!(requests.begin(None).is_none());
        assert!(
            requests
                .begin(Some(&ExportState::Done("saved".into())))
                .is_none()
        );

        // When the first dialog returns, only its export may start.
        assert!(requests.finish(first, None));
        assert!(!requests.busy(None));
        // Its export now runs, and blocks a new request.
        assert!(requests.begin(Some(&ExportState::Running)).is_none());
    }

    #[test]
    fn a_delayed_or_cancelled_dialog_never_writes_its_destination() {
        let mut requests = ExportRequests::default();
        let cancelled = requests.begin(None).unwrap();
        requests.cancel(cancelled);
        assert!(!requests.busy(None));
        // A result arriving after the dialog was cancelled starts nothing.
        assert!(!requests.finish(cancelled, None));

        // A later request owns the slot; the old result cannot take it.
        let current = requests.begin(None).unwrap();
        assert_ne!(cancelled, current);
        assert!(!requests.finish(cancelled, None));
        assert!(requests.pending == Some(current));
        assert!(requests.finish(current, None));
    }

    #[test]
    fn a_delayed_dialog_cannot_replace_a_running_export() {
        let mut requests = ExportRequests::default();
        let delayed = requests.begin(None).unwrap();
        // Even if the slot were somehow already writing, the delayed request
        // must not report that it may start.
        assert!(!requests.finish(delayed, Some(&ExportState::Running)));
        // The running export keeps the slot.
        assert!(requests.busy(Some(&ExportState::Running)));
    }

    #[test]
    fn initial_dir_is_the_folder_holding_the_source() {
        // A plain path that does not exist falls back to its own folder.
        assert_eq!(
            initial_export_dir(Path::new("plain/dir/file.bin")),
            PathBuf::from("plain/dir")
        );

        // An archive entry opens in the archive file's folder.
        let temp = tempfile::tempdir().unwrap();
        let archive = temp.path().join("pack.rpf");
        std::fs::write(&archive, b"9FPR0000").unwrap();
        let entry = archive.join("Recovered Entries").join("XML").join("x.xml");
        assert_eq!(initial_export_dir(&entry), temp.path());
    }

    #[test]
    fn archive_steps_have_short_labels() {
        assert_eq!(stage_label(Stage::VERIFYING), "Authenticating…");
        assert_eq!(stage_label(Stage::SCANNING), "Scanning…");
        assert_eq!(stage_label(Stage::OPENING), "Indexing archive…");
    }
}
