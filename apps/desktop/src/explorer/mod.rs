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
    App, Bounds, Context, DispatchPhase, Entity, FocusHandle, FontWeight, KeyBinding, MouseButton,
    MouseMoveEvent, MouseUpEvent, PathPromptOptions, Pixels, Point, RenderImage, ScrollHandle,
    Subscription, Task, TitlebarOptions, UniformListScrollHandle, Window, WindowBounds,
    WindowHandle, WindowOptions, actions, canvas, div, prelude::*, px, rgb, size,
};

use lforge_rage9::rpf::Progress;

use crate::files::archive::Identified;
use crate::files::shell::ShellWorker;
use crate::files::{self, Entry, EntryKind, Sort, SortKey, images};
use crate::settings::{Settings, ViewMode};
use crate::ui;
use crate::ui::assets::Icon;
use crate::ui::theme;
use crate::viewers::{BinaryInspector, ImageViewer, RendererDemo};
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

pub fn bind_keys(cx: &mut App) {
    cx.bind_keys([
        KeyBinding::new("alt-left", GoBack, Some(KEY_CONTEXT)),
        KeyBinding::new("backspace", GoBack, Some(KEY_CONTEXT)),
        KeyBinding::new("alt-right", GoForward, Some(KEY_CONTEXT)),
        KeyBinding::new("alt-up", GoUp, Some(KEY_CONTEXT)),
        KeyBinding::new("f5", Refresh, Some(KEY_CONTEXT)),
        KeyBinding::new("escape", CloseMenu, Some(KEY_CONTEXT)),
    ]);
}

enum Listing {
    Loading,
    /// Waiting for the archive at this path to be decompressed or indexed.
    Indexing(PathBuf),
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
    cancel: Arc<AtomicBool>,
    _work: Task<()>,
    _ticker: Task<()>,
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
    loading: HashSet<PathBuf>,
    indexing: HashMap<PathBuf, IndexJob>,
    expanded: HashSet<PathBuf>,
    history: History,
    selected: Option<PathBuf>,
    sort: Sort,
    view_mode: ViewMode,
    preview_visible: bool,
    tree_width: f32,
    preview_width: f32,
    open_menu: Option<Menu>,
    resizing: Option<Divider>,
    export: Option<Export>,
    export_generation: u64,
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
    focus_handle: FocusHandle,
    settings_path: Option<PathBuf>,
    save_task: Option<Task<()>>,
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
            loading: HashSet::new(),
            indexing: HashMap::new(),
            expanded: HashSet::new(),
            history: History::default(),
            selected: None,
            sort: settings.sort,
            view_mode: settings.view_mode,
            preview_visible: settings.preview_visible,
            tree_width: settings.tree_width,
            preview_width: settings.preview_width,
            open_menu: None,
            resizing: None,
            export: None,
            export_generation: 0,
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
            focus_handle: cx.focus_handle(),
            settings_path,
            save_task: None,
            renderer_demo: None,
            _quit_subscription: cx.on_app_quit(|this, _| {
                this.save_task = None;
                this.save_now();
                async {}
            }),
        };

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

    /// Reopens the last directory if it still exists, otherwise the GTA VI root.
    fn restore_directory(&mut self, last: Option<PathBuf>, cx: &mut Context<Self>) {
        let last = last.filter(|dir| self.workspace.root_of(dir).is_some());
        let fallback = self.workspace.gta.clone();
        let exists = cx.background_spawn({
            let last = last.clone();
            async move {
                last.is_some_and(|dir| match files::list(&dir) {
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
            Listing::Loading | Listing::Indexing(_) | Listing::Failed(_) => None,
        }
    }

    fn selected_entry(&self) -> Option<&Entry> {
        let selected = self.selected.as_deref()?;
        let parent = selected.parent()?;
        match self.listings.get(parent)? {
            Listing::Loaded(entries) => entries.iter().find(|entry| entry.path == selected),
            Listing::Loading | Listing::Indexing(_) | Listing::Failed(_) => None,
        }
    }

    /// Lists `dir` in the background. Cached contents stay visible until the
    /// new listing arrives.
    fn load(&mut self, dir: PathBuf, cx: &mut Context<Self>) {
        if !self.loading.insert(dir.clone()) {
            return;
        }
        self.listings.entry(dir.clone()).or_insert(Listing::Loading);
        let sort = self.sort;
        let task = cx.background_spawn({
            let dir = dir.clone();
            async move {
                match files::list(&dir) {
                    Ok(mut entries) => {
                        files::sort_entries(&mut entries, sort);
                        Loaded::Entries(entries, files::describe(&dir))
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
                this.loading.remove(&dir);
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
                        this.start_indexing(archive.clone(), cx);
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
    /// it is stored in and scans it, as needed. Listings waiting for it are
    /// loaded again when the scan ends.
    fn start_indexing(&mut self, archive: PathBuf, cx: &mut Context<Self>) {
        if self.indexing.contains_key(&archive) {
            return;
        }
        let progress = Arc::new(Progress::default());
        let cancel = Arc::new(AtomicBool::new(false));
        let work = cx.background_spawn({
            let (archive, progress, cancel) = (archive.clone(), progress.clone(), cancel.clone());
            async move { files::archive::prepare(&archive, &progress, &cancel) }
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
                let message = if err.kind() == io::ErrorKind::Interrupted {
                    "Opening the archive was cancelled. Press F5 to open it.".to_string()
                } else {
                    format!("The archive could not be opened: {err}")
                };
                for dir in waiting {
                    self.listings.insert(dir, Listing::Failed(message.clone()));
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

    /// The running scan of `archive`: its progress, if known yet, and
    /// whether it was asked to stop.
    fn indexing_state(&self, archive: &Path) -> Option<(Option<f32>, bool)> {
        let job = self.indexing.get(archive)?;
        Some((job.progress.fraction(), job.cancel.load(Ordering::Relaxed)))
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
        let identified = cx.background_spawn({
            let path = path.clone();
            async move { files::identify(&path) }
        });
        cx.spawn(async move |this, cx| {
            let identified = identified.await;
            this.update(cx, |this, cx| match identified {
                Ok(Identified::Archive(_)) => {
                    this.mark_archive(&path);
                    this.navigate(path, cx);
                }
                // Opening it explains why it is not a valid archive.
                Ok(Identified::Invalid { .. }) => this.navigate(path, cx),
                Ok(Identified::Unknown) if image => open_image_viewer(path, cx),
                Ok(Identified::Unknown) => open_binary_inspector(path, cx),
                Err(err) => {
                    log::warn!("could not identify {}: {err}", path.display());
                    open_binary_inspector(path, cx);
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
            preview_visible: self.preview_visible,
            tree_width: self.tree_width,
            preview_width: self.preview_width,
            last_directory: self.current_dir().map(Path::to_path_buf),
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

    /// Whether an export is running. Only one runs at a time, so the Save As
    /// actions are disabled while one is in progress (see [`can_start_export`]).
    fn exporting(&self) -> bool {
        !can_start_export(self.export.as_ref().map(|export| &export.state))
    }

    /// Asks where to save `entry`, then exports it in the background. Only
    /// regular files are exportable; directories and archives open as folders.
    /// Refuses to start while another export is running, so a second Save As
    /// never takes over or cancels an export already in progress.
    fn start_export(&mut self, entry: &Entry, cx: &mut Context<Self>) {
        if entry.kind != EntryKind::File || self.exporting() {
            return;
        }
        let source = entry.path.clone();
        let label = entry.name.clone();
        let caveat = export_caveat(entry);
        let dir = initial_export_dir(&source);
        let prompt = cx.prompt_for_new_path(&dir, Some(entry.name.as_str()));
        cx.spawn(async move |this, cx| {
            let dest = match prompt.await {
                Ok(Ok(Some(dest))) => dest,
                Ok(Ok(None)) | Err(_) => return,
                Ok(Err(err)) => {
                    log::error!("save dialog failed: {err:#}");
                    return;
                }
            };
            this.update(cx, |this, cx| {
                this.run_export(source, label, caveat, dest, cx)
            })
            .ok();
        })
        .detach();
    }

    fn run_export(
        &mut self,
        source: PathBuf,
        label: String,
        caveat: Option<String>,
        dest: PathBuf,
        cx: &mut Context<Self>,
    ) {
        self.export_generation += 1;
        let generation = self.export_generation;
        let cancel = Arc::new(AtomicBool::new(false));
        let task = cx.spawn({
            let cancel = cancel.clone();
            async move |this, cx| {
                let result = cx
                    .background_spawn({
                        let (source, dest) = (source, dest.clone());
                        async move { files::export(&source, &dest, &cancel) }
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
                            .child(self.render_preview(layout.preview))
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
                        });
                    }
                });
                window.on_mouse_event(move |event: &MouseUpEvent, phase, _, cx| {
                    if phase == DispatchPhase::Bubble && event.button == MouseButton::Left {
                        this.update(cx, |this, cx| {
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
                Some((Some(fraction), _)) => format!("Indexing archive… {:.0}%", fraction * 100.0),
                _ => "Opening archive…".to_string(),
            },
            Some(Listing::Failed(_)) => "Folder unavailable".to_string(),
            None => String::new(),
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
fn open_binary_inspector(path: PathBuf, cx: &mut App) {
    let mut options = window_options(&window_title(&path), size(px(1200.), px(760.)), cx);
    options.window_min_size = Some(size(px(720.), px(420.)));
    if let Err(err) = cx.open_window(options, |window, cx| {
        ui::close_through_gpui(window, cx);
        let inspector = cx.new(|cx| BinaryInspector::new(path, window, cx));
        let focus_handle = inspector.read(cx).focus_handle().clone();
        focus_handle.focus(window, cx);
        inspector
    }) {
        log::error!("failed to open binary inspector: {err:#}");
    }
}

fn open_image_viewer(path: PathBuf, cx: &mut App) {
    let options = window_options(&window_title(&path), size(px(960.), px(720.)), cx);
    if let Err(err) = cx.open_window(options, |window, cx| {
        ui::close_through_gpui(window, cx);
        cx.new(|cx| ImageViewer::new(path, window, cx))
    }) {
        log::error!("failed to open image viewer: {err:#}");
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
}
