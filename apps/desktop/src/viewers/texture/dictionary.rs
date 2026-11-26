//! A texture dictionary in its own window: a list on the left and the
//! selected texture on the right.

use std::collections::{HashMap, VecDeque};
use std::ops::Range;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use gpui::{
    ClickEvent, Context, DispatchPhase, Entity, FocusHandle, KeyDownEvent, MouseButton,
    MouseMoveEvent, MouseUpEvent, ObjectFit, Pixels, ScrollStrategy, Task, UniformListScrollHandle,
    Window, div, img, prelude::*, px, rgb, uniform_list,
};
use lforge_texture::{ImageCache, Store, TextureInfo};

use super::{
    ImagePreview, PREVIEW_CACHE_BYTES, THUMBNAIL_SIZE, file_name, metadata_panel, render_image,
};
use crate::ui;
use crate::ui::theme;

const TOOLBAR_HEIGHT: f32 = 40.;
const STATUS_BAR_HEIGHT: f32 = 24.;
const METADATA_HEIGHT: f32 = 210.;
const HEADER_HEIGHT: f32 = 34.;
const DIVIDER_WIDTH: f32 = 5.;
const ROW_HEIGHT: f32 = 64.;
const MIN_LEFT: f32 = 240.;
const MAX_LEFT: f32 = 600.;
const MAX_THUMBNAILS: usize = 512;

enum ThumbnailState {
    Loading,
    Ready(Arc<gpui::RenderImage>),
    Failed,
}

struct Thumbnail {
    state: ThumbnailState,
    _task: Option<Task<()>>,
}

pub struct TextureDictionaryViewer {
    path: PathBuf,
    store: Store,
    textures: Vec<TextureInfo>,
    selected: usize,
    level: u32,
    preview: Entity<ImagePreview>,
    cache: ImageCache,
    thumbnails: HashMap<u32, Thumbnail>,
    thumbnail_order: VecDeque<u32>,
    left_width: f32,
    resizing: bool,
    revealed: bool,
    list_scroll: UniformListScrollHandle,
    focus_handle: FocusHandle,
    generation: u64,
    cancel: Option<Arc<AtomicBool>>,
    _decode: Option<Task<()>>,
    loading: bool,
    decode_error: Option<String>,
}

impl TextureDictionaryViewer {
    pub fn new(store: Store, path: PathBuf, _window: &mut Window, cx: &mut Context<Self>) -> Self {
        let textures = store.textures().to_vec();
        let selected = textures
            .iter()
            .position(|texture| texture.status.is_decodable())
            .unwrap_or(0);
        let preview = cx.new(|_| ImagePreview::new());
        let mut viewer = Self {
            path,
            store,
            textures,
            selected,
            level: 0,
            preview,
            cache: ImageCache::new(PREVIEW_CACHE_BYTES),
            thumbnails: HashMap::new(),
            thumbnail_order: VecDeque::new(),
            left_width: 320.,
            resizing: false,
            revealed: false,
            list_scroll: UniformListScrollHandle::new(),
            focus_handle: cx.focus_handle(),
            generation: 0,
            cancel: None,
            _decode: None,
            loading: false,
            decode_error: None,
        };
        viewer.start_preview(cx);
        viewer
    }

    pub fn focus_handle(&self) -> &FocusHandle {
        &self.focus_handle
    }

    fn selected_info(&self) -> Option<&TextureInfo> {
        self.textures.get(self.selected)
    }

    fn viewer_status(&self) -> Option<String> {
        if self.loading {
            Some("Decoding".to_string())
        } else {
            self.decode_error.clone()
        }
    }

    fn start_preview(&mut self, cx: &mut Context<Self>) {
        if let Some(previous) = self.cancel.take() {
            previous.store(true, Ordering::Relaxed);
        }
        let Some(info) = self.textures.get(self.selected).cloned() else {
            self.loading = false;
            self.decode_error = None;
            self.preview.update(cx, |preview, cx| preview.clear(cx));
            return;
        };
        if self.level as usize >= info.levels.len().max(1) {
            self.level = 0;
        }
        let index = self.selected as u32;
        let level = self.level;
        if let Some(image) = self.cache.get(index, level) {
            let (width, height) = (image.width, image.height);
            if let Ok((render, _, _)) = render_image((*image).clone()) {
                self.loading = false;
                self.decode_error = None;
                self.preview.update(cx, |preview, cx| {
                    preview.set_image(render, width, height, cx)
                });
                cx.notify();
                return;
            }
        }
        if !info.status.is_decodable() {
            let reason = info
                .status
                .reason()
                .unwrap_or("this texture cannot be decoded")
                .to_string();
            self.loading = false;
            self.decode_error = Some(reason.clone());
            self.preview
                .update(cx, |preview, cx| preview.set_error(reason, cx));
            cx.notify();
            return;
        }
        self.loading = true;
        self.decode_error = None;
        self.preview
            .update(cx, |preview, cx| preview.set_loading(cx));
        cx.notify();
        let store = self.store.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        self.cancel = Some(cancel.clone());
        self.generation += 1;
        let generation = self.generation;
        let task = cx.spawn(async move |this, cx| {
            let decoded = cx
                .background_spawn(async move {
                    match store.decode(index, level, &cancel) {
                        Ok(image) => {
                            let cached = Arc::new(image.clone());
                            let (width, height) = (image.width, image.height);
                            match render_image(image) {
                                Ok((render, _, _)) => Ok(Some((cached, render, width, height))),
                                Err(err) => Err(err),
                            }
                        }
                        Err(lforge_texture::Error::Cancelled) => Ok(None),
                        Err(err) => Err(err.to_string()),
                    }
                })
                .await;
            this.update(cx, |this, cx| {
                if this.generation != generation {
                    return;
                }
                match decoded {
                    Ok(Some((cached, render, width, height))) => {
                        this.loading = false;
                        this.decode_error = None;
                        this.cache.insert(index, level, cached);
                        this.preview.update(cx, |preview, cx| {
                            preview.set_image(render, width, height, cx)
                        });
                        cx.notify();
                    }
                    Ok(None) => {}
                    Err(err) => {
                        this.loading = false;
                        this.decode_error = Some(err.clone());
                        this.preview
                            .update(cx, |preview, cx| preview.set_error(err, cx));
                        cx.notify();
                    }
                }
            })
            .ok();
        });
        self._decode = Some(task);
    }

    fn select(&mut self, index: usize, cx: &mut Context<Self>) {
        if index >= self.textures.len() || index == self.selected {
            return;
        }
        self.selected = index;
        self.level = 0;
        self.list_scroll
            .scroll_to_item(index, ScrollStrategy::Nearest);
        self.start_preview(cx);
        cx.notify();
    }

    fn set_level(&mut self, level: u32, cx: &mut Context<Self>) {
        if self.level == level {
            return;
        }
        self.level = level;
        self.start_preview(cx);
        cx.notify();
    }

    fn open_selected(&mut self, index: usize, cx: &mut Context<Self>) {
        if index >= self.textures.len() {
            return;
        }
        super::open_entry(self.store.clone(), index as u32, self.path.clone(), cx);
    }

    fn request_thumbnail(&mut self, index: usize, cx: &mut Context<Self>) {
        let index = index as u32;
        if self.thumbnails.contains_key(&index) {
            return;
        }
        let Some(info) = self.textures.get(index as usize).cloned() else {
            return;
        };
        if !info.status.is_decodable() {
            self.thumbnails.insert(
                index,
                Thumbnail {
                    state: ThumbnailState::Failed,
                    _task: None,
                },
            );
            self.thumbnail_order.push_back(index);
            return;
        }
        let store = self.store.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let task = cx.spawn({
            let cancel = cancel.clone();
            async move |this, cx| {
                let decoded = cx
                    .background_spawn(async move {
                        match store.thumbnail(index, THUMBNAIL_SIZE, &cancel) {
                            Ok(image) => render_image(image).map(|(render, _, _)| Some(render)),
                            Err(lforge_texture::Error::Cancelled) => Ok(None),
                            Err(err) => Err(err.to_string()),
                        }
                    })
                    .await;
                this.update(cx, |this, cx| {
                    if let Some(thumbnail) = this.thumbnails.get_mut(&index) {
                        thumbnail.state = match decoded {
                            Ok(Some(render)) => ThumbnailState::Ready(render),
                            Ok(None) => ThumbnailState::Failed,
                            Err(_) => ThumbnailState::Failed,
                        };
                        thumbnail._task = None;
                        cx.notify();
                    }
                })
                .ok();
            }
        });
        self.thumbnails.insert(
            index,
            Thumbnail {
                state: ThumbnailState::Loading,
                _task: Some(task),
            },
        );
        self.thumbnail_order.push_back(index);
        while self.thumbnail_order.len() > MAX_THUMBNAILS {
            let Some(oldest) = self.thumbnail_order.pop_front() else {
                break;
            };
            if oldest != self.selected as u32 {
                self.thumbnails.remove(&oldest);
            }
        }
    }

    fn key_down(&mut self, event: &KeyDownEvent, _window: &mut Window, cx: &mut Context<Self>) {
        match event.keystroke.key.as_str() {
            "up" => {
                if self.selected > 0 {
                    self.select(self.selected - 1, cx);
                }
            }
            "down" => {
                if self.selected + 1 < self.textures.len() {
                    self.select(self.selected + 1, cx);
                }
            }
            "home" => self.select(0, cx),
            "end" => {
                if !self.textures.is_empty() {
                    self.select(self.textures.len() - 1, cx);
                }
            }
            "enter" => self.open_selected(self.selected, cx),
            "f" => self.preview.update(cx, |preview, cx| preview.fit(cx)),
            _ => {}
        }
    }

    fn zoom(&mut self, zoom_in: bool, cx: &mut Context<Self>) {
        let factor = if zoom_in { 1.25 } else { 1. / 1.25 };
        self.preview
            .update(cx, |preview, cx| preview.step_zoom_public(factor, cx));
    }

    fn toolbar(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let zoom = self.preview.read(cx).zoom_label();
        let levels = self
            .selected_info()
            .map(|info| info.levels.len())
            .unwrap_or(0);
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
                ui::button("dictionary-fit", "Fit").on_click(cx.listener(|this, _, _, cx| {
                    this.preview.update(cx, |preview, cx| preview.fit(cx));
                })),
            )
            .child(
                ui::button("dictionary-zoom-out", "-")
                    .on_click(cx.listener(|this, _, _, cx| this.zoom(false, cx))),
            )
            .child(
                div()
                    .w(px(58.))
                    .text_center()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(zoom),
            )
            .child(
                ui::button("dictionary-zoom-in", "+")
                    .on_click(cx.listener(|this, _, _, cx| this.zoom(true, cx))),
            )
            .child(
                ui::button("dictionary-zoom-one", "100%").on_click(cx.listener(
                    |this, _, _, cx| {
                        this.preview.update(cx, |preview, cx| {
                            preview.set_zoom_public(1., cx);
                        });
                    },
                )),
            )
            .when(levels > 1, |el| {
                el.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_1()
                        .child(div().text_color(rgb(theme::TEXT_MUTED)).child("Mip"))
                        .children((0..levels as u32).map(|level| {
                            ui::button(("dictionary-mip", level as usize), format!("{level}"))
                                .on_click(
                                    cx.listener(move |this, _, _, cx| this.set_level(level, cx)),
                                )
                        })),
                )
            })
            .child(div().flex_1())
            .child(
                div()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(format!("{} texture(s)", self.textures.len())),
            )
    }

    fn render_row(&self, index: usize, cx: &Context<Self>) -> gpui::AnyElement {
        let Some(info) = self.textures.get(index) else {
            return div().into_any_element();
        };
        let selected = index == self.selected;
        let thumbnail = self.thumbnails.get(&(index as u32));
        let picture = match thumbnail.map(|thumbnail| &thumbnail.state) {
            Some(ThumbnailState::Ready(image)) => div()
                .flex_none()
                .size(px(48.))
                .rounded_sm()
                .bg(rgb(theme::VIEWPORT))
                .child(
                    img(image.clone())
                        .size_full()
                        .object_fit(ObjectFit::Contain),
                )
                .into_any_element(),
            Some(ThumbnailState::Loading) => {
                placeholder(px(48.), "…", theme::TEXT_MUTED).into_any_element()
            }
            Some(ThumbnailState::Failed) => {
                placeholder(px(48.), "!", theme::ERROR).into_any_element()
            }
            None => placeholder(px(48.), "", theme::TEXT_DISABLED).into_any_element(),
        };
        let format = format!("{} (id {})", info.format.name, info.format.id);
        div()
            .id(("texture-row", index))
            .flex()
            .items_center()
            .gap_2()
            .h(px(ROW_HEIGHT))
            .px_2()
            .rounded_sm()
            .border_1()
            .border_color(if selected {
                rgb(theme::SELECTION_BORDER)
            } else {
                rgb(theme::PANEL)
            })
            .when(selected, |el| el.bg(rgb(theme::SELECTION)))
            .when(!selected, |el| el.hover(|s| s.bg(rgb(theme::HOVER))))
            .child(picture)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .flex_1()
                    .min_w_0()
                    .gap_0p5()
                    .child(div().truncate().child(info.name()))
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(theme::TEXT_MUTED))
                            .truncate()
                            .child(format!("{}  ·  {}", info.dimensions(), format)),
                    )
                    .child(
                        div()
                            .text_xs()
                            .text_color(rgb(theme::TEXT_DISABLED))
                            .truncate()
                            .child(format!("key 0x{:016X}", info.key)),
                    ),
            )
            .when(info.status.reason().is_some(), |el| {
                el.child(
                    div()
                        .flex_none()
                        .text_xs()
                        .text_color(rgb(theme::ERROR))
                        .child("!"),
                )
            })
            .on_click(cx.listener(move |this, event: &ClickEvent, _, cx| {
                if event.click_count() >= 2 {
                    this.open_selected(index, cx);
                } else {
                    this.select(index, cx);
                }
            }))
            .into_any_element()
    }

    fn resizer(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let active = self.resizing;
        div()
            .id("texture-dictionary-divider")
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
                cx.listener(|this, _, _, cx| {
                    this.resizing = true;
                    cx.notify();
                }),
            )
    }

    fn resize_tracker(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let this = cx.entity();
        gpui::canvas(
            |_, _, _| {},
            move |_: gpui::Bounds<Pixels>, (), window, _| {
                let move_target = this.clone();
                window.on_mouse_event(move |event: &MouseMoveEvent, phase, window, cx| {
                    if phase == DispatchPhase::Bubble {
                        move_target.update(cx, |this, cx| {
                            if this.resizing {
                                let max = (f32::from(window.viewport_size().width) * 0.45)
                                    .clamp(MIN_LEFT, MAX_LEFT);
                                this.left_width = f32::from(event.position.x).clamp(MIN_LEFT, max);
                                cx.notify();
                            }
                        });
                    }
                });
                let up_target = this.clone();
                window.on_mouse_event(move |event: &MouseUpEvent, phase, _, cx| {
                    if phase == DispatchPhase::Bubble && event.button == MouseButton::Left {
                        up_target.update(cx, |this, cx| {
                            if this.resizing {
                                this.resizing = false;
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
}

impl Render for TextureDictionaryViewer {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let viewport = window.viewport_size();
        let viewport_width = f32::from(viewport.width);
        let max_left = (viewport_width * 0.45).clamp(MIN_LEFT, MAX_LEFT);
        self.left_width = self.left_width.clamp(MIN_LEFT, max_left);
        let preview_width = (viewport_width - self.left_width - DIVIDER_WIDTH - 24.).max(120.);
        let preview_height = (f32::from(viewport.height)
            - TOOLBAR_HEIGHT
            - STATUS_BAR_HEIGHT
            - METADATA_HEIGHT
            - HEADER_HEIGHT
            - 24.)
            .max(80.);
        self.preview.update(cx, |preview, _| {
            preview.set_available(preview_width, preview_height)
        });

        let empty = self.textures.is_empty();
        if !self.revealed && !empty {
            self.revealed = true;
            self.list_scroll
                .scroll_to_item(self.selected, ScrollStrategy::Center);
        }
        let count = self.textures.len();
        let rows = self.textures.len();
        let list = uniform_list(
            "texture-list",
            rows,
            cx.processor(move |this, range: Range<usize>, _, cx| {
                range
                    .map(|index| {
                        this.request_thumbnail(index, cx);
                        this.render_row(index, cx)
                    })
                    .collect::<Vec<_>>()
            }),
        )
        .track_scroll(&self.list_scroll)
        .flex_1()
        .px_1()
        .py_1();

        let left = div()
            .flex()
            .flex_col()
            .flex_none()
            .w(px(self.left_width))
            .h_full()
            .bg(rgb(theme::PANEL))
            .border_r_1()
            .border_color(rgb(theme::BORDER))
            .child(
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .justify_between()
                    .h(px(HEADER_HEIGHT))
                    .px_3()
                    .text_xs()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child("Textures")
                    .child(count.to_string()),
            )
            .when(empty, |el| {
                el.child(
                    div()
                        .flex()
                        .flex_1()
                        .items_center()
                        .justify_center()
                        .p_4()
                        .text_center()
                        .text_color(rgb(theme::TEXT_MUTED))
                        .child("This texture dictionary is empty."),
                )
            })
            .when(!empty, |el| el.child(list));

        let status = self
            .selected_info()
            .map(|info| format!("{}  ·  {} bytes", info.name(), info.encoded_len))
            .unwrap_or_default();
        let file = file_name(&self.path);

        div()
            .relative()
            .flex()
            .flex_col()
            .size_full()
            .bg(rgb(theme::BACKGROUND))
            .text_color(rgb(theme::TEXT))
            .font_family(theme::UI_FONT)
            .text_sm()
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(Self::key_down))
            .child(self.toolbar(cx))
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(left)
                    .child(self.resizer(cx))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .flex_1()
                            .min_w_0()
                            .min_h_0()
                            .child(div().flex_1().min_h_0().child(self.preview.clone()))
                            .child(metadata_panel(self.selected_info(), self.viewer_status())),
                    ),
            )
            .child(
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .justify_between()
                    .h(px(STATUS_BAR_HEIGHT))
                    .px_3()
                    .border_t_1()
                    .border_color(rgb(theme::BORDER))
                    .text_xs()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(status)
                    .child(file),
            )
            .child(self.resize_tracker(cx))
    }
}

fn placeholder(size: Pixels, text: &'static str, color: u32) -> gpui::Div {
    div()
        .flex()
        .flex_none()
        .items_center()
        .justify_center()
        .size(size)
        .rounded_sm()
        .border_1()
        .border_color(rgb(theme::BORDER))
        .bg(rgb(theme::VIEWPORT))
        .text_xs()
        .text_color(rgb(color))
        .child(text)
}
