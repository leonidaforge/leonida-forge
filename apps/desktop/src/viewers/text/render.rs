//! Drawing the text viewer: the rows on screen, the chrome and the menus.
//!
//! A row is drawn as one shaped text element whose runs carry the syntax
//! colours, the selection and the current match. Only the visible rows are
//! built, and only the visible columns of each row are shaped, so a line of any
//! length costs the viewport and not the line.

use gpui::{
    AnyElement, App, Context, DispatchPhase, Div, MouseButton, MouseDownEvent, MouseMoveEvent,
    MouseUpEvent, Pixels, SharedString, StyledText, TextRun, Window, anchored, canvas, deferred,
    div, font, prelude::*, px, rgb,
};
use lforge_text::document;
use lforge_text::syntax::Token;

use super::{
    CloseWindow, Copy, Drag, Escape, Find, FindNext, FindPrevious, GoToLine, KEY_CONTEXT, Menu,
    SearchState, SelectAll, State, TextViewer, ToggleWrap,
};
use crate::files;
use crate::ui;
use crate::ui::assets::Icon;
use crate::ui::theme;

pub(super) const ROW_HEIGHT: f32 = 19.;
const MENU_BAR_HEIGHT: f32 = 30.;
const TOOLBAR_HEIGHT: f32 = 38.;
const STATUS_HEIGHT: f32 = 24.;
const GUTTER_PADDING: f32 = 10.;
const TEXT_PADDING: f32 = 8.;
const SCROLLBAR_WIDTH: f32 = 12.;
const HORIZONTAL_BAR_HEIGHT: f32 = 12.;
const MIN_THUMB: f32 = 24.;
const MONO_SIZE: f32 = 13.;

/// The row height the scroll maths uses.
pub(super) fn row_height() -> Pixels {
    px(ROW_HEIGHT)
}

/// The top and height of the scrolling row area, in window coordinates.
/// `horizontal` says whether the horizontal scrollbar is shown below it.
pub(super) fn track(window: &Window, horizontal: bool) -> (f32, f32) {
    let height = f32::from(window.viewport_size().height)
        - MENU_BAR_HEIGHT
        - TOOLBAR_HEIGHT
        - STATUS_HEIGHT
        - if horizontal {
            HORIZONTAL_BAR_HEIGHT
        } else {
            0.
        };
    (MENU_BAR_HEIGHT + TOOLBAR_HEIGHT, height.max(0.))
}

/// Where the text of a row starts, in window coordinates.
pub(super) fn text_origin(this: &TextViewer, _window: &Window) -> (f32, f32) {
    (
        this.gutter + TEXT_PADDING,
        MENU_BAR_HEIGHT + TOOLBAR_HEIGHT + 2.,
    )
}

pub(super) fn thumb_height(this: &TextViewer, track_height: f32) -> f32 {
    let total = this.row_count();
    if total <= this.visible_rows || total == 0 {
        return track_height;
    }
    (track_height * (this.visible_rows as f64 / total as f64) as f32)
        .max(MIN_THUMB)
        .min(track_height)
}

pub(super) fn horizontal_track(window: &Window) -> (f32, f32) {
    let width = f32::from(window.viewport_size().width);
    (TEXT_PADDING, (width - 2. * TEXT_PADDING).max(1.))
}

pub(super) fn horizontal_thumb(this: &TextViewer, track_width: f32) -> f32 {
    let widest = this.open().map_or(0, |open| open.document.max_columns());
    if widest == 0 || widest <= this.columns {
        return track_width;
    }
    (track_width * (this.columns as f64 / widest as f64) as f32)
        .max(MIN_THUMB)
        .min(track_width)
}

fn mono() -> Div {
    div()
        .font_family(theme::MONO_FONT)
        .text_size(px(MONO_SIZE))
        .line_height(px(ROW_HEIGHT))
}

fn muted(text: impl Into<SharedString>) -> Div {
    div().text_color(rgb(theme::TEXT_MUTED)).child(text.into())
}

fn separator() -> Div {
    div()
        .flex_none()
        .w(px(1.))
        .h(px(14.))
        .bg(rgb(theme::BORDER))
}

/// The advance width of one monospace character.
fn advance(window: &Window) -> f32 {
    let sample = "MMMMMMMMMM";
    let run = TextRun {
        len: sample.len(),
        font: font(theme::MONO_FONT),
        color: rgb(theme::TEXT).into(),
        background_color: None,
        underline: None,
        strikethrough: None,
    };
    let width = window
        .text_system()
        .layout_line(sample, px(MONO_SIZE), &[run], None)
        .width;
    (f32::from(width) / sample.len() as f32).max(1.)
}

fn gutter_width(this: &TextViewer) -> f32 {
    let lines = this
        .open()
        .map_or(1, |open| open.document.line_count())
        .max(1);
    let digits = lines.ilog10() as usize + 1;
    this.advance * digits as f32 + GUTTER_PADDING
}

fn token_color(token: Token) -> u32 {
    match token {
        Token::Tag => theme::CODE_TAG,
        Token::Attribute => theme::CODE_ATTRIBUTE,
        Token::String => theme::CODE_STRING,
        Token::Comment => theme::CODE_COMMENT,
        Token::Number => theme::CODE_NUMBER,
        Token::Keyword => theme::CODE_KEYWORD,
        Token::Literal => theme::CODE_LITERAL,
        Token::Punctuation => theme::CODE_PUNCTUATION,
    }
}

/// The colours a column can be drawn in, in priority order. Later entries
/// override earlier ones.
#[derive(Clone, Copy, PartialEq)]
enum Style {
    Plain,
    Token(Token),
    Selection,
    Match,
    CurrentMatch,
    Cursor,
}

fn run(length: usize, color: u32, background: Option<u32>) -> TextRun {
    TextRun {
        len: length,
        font: font(theme::MONO_FONT),
        color: rgb(color).into(),
        background_color: background.map(|color| rgb(color).into()),
        underline: None,
        strikethrough: None,
    }
}

impl Render for TextViewer {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let advance = advance(window);
        self.advance = advance;
        let (_, track_height) = track(window, !self.wrap);
        self.visible_rows = ((track_height - 4.) / ROW_HEIGHT).floor().max(1.) as u64;
        let gutter = gutter_width(self);
        self.gutter = gutter;
        let width =
            f32::from(window.viewport_size().width) - SCROLLBAR_WIDTH - gutter - TEXT_PADDING;
        let columns = ((width / advance).floor() as u32).max(1);
        if columns != self.columns {
            self.columns = columns;
            if self.wrap {
                self.rebuild_wrap(cx);
            }
        }
        self.top_row = self.top_row.min(self.max_top_row());
        self.request_page(cx);

        div()
            .key_context(KEY_CONTEXT)
            .on_action(cx.listener(|this, _: &Find, window, cx| this.focus_find(window, cx)))
            .on_action(cx.listener(|this, _: &FindNext, _, cx| this.step_match(false, cx)))
            .on_action(cx.listener(|this, _: &FindPrevious, _, cx| this.step_match(true, cx)))
            .on_action(cx.listener(|this, _: &GoToLine, window, cx| this.focus_goto(window, cx)))
            .on_action(cx.listener(|this, _: &Copy, _, cx| this.copy(cx)))
            .on_action(cx.listener(|this, _: &SelectAll, _, cx| this.select_all(cx)))
            .on_action(cx.listener(|this, _: &ToggleWrap, _, cx| this.toggle_wrap(cx)))
            .on_action(cx.listener(|this, _: &Escape, window, cx| this.escape(window, cx)))
            .on_action(cx.listener(|_, _: &CloseWindow, window, _| window.remove_window()))
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
            .child(div().flex().flex_1().min_h_0().child(self.render_content(
                advance,
                track_height,
                cx,
            )))
            .when(!self.wrap, |el| {
                el.child(self.render_horizontal_bar(window, cx))
            })
            .child(self.render_status_bar(cx))
            .child(self.render_drag_tracker(cx))
            .when(self.open_menu.is_some(), |el| {
                el.child(self.render_menu_overlay(cx))
            })
    }
}

impl TextViewer {
    fn render_menu_bar(&self, cx: &Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_none()
            .items_center()
            .gap_0p5()
            .h(px(MENU_BAR_HEIGHT))
            .px_1p5()
            .child(self.render_menu_title(Menu::File, "File", cx))
            .child(self.render_menu_title(Menu::View, "View", cx))
            .child(self.render_menu_title(Menu::Search, "Search", cx))
            .child(div().flex_1())
            .child(div().text_color(rgb(theme::TEXT_MUTED)).child(self.title()))
    }

    /// The canonical resource path of the payload, exactly as the Explorer and
    /// the file views show it, or the file name of a standalone file.
    fn title(&self) -> String {
        match &self.resource {
            Some(resource) => resource.display(),
            None => self.file_name.clone(),
        }
    }

    fn render_menu_title(
        &self,
        menu: Menu,
        label: &'static str,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let open = self.open_menu == Some(menu);
        div()
            .id(label)
            .relative()
            .flex()
            .items_center()
            .h(px(24.))
            .px_2p5()
            .rounded_sm()
            .when(open, |el| el.bg(rgb(theme::HOVER)))
            .hover(|s| s.bg(rgb(theme::HOVER)))
            .child(label)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, _, _, cx| {
                    this.open_menu = if this.open_menu == Some(menu) {
                        None
                    } else {
                        Some(menu)
                    };
                    cx.notify();
                }),
            )
            .on_hover(cx.listener(move |this, hovered: &bool, _, cx| {
                if *hovered && this.open_menu.is_some_and(|open| open != menu) {
                    this.open_menu = Some(menu);
                    cx.notify();
                }
            }))
            .when(open, |el| {
                el.child(
                    div().absolute().top_full().left_0().child(
                        deferred(
                            anchored()
                                .snap_to_window_with_margin(px(4.))
                                .child(self.render_menu_items(menu, cx)),
                        )
                        .priority(2),
                    ),
                )
            })
    }

    fn render_menu_overlay(&self, cx: &Context<Self>) -> impl IntoElement {
        deferred(
            div()
                .id("text-menu-overlay")
                .absolute()
                .top(px(MENU_BAR_HEIGHT))
                .left_0()
                .right_0()
                .bottom_0()
                .occlude()
                .on_any_mouse_down(cx.listener(|this, _, _, cx| {
                    this.open_menu = None;
                    cx.notify();
                })),
        )
        .priority(1)
    }

    fn menu_action(
        &self,
        action: impl Fn(&mut Self, &mut Window, &mut Context<Self>) + 'static,
        cx: &Context<Self>,
    ) -> impl Fn(&gpui::ClickEvent, &mut Window, &mut App) + 'static {
        cx.listener(move |this, _, window, cx| {
            this.open_menu = None;
            action(this, window, cx);
            cx.notify();
        })
    }

    fn render_menu_items(&self, menu: Menu, cx: &Context<Self>) -> impl IntoElement {
        let ready = self.open().is_some();
        let has_selection = self.selection().is_some();
        let item = |id: &'static str,
                    label: &'static str,
                    checked: bool,
                    enabled: bool,
                    shortcut: Option<&'static str>,
                    action: fn(&mut Self, &mut Window, &mut Context<Self>)| {
            ui::menu_item(id, label, checked, enabled, shortcut)
                .when(enabled, |el| el.on_click(self.menu_action(action, cx)))
        };
        let panel = ui::menu_panel().occlude();
        match menu {
            Menu::File => panel
                .child(item(
                    "copy",
                    "Copy Selection",
                    false,
                    has_selection,
                    Some("Ctrl+C"),
                    |this, _, cx| this.copy(cx),
                ))
                .child(item(
                    "select-all",
                    "Select All",
                    false,
                    ready,
                    Some("Ctrl+A"),
                    |this, _, cx| this.select_all(cx),
                ))
                .child(ui::menu_separator())
                .child(
                    ui::menu_item(
                        "open-inspector",
                        "Open in Binary Inspector",
                        false,
                        true,
                        None,
                    )
                    .on_click(self.menu_action(
                        |this, _, cx| {
                            crate::explorer::open_binary_inspector(
                                this.path.clone(),
                                this.access.clone(),
                                cx,
                            )
                        },
                        cx,
                    )),
                )
                .child(ui::menu_separator())
                .child(item(
                    "close",
                    "Close",
                    false,
                    true,
                    Some("Ctrl+W"),
                    |_, window, _| window.remove_window(),
                )),
            Menu::View => {
                let panel = panel.child(item(
                    "word-wrap",
                    "Word Wrap",
                    self.wrap,
                    true,
                    Some("Alt+Z"),
                    |this, _, cx| this.toggle_wrap(cx),
                ));
                let panel = panel.child(ui::menu_separator());
                let encoding = self.encoding;
                let mut panel = panel;
                for choice in lforge_text::Encoding::ALL {
                    let label = choice.label(false);
                    panel = panel.child(
                        ui::menu_item(label, label, encoding == choice, ready, None).when(
                            ready,
                            |el| {
                                el.on_click(self.menu_action(
                                    move |this, _, cx| this.set_encoding(choice, cx),
                                    cx,
                                ))
                            },
                        ),
                    );
                }
                panel
            }
            Menu::Search => panel
                .child(item(
                    "find",
                    "Find…",
                    false,
                    ready,
                    Some("Ctrl+F"),
                    |this, window, cx| this.focus_find(window, cx),
                ))
                .child(item(
                    "find-next",
                    "Find Next",
                    false,
                    ready,
                    Some("F3"),
                    |this, _, cx| this.step_match(false, cx),
                ))
                .child(item(
                    "find-previous",
                    "Find Previous",
                    false,
                    ready,
                    Some("Shift+F3"),
                    |this, _, cx| this.step_match(true, cx),
                ))
                .child(ui::menu_separator())
                .child(item(
                    "go-to-line",
                    "Go to Line…",
                    false,
                    ready,
                    Some("Ctrl+G"),
                    |this, window, cx| this.focus_goto(window, cx),
                )),
        }
    }

    fn render_toolbar(&self, cx: &Context<Self>) -> impl IntoElement {
        let searching = matches!(self.search, SearchState::Running { .. });
        let ready = self.open().is_some();
        div()
            .flex()
            .flex_none()
            .items_center()
            .gap_2()
            .h(px(TOOLBAR_HEIGHT))
            .px_2()
            .border_t_1()
            .border_b_1()
            .border_color(rgb(theme::BORDER))
            .child(muted("Find"))
            .child(div().w(px(220.)).child(self.find_field.clone()))
            .child(
                ui::button("match-case", "Aa")
                    .when(self.match_case, |el| {
                        el.bg(rgb(theme::SELECTION))
                            .border_color(rgb(theme::SELECTION_BORDER))
                    })
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.match_case = !this.match_case;
                        if matches!(this.search, SearchState::Done { .. }) {
                            this.start_search(cx);
                        }
                        cx.notify();
                    })),
            )
            .child(
                ui::icon_button("find-previous", Icon::ArrowUp, ready, false).when(ready, |el| {
                    el.on_click(cx.listener(|this, _, _, cx| this.step_match(true, cx)))
                }),
            )
            .child(
                ui::icon_button("find-next", Icon::ArrowDown, ready, false).when(ready, |el| {
                    el.on_click(cx.listener(|this, _, _, cx| this.step_match(false, cx)))
                }),
            )
            .when(searching, |el| el.child(muted("Searching…")))
            .child(div().flex_1())
            .child(muted("Go to"))
            .child(div().w(px(90.)).child(self.goto_field.clone()))
            .child(ui::button("go-to-line", "Go").when(ready, |el| {
                el.on_click(cx.listener(|this, _, window, cx| this.focus_goto(window, cx)))
            }))
            .child(separator())
            .child(
                ui::button("word-wrap", "Wrap")
                    .when(self.wrap, |el| {
                        el.bg(rgb(theme::SELECTION))
                            .border_color(rgb(theme::SELECTION_BORDER))
                    })
                    .on_click(cx.listener(|this, _, _, cx| this.toggle_wrap(cx))),
            )
    }

    fn render_content(&self, advance: f32, track_height: f32, cx: &Context<Self>) -> AnyElement {
        match &self.state {
            State::Loading => {
                let detail = self.load.as_ref().map(|load| {
                    let read = load
                        .progress
                        .read
                        .load(std::sync::atomic::Ordering::Relaxed);
                    let total = load
                        .progress
                        .total
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if total == 0 {
                        "Reading the payload…".to_string()
                    } else {
                        format!(
                            "Indexing lines: {} of {}",
                            files::format_size(read),
                            files::format_size(total)
                        )
                    }
                });
                ui::centered_message("Opening…", detail)
            }
            State::Failed(err) => {
                ui::centered_message("This file cannot be opened as text.", Some(err.clone()))
            }
            State::Ready(open) if open.document.line_count() == 0 => {
                ui::centered_message("This file is empty.", None)
            }
            State::Ready(_) => div()
                .flex()
                .flex_1()
                .min_w_0()
                .min_h_0()
                .child(self.render_body(advance, cx))
                .child(self.render_scrollbar(track_height, cx))
                .into_any_element(),
        }
    }

    fn render_body(&self, advance: f32, cx: &Context<Self>) -> impl IntoElement {
        div()
            .id("text-body")
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(Self::key_down))
            .on_scroll(cx.listener(Self::scroll))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, event: &MouseDownEvent, window, cx| {
                    this.focus_handle.focus(window, cx);
                    let position = this.caret_at(event.position, window);
                    this.press(position, event.modifiers.shift, cx);
                }),
            )
            .on_mouse_move(cx.listener(|this, event: &MouseMoveEvent, window, cx| {
                if this.drag == Some(Drag::Selection)
                    && event.pressed_button == Some(MouseButton::Left)
                {
                    let position = this.caret_at(event.position, window);
                    this.set_cursor(position, true, cx);
                }
            }))
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .min_h_0()
            .overflow_hidden()
            .bg(rgb(theme::PANEL))
            .child(self.render_rows(advance, cx))
    }

    fn render_rows(&self, advance: f32, cx: &Context<Self>) -> impl IntoElement {
        let count = self.row_count();
        let first = self.top_row;
        let last = (first + self.visible_rows).min(count);
        mono()
            .flex()
            .flex_col()
            .flex_none()
            .py(px(2.))
            .children((first..last).map(|row| self.render_row(row, advance, cx)))
    }

    fn render_row(&self, row: u64, advance: f32, _cx: &Context<Self>) -> AnyElement {
        let (line, segment) = self.line_of_row(row);
        let gutter = self.gutter;
        let number = if segment == 0 || !self.wrap {
            format!("{}", line + 1)
        } else {
            String::new()
        };
        let gutter_element = div()
            .flex_none()
            .w(px(gutter))
            .pr(px(GUTTER_PADDING))
            .text_right()
            .text_color(rgb(theme::TEXT_MUTED))
            .child(number);

        let Some(page_line) = self.page.as_ref().and_then(|page| page.get(line)) else {
            return div()
                .flex()
                .flex_none()
                .items_center()
                .h(px(ROW_HEIGHT))
                .child(gutter_element)
                .into_any_element();
        };
        let start_col = if self.wrap {
            u32::try_from(segment).unwrap_or(u32::MAX) * self.columns.max(1)
        } else {
            self.scroll_x
        };
        let width = self.columns.max(1);

        let selection = self.selection().and_then(|(from, to)| {
            (line >= from.line && line <= to.line).then_some((
                if line == from.line { from.col } else { 0 },
                if line == to.line {
                    to.col
                } else {
                    page_line.columns
                },
            ))
        });
        let matches = self.line_matches(line);
        let current = self
            .current_match()
            .filter(|found| found.line as usize == line);
        let cursor = (self.cursor.line == line).then_some(self.cursor.col);

        let (text, runs, actual) = styled_line(
            page_line, start_col, width, selection, &matches, current, cursor,
        );
        let shown = document::display_columns(&text);
        let caret = cursor
            .filter(|column| *column >= actual + shown)
            .filter(|column| *column <= start_col + width)
            .map(|column| {
                let offset = column.saturating_sub(actual);
                div()
                    .absolute()
                    .left(px(offset as f32 * advance))
                    .top(px(2.))
                    .w(px(1.5))
                    .h(px(ROW_HEIGHT - 4.))
                    .bg(rgb(theme::SELECTION_BORDER))
            });
        div()
            .id(("row", row as usize))
            .flex()
            .flex_none()
            .items_center()
            .h(px(ROW_HEIGHT))
            .child(gutter_element)
            .child(
                div()
                    .relative()
                    .flex()
                    .flex_1()
                    .min_w_0()
                    .h_full()
                    .items_center()
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .children(caret)
                    .child(StyledText::new(text).with_runs(runs)),
            )
            .into_any_element()
    }

    fn render_scrollbar(&self, track_height: f32, cx: &Context<Self>) -> impl IntoElement {
        let thumb = thumb_height(self, track_height);
        let max_top = self.max_top_row();
        let thumb_top = if max_top == 0 {
            0.
        } else {
            (self.top_row as f64 / max_top as f64) as f32 * (track_height - thumb)
        };
        let scrollable = max_top > 0;
        let active = matches!(self.drag, Some(Drag::Scrollbar(_)));
        div()
            .id("text-scrollbar")
            .relative()
            .flex_none()
            .w(px(SCROLLBAR_WIDTH))
            .h_full()
            .border_l_1()
            .border_color(rgb(theme::BORDER))
            .when(scrollable, |el| {
                el.child(
                    div()
                        .absolute()
                        .top(px(thumb_top))
                        .left(px(2.))
                        .w(px(SCROLLBAR_WIDTH - 5.))
                        .h(px(thumb))
                        .rounded_sm()
                        .bg(rgb(if active { theme::ACCENT } else { theme::HOVER }))
                        .hover(|s| s.bg(rgb(theme::TEXT_DISABLED))),
                )
                .on_mouse_down(
                    MouseButton::Left,
                    cx.listener(move |this, event: &MouseDownEvent, window, cx| {
                        let (track_top, _) = track(window, !this.wrap);
                        let y = f32::from(event.position.y) - track_top;
                        let grab = if (thumb_top..thumb_top + thumb).contains(&y) {
                            y - thumb_top
                        } else {
                            thumb / 2.
                        };
                        this.drag = Some(Drag::Scrollbar(grab));
                        this.drag_to(event.position, window, cx);
                        cx.stop_propagation();
                    }),
                )
            })
    }

    fn render_horizontal_bar(&self, window: &Window, cx: &Context<Self>) -> impl IntoElement {
        let (track_left, track_width) = horizontal_track(window);
        let thumb = horizontal_thumb(self, track_width);
        let max_x = self.max_scroll_x();
        let thumb_left = if max_x == 0 {
            0.
        } else {
            (self.scroll_x as f64 / max_x as f64) as f32 * (track_width - thumb)
        };
        let scrollable = max_x > 0;
        let active = matches!(self.drag, Some(Drag::Horizontal(_)));
        div()
            .id("text-horizontal-bar")
            .flex_none()
            .h(px(HORIZONTAL_BAR_HEIGHT))
            .w_full()
            .border_t_1()
            .border_color(rgb(theme::BORDER))
            .bg(rgb(theme::PANEL))
            .when(scrollable, |el| {
                el.child(
                    div()
                        .relative()
                        .ml(px(track_left))
                        .w(px(track_width))
                        .h_full()
                        .child(
                            div()
                                .absolute()
                                .top(px(3.))
                                .left(px(thumb_left))
                                .h(px(HORIZONTAL_BAR_HEIGHT - 6.))
                                .w(px(thumb))
                                .rounded_sm()
                                .bg(rgb(if active { theme::ACCENT } else { theme::HOVER }))
                                .hover(|s| s.bg(rgb(theme::TEXT_DISABLED))),
                        )
                        .on_mouse_down(
                            MouseButton::Left,
                            cx.listener(move |this, event: &MouseDownEvent, window, cx| {
                                let (track_left, _) = horizontal_track(window);
                                let x = f32::from(event.position.x) - track_left;
                                let grab = if (thumb_left..thumb_left + thumb).contains(&x) {
                                    x - thumb_left
                                } else {
                                    thumb / 2.
                                };
                                this.drag = Some(Drag::Horizontal(grab));
                                this.drag_to(event.position, window, cx);
                                cx.stop_propagation();
                            }),
                        ),
                )
            })
    }

    fn render_status_bar(&self, cx: &Context<Self>) -> impl IntoElement {
        let (encoding, language, lines, size, malformed) = match &self.state {
            State::Ready(open) => (
                self.encoding.label(self.bom).to_string(),
                open.language.name(),
                open.document.line_count(),
                files::format_size(open.document.len()),
                open.document.malformed(),
            ),
            _ => (
                self.encoding.label(false).to_string(),
                "—",
                0,
                "—".to_string(),
                0,
            ),
        };
        let position = format!("Ln {}, Col {}", self.cursor.line + 1, self.cursor.col + 1);
        let notice = self.notice.as_ref().map(|notice| {
            div()
                .flex_1()
                .min_w_0()
                .truncate()
                .text_color(rgb(if notice.error {
                    theme::ERROR
                } else {
                    theme::TEXT_MUTED
                }))
                .child(notice.text.clone())
        });
        div()
            .id("text-status")
            .flex()
            .flex_none()
            .items_center()
            .gap_2()
            .h(px(STATUS_HEIGHT))
            .px_2()
            .border_t_1()
            .border_color(rgb(theme::BORDER))
            .text_color(rgb(theme::TEXT_MUTED))
            .child(format!("{encoding}  ·  {language}"))
            .child(separator())
            .child(position)
            .child(separator())
            .child(files::count(lines, "line", "lines"))
            .child(separator())
            .child(size)
            .when(malformed > 0, |el| {
                el.child(separator()).child(
                    div()
                        .text_color(rgb(theme::ERROR))
                        .child(format!("{malformed} undecodable")),
                )
            })
            .when_some(notice, |el, notice| el.child(notice))
            .when(self.notice.is_none(), |el| {
                el.child(div().flex_1()).child(
                    div()
                        .text_color(rgb(theme::TEXT_DISABLED))
                        .child("Read-only"),
                )
            })
            .when(self.notice.is_some(), |el| {
                el.child(div().flex_none()).child(
                    div()
                        .text_color(rgb(theme::TEXT_DISABLED))
                        .child("Read-only"),
                )
            })
            .on_click(cx.listener(|this, _, _, cx| {
                this.notice = None;
                cx.notify();
            }))
    }

    /// Window-level listeners keep a drag going when the pointer leaves the row
    /// or scrollbar that started it.
    fn render_drag_tracker(&self, cx: &Context<Self>) -> impl IntoElement {
        let this = cx.entity();
        canvas(
            |_, _, _| {},
            move |_: gpui::Bounds<Pixels>, (), window, _| {
                let move_target = this.clone();
                window.on_mouse_event(move |event: &MouseMoveEvent, phase, window, cx| {
                    if phase == DispatchPhase::Bubble {
                        move_target.update(cx, |this, cx| {
                            if this.drag.is_some() {
                                this.drag_to(event.position, window, cx);
                            }
                        });
                    }
                });
                window.on_mouse_event(move |event: &MouseUpEvent, phase, _, cx| {
                    if phase == DispatchPhase::Bubble && event.button == MouseButton::Left {
                        this.update(cx, |this, cx| {
                            if this.drag.take().is_some() {
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

/// One row's text and the runs that colour it.
///
/// Only the columns `start..start + width` are shaped. Syntax colours, the
/// selection, the matches and the caret are painted per column into one style
/// buffer, so the run list is as long as the colour changes and not as long as
/// the line. The third value is the column the slice really starts on, which
/// differs from `start` when `start` falls inside a wide character.
pub(super) fn styled_line(
    line: &super::PageLine,
    start: u32,
    width: u32,
    selection: Option<(u32, u32)>,
    matches: &[lforge_text::Match],
    current: Option<lforge_text::Match>,
    cursor: Option<u32>,
) -> (SharedString, Vec<TextRun>, u32) {
    let (slice, actual) = document::slice_columns(&line.text, start, width);
    let end = actual.saturating_add(document::display_columns(&slice));
    if slice.is_empty() {
        return (SharedString::from(""), Vec::new(), actual);
    }
    let length = (end - actual) as usize;
    let mut styles = vec![Style::Plain; length];
    let last = length.saturating_sub(1);
    let index = |column: u32| (column.saturating_sub(actual) as usize).min(last);
    for span in &line.spans {
        let from = span.start.max(actual);
        let to = span.end.min(end);
        if from >= to {
            continue;
        }
        for style in &mut styles[index(from)..index(to)] {
            *style = Style::Token(span.token);
        }
    }
    if let Some((from, to)) = selection {
        let from = from.max(actual).min(end);
        let to = to.max(actual).min(end);
        if from < to {
            for style in &mut styles[index(from)..index(to)] {
                *style = Style::Selection;
            }
        }
    }
    for found in matches {
        let from = found.start.max(actual).min(end);
        let to = found.end().max(actual).min(end);
        if from < to {
            for style in &mut styles[index(from)..index(to)] {
                *style = Style::Match;
            }
        }
    }
    if let Some(found) = current {
        let from = found.start.max(actual).min(end);
        let to = found.end().max(actual).min(end);
        if from < to {
            for style in &mut styles[index(from)..index(to)] {
                *style = Style::CurrentMatch;
            }
        }
    }
    if let Some(column) = cursor
        && (actual..end).contains(&column)
    {
        styles[index(column)] = Style::Cursor;
    }

    let mut text = String::with_capacity(slice.len());
    let mut runs = Vec::new();
    let mut column = actual;
    let mut current_style = styles[0];
    let mut bytes = 0;
    for c in slice.chars() {
        // A zero-width character is drawn over the cell before it.
        let cell = if document::column_width(c, column) == 0 {
            column.saturating_sub(1).max(actual)
        } else {
            column
        };
        let style = styles[index(cell)];
        if style != current_style {
            runs.push(run(
                bytes,
                style_color(current_style),
                style_background(current_style),
            ));
            bytes = 0;
            current_style = style;
        }
        text.push(c);
        bytes += c.len_utf8();
        column += document::column_width(c, column);
    }
    runs.push(run(
        bytes,
        style_color(current_style),
        style_background(current_style),
    ));
    runs.retain(|run| run.len > 0);
    (text.into(), runs, actual)
}

fn style_color(style: Style) -> u32 {
    match style {
        Style::Plain => theme::TEXT,
        Style::Token(token) => token_color(token),
        Style::Selection | Style::Match | Style::CurrentMatch => theme::TEXT,
        Style::Cursor => theme::TEXT,
    }
}

fn style_background(style: Style) -> Option<u32> {
    match style {
        Style::Plain | Style::Token(_) => None,
        Style::Selection | Style::Cursor => Some(theme::SELECTION),
        Style::Match => Some(theme::SEARCH_MATCH),
        Style::CurrentMatch => Some(theme::SELECTION_BORDER),
    }
}
