use std::ops::Range;
use std::rc::Rc;

use gpui::{
    AnyElement, App, Bounds, ClickEvent, Context, DispatchPhase, Div, Entity, FontWeight,
    MouseButton, MouseDownEvent, MouseMoveEvent, MouseUpEvent, Pixels, SharedString, Stateful,
    Window, anchored, canvas, deferred, div, prelude::*, px, rgb,
};
use lforge_binary::{Endian, Utf8Preview};

use super::{
    BinaryInspector, CloseWindow, CopyHex, Drag, Escape, Find, FindNext, FindPrevious, GoToOffset,
    Hash, KEY_CONTEXT, Menu, SearchMode, State,
};
use crate::files;
use crate::ui;
use crate::ui::assets::Icon;
use crate::ui::theme;

pub(super) const ROW_HEIGHT: f32 = 20.;
pub(super) const DEFAULT_PANEL_WIDTH: f32 = 320.;
const MENU_BAR_HEIGHT: f32 = 30.;
const TOOLBAR_HEIGHT: f32 = 40.;
const HEADER_HEIGHT: f32 = 26.;
const STATUS_BAR_HEIGHT: f32 = 26.;
const ROWS_PADDING: f32 = 4.;
const SCROLLBAR_WIDTH: f32 = 12.;
const MIN_THUMB_HEIGHT: f32 = 24.;
const DIVIDER_WIDTH: f32 = 5.;
const MIN_PANEL_WIDTH: f32 = 240.;
const MAX_PANEL_WIDTH: f32 = 560.;
const MIN_HEX_WIDTH: f32 = 360.;
const HEX_CELL_WIDTH: f32 = 22.;
const ASCII_CELL_WIDTH: f32 = 8.;
/// Extra space after every eight bytes.
const GROUP_GAP: f32 = 8.;
const MONO_SIZE: f32 = 13.;
const ZERO_BYTE_COLOR: u32 = 0x6a6a7a;
const LABEL_WIDTH: f32 = 76.;

/// The top and height of the scrollbar track, in window coordinates.
pub(super) fn scrollbar_track(window: &Window) -> (f32, f32) {
    let height = f32::from(window.viewport_size().height)
        - MENU_BAR_HEIGHT
        - TOOLBAR_HEIGHT
        - HEADER_HEIGHT
        - STATUS_BAR_HEIGHT;
    (
        MENU_BAR_HEIGHT + TOOLBAR_HEIGHT + HEADER_HEIGHT,
        height.max(0.),
    )
}

pub(super) fn thumb_height(this: &BinaryInspector, track_height: f32) -> f32 {
    let total = this.total_rows();
    if total <= this.visible_rows {
        return track_height;
    }
    (track_height * (this.visible_rows as f64 / total as f64) as f32)
        .max(MIN_THUMB_HEIGHT)
        .min(track_height)
}

pub(super) fn clamp_panel_width(width: f32, window_width: f32) -> f32 {
    width
        .min(window_width - MIN_HEX_WIDTH - DIVIDER_WIDTH)
        .clamp(MIN_PANEL_WIDTH, MAX_PANEL_WIDTH)
}

fn mono() -> Div {
    div().font_family(theme::MONO_FONT).text_size(px(MONO_SIZE))
}

fn muted(text: impl Into<SharedString>) -> Div {
    div().text_color(rgb(theme::TEXT_MUTED)).child(text.into())
}

fn separator() -> Div {
    div()
        .flex_none()
        .w(px(1.))
        .h(px(12.))
        .bg(rgb(theme::BORDER))
}

fn plural(count: u64, unit: &str) -> String {
    if count == 1 {
        format!("1 {unit}")
    } else {
        format!("{count} {unit}s")
    }
}

impl Render for BinaryInspector {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let (_, track_height) = scrollbar_track(window);
        self.visible_rows = (((track_height - 2. * ROWS_PADDING) / ROW_HEIGHT) as u64).max(1);
        self.top_row = self.top_row.min(self.max_top_row());
        self.request_data(cx);

        let viewport_width = f32::from(window.viewport_size().width);
        let panel_width = clamp_panel_width(self.panel_width, viewport_width);

        div()
            .key_context(KEY_CONTEXT)
            .on_action(
                cx.listener(|this, _: &GoToOffset, window, cx| this.focus_offset_field(window, cx)),
            )
            .on_action(
                cx.listener(|this, _: &Find, window, cx| this.focus_search_field(window, cx)),
            )
            .on_action(cx.listener(|this, _: &FindNext, _, cx| this.find(false, cx)))
            .on_action(cx.listener(|this, _: &FindPrevious, _, cx| this.find(true, cx)))
            .on_action(cx.listener(|this, _: &CopyHex, _, cx| this.copy(false, cx)))
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
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(self.render_hex_area(track_height, cx))
                    .when(self.panel_visible, |el| {
                        el.child(self.render_divider(cx))
                            .child(self.render_panel(panel_width, cx))
                    }),
            )
            .child(self.render_status_bar())
            .child(self.render_drag_tracker(cx))
            .when(self.open_menu.is_some(), |el| {
                el.child(self.render_menu_overlay(cx))
            })
    }
}

impl BinaryInspector {
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

    /// Catches clicks outside an open menu below the menu bar.
    fn render_menu_overlay(&self, cx: &Context<Self>) -> impl IntoElement {
        deferred(
            div()
                .id("menu-overlay")
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

    /// A click handler for a menu entry that closes the menu first.
    fn menu_action(
        &self,
        action: impl Fn(&mut Self, &mut Window, &mut Context<Self>) + 'static,
        cx: &Context<Self>,
    ) -> impl Fn(&ClickEvent, &mut Window, &mut App) + 'static {
        cx.listener(move |this, _, window, cx| {
            this.open_menu = None;
            action(this, window, cx);
            cx.notify();
        })
    }

    fn render_menu_items(&self, menu: Menu, cx: &Context<Self>) -> impl IntoElement {
        let ready = self.file().is_some();
        let has_bytes = self.len() > 0;
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
                    "copy-hex",
                    "Copy as Hex",
                    false,
                    has_bytes,
                    Some("Ctrl+C"),
                    |this, _, cx| this.copy(false, cx),
                ))
                .child(item(
                    "copy-text",
                    "Copy as Text",
                    false,
                    has_bytes,
                    None,
                    |this, _, cx| this.copy(true, cx),
                ))
                .child(ui::menu_separator())
                .child(item(
                    "compute-sha256",
                    "Compute SHA-256",
                    false,
                    ready && !matches!(self.hash, Hash::Running { .. }),
                    None,
                    |this, _, cx| this.compute_hash(cx),
                ))
                .child(ui::menu_separator())
                .child(item(
                    "close",
                    "Close",
                    false,
                    true,
                    Some("Ctrl+W"),
                    |_, window, _| window.remove_window(),
                )),
            Menu::View => panel
                .child(item(
                    "row-8",
                    "8 Bytes per Row",
                    self.bytes_per_row == 8,
                    true,
                    None,
                    |this, _, cx| this.set_bytes_per_row(8, cx),
                ))
                .child(item(
                    "row-16",
                    "16 Bytes per Row",
                    self.bytes_per_row == 16,
                    true,
                    None,
                    |this, _, cx| this.set_bytes_per_row(16, cx),
                ))
                .child(item(
                    "row-32",
                    "32 Bytes per Row",
                    self.bytes_per_row == 32,
                    true,
                    None,
                    |this, _, cx| this.set_bytes_per_row(32, cx),
                ))
                .child(ui::menu_separator())
                .child(item(
                    "little-endian",
                    "Little-Endian",
                    self.endian == Endian::Little,
                    true,
                    None,
                    |this, _, cx| this.set_endian(Endian::Little, cx),
                ))
                .child(item(
                    "big-endian",
                    "Big-Endian",
                    self.endian == Endian::Big,
                    true,
                    None,
                    |this, _, cx| this.set_endian(Endian::Big, cx),
                ))
                .child(ui::menu_separator())
                .child(item(
                    "data-inspector",
                    "Data Inspector",
                    self.panel_visible,
                    true,
                    None,
                    |this, _, _| this.panel_visible = !this.panel_visible,
                )),
            Menu::Search => panel
                .child(item(
                    "find",
                    "Find…",
                    false,
                    ready,
                    Some("Ctrl+F"),
                    |this, window, cx| this.focus_search_field(window, cx),
                ))
                .child(item(
                    "find-next",
                    "Find Next",
                    false,
                    ready,
                    Some("F3"),
                    |this, _, cx| this.find(false, cx),
                ))
                .child(item(
                    "find-previous",
                    "Find Previous",
                    false,
                    ready,
                    Some("Shift+F3"),
                    |this, _, cx| this.find(true, cx),
                ))
                .child(ui::menu_separator())
                .child(item(
                    "go-to-offset",
                    "Go to Offset…",
                    false,
                    has_bytes,
                    Some("Ctrl+G"),
                    |this, window, cx| this.focus_offset_field(window, cx),
                )),
        }
    }

    fn render_toolbar(&self, cx: &Context<Self>) -> impl IntoElement {
        let searching = self.search.is_some();
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
            .child(muted("Go to"))
            .child(div().w(px(150.)).child(self.offset_field.clone()))
            .child(div().w(px(6.)))
            .child(muted("Endian"))
            .child(segmented(
                "endian",
                [
                    ("Little", self.endian == Endian::Little),
                    ("Big", self.endian == Endian::Big),
                ],
                cx.listener(|this, ix: &usize, _, cx| {
                    let endian = if *ix == 0 {
                        Endian::Little
                    } else {
                        Endian::Big
                    };
                    this.set_endian(endian, cx)
                }),
            ))
            .child(div().flex_1())
            .child(segmented(
                "search-mode",
                [
                    ("Hex", self.search_mode == SearchMode::Hex),
                    ("Text", self.search_mode == SearchMode::Text),
                ],
                cx.listener(|this, ix: &usize, _, cx| {
                    let mode = if *ix == 0 {
                        SearchMode::Hex
                    } else {
                        SearchMode::Text
                    };
                    this.set_search_mode(mode, cx)
                }),
            ))
            .child(div().w(px(240.)).child(self.search_field.clone()))
            .child(
                ui::icon_button("find-previous", Icon::ArrowUp, true, false)
                    .on_click(cx.listener(|this, _, _, cx| this.find(true, cx))),
            )
            .child(
                ui::icon_button("find-next", Icon::ArrowDown, true, false)
                    .on_click(cx.listener(|this, _, _, cx| this.find(false, cx))),
            )
            .when(searching, |el| {
                el.child(muted("Searching…"))
                    .child(ui::button("cancel-search", "Cancel").on_click(cx.listener(
                        |this, _, _, cx| {
                            this.cancel_search();
                            this.notify_notice("Search cancelled", false);
                            cx.notify();
                        },
                    )))
            })
    }

    fn render_hex_area(&self, track_height: f32, cx: &Context<Self>) -> AnyElement {
        let content = match &self.state {
            State::Opening => return ui::centered_message("Opening…", None),
            State::Failed(err) => {
                return ui::centered_message("This file cannot be opened.", Some(err.clone()));
            }
            State::Ready(_) if self.len() == 0 => {
                return ui::centered_message("This file is empty.", None);
            }
            State::Ready(_) => self.render_rows(cx),
        };
        div()
            .id("hex-view")
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(Self::hex_key_down))
            .on_scroll(cx.listener(Self::scroll))
            .flex()
            .flex_col()
            .flex_1()
            .min_w_0()
            .bg(rgb(theme::PANEL))
            .child(self.render_column_header())
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .overflow_hidden()
                            .py(px(ROWS_PADDING))
                            .child(content),
                    )
                    .child(self.render_scrollbar(track_height, cx)),
            )
            .into_any_element()
    }

    fn offset_digits(&self) -> usize {
        if self.len() > u64::from(u32::MAX) + 1 {
            16
        } else {
            8
        }
    }

    fn offset_width(&self) -> f32 {
        self.offset_digits() as f32 * 7.5 + 24.
    }

    fn render_column_header(&self) -> impl IntoElement {
        let bpr = self.bytes_per_row;
        mono()
            .flex()
            .flex_none()
            .items_center()
            .h(px(HEADER_HEIGHT))
            .pl_3()
            .border_b_1()
            .border_color(rgb(theme::BORDER))
            .bg(rgb(theme::SURFACE))
            .text_color(rgb(theme::TEXT_MUTED))
            .overflow_hidden()
            .child(div().flex_none().w(px(self.offset_width())).child("Offset"))
            .children((0..bpr).map(|i| {
                div()
                    .flex_none()
                    .w(px(HEX_CELL_WIDTH))
                    .when(i > 0 && i % 8 == 0, |el| el.ml(px(GROUP_GAP)))
                    .text_center()
                    .child(format!("{i:02X}"))
            }))
            .child(div().flex_none().ml_4().child("ASCII"))
    }

    fn render_rows(&self, cx: &Context<Self>) -> AnyElement {
        let len = self.len();
        let bpr = self.bytes_per_row;
        let selection = self.selection();
        let digits = self.offset_digits();
        let first = self.top_row;
        let last = (first + self.visible_rows).min(self.total_rows());
        mono()
            .flex()
            .flex_col()
            .pl_3()
            .children((first..last).map(|row| {
                let start = row * bpr;
                let count = bpr.min(len - start);
                let bytes = self.bytes(start..start + count);
                let byte = |i: u64| bytes.map(|bytes| bytes[i as usize]);
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .h(px(ROW_HEIGHT))
                    .child(
                        div()
                            .flex_none()
                            .w(px(self.offset_width()))
                            .text_color(rgb(theme::TEXT_MUTED))
                            .child(format!("{start:0digits$X}")),
                    )
                    .children((0..bpr).map(|i| {
                        let cell = if i < count {
                            self.byte_cell(start + i, byte(i), false, &selection, cx)
                        } else {
                            div()
                        };
                        cell.flex_none()
                            .w(px(HEX_CELL_WIDTH))
                            .when(i > 0 && i % 8 == 0, |el| el.ml(px(GROUP_GAP)))
                    }))
                    .child(div().flex_none().w_4())
                    .children((0..count).map(|i| {
                        self.byte_cell(start + i, byte(i), true, &selection, cx)
                            .flex_none()
                            .w(px(ASCII_CELL_WIDTH))
                    }))
            }))
            .into_any_element()
    }

    /// One byte in the hex or ASCII column. Pressing and dragging selects.
    fn byte_cell(
        &self,
        offset: u64,
        byte: Option<u8>,
        ascii: bool,
        selection: &Range<u64>,
        cx: &Context<Self>,
    ) -> Div {
        let is_cursor = offset == self.cursor;
        let selected = selection.contains(&offset);
        let text = match byte {
            Some(byte) if ascii => lforge_binary::ascii_char(byte).to_string(),
            Some(byte) => format!("{byte:02X}"),
            None if ascii => " ".to_string(),
            None => "··".to_string(),
        };
        let color = match byte {
            None => theme::TEXT_DISABLED,
            Some(0) if !selected => ZERO_BYTE_COLOR,
            Some(_) => theme::TEXT,
        };
        div()
            .h(px(ROW_HEIGHT - 2.))
            .flex()
            .items_center()
            .justify_center()
            .text_color(rgb(color))
            .when(selected, |el| el.bg(rgb(theme::SELECTION)))
            .when(is_cursor, |el| el.bg(rgb(theme::SELECTION_BORDER)))
            .child(text)
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, event: &MouseDownEvent, window, cx| {
                    this.press_byte(offset, event.modifiers.shift, window, cx)
                }),
            )
            .on_mouse_move(cx.listener(move |this, event: &MouseMoveEvent, _, cx| {
                if this.drag == Some(Drag::Selection)
                    && event.pressed_button == Some(MouseButton::Left)
                    && this.cursor != offset
                {
                    this.set_cursor(offset, true, cx);
                }
            }))
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
            .id("scrollbar")
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
                        let (track_top, _) = scrollbar_track(window);
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

    fn render_divider(&self, cx: &Context<Self>) -> impl IntoElement {
        let active = self.drag == Some(Drag::Panel);
        div()
            .id("panel-divider")
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
                    this.drag = Some(Drag::Panel);
                    cx.notify();
                }),
            )
    }

    /// Window-level listeners keep drags going when the cursor leaves the
    /// element that started them.
    fn render_drag_tracker(&self, cx: &Context<Self>) -> impl IntoElement {
        let this: Entity<Self> = cx.entity();
        canvas(
            |_, _, _| {},
            move |_: Bounds<Pixels>, (), window, _| {
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

    fn render_panel(&self, width: f32, cx: &Context<Self>) -> impl IntoElement {
        div()
            .id("data-inspector")
            .flex()
            .flex_col()
            .flex_none()
            .w(px(width))
            .h_full()
            .overflow_y_scroll()
            .bg(rgb(theme::PANEL))
            .child(section_title("Data Inspector"))
            .child(self.render_values())
            .child(section_title("File"))
            .child(self.render_file_info(cx))
    }

    fn render_values(&self) -> impl IntoElement {
        let available = self.file().is_some() && self.len() > 0;
        let bytes = available
            .then(|| self.bytes(self.inspect_range()))
            .flatten();
        let values = bytes.map(|bytes| lforge_binary::interpret(bytes, self.endian));
        let rows: Vec<(&str, Option<String>, Option<String>)> = match &values {
            None => Vec::new(),
            Some(v) => vec![
                (
                    "UInt8",
                    v.u8.map(|x| x.to_string()),
                    v.u8.map(|x| format!("{x:#04X}")),
                ),
                ("Int8", v.i8.map(|x| x.to_string()), None),
                (
                    "UInt16",
                    v.u16.map(|x| x.to_string()),
                    v.u16.map(|x| format!("{x:#06X}")),
                ),
                ("Int16", v.i16.map(|x| x.to_string()), None),
                (
                    "UInt32",
                    v.u32.map(|x| x.to_string()),
                    v.u32.map(|x| format!("{x:#010X}")),
                ),
                ("Int32", v.i32.map(|x| x.to_string()), None),
                (
                    "UInt64",
                    v.u64.map(|x| x.to_string()),
                    v.u64.map(|x| format!("{x:#018X}")),
                ),
                ("Int64", v.i64.map(|x| x.to_string()), None),
                ("Float32", v.f32.map(lforge_binary::format_f32), None),
                ("Float64", v.f64.map(lforge_binary::format_f64), None),
            ],
        };
        let endian = match self.endian {
            Endian::Little => "little-endian",
            Endian::Big => "big-endian",
        };

        div()
            .flex()
            .flex_col()
            .px_3()
            .pb_3()
            .gap_0p5()
            .child(info_row(
                "Offset",
                if available {
                    format!("{:#X} ({})", self.cursor, self.cursor)
                } else {
                    "—".to_string()
                },
            ))
            .child(info_row("Byte order", endian.to_string()))
            .when(available && bytes.is_none(), |el| {
                el.child(muted("Reading…"))
            })
            .children(rows.into_iter().map(|(label, decimal, hex)| {
                // The hex value wraps below the decimal one when both do not fit.
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .min_h(px(22.))
                    .child(muted(label).flex_none().w(px(LABEL_WIDTH)))
                    .child(
                        div()
                            .flex()
                            .flex_1()
                            .flex_wrap()
                            .justify_between()
                            .gap_x_2()
                            .child(match decimal {
                                Some(decimal) => mono().child(decimal),
                                None => div()
                                    .text_color(rgb(theme::TEXT_DISABLED))
                                    .child("unavailable"),
                            })
                            .children(
                                hex.map(|hex| mono().text_color(rgb(theme::TEXT_MUTED)).child(hex)),
                            ),
                    )
            }))
            .children(bytes.map(|bytes| {
                let ascii: String = bytes
                    .iter()
                    .map(|b| lforge_binary::ascii_char(*b))
                    .collect();
                let (utf8, invalid) = match lforge_binary::utf8_preview(bytes) {
                    Utf8Preview::Text(text) => (text, None),
                    Utf8Preview::Invalid { text, offset } => (text, Some(offset)),
                };
                div()
                    .flex()
                    .flex_col()
                    .gap_0p5()
                    .mt_1()
                    .child(text_preview("ASCII", ascii, None))
                    .child(text_preview(
                        "UTF-8",
                        utf8,
                        invalid.map(|offset| format!("Invalid UTF-8 at +{offset}")),
                    ))
            }))
    }

    fn render_file_info(&self, cx: &Context<Self>) -> impl IntoElement {
        let file = self.file();
        let size = file.map(|file| {
            let len = file.source.len();
            format!(
                "{} ({} bytes)",
                files::format_size(len),
                files::format_bytes_exact(len)
            )
        });
        let location = match files::locate_inner(&self.path) {
            Some((archive, inner)) => format!("{} in {}", inner.display(), archive.display()),
            None => self.path.display().to_string(),
        };
        let hash = match &self.hash {
            Hash::Idle => div().flex().child(
                ui::button("compute-sha256", "Compute")
                    .when(file.is_none(), |el| {
                        el.text_color(rgb(theme::TEXT_DISABLED))
                    })
                    .when(file.is_some(), |el| {
                        el.on_click(cx.listener(|this, _, _, cx| this.compute_hash(cx)))
                    }),
            ),
            Hash::Running { .. } => div()
                .flex()
                .items_center()
                .gap_2()
                .child(muted("Computing…"))
                .child(
                    ui::button("cancel-sha256", "Cancel")
                        .on_click(cx.listener(|this, _, _, cx| this.cancel_hash(cx))),
                ),
            Hash::Done(digest) => {
                let digest = digest.clone();
                div()
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(mono().text_xs().child(digest.clone()))
                    .child(
                        div()
                            .flex()
                            .child(ui::button("copy-sha256", "Copy").on_click(cx.listener(
                                move |this, _, _, cx| {
                                    cx.write_to_clipboard(gpui::ClipboardItem::new_string(
                                        digest.clone(),
                                    ));
                                    this.notify_notice("Copied SHA-256", false);
                                    cx.notify();
                                },
                            ))),
                    )
            }
            Hash::Failed(err) => div()
                .text_color(rgb(theme::ERROR))
                .child(format!("Failed: {err}")),
        };

        div()
            .flex()
            .flex_col()
            .px_3()
            .pb_3()
            .gap_1()
            .child(info_row("Name", self.name.clone()))
            .child(info_block("Location", div().child(location)))
            .child(info_row("Size", size.unwrap_or_else(|| "—".into())))
            .child(info_row(
                "Modified",
                file.and_then(|file| file.modified)
                    .map(files::format_modified)
                    .unwrap_or_else(|| "Unknown".into()),
            ))
            .children(file.map(|file| {
                info_block(
                    "Signature",
                    mono().child(if file.signature.is_empty() {
                        "—".to_string()
                    } else {
                        lforge_binary::hex_bytes(&file.signature)
                    }),
                )
            }))
            .child(info_block("SHA-256", hash))
    }

    fn render_status_bar(&self) -> impl IntoElement {
        let file = self.file();
        let selection = self.selection();
        let count = selection.end - selection.start;
        div()
            .flex()
            .flex_none()
            .items_center()
            .gap_3()
            .h(px(STATUS_BAR_HEIGHT))
            .px_3()
            .border_t_1()
            .border_color(rgb(theme::BORDER))
            .text_xs()
            .text_color(rgb(theme::TEXT_MUTED))
            .child("Read-only")
            .when_some(file, |el, file| {
                el.child(separator())
                    .child(format!("Size: {}", files::format_size(file.source.len())))
            })
            .when(count > 0, |el| {
                el.child(separator())
                    .child(format!("Offset: {:#X}", self.cursor))
                    .child(separator())
                    .child(if count > 1 {
                        format!(
                            "Selection: {} ({:#X}–{:#X})",
                            plural(count, "byte"),
                            selection.start,
                            selection.end - 1
                        )
                    } else {
                        "Selection: 1 byte".to_string()
                    })
            })
            .child(div().flex_1())
            .when_some(self.notice.as_ref(), |el, notice| {
                el.child(
                    div()
                        .truncate()
                        .when(notice.error, |el| el.text_color(rgb(theme::ERROR)))
                        .child(notice.text.clone()),
                )
            })
            .child(separator())
            .child(format!("{} bytes per row", self.bytes_per_row))
    }
}

fn section_title(title: &'static str) -> impl IntoElement {
    div()
        .flex()
        .flex_none()
        .items_center()
        .h(px(32.))
        .px_3()
        .text_xs()
        .font_weight(FontWeight::SEMIBOLD)
        .text_color(rgb(theme::TEXT_MUTED))
        .child(title.to_uppercase())
}

fn info_row(label: &'static str, value: String) -> impl IntoElement {
    div()
        .flex()
        .gap_2()
        .min_h(px(22.))
        .items_center()
        .child(muted(label).flex_none().w(px(LABEL_WIDTH)))
        .child(div().flex_1().min_w_0().truncate().child(value))
}

/// A label above a value that may wrap.
fn info_block(label: &'static str, value: impl IntoElement) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_0p5()
        .py_0p5()
        .child(muted(label))
        .child(div().text_xs().child(value))
}

fn text_preview(label: &'static str, text: String, problem: Option<String>) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .gap_0p5()
        .child(div().flex().gap_2().child(muted(label)).children(
            problem.map(|problem| div().text_xs().text_color(rgb(theme::ERROR)).child(problem)),
        ))
        .child(
            mono()
                .px_2()
                .py_1()
                .rounded_sm()
                .bg(rgb(theme::BACKGROUND))
                .child(if text.is_empty() {
                    " ".to_string()
                } else {
                    text
                }),
        )
}

/// A row of mutually exclusive options. `on_select` receives the index.
fn segmented<const N: usize>(
    id: &'static str,
    options: [(&'static str, bool); N],
    on_select: impl Fn(&usize, &mut Window, &mut App) + 'static,
) -> Stateful<Div> {
    let on_select = Rc::new(on_select);
    div()
        .id(id)
        .flex()
        .flex_none()
        .gap_0p5()
        .p_0p5()
        .rounded_md()
        .border_1()
        .border_color(rgb(theme::BORDER))
        .bg(rgb(theme::PANEL))
        .children(
            options
                .into_iter()
                .enumerate()
                .map(|(ix, (label, active))| {
                    let on_select = on_select.clone();
                    div()
                        .id(ix)
                        .flex()
                        .items_center()
                        .h(px(22.))
                        .px_2()
                        .rounded_sm()
                        .border_1()
                        .border_color(gpui::transparent_black())
                        .when(active, |el| {
                            el.bg(rgb(theme::SELECTION))
                                .border_color(rgb(theme::SELECTION_BORDER))
                        })
                        .when(!active, |el| el.hover(|s| s.bg(rgb(theme::HOVER))))
                        .child(label)
                        .on_click(move |_, window, cx| on_select(&ix, window, cx))
                }),
        )
}
