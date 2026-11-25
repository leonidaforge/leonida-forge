//! A single-line text field for short input such as offsets and patterns.
//!
//! Characters come from key events, so IME composition is not supported.

use std::cell::Cell;
use std::rc::Rc;

use gpui::{
    Bounds, Context, EventEmitter, FocusHandle, KeyDownEvent, MouseButton, MouseDownEvent, Pixels,
    SharedString, TextRun, Window, canvas, div, font, prelude::*, px, rgb,
};

use super::theme;

/// Font size of the field's text and the height it is shaped at.
const TEXT_SIZE: f32 = 13.;
/// Left padding and border before the first glyph: `px_2` plus the 1px border.
const TEXT_INSET: f32 = 9.;

pub enum TextFieldEvent {
    /// Enter was pressed; `shift` is set for Shift+Enter.
    Submit { shift: bool },
}

pub struct TextField {
    text: String,
    /// Byte index into `text`, always on a character boundary.
    cursor: usize,
    placeholder: SharedString,
    focus_handle: FocusHandle,
    /// The field's bounds in window coordinates, captured each frame so a
    /// click can be mapped to a byte index.
    bounds: Rc<Cell<Bounds<Pixels>>>,
}

impl EventEmitter<TextFieldEvent> for TextField {}

impl TextField {
    pub fn new(placeholder: impl Into<SharedString>, cx: &mut Context<Self>) -> Self {
        Self {
            text: String::new(),
            cursor: 0,
            placeholder: placeholder.into(),
            focus_handle: cx.focus_handle(),
            bounds: Rc::default(),
        }
    }

    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn set_placeholder(&mut self, placeholder: impl Into<SharedString>) {
        self.placeholder = placeholder.into();
    }

    pub fn clear(&mut self, cx: &mut Context<Self>) {
        self.text.clear();
        self.cursor = 0;
        cx.notify();
    }

    pub fn focus(&self, window: &mut Window, cx: &mut Context<Self>) {
        self.focus_handle.focus(window, cx);
    }

    fn insert(&mut self, text: &str) {
        let text: String = text.chars().filter(|c| !c.is_control()).collect();
        self.text.insert_str(self.cursor, &text);
        self.cursor += text.len();
    }

    /// The byte index of the glyph nearest to window position `x`.
    fn cursor_at(&self, x: Pixels, window: &Window) -> usize {
        let left = self.bounds.get().left() + px(TEXT_INSET);
        let local = x - left;
        if local <= px(0.) || self.text.is_empty() {
            return 0;
        }
        let run = TextRun {
            len: self.text.len(),
            font: font(theme::MONO_FONT),
            color: rgb(theme::TEXT).into(),
            background_color: None,
            underline: None,
            strikethrough: None,
        };
        let layout =
            window
                .text_system()
                .layout_line(self.text.as_str(), px(TEXT_SIZE), &[run], None);
        layout.closest_index_for_x(local).min(self.text.len())
    }

    fn previous_boundary(&self) -> usize {
        self.text[..self.cursor]
            .char_indices()
            .next_back()
            .map_or(0, |(ix, _)| ix)
    }

    fn next_boundary(&self) -> usize {
        self.text[self.cursor..]
            .chars()
            .next()
            .map_or(self.cursor, |c| self.cursor + c.len_utf8())
    }

    fn key_down(&mut self, event: &KeyDownEvent, _: &mut Window, cx: &mut Context<Self>) {
        let keystroke = &event.keystroke;
        let modifiers = keystroke.modifiers;
        // AltGr arrives as Ctrl+Alt and still types characters.
        let shortcut = (modifiers.control && !modifiers.alt) || modifiers.platform;
        match keystroke.key.as_str() {
            "enter" => {
                cx.emit(TextFieldEvent::Submit {
                    shift: modifiers.shift,
                });
            }
            "backspace" => {
                let start = self.previous_boundary();
                self.text.replace_range(start..self.cursor, "");
                self.cursor = start;
            }
            "delete" => {
                let end = self.next_boundary();
                self.text.replace_range(self.cursor..end, "");
            }
            "left" => self.cursor = self.previous_boundary(),
            "right" => self.cursor = self.next_boundary(),
            "home" => self.cursor = 0,
            "end" => self.cursor = self.text.len(),
            "v" if shortcut => {
                let pasted = cx.read_from_clipboard().and_then(|item| item.text());
                if let Some(line) = pasted.as_deref().and_then(|text| text.lines().next()) {
                    self.insert(line);
                }
            }
            _ => match &keystroke.key_char {
                Some(text) if !shortcut => self.insert(text),
                _ => return,
            },
        }
        cx.stop_propagation();
        cx.notify();
    }
}

impl Render for TextField {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let focused = self.focus_handle.is_focused(window);
        let (before, after) = self.text.split_at(self.cursor);
        let bounds = self.bounds.clone();
        div()
            .id("text-field")
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(Self::key_down))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(move |this, event: &MouseDownEvent, window, cx| {
                    this.cursor = this.cursor_at(event.position.x, window);
                    this.focus(window, cx);
                    cx.notify();
                }),
            )
            .relative()
            .flex()
            .items_center()
            .h(px(26.))
            .px_2()
            .overflow_hidden()
            .whitespace_nowrap()
            .text_size(px(TEXT_SIZE))
            .rounded_md()
            .border_1()
            .border_color(rgb(if focused {
                theme::SELECTION_BORDER
            } else {
                theme::BORDER
            }))
            .bg(rgb(theme::PANEL))
            .font_family(theme::MONO_FONT)
            .cursor_text()
            .child(div().absolute().inset_0().child(canvas(
                move |field_bounds, _, _| bounds.set(field_bounds),
                |_, _, _, _| {},
            )))
            .when(self.text.is_empty() && !focused, |el| {
                el.text_color(rgb(theme::TEXT_DISABLED))
                    .child(self.placeholder.clone())
            })
            .when(!self.text.is_empty() || focused, |el| {
                el.child(before.to_string())
                    .when(focused, |el| {
                        el.child(
                            div()
                                .flex_none()
                                .w(px(1.))
                                .h(px(15.))
                                .bg(rgb(theme::ACCENT)),
                        )
                    })
                    .child(after.to_string())
            })
    }
}
