//! A single-line text field for short input such as offsets and patterns.
//!
//! Characters come from key events, so IME composition is not supported.

use gpui::{
    Context, EventEmitter, FocusHandle, KeyDownEvent, MouseButton, SharedString, Window, div,
    prelude::*, px, rgb,
};

use super::theme;

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
}

impl EventEmitter<TextFieldEvent> for TextField {}

impl TextField {
    pub fn new(placeholder: impl Into<SharedString>, cx: &mut Context<Self>) -> Self {
        Self {
            text: String::new(),
            cursor: 0,
            placeholder: placeholder.into(),
            focus_handle: cx.focus_handle(),
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
        div()
            .id("text-field")
            .track_focus(&self.focus_handle)
            .on_key_down(cx.listener(Self::key_down))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, window, cx| {
                    this.cursor = this.text.len();
                    this.focus(window, cx);
                    cx.notify();
                }),
            )
            .flex()
            .items_center()
            .h(px(26.))
            .px_2()
            .overflow_hidden()
            .whitespace_nowrap()
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
