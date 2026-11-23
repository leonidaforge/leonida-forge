//! Small styled building blocks shared by the windows.

use gpui::{
    AnyElement, App, Div, ElementId, Pixels, SharedString, Stateful, Svg, Window, div, prelude::*,
    px, rgb, svg,
};

pub mod assets;
pub mod theme;

use assets::Icon;

pub fn icon(icon: Icon, size: Pixels, color: u32) -> Svg {
    svg()
        .path(icon.path())
        .size(size)
        .flex_none()
        .text_color(rgb(color))
}

/// A square toolbar button. Callers attach click handlers only when enabled.
pub fn icon_button(
    id: impl Into<ElementId>,
    glyph: Icon,
    enabled: bool,
    active: bool,
) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .flex_none()
        .items_center()
        .justify_center()
        .size(px(28.))
        .rounded_md()
        .border_1()
        .border_color(gpui::transparent_black())
        .when(active, |el| {
            el.bg(rgb(theme::SELECTION))
                .border_color(rgb(theme::SELECTION_BORDER))
        })
        .when(enabled && !active, |el| {
            el.hover(|s| s.bg(rgb(theme::HOVER)))
        })
        .child(icon(
            glyph,
            px(16.),
            if enabled {
                theme::TEXT
            } else {
                theme::TEXT_DISABLED
            },
        ))
}

/// A bordered text button.
pub fn button(id: impl Into<ElementId>, label: impl Into<SharedString>) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .flex_none()
        .items_center()
        .gap_1p5()
        .h(px(28.))
        .px_2p5()
        .rounded_md()
        .border_1()
        .border_color(rgb(theme::BORDER))
        .bg(rgb(theme::SURFACE))
        .hover(|s| s.bg(rgb(theme::HOVER)))
        .child(label.into())
}

pub fn menu_panel() -> Div {
    div()
        .flex()
        .flex_col()
        .min_w(px(220.))
        .p_1()
        .bg(rgb(theme::SURFACE))
        .border_1()
        .border_color(rgb(theme::BORDER))
        .rounded_md()
        .shadow_lg()
        .text_sm()
        .text_color(rgb(theme::TEXT))
        .font_family(theme::UI_FONT)
}

/// A menu entry. Callers attach click handlers only when enabled.
pub fn menu_item(
    id: impl Into<ElementId>,
    label: impl Into<SharedString>,
    checked: bool,
    enabled: bool,
    shortcut: Option<&'static str>,
) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .items_center()
        .gap_2()
        .h(px(26.))
        .pl_1()
        .pr_3()
        .rounded_sm()
        .text_color(rgb(if enabled {
            theme::TEXT
        } else {
            theme::TEXT_DISABLED
        }))
        .when(enabled, |el| el.hover(|s| s.bg(rgb(theme::SELECTION))))
        .child(
            div()
                .flex()
                .justify_center()
                .w(px(20.))
                .when(checked, |el| {
                    el.child(icon(Icon::Check, px(14.), theme::ACCENT))
                }),
        )
        .child(div().flex_1().child(label.into()))
        .children(shortcut.map(|shortcut| {
            div()
                .pl_6()
                .text_xs()
                .text_color(rgb(theme::TEXT_MUTED))
                .child(shortcut)
        }))
}

pub fn menu_separator() -> Div {
    div().my_1().mx_1().h(px(1.)).bg(rgb(theme::BORDER))
}

/// A muted message centered in the available space, with optional detail.
pub fn centered_message(message: &'static str, detail: Option<String>) -> AnyElement {
    div()
        .flex()
        .flex_col()
        .size_full()
        .items_center()
        .justify_center()
        .gap_1()
        .p_4()
        .text_color(rgb(theme::TEXT_MUTED))
        .child(message)
        .children(detail.map(|detail| div().text_xs().child(detail)))
        .into_any_element()
}

/// Closes the window through GPUI instead of letting Windows destroy it first.
///
/// When `WM_CLOSE` reaches `DefWindowProc`, Windows destroys the window before
/// GPUI tears it down, and gpui_windows then logs "invalid window handle"
/// errors for the dead handle.
pub fn close_through_gpui(window: &Window, cx: &App) {
    window.on_window_should_close(cx, |window, _| {
        window.remove_window();
        false
    });
}
