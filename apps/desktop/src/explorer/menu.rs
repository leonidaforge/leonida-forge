use gpui::{
    App, ClickEvent, Context, MouseButton, Window, anchored, deferred, div, prelude::*, px, rgb,
};

use super::{Explorer, MENU_BAR_HEIGHT, Menu};
use crate::files::{EntryKind, Sort, SortKey};
use crate::settings::ViewMode;
use crate::ui;
use crate::ui::theme;

impl Explorer {
    pub(super) fn render_menu_bar(&self, cx: &Context<Self>) -> impl IntoElement {
        div()
            .flex()
            .flex_none()
            .items_center()
            .gap_0p5()
            .h(px(MENU_BAR_HEIGHT))
            .px_1p5()
            .bg(rgb(theme::BACKGROUND))
            .child(self.render_menu_title(Menu::File, "File", cx))
            .child(self.render_menu_title(Menu::View, "View", cx))
            // The renderer demo is a development tool.
            .when(cfg!(debug_assertions), |el| {
                el.child(self.render_menu_title(Menu::Tools, "Tools", cx))
            })
    }

    fn render_menu_title(
        &self,
        menu: Menu,
        label: &'static str,
        cx: &Context<Self>,
    ) -> impl IntoElement {
        let open = self.open_menu.as_ref() == Some(&menu);
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
            .on_mouse_down(MouseButton::Left, {
                let menu = menu.clone();
                cx.listener(move |this, _, _, cx| {
                    this.open_menu = if this.open_menu.as_ref() == Some(&menu) {
                        None
                    } else {
                        Some(menu.clone())
                    };
                    cx.notify();
                })
            })
            .on_hover({
                let menu = menu.clone();
                cx.listener(move |this, hovered: &bool, _, cx| {
                    let other_title_open =
                        matches!(this.open_menu, Some(Menu::File | Menu::View | Menu::Tools))
                            && this.open_menu.as_ref() != Some(&menu);
                    if *hovered && other_title_open {
                        this.open_menu = Some(menu.clone());
                        cx.notify();
                    }
                })
            })
            .when(open, |el| {
                el.child(
                    div().absolute().top_full().left_0().child(
                        deferred(
                            anchored()
                                .snap_to_window_with_margin(px(4.))
                                .child(self.render_menu_items(&menu, cx)),
                        )
                        .priority(2),
                    ),
                )
            })
    }

    /// Catches clicks outside an open menu. The menu bar stays uncovered so
    /// its titles can switch or close menus.
    pub(super) fn render_menu_overlay(&self, menu: &Menu, cx: &Context<Self>) -> impl IntoElement {
        let overlay = div()
            .id("menu-overlay")
            .absolute()
            .top(px(MENU_BAR_HEIGHT))
            .left_0()
            .right_0()
            .bottom_0()
            .occlude()
            .on_any_mouse_down(cx.listener(|this, _, _, cx| this.close_menu(cx)));

        div().child(deferred(overlay).priority(1)).when_some(
            match menu {
                Menu::Root { position, .. } | Menu::Entry { position, .. } => Some(*position),
                _ => None,
            },
            |el, position| {
                el.child(
                    deferred(
                        anchored()
                            .position(position)
                            .snap_to_window_with_margin(px(4.))
                            .child(self.render_menu_items(menu, cx)),
                    )
                    .priority(2),
                )
            },
        )
    }

    pub(super) fn render_menu_items(&self, menu: &Menu, cx: &Context<Self>) -> impl IntoElement {
        let panel = ui::menu_panel().occlude();
        match menu {
            Menu::File => {
                let folder_root = self.current_folder_root();
                let inspectable = self
                    .selected_entry()
                    .filter(|entry| entry.is_inspectable())
                    .map(|entry| entry.path.clone());
                let exporting = self.exporting();
                let exportable = self
                    .selected_entry()
                    .filter(|entry| entry.kind == EntryKind::File)
                    .cloned();
                panel
                    .child(
                        ui::menu_item("set-gta", "Set GTA VI Folder…", false, true, None).on_click(
                            self.menu_action(|this, _, cx| this.choose_gta_folder(cx), cx),
                        ),
                    )
                    .child(
                        ui::menu_item("open-folder", "Open Folder…", false, true, None).on_click(
                            self.menu_action(|this, _, cx| this.choose_folder_to_open(cx), cx),
                        ),
                    )
                    .child(
                        ui::menu_item(
                            "remove-folder",
                            "Remove Folder from Workspace",
                            false,
                            folder_root.is_some(),
                            None,
                        )
                        .when_some(folder_root, |el, root| {
                            el.on_click(self.menu_action(
                                move |this, _, cx| this.remove_folder(root.clone(), cx),
                                cx,
                            ))
                        }),
                    )
                    .child(ui::menu_separator())
                    .child(
                        ui::menu_item(
                            "open-in-inspector",
                            "Open in Binary Inspector",
                            false,
                            inspectable.is_some(),
                            None,
                        )
                        .when_some(inspectable, |el, path| {
                            el.on_click(self.menu_action(
                                move |_, _, cx| super::open_binary_inspector(path.clone(), cx),
                                cx,
                            ))
                        }),
                    )
                    .child(
                        ui::menu_item(
                            "save-selection-as",
                            "Save Selection As…",
                            false,
                            exportable.is_some() && !exporting,
                            None,
                        )
                        .when_some(
                            exportable.filter(|_| !exporting),
                            |el, entry| {
                                el.on_click(self.menu_action(
                                    move |this, _, cx| this.start_export(&entry, cx),
                                    cx,
                                ))
                            },
                        ),
                    )
                    .child(ui::menu_separator())
                    .child(
                        ui::menu_item("exit", "Exit", false, true, None)
                            .on_click(self.menu_action(|_, _, cx| cx.quit(), cx)),
                    )
            }
            Menu::View => panel
                .children(ViewMode::ALL.into_iter().map(|mode| {
                    ui::menu_item(
                        mode.label(),
                        mode.label(),
                        self.view_mode == mode,
                        true,
                        None,
                    )
                    .on_click(self.menu_action(move |this, _, cx| this.set_view_mode(mode, cx), cx))
                }))
                .child(ui::menu_separator())
                .child(
                    ui::menu_item(
                        "preview-pane",
                        "Preview Pane",
                        self.preview_visible,
                        true,
                        None,
                    )
                    .on_click(self.menu_action(|this, _, cx| this.toggle_preview(cx), cx)),
                )
                .child(ui::menu_separator())
                .child(
                    ui::menu_item("refresh", "Refresh", false, true, Some("F5"))
                        .on_click(self.menu_action(|this, _, cx| this.refresh(cx), cx)),
                ),
            Menu::Tools => panel.child(
                ui::menu_item("renderer-demo", "Renderer Demo", false, true, None)
                    .on_click(self.menu_action(|this, _, cx| this.open_renderer_demo(cx), cx)),
            ),
            Menu::Sort => panel
                .children(
                    [
                        (SortKey::Name, "Name"),
                        (SortKey::Type, "Type"),
                        (SortKey::Size, "Size"),
                        (SortKey::Modified, "Date modified"),
                    ]
                    .into_iter()
                    .map(|(key, label)| {
                        ui::menu_item(label, label, self.sort.key == key, true, None).on_click(
                            self.menu_action(
                                move |this, _, cx| {
                                    let sort = Sort { key, ..this.sort };
                                    this.set_sort(sort, cx)
                                },
                                cx,
                            ),
                        )
                    }),
                )
                .child(ui::menu_separator())
                .children(
                    [(false, "Ascending"), (true, "Descending")]
                        .into_iter()
                        .map(|(descending, label)| {
                            ui::menu_item(
                                label,
                                label,
                                self.sort.descending == descending,
                                true,
                                None,
                            )
                            .on_click(self.menu_action(
                                move |this, _, cx| {
                                    let sort = Sort {
                                        descending,
                                        ..this.sort
                                    };
                                    this.set_sort(sort, cx)
                                },
                                cx,
                            ))
                        }),
                ),
            Menu::Root { root, .. } => {
                let root = root.clone();
                if self.workspace.gta.as_ref() == Some(&root) {
                    panel.child(
                        ui::menu_item("change-gta", "Change GTA VI Folder…", false, true, None)
                            .on_click(
                                self.menu_action(|this, _, cx| this.choose_gta_folder(cx), cx),
                            ),
                    )
                } else {
                    panel.child(
                        ui::menu_item("remove-root", "Remove from Workspace", false, true, None)
                            .on_click(self.menu_action(
                                move |this, _, cx| this.remove_folder(root.clone(), cx),
                                cx,
                            )),
                    )
                }
            }
            Menu::Entry { entry, .. } => {
                let open = entry.clone();
                let path = entry.path.clone();
                let exporting = self.exporting();
                let exportable = (entry.kind == EntryKind::File).then(|| entry.clone());
                panel
                    .child(
                        ui::menu_item("open-entry", "Open", false, true, None).on_click(
                            self.menu_action(move |this, _, cx| this.open_entry(&open, cx), cx),
                        ),
                    )
                    .child(
                        ui::menu_item(
                            "open-in-inspector",
                            "Open in Binary Inspector",
                            false,
                            true,
                            None,
                        )
                        .on_click(self.menu_action(
                            move |_, _, cx| super::open_binary_inspector(path.clone(), cx),
                            cx,
                        )),
                    )
                    .when_some(exportable, |panel, entry| {
                        panel.child(
                            ui::menu_item("save-entry-as", "Save As…", false, !exporting, None)
                                .when(!exporting, |el| {
                                    el.on_click(self.menu_action(
                                        move |this, _, cx| this.start_export(&entry, cx),
                                        cx,
                                    ))
                                }),
                        )
                    })
            }
        }
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
}
