//! The pose inspector controls, shared by the model and dictionary viewers.
//!
//! The panel owns no state: it reads the viewport's [`PoseSession`] and every
//! button sends one discrete step back through
//! [`Viewport`]. Rotations are Euler XYZ
//! degrees and translations are metres, both in the bone's parent space.
//! Nothing here writes to the resource or survives the window.
//!
//! The functions are generic over the calling view type so both windows can
//! share one definition; only the viewport entity is touched.

use gpui::{AnyElement, Context, Entity, FontWeight, div, prelude::*, px, rgb};

use super::PoseDisplay;
use super::viewport::Viewport;
use crate::ui;
use crate::ui::theme;

/// The pose panel for `viewport`, or nothing when the scene cannot deform.
pub fn pose_section<V: 'static>(viewport: Entity<Viewport>, cx: &Context<V>) -> AnyElement {
    if !viewport.read(cx).pose_supported() {
        return div().into_any_element();
    }
    let (active, report, display, influence) = {
        let state = viewport.read(cx);
        let edited = state.pose().is_some_and(|pose| !pose.is_reference());
        (
            state.is_pose_mode(),
            format!(
                "{}  \u{00B7}  {}",
                state.deformation_report(),
                if edited {
                    "edited pose"
                } else {
                    "reference pose"
                }
            ),
            state
                .pose()
                .map_or(PoseDisplay::Posed, |pose| pose.display()),
            state.pose().is_some_and(|pose| pose.influence_view()),
        )
    };
    let mut section = div()
        .flex()
        .flex_col()
        .gap_1()
        .px_3()
        .pb_2()
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(
                    div()
                        .text_xs()
                        .font_weight(FontWeight::SEMIBOLD)
                        .text_color(rgb(theme::TEXT_MUTED))
                        .child("POSE"),
                )
                .child(
                    ui::small_button("pose-mode", if active { "Exit Pose" } else { "Pose Mode" })
                        .on_click(cx.listener({
                            let viewport = viewport.clone();
                            move |_this, _, _, cx| {
                                viewport.clone().update(cx, |viewport, cx| {
                                    if viewport.is_pose_mode() {
                                        viewport.exit_pose_mode(cx);
                                    } else {
                                        viewport.enter_pose_mode(cx);
                                    }
                                });
                            }
                        })),
                ),
        )
        .child(
            div()
                .text_xs()
                .text_color(rgb(theme::TEXT_MUTED))
                .child(report),
        );
    if !active {
        return section.into_any_element();
    }

    let mut display_row = div().flex().items_center().gap_1();
    for value in [PoseDisplay::Authored, PoseDisplay::Posed] {
        let label = value.name();
        let id = match value {
            PoseDisplay::Authored => "pose-display-authored",
            PoseDisplay::Posed => "pose-display-posed",
        };
        display_row = display_row.child(
            ui::small_button(id, label)
                .when(display == value, |el| {
                    el.bg(rgb(theme::SELECTION))
                        .border_color(rgb(theme::SELECTION_BORDER))
                })
                .on_click(cx.listener({
                    let viewport = viewport.clone();
                    move |_this, _, _, cx| {
                        viewport
                            .clone()
                            .update(cx, |viewport, cx| viewport.set_pose_display(value, cx));
                    }
                })),
        );
    }
    display_row = display_row.child(
        ui::small_button("pose-influence", "Influence View")
            .when(influence, |el| {
                el.bg(rgb(theme::SELECTION))
                    .border_color(rgb(theme::SELECTION_BORDER))
            })
            .on_click(cx.listener({
                let viewport = viewport.clone();
                move |_this, _, _, cx| {
                    let enabled = !viewport
                        .read(cx)
                        .pose()
                        .is_some_and(|pose| pose.influence_view());
                    viewport
                        .clone()
                        .update(cx, |viewport, cx| viewport.set_influence_view(enabled, cx));
                }
            })),
    );
    section = section.child(display_row);

    let selected = viewport.read(cx).selected_bone();
    if let Some(bone) = selected {
        let (degrees, offset) = {
            let state = viewport.read(cx);
            (
                state.pose_rotation_degrees(bone).unwrap_or([0.0; 3]),
                state.pose_translation(bone).unwrap_or_default(),
            )
        };
        section = section.child(
            div()
                .text_xs()
                .text_color(rgb(theme::TEXT_MUTED))
                .child(format!(
                    "Bone {bone}  \u{00B7}  {:.0}\u{00B0} {:.0}\u{00B0} {:.0}\u{00B0}  \u{00B7}  {:.3} {:.3} {:.3} m",
                    degrees[0], degrees[1], degrees[2], offset.x, offset.y, offset.z
                )),
        );
        section = section.child(steps(viewport.clone(), bone, false, cx));
        section = section.child(steps(viewport.clone(), bone, true, cx));
        section = section.child(ui::small_button("pose-reset-bone", "Reset Bone").on_click(
            cx.listener({
                let viewport = viewport.clone();
                move |_this, _, _, cx| {
                    viewport
                        .clone()
                        .update(cx, |viewport, cx| viewport.reset_pose_bone(cx));
                }
            }),
        ));
    } else {
        section = section.child(
            div()
                .text_xs()
                .text_color(rgb(theme::TEXT_MUTED))
                .child("Select a bone to pose it."),
        );
    }
    section
        .child(
            ui::small_button("pose-reset-all", "Reset Pose").on_click(cx.listener({
                let viewport = viewport.clone();
                move |_this, _, _, cx| {
                    viewport
                        .clone()
                        .update(cx, |viewport, cx| viewport.reset_pose(cx));
                }
            })),
        )
        .into_any_element()
}

/// One row of six step buttons, for rotation or translation of `bone`.
fn steps<V: 'static>(
    viewport: Entity<Viewport>,
    bone: usize,
    translation: bool,
    cx: &Context<V>,
) -> AnyElement {
    let mut row = div().flex().items_center().gap_1().child(
        div()
            .w(px(58.))
            .flex_none()
            .text_xs()
            .text_color(rgb(theme::TEXT_MUTED))
            .child(if translation { "Move" } else { "Rotate" }),
    );
    for (axis, name) in ["X", "Y", "Z"].iter().enumerate() {
        for (slot, (sign, suffix)) in [(-1i32, "-"), (1i32, "+")].into_iter().enumerate() {
            let id = bone * 8 + axis * 2 + slot + if translation { 4096 } else { 0 };
            row = row.child(
                ui::small_button(("pose-step", id), format!("{name}{suffix}")).on_click(
                    cx.listener({
                        let viewport = viewport.clone();
                        move |_this, _, _, cx| {
                            let result = viewport.clone().update(cx, |viewport, cx| {
                                if translation {
                                    viewport.adjust_pose_translation(axis, sign, cx)
                                } else {
                                    viewport.adjust_pose_rotation(axis, sign, cx)
                                }
                            });
                            if let Err(err) = result {
                                log::warn!("pose step rejected: {err}");
                            }
                        }
                    }),
                ),
            );
        }
    }
    row.into_any_element()
}
