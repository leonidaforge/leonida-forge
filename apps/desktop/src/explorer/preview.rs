use std::path::PathBuf;

use gpui::{Context, FontWeight, ObjectFit, SharedString, Task, div, img, prelude::*, px, rgb};

use super::{Explorer, browser::entry_icon};
use crate::fs::{self, Entry};
use crate::images::{self, DecodedImage};
use crate::theme;
use crate::ui;

/// Longest side of decoded thumbnails, in pixels.
const THUMBNAIL_SIZE: u32 = 512;

pub(super) struct Thumbnail {
    path: PathBuf,
    state: ThumbnailState,
    _task: Task<()>,
}

enum ThumbnailState {
    Loading,
    Ready(DecodedImage),
    Failed(String),
}

impl Explorer {
    /// Starts or drops the thumbnail so it matches the selected entry.
    pub(super) fn update_thumbnail(&mut self, cx: &mut Context<Self>) {
        let wanted = self
            .selected_entry()
            .filter(|entry| entry.is_supported_image())
            .map(|entry| entry.path.clone());
        if self.thumbnail.as_ref().map(|thumbnail| &thumbnail.path) == wanted.as_ref() {
            return;
        }
        if let Some(Thumbnail {
            state: ThumbnailState::Ready(decoded),
            ..
        }) = self.thumbnail.take()
        {
            self.stale_images.push(decoded.image);
        }
        let Some(path) = wanted else {
            return;
        };

        let decode = cx.background_spawn({
            let path = path.clone();
            async move { images::load_thumbnail(&path, THUMBNAIL_SIZE) }
        });
        let task = cx.spawn({
            let path = path.clone();
            async move |this, cx| {
                let result = decode.await;
                this.update(cx, |this, cx| {
                    if let Some(thumbnail) = &mut this.thumbnail
                        && thumbnail.path == path
                    {
                        thumbnail.state = match result {
                            Ok(decoded) => ThumbnailState::Ready(decoded),
                            Err(err) => ThumbnailState::Failed(err),
                        };
                        cx.notify();
                    }
                })
                .ok();
            }
        });
        self.thumbnail = Some(Thumbnail {
            path,
            state: ThumbnailState::Loading,
            _task: task,
        });
    }

    pub(super) fn render_preview(&self, width: f32) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .flex_none()
            .w(px(width))
            .h_full()
            .overflow_hidden()
            .bg(rgb(theme::PANEL))
            .child(
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .h(px(32.))
                    .px_3()
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Preview"),
            )
            .child(match self.selected_entry() {
                Some(entry) => self.render_entry_preview(entry).into_any_element(),
                None => div()
                    .flex()
                    .flex_1()
                    .items_center()
                    .justify_center()
                    .p_4()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child("No item selected")
                    .into_any_element(),
            })
    }

    fn render_entry_preview(&self, entry: &Entry) -> impl IntoElement {
        let (glyph, color) = entry_icon(entry);
        let thumbnail = self
            .thumbnail
            .as_ref()
            .filter(|thumbnail| thumbnail.path == entry.path)
            .map(|thumbnail| &thumbnail.state);

        let picture = match thumbnail {
            Some(ThumbnailState::Ready(decoded)) => img(decoded.image.clone())
                .size_full()
                .object_fit(ObjectFit::Contain)
                .into_any_element(),
            Some(ThumbnailState::Failed(_)) => div()
                .flex()
                .flex_col()
                .items_center()
                .gap_2()
                .child(ui::icon(glyph, px(56.), color))
                .child(
                    div()
                        .text_xs()
                        .text_color(rgb(theme::TEXT_MUTED))
                        .child("Preview unavailable"),
                )
                .into_any_element(),
            Some(ThumbnailState::Loading) | None => {
                ui::icon(glyph, px(64.), color).into_any_element()
            }
        };

        let mut properties: Vec<(&str, SharedString)> = vec![("Type", entry.type_name().into())];
        if let Some(size) = entry.size {
            properties.push((
                "Size",
                format!(
                    "{} ({} bytes)",
                    fs::format_size(size),
                    fs::format_bytes_exact(size)
                )
                .into(),
            ));
        }
        if let Some(ThumbnailState::Ready(decoded)) = thumbnail {
            properties.push((
                "Dimensions",
                format!("{} × {}", decoded.width, decoded.height).into(),
            ));
        }
        if let Some(ThumbnailState::Failed(err)) = thumbnail {
            properties.push(("Image", err.clone().into()));
        }
        if let Some(modified) = entry.modified {
            properties.push(("Modified", fs::format_modified(modified).into()));
        }
        properties.push(("Path", entry.path.display().to_string().into()));

        div()
            .id("preview")
            .flex()
            .flex_col()
            .flex_1()
            .min_h_0()
            .overflow_y_scroll()
            .px_3()
            .pb_3()
            .child(
                div()
                    .flex()
                    .flex_none()
                    .items_center()
                    .justify_center()
                    .h(px(200.))
                    .p_2()
                    .rounded_md()
                    .border_1()
                    .border_color(rgb(theme::BORDER))
                    .bg(rgb(theme::VIEWPORT))
                    .child(picture),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .mt_3()
                    .child(ui::icon(glyph, px(24.), color))
                    .child(
                        div()
                            .flex()
                            .flex_col()
                            .min_w_0()
                            .child(
                                div()
                                    .font_weight(FontWeight::SEMIBOLD)
                                    .child(entry.name.clone()),
                            )
                            .child(
                                div()
                                    .text_xs()
                                    .text_color(rgb(theme::TEXT_MUTED))
                                    .child(entry.type_name()),
                            ),
                    ),
            )
            .child(
                div()
                    .mt_4()
                    .mb_1()
                    .pt_3()
                    .border_t_1()
                    .border_color(rgb(theme::BORDER))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child("Properties"),
            )
            .children(properties.into_iter().map(|(label, value)| {
                div()
                    .flex()
                    .gap_3()
                    .py(px(3.))
                    .text_xs()
                    .child(
                        div()
                            .flex_none()
                            .w(px(76.))
                            .text_color(rgb(theme::TEXT_MUTED))
                            .child(label),
                    )
                    .child(div().flex_1().min_w_0().child(value))
            }))
    }
}
