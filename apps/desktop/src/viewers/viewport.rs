//! 3D viewport backed by `lforge-renderer`.
//!
//! GPUI on Windows cannot composite textures from a foreign GPU device, so the
//! renderer draws offscreen on its own thread and frames reach GPUI as images.
//! The renderer itself is window-system independent and is also used for
//! headless images.

use std::sync::{Arc, mpsc};
use std::thread;
use std::time::Instant;

use futures::StreamExt;
use futures::channel::mpsc::{UnboundedSender, unbounded};
use gpui::{
    App, Bounds, Context, Corners, DevicePixels, DispatchPhase, Entity, MouseButton,
    MouseDownEvent, MouseMoveEvent, MouseUpEvent, Pixels, Point, RenderImage, ScrollEvent, Size,
    Window, canvas, div, prelude::*, rgb, size,
};
use image::{Frame as ImageFrame, RgbaImage};
use lforge_renderer::{Background, Frame, OrbitCamera, Renderer};
use lforge_scene::{Aabb, Scene};

use crate::ui::theme;

const ORBIT_RADIANS_PER_PIXEL: f32 = 0.008;
const ZOOM_PER_PIXEL: f32 = 0.0025;
const AUTO_ROTATE_RADIANS_PER_SECOND: f32 = 0.6;

pub enum RendererStatus {
    Starting,
    Ready { adapter: String, backend: String },
    Failed(String),
}

enum Response {
    Ready { adapter: String, backend: String },
    Frame(Frame),
    Failed(String),
}

struct Request {
    size: Size<DevicePixels>,
    camera: OrbitCamera,
}

#[derive(Clone, Copy)]
struct Drag {
    button: MouseButton,
    origin: Point<Pixels>,
}

pub struct Viewport {
    pub camera: OrbitCamera,
    pub status: RendererStatus,
    pub size: Size<DevicePixels>,
    pub auto_rotate: bool,
    bounds: Aabb,
    framed: bool,
    requests: Option<mpsc::Sender<Request>>,
    image: Option<Arc<RenderImage>>,
    stale_images: Vec<Arc<RenderImage>>,
    drag: Option<Drag>,
    last_tick: Option<Instant>,
}

impl Viewport {
    pub fn new(scene: Arc<Scene>, cx: &mut Context<Self>) -> Self {
        let bounds = scene.bounds.sanitized();
        let camera = OrbitCamera::framing(bounds, 1.0);
        let (response_tx, mut responses) = unbounded();
        let (requests, status) = match spawn_render_thread(scene, response_tx) {
            Ok(requests) => (Some(requests), RendererStatus::Starting),
            Err(err) => (
                None,
                RendererStatus::Failed(format!("failed to start render thread: {err}")),
            ),
        };

        cx.spawn(async move |this, cx| {
            while let Some(response) = responses.next().await {
                if this
                    .update(cx, |this, cx| this.handle_response(response, cx))
                    .is_err()
                {
                    break;
                }
            }
        })
        .detach();

        Self {
            camera,
            status,
            size: Size::default(),
            auto_rotate: false,
            bounds,
            framed: false,
            requests,
            image: None,
            stale_images: Vec::new(),
            drag: None,
            last_tick: None,
        }
    }

    pub fn reset_camera(&mut self, cx: &mut Context<Self>) {
        let aspect = if self.size.height.0 > 0 {
            self.size.width.0 as f32 / self.size.height.0 as f32
        } else {
            1.0
        };
        self.camera = OrbitCamera::framing(self.bounds, aspect);
        self.request_frame();
        cx.notify();
    }

    pub fn toggle_auto_rotate(&mut self, cx: &mut Context<Self>) {
        self.auto_rotate = !self.auto_rotate;
        self.last_tick = None;
        cx.notify();
    }

    fn handle_response(&mut self, response: Response, cx: &mut Context<Self>) {
        match response {
            Response::Ready { adapter, backend } => {
                self.status = RendererStatus::Ready { adapter, backend };
                self.request_frame();
            }
            Response::Frame(frame) => {
                let image = to_render_image(frame);
                self.stale_images.extend(self.image.replace(image));
            }
            Response::Failed(message) => {
                self.status = RendererStatus::Failed(message);
                self.requests = None;
            }
        }
        cx.notify();
    }

    fn request_frame(&mut self) {
        if self.size.width.0 <= 0 || self.size.height.0 <= 0 {
            return;
        }
        let Some(requests) = &self.requests else {
            return;
        };
        let request = Request {
            size: self.size,
            camera: self.camera,
        };
        if requests.send(request).is_err() {
            self.requests = None;
        }
    }

    fn resize(&mut self, size: Size<DevicePixels>) {
        if self.size == size {
            return;
        }
        self.size = size;
        if !self.framed && size.width.0 > 0 && size.height.0 > 0 {
            let aspect = size.width.0 as f32 / size.height.0 as f32;
            self.camera = OrbitCamera::framing(self.bounds, aspect);
            self.framed = true;
        }
        self.request_frame();
    }

    fn drag_to(&mut self, position: Point<Pixels>, scale_factor: f32, cx: &mut Context<Self>) {
        let Some(drag) = self.drag else {
            return;
        };
        let delta = position - drag.origin;
        self.drag = Some(Drag {
            origin: position,
            ..drag
        });
        match drag.button {
            MouseButton::Left => self.camera.orbit(
                -f32::from(delta.x) * ORBIT_RADIANS_PER_PIXEL,
                f32::from(delta.y) * ORBIT_RADIANS_PER_PIXEL,
            ),
            MouseButton::Middle => {
                let viewport_height = self.size.height.0 as f32 / scale_factor.max(0.01);
                self.camera
                    .pan(f32::from(delta.x), f32::from(delta.y), viewport_height);
            }
            _ => {}
        }
        self.request_frame();
        cx.notify();
    }

    fn scroll(&mut self, event: &ScrollEvent, window: &Window, cx: &mut Context<Self>) {
        let delta_y = f32::from(event.delta.pixel_delta(window.line_height()).y);
        self.camera.zoom((-delta_y * ZOOM_PER_PIXEL).exp());
        self.request_frame();
        cx.notify();
    }

    fn advance_auto_rotation(&mut self, window: &mut Window) {
        let now = Instant::now();
        if let Some(last_tick) = self.last_tick {
            let elapsed = now.duration_since(last_tick).as_secs_f32();
            self.camera
                .orbit(elapsed * AUTO_ROTATE_RADIANS_PER_SECOND, 0.0);
            self.request_frame();
        }
        self.last_tick = Some(now);
        window.request_animation_frame();
    }
}

impl Render for Viewport {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        for image in self.stale_images.drain(..) {
            if let Err(err) = window.drop_image(image) {
                log::error!("failed to release viewport frame: {err}");
            }
        }
        if self.auto_rotate {
            self.advance_auto_rotation(window);
        }

        let message = match &self.status {
            RendererStatus::Starting => Some("Initializing renderer."),
            RendererStatus::Failed(_) => Some("Renderer unavailable"),
            RendererStatus::Ready { .. } => None,
        };

        div()
            .id("viewport")
            .relative()
            .size_full()
            .overflow_hidden()
            .bg(rgb(theme::VIEWPORT))
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, event: &MouseDownEvent, _, _| {
                    this.drag = Some(Drag {
                        button: MouseButton::Left,
                        origin: event.position,
                    });
                }),
            )
            .on_mouse_down(
                MouseButton::Middle,
                cx.listener(|this, event: &MouseDownEvent, _, _| {
                    this.drag = Some(Drag {
                        button: MouseButton::Middle,
                        origin: event.position,
                    });
                }),
            )
            .on_mouse_up(
                MouseButton::Left,
                cx.listener(|this, _, _, _| this.drag = None),
            )
            .on_mouse_up(
                MouseButton::Middle,
                cx.listener(|this, _, _, _| this.drag = None),
            )
            .on_scroll(cx.listener(|this, event, window, cx| this.scroll(event, window, cx)))
            .child(viewport_canvas(cx.entity(), self.image.clone()))
            .children(message.map(|message| {
                div()
                    .absolute()
                    .inset_0()
                    .flex()
                    .items_center()
                    .justify_center()
                    .text_color(rgb(theme::TEXT_MUTED))
                    .child(message)
            }))
    }
}

fn viewport_canvas(
    viewport: Entity<Viewport>,
    image: Option<Arc<RenderImage>>,
) -> impl IntoElement {
    canvas(
        {
            let viewport = viewport.clone();
            move |bounds: Bounds<Pixels>, window: &mut Window, cx: &mut App| {
                let scale = window.scale_factor();
                let scaled = bounds.size.scale(scale);
                let size = size(
                    DevicePixels(scaled.width.0.round() as i32),
                    DevicePixels(scaled.height.0.round() as i32),
                );
                viewport.update(cx, |viewport, _| viewport.resize(size));
            }
        },
        move |bounds, (), window, _| {
            if let Some(image) = image
                && let Err(err) =
                    window.paint_image(bounds, bounds, Corners::default(), image, 0, false)
            {
                log::error!("failed to paint viewport frame: {err}");
            }

            // Window-level listeners keep a drag alive when the cursor leaves
            // the viewport.
            let drag_viewport = viewport.clone();
            window.on_mouse_event(move |event: &MouseMoveEvent, phase, window, cx| {
                if phase == DispatchPhase::Bubble {
                    let scale = window.scale_factor();
                    drag_viewport.update(cx, |viewport, cx| {
                        viewport.drag_to(event.position, scale, cx)
                    });
                }
            });
            window.on_mouse_event(move |event: &MouseUpEvent, phase, _, cx| {
                if phase == DispatchPhase::Bubble {
                    viewport.update(cx, |viewport, _| {
                        if viewport
                            .drag
                            .is_some_and(|drag| drag.button == event.button)
                        {
                            viewport.drag = None;
                        }
                    });
                }
            });
        },
    )
    .size_full()
}

fn spawn_render_thread(
    scene: Arc<Scene>,
    responses: UnboundedSender<Response>,
) -> std::io::Result<mpsc::Sender<Request>> {
    let (request_tx, requests) = mpsc::channel::<Request>();
    thread::Builder::new()
        .name("renderer".into())
        .spawn(move || {
            let mut renderer = match Renderer::new() {
                Ok(renderer) => renderer,
                Err(err) => {
                    let _ = responses.unbounded_send(Response::Failed(err.to_string()));
                    return;
                }
            };
            let info = renderer.adapter_info();
            let ready = Response::Ready {
                adapter: info.name.clone(),
                backend: info.backend.to_string(),
            };
            let gpu_scene = match renderer.upload_scene(&scene) {
                Ok(scene) => scene,
                Err(err) => {
                    let _ = responses.unbounded_send(Response::Failed(err.to_string()));
                    return;
                }
            };
            if responses.unbounded_send(ready).is_err() {
                return;
            }

            while let Ok(mut request) = requests.recv() {
                // Only the latest camera and size matter; skip frames that are
                // already stale.
                while let Ok(newer) = requests.try_recv() {
                    request = newer;
                }
                let response = match renderer.render(
                    &gpu_scene,
                    &request.camera,
                    request.size.width.0 as u32,
                    request.size.height.0 as u32,
                    Background::DARK,
                ) {
                    Ok(frame) => Response::Frame(frame),
                    Err(err) => Response::Failed(err.to_string()),
                };
                let failed = matches!(response, Response::Failed(_));
                if responses.unbounded_send(response).is_err() || failed {
                    return;
                }
            }
        })?;
    Ok(request_tx)
}

fn to_render_image(frame: Frame) -> Arc<RenderImage> {
    // GPUI's RenderImage expects BGRA8; the renderer's native order is RGBA8.
    let buffer = RgbaImage::from_raw(frame.width, frame.height, frame.to_bgra8())
        .expect("renderer returns width * height * 4 bytes");
    Arc::new(RenderImage::new([ImageFrame::new(buffer)]))
}
