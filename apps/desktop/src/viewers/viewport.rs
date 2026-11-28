//! 3D viewport backed by `lforge-renderer`.
//!
//! GPUI on Windows cannot composite textures from a foreign GPU device, so the
//! renderer draws offscreen on its own thread and frames reach GPUI as images.
//! The renderer itself is window-system independent and is also used for
//! headless images.

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Instant;

use futures::StreamExt;
use futures::channel::mpsc::{Receiver, Sender, channel};
use gpui::{
    App, Bounds, Context, Corners, DevicePixels, DispatchPhase, Entity, MouseButton,
    MouseDownEvent, MouseMoveEvent, MouseUpEvent, Pixels, Point, RenderImage, ScrollEvent, Size,
    Window, canvas, div, prelude::*, rgb, size,
};
use image::{Frame as ImageFrame, RgbaImage};
use lforge_renderer::{Background, Frame, OrbitCamera, Overlay, Renderer};
use lforge_scene::{Aabb, DeformationPolicy, Scene};

use super::pose::{PoseDisplay, PoseFrame, PoseSession};
use crate::ui::theme;

const ORBIT_RADIANS_PER_PIXEL: f32 = 0.008;
const ZOOM_PER_PIXEL: f32 = 0.0025;
const AUTO_ROTATE_RADIANS_PER_SECOND: f32 = 0.6;

pub enum RendererStatus {
    Starting,
    Ready { adapter: String, backend: String },
    Failed(String),
}

/// One pending replaceable render state. Submitting a newer state overwrites
/// the previous one, so the queue length cannot grow with resize or drag
/// events.
struct LatestState<T> {
    state: Mutex<Pending<T>>,
    ready: Condvar,
}

struct Pending<T> {
    value: Option<T>,
    closed: bool,
}

struct LatestSender<T> {
    state: Arc<LatestState<T>>,
}

impl<T> LatestState<T> {
    fn new() -> Self {
        Self {
            state: Mutex::new(Pending {
                value: None,
                closed: false,
            }),
            ready: Condvar::new(),
        }
    }

    fn submit(&self, value: T) -> bool {
        let mut pending = self.state.lock().unwrap_or_else(|err| err.into_inner());
        if pending.closed {
            return false;
        }
        pending.value = Some(value);
        self.ready.notify_one();
        true
    }

    fn next(&self) -> Option<T> {
        let mut pending = self.state.lock().unwrap_or_else(|err| err.into_inner());
        loop {
            if pending.closed {
                pending.value = None;
                return None;
            }
            if let Some(value) = pending.value.take() {
                return Some(value);
            }
            pending = self
                .ready
                .wait(pending)
                .unwrap_or_else(|err| err.into_inner());
        }
    }

    fn close(&self) {
        let mut pending = self.state.lock().unwrap_or_else(|err| err.into_inner());
        pending.closed = true;
        pending.value = None;
        self.ready.notify_all();
    }

    #[cfg(test)]
    fn pending_count(&self) -> usize {
        usize::from(
            self.state
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .value
                .is_some(),
        )
    }
}

impl<T> LatestSender<T> {
    fn new() -> (Self, Arc<LatestState<T>>) {
        let state = Arc::new(LatestState::new());
        (
            Self {
                state: state.clone(),
            },
            state,
        )
    }

    fn submit(&self, value: T) -> bool {
        self.state.submit(value)
    }
}

impl<T> Drop for LatestSender<T> {
    fn drop(&mut self) {
        self.state.close();
    }
}

enum Response {
    Ready { adapter: String, backend: String },
    Frame { generation: u64, frame: Frame },
    Failed(String),
}

/// A bounded completed-response queue. At most one frame is retained: a newer
/// completed frame replaces the queued one. Lifecycle messages are never
/// coalesced away.
struct ResponseQueue {
    pending: Mutex<VecDeque<Response>>,
    notify: Mutex<Sender<()>>,
}

const MAX_PENDING_RESPONSES: usize = 4;

impl ResponseQueue {
    fn new() -> (Arc<Self>, Receiver<()>) {
        let (notify, receiver) = channel(1);
        (
            Arc::new(Self {
                pending: Mutex::new(VecDeque::new()),
                notify: Mutex::new(notify),
            }),
            receiver,
        )
    }

    fn send(&self, response: Response) {
        let mut pending = self.pending.lock().unwrap_or_else(|err| err.into_inner());
        if matches!(response, Response::Frame { .. })
            && let Some(index) = pending
                .iter()
                .position(|queued| matches!(queued, Response::Frame { .. }))
        {
            pending.remove(index);
        }
        if pending.len() >= MAX_PENDING_RESPONSES
            && let Some(index) = pending
                .iter()
                .position(|queued| matches!(queued, Response::Frame { .. }))
                .or_else(|| (!pending.is_empty()).then_some(0))
        {
            pending.remove(index);
        }
        pending.push_back(response);
        drop(pending);
        let mut notify = self.notify.lock().unwrap_or_else(|err| err.into_inner());
        let _ = notify.try_send(());
    }

    fn take(&self) -> Option<Response> {
        self.pending
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .pop_front()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .len()
    }
}

#[derive(Clone)]
struct Request {
    generation: u64,
    size: Size<DevicePixels>,
    camera: OrbitCamera,
    /// One flag per scene mesh. Shared so a request stays cheap to clone.
    visibility: Arc<Vec<bool>>,
    skeleton: bool,
    selected_bone: Option<usize>,
    /// The pose to apply, built on the UI thread only while pose mode is on.
    pose: Option<Arc<PoseFrame>>,
    pose_active: bool,
    influence_view: bool,
    policy: lforge_scene::DeformationPolicy,
}

#[derive(Clone, Copy)]
struct Drag {
    button: MouseButton,
    origin: Point<Pixels>,
}

/// One visibility flag per scene mesh.
///
/// A fragment component owns a range of meshes, so a component toggle is a
/// range write and a mesh toggle is a single write. Visibility is a drawing
/// property only: no flag here can change a decoding or completeness verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Visibility {
    flags: Vec<bool>,
}

impl Visibility {
    fn new(meshes: usize) -> Self {
        Self {
            flags: vec![true; meshes],
        }
    }

    fn flags(&self) -> &[bool] {
        &self.flags
    }

    fn mesh(&self, mesh: usize) -> bool {
        self.flags.get(mesh).copied().unwrap_or(true)
    }

    /// Whether any mesh in `meshes` is shown.
    fn any(&self, meshes: std::ops::Range<usize>) -> bool {
        meshes.into_iter().any(|mesh| self.mesh(mesh))
    }

    /// Writes one flag. Returns whether anything changed.
    fn set_mesh(&mut self, mesh: usize, visible: bool) -> bool {
        match self.flags.get_mut(mesh) {
            Some(flag) if *flag != visible => {
                *flag = visible;
                true
            }
            _ => false,
        }
    }

    /// Writes every flag in a range. Returns whether anything changed.
    fn set_range(&mut self, meshes: std::ops::Range<usize>, visible: bool) -> bool {
        let mut changed = false;
        for mesh in meshes {
            changed |= self.set_mesh(mesh, visible);
        }
        changed
    }

    /// Writes every flag. Returns whether anything changed.
    fn set_all(&mut self, visible: bool) -> bool {
        if self.flags.iter().all(|flag| *flag == visible) {
            return false;
        }
        self.flags.fill(visible);
        true
    }

    /// The flags as they stand, for a later restore.
    fn snapshot(&self) -> Vec<bool> {
        self.flags.clone()
    }

    /// Puts a snapshot back. Returns whether anything changed, and never mixes
    /// a snapshot of a different scene into this one.
    fn restore(&mut self, snapshot: &[bool]) -> bool {
        if snapshot.len() != self.flags.len() || self.flags == snapshot {
            return false;
        }
        self.flags.clone_from_slice(snapshot);
        true
    }
}

pub struct Viewport {
    pub camera: OrbitCamera,
    pub status: RendererStatus,
    pub size: Size<DevicePixels>,
    pub auto_rotate: bool,
    bounds: Aabb,
    scene: Arc<Scene>,
    /// Mesh visibility, one flag per scene mesh. The decoded scene is never
    /// modified; the render thread applies the flags before drawing.
    visibility: Visibility,
    /// The flags in force before every mesh was hidden, so showing the meshes
    /// again restores a per-component or per-mesh choice instead of turning
    /// every mesh on.
    visibility_before_hide: Option<Vec<bool>>,
    /// Whether the skeleton overlay is drawn. Hidden by default so the model
    /// inspection experience is unchanged.
    skeleton_visible: bool,
    /// The highlighted bone, as an index into the scene's skeleton.
    selected_bone: Option<usize>,
    /// Pose mode state. `None` keeps the ordinary authored inspection path.
    pose: Option<PoseSession>,
    pose_cache: Option<Arc<PoseFrame>>,
    /// The reference frame that restores the authored skeleton after pose mode.
    pose_restore: Option<Arc<PoseFrame>>,
    framed: bool,
    requests: Option<LatestSender<Request>>,
    next_generation: u64,
    applied_generation: u64,
    image: Option<Arc<RenderImage>>,
    stale_images: Vec<Arc<RenderImage>>,
    drag: Option<Drag>,
    last_tick: Option<Instant>,
}

impl Viewport {
    pub fn new(scene: Arc<Scene>, cx: &mut Context<Self>) -> Self {
        let bounds = scene.bounds.sanitized();
        let visibility = Visibility::new(scene.meshes.len());
        let camera = OrbitCamera::framing(bounds, 1.0);
        let (responses, mut notifications) = ResponseQueue::new();
        let (requests, status) = match spawn_render_thread(scene.clone(), responses.clone()) {
            Ok(requests) => (Some(requests), RendererStatus::Starting),
            Err(err) => (
                None,
                RendererStatus::Failed(format!("failed to start render thread: {err}")),
            ),
        };

        cx.spawn(async move |this, cx| {
            while notifications.next().await.is_some() {
                while let Some(response) = responses.take() {
                    if this
                        .update(cx, |this, cx| this.handle_response(response, cx))
                        .is_err()
                    {
                        return;
                    }
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
            scene,
            visibility,
            visibility_before_hide: None,
            skeleton_visible: false,
            selected_bone: None,
            pose: None,
            pose_cache: None,
            pose_restore: None,
            framed: false,
            requests,
            next_generation: 0,
            applied_generation: 0,
            image: None,
            stale_images: Vec::new(),
            drag: None,
            last_tick: None,
        }
    }

    /// Whether scene mesh `mesh` is currently shown.
    pub fn mesh_visible(&self, mesh: usize) -> bool {
        self.visibility.mesh(mesh)
    }

    /// The scene's mesh count. Visibility is one flag per mesh, which is the
    /// model level: a component can own several meshes.
    pub fn mesh_count(&self) -> usize {
        self.scene.meshes.len()
    }

    /// The display name of scene mesh `mesh`.
    pub fn mesh_name(&self, mesh: usize) -> Option<&str> {
        self.scene.meshes.get(mesh).map(|mesh| mesh.name.as_str())
    }

    /// The primitive count of scene mesh `mesh`.
    pub fn mesh_primitives(&self, mesh: usize) -> usize {
        self.scene
            .meshes
            .get(mesh)
            .map(|mesh| mesh.primitives.len())
            .unwrap_or(0)
    }

    /// Whether any mesh of one component is currently shown.
    pub fn component_visible(&self, meshes: std::ops::Range<usize>) -> bool {
        self.visibility.any(meshes)
    }

    /// Shows or hides one mesh. This changes drawing only: it never changes a
    /// component's or a geometry's decoding status.
    pub fn set_mesh_visible(&mut self, mesh: usize, visible: bool, cx: &mut Context<Self>) {
        if self.visibility.set_mesh(mesh, visible) {
            self.request_frame();
            cx.notify();
        }
    }

    /// Shows or hides the meshes of one component.
    pub fn set_meshes_visible(
        &mut self,
        meshes: std::ops::Range<usize>,
        visible: bool,
        cx: &mut Context<Self>,
    ) {
        if self.visibility.set_range(meshes, visible) {
            self.request_frame();
            cx.notify();
        }
    }

    /// Shows every component.
    pub fn show_all_components(&mut self, cx: &mut Context<Self>) {
        if self.visibility.set_all(true) {
            self.request_frame();
            cx.notify();
        }
    }

    /// The scene's skeleton, when it has one. Reading it never decodes a
    /// resource: the decoded skeleton lives with the scene.
    pub fn skeleton(&self) -> Option<&lforge_scene::Skeleton> {
        self.scene.skeleton.as_ref()
    }

    /// The scene's validated primitive-to-bone associations.
    pub fn associations(&self) -> &[lforge_scene::PrimitiveBones] {
        &self.scene.associations
    }

    pub fn has_skeleton(&self) -> bool {
        self.scene.skeleton.is_some()
    }

    pub fn skeleton_visible(&self) -> bool {
        self.skeleton_visible
    }

    /// Shows or hides the skeleton overlay. This changes drawing only: no
    /// resource is read and no GPU geometry is replaced.
    pub fn set_skeleton_visible(&mut self, visible: bool, cx: &mut Context<Self>) {
        if self.skeleton_visible != visible {
            self.skeleton_visible = visible;
            self.request_frame();
            cx.notify();
        }
    }

    pub fn toggle_skeleton(&mut self, cx: &mut Context<Self>) {
        let visible = !self.skeleton_visible;
        self.set_skeleton_visible(visible, cx);
    }

    pub fn selected_bone(&self) -> Option<usize> {
        self.selected_bone
    }

    /// Highlights one bone. The selection is a uniform range, so no buffer is
    /// rebuilt and no resource is read.
    pub fn select_bone(&mut self, index: Option<usize>, cx: &mut Context<Self>) {
        let index = index.filter(|index| {
            self.scene
                .skeleton
                .as_ref()
                .is_some_and(|skeleton| *index < skeleton.bones.len())
        });
        if self.selected_bone != index {
            self.selected_bone = index;
            self.request_frame();
            cx.notify();
        }
    }

    /// Whether this scene has a pose-ready skeleton and at least one
    /// primitive with verified influences.
    pub fn pose_supported(&self) -> bool {
        self.scene.supports_deformation()
    }

    pub fn is_pose_mode(&self) -> bool {
        self.pose.is_some()
    }

    pub fn pose(&self) -> Option<&PoseSession> {
        self.pose.as_ref()
    }

    /// Enters pose mode at the verified reference pose.
    pub fn enter_pose_mode(&mut self, cx: &mut Context<Self>) {
        if self.pose.is_some() || !self.pose_supported() {
            return;
        }
        let bones = self
            .scene
            .skeleton
            .as_ref()
            .map_or(0, |skeleton| skeleton.bones.len());
        self.pose = Some(PoseSession::new(bones));
        self.pose_cache = None;
        self.pose_restore = None;
        self.request_frame();
        cx.notify();
    }

    /// Leaves pose mode and returns to the authored geometry.
    pub fn exit_pose_mode(&mut self, cx: &mut Context<Self>) {
        if self.pose.take().is_some() {
            self.pose_cache = None;
            // The joint matrices and the overlay lines still hold the last
            // pose, so one reference frame restores them.
            self.pose_restore = self
                .scene
                .skeleton
                .as_ref()
                .and_then(|skeleton| PoseFrame::reference(skeleton).ok())
                .map(Arc::new);
            self.request_frame();
            cx.notify();
        }
    }

    pub fn set_pose_display(&mut self, display: PoseDisplay, cx: &mut Context<Self>) {
        if let Some(pose) = &mut self.pose {
            pose.set_display(display);
            self.pose_cache = None;
            self.request_frame();
            cx.notify();
        }
    }

    pub fn set_influence_view(&mut self, enabled: bool, cx: &mut Context<Self>) {
        if let Some(pose) = &mut self.pose {
            pose.set_influence_view(enabled);
            self.pose_cache = None;
            self.request_frame();
            cx.notify();
        }
    }

    /// Adds rotation button presses to the selected bone.
    pub fn adjust_pose_rotation(
        &mut self,
        axis: usize,
        steps: i32,
        cx: &mut Context<Self>,
    ) -> Result<(), String> {
        let Some(bone) = self.selected_bone else {
            return Err("select a bone first".into());
        };
        let Some(pose) = &mut self.pose else {
            return Err("pose mode is not enabled".into());
        };
        pose.adjust_rotation(bone, axis, steps)
            .map_err(|err| err.to_string())?;
        self.pose_cache = None;
        self.request_frame();
        cx.notify();
        Ok(())
    }

    /// Adds translation button presses to the selected bone.
    pub fn adjust_pose_translation(
        &mut self,
        axis: usize,
        steps: i32,
        cx: &mut Context<Self>,
    ) -> Result<(), String> {
        let Some(bone) = self.selected_bone else {
            return Err("select a bone first".into());
        };
        let Some(pose) = &mut self.pose else {
            return Err("pose mode is not enabled".into());
        };
        pose.adjust_translation(bone, axis, steps)
            .map_err(|err| err.to_string())?;
        self.pose_cache = None;
        self.request_frame();
        cx.notify();
        Ok(())
    }

    pub fn reset_pose_bone(&mut self, cx: &mut Context<Self>) {
        let Some(bone) = self.selected_bone else {
            return;
        };
        if let Some(pose) = &mut self.pose {
            let _ = pose.reset_bone(bone);
            self.pose_cache = None;
            self.request_frame();
            cx.notify();
        }
    }

    pub fn reset_pose(&mut self, cx: &mut Context<Self>) {
        if let Some(pose) = &mut self.pose {
            pose.reset_all();
            self.pose_cache = None;
            self.request_frame();
            cx.notify();
        }
    }

    /// Includes or excludes inferred single-bone associations. Switches the
    /// renderer policy and nothing else: no reload, no re-decode, no upload.
    pub fn set_include_inferred(&mut self, include: bool, cx: &mut Context<Self>) {
        if let Some(pose) = &mut self.pose {
            pose.set_include_inferred(include);
            self.pose_cache = None;
            self.request_frame();
            cx.notify();
        }
    }

    /// How many primitives are associated only by inference.
    pub fn scene_inferred_primitive_count(&self) -> usize {
        self.scene.inferred_primitive_count()
    }

    pub fn include_inferred(&self) -> bool {
        self.pose
            .as_ref()
            .is_some_and(|pose| pose.include_inferred())
    }

    pub fn pose_rotation_degrees(&self, bone: usize) -> Option<[f32; 3]> {
        self.pose.as_ref()?.rotation_degrees(bone)
    }

    pub fn pose_translation(&self, bone: usize) -> Option<glam::Vec3> {
        self.pose.as_ref()?.translation(bone)
    }

    /// The current pose frame, cached by the session revision.
    fn pose_frame(&mut self) -> Option<Arc<PoseFrame>> {
        let session = self.pose.as_ref()?;
        let skeleton = self.scene.skeleton.as_ref()?;
        if let Some(cached) = &self.pose_cache
            && cached.revision == session.revision()
        {
            return Some(cached.clone());
        }
        let frame = Arc::new(session.frame(skeleton).ok()?);
        self.pose_cache = Some(frame.clone());
        Some(frame)
    }

    /// A short report of what deforms and what stays authored.
    ///
    /// An inferred association is counted apart: the geometry declares no
    /// influence attribute, so its single bone is an inference from the
    /// one-bone count rather than a decoded stream.
    pub fn deformation_report(&self) -> String {
        let include_inferred = self.include_inferred();
        let policy = lforge_scene::DeformationPolicy { include_inferred };
        let deformable = self.scene.deformable_primitive_count_under(policy);
        let inferred = self.scene.inferred_primitive_count();
        let total: usize = self
            .scene
            .meshes
            .iter()
            .map(|mesh| mesh.primitives.len())
            .sum();
        match &self.scene.skeleton {
            Some(skeleton) => {
                let inferred = match (inferred, include_inferred) {
                    (0, _) => String::new(),
                    (count, true) => format!(" ({count} inferred single-bone included)"),
                    (count, false) => format!(" ({count} inferred single-bone excluded)"),
                };
                format!(
                    "{deformable} of {total} primitive(s) deform{inferred}; {} bone(s)",
                    skeleton.bones.len()
                )
            }
            None => "no skeleton".to_string(),
        }
    }

    /// Whether at least one scene mesh is currently shown.
    pub fn any_mesh_visible(&self) -> bool {
        self.visibility.flags().iter().any(|flag| *flag)
    }

    /// Shows or hides every scene mesh. Independent of the skeleton overlay.
    ///
    /// Hiding every mesh remembers the flags that were in force, so showing
    /// them again restores the per-mesh and per-component choices rather than
    /// turning on a mesh the user had hidden.
    pub fn set_all_meshes_visible(&mut self, visible: bool, cx: &mut Context<Self>) {
        if visible {
            if let Some(previous) = self.visibility_before_hide.take()
                && self.visibility.restore(&previous)
            {
                self.request_frame();
                cx.notify();
                return;
            }
        } else if self.any_mesh_visible() {
            self.visibility_before_hide = Some(self.visibility.snapshot());
        }
        if self.visibility.set_all(visible) {
            self.request_frame();
            cx.notify();
        }
    }

    /// Restores the initial visibility state, which is every component shown.
    pub fn restore_default_visibility(&mut self, cx: &mut Context<Self>) {
        self.show_all_components(cx);
    }

    /// Bounds of the deformed geometry while the posed display is active.
    ///
    /// Only `Reset View` reads this; the frame loop never recomputes it.
    fn posed_view_bounds(&self) -> Option<Aabb> {
        let session = self.pose.as_ref()?;
        if session.display() != PoseDisplay::Posed {
            return None;
        }
        let mut bounds = self.scene.posed_bounds(session.pose()).ok().flatten()?;
        // Framing includes the primitives the pose does not move. Their
        // authored bounds are where they still are, so leaving them out would
        // crop them.
        bounds = bounds.union(self.scene.authored_bounds_outside(DeformationPolicy {
            include_inferred: session.include_inferred(),
        }));
        if self.skeleton_visible
            && let Some(skeleton) = self.scene.skeleton.as_ref()
            && let Ok(globals) = session.pose().globals(skeleton)
        {
            for bone in globals {
                bounds = bounds.extend(bone.model_position);
            }
        }
        Some(bounds)
    }

    /// Bounds of the meshes that are currently shown. Falls back to the whole
    /// scene when nothing is visible, so framing never fails.
    fn visible_bounds(&self) -> Aabb {
        if let Some(bounds) = self.posed_view_bounds()
            && bounds.is_finite()
            && !bounds.is_empty()
        {
            return bounds.sanitized();
        }
        let mut bounds = Aabb::EMPTY;
        let mut any = false;
        for (index, mesh) in self.scene.meshes.iter().enumerate() {
            if !self.visibility.mesh(index) {
                continue;
            }
            any = true;
            for primitive in &mesh.primitives {
                for vertex in &primitive.vertices {
                    let point = mesh
                        .transform
                        .transform_point3(glam::Vec3::from(vertex.position));
                    bounds = bounds.extend(point);
                }
            }
        }
        if any && bounds.is_finite() && !bounds.is_empty() {
            bounds.sanitized()
        } else if self.skeleton_visible
            && let Some(skeleton) = self.scene.skeleton.as_ref()
        {
            let bounds = skeleton.bounds();
            if bounds.is_finite() && !bounds.is_empty() {
                bounds.sanitized()
            } else {
                self.bounds
            }
        } else {
            self.bounds
        }
    }

    pub fn reset_camera(&mut self, cx: &mut Context<Self>) {
        let aspect = if self.size.height.0 > 0 {
            self.size.width.0 as f32 / self.size.height.0 as f32
        } else {
            1.0
        };
        self.camera = OrbitCamera::framing(self.visible_bounds(), aspect);
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
            Response::Frame { generation, frame } => {
                if generation < self.applied_generation {
                    return;
                }
                self.applied_generation = generation;
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
        let pose = self.pose_frame().or_else(|| self.pose_restore.clone());
        let Some(requests) = &self.requests else {
            return;
        };
        self.next_generation = self.next_generation.wrapping_add(1);
        let pose_active = pose.as_ref().is_some_and(|frame| frame.active);
        let influence_view = pose.as_ref().is_some_and(|frame| frame.influence);
        let policy = pose
            .as_ref()
            .map_or(lforge_scene::DeformationPolicy::EXPLICIT, |frame| {
                frame.policy
            });
        let request = Request {
            generation: self.next_generation,
            size: self.size,
            camera: self.camera,
            visibility: Arc::new(self.visibility.flags().to_vec()),
            skeleton: self.skeleton_visible,
            selected_bone: self.selected_bone,
            pose,
            pose_active,
            influence_view,
            policy,
        };
        if !requests.submit(request) {
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
    responses: Arc<ResponseQueue>,
) -> std::io::Result<LatestSender<Request>> {
    let (request_tx, requests) = LatestSender::<Request>::new();
    thread::Builder::new()
        .name("renderer".into())
        .spawn(move || {
            let mut renderer = match Renderer::new() {
                Ok(renderer) => renderer,
                Err(err) => {
                    responses.send(Response::Failed(err.to_string()));
                    return;
                }
            };
            let info = renderer.adapter_info();
            let ready = Response::Ready {
                adapter: info.name.clone(),
                backend: info.backend.to_string(),
            };
            let mut gpu_scene = match renderer.upload_scene(&scene) {
                Ok(scene) => scene,
                Err(err) => {
                    responses.send(Response::Failed(err.to_string()));
                    return;
                }
            };
            responses.send(ready);

            let mut applied: Option<Arc<Vec<bool>>> = None;
            let mut applied_pose: Option<u64> = None;
            while let Some(request) = requests.next() {
                if applied
                    .as_ref()
                    .is_none_or(|current| **current != *request.visibility)
                {
                    for (mesh, visible) in request.visibility.iter().enumerate() {
                        gpu_scene.set_mesh_visible(mesh, *visible);
                    }
                    applied = Some(request.visibility.clone());
                }
                if let Some(pose) = &request.pose
                    && applied_pose != Some(pose.revision)
                {
                    if let Err(err) =
                        renderer.update_pose(&mut gpu_scene, &pose.matrices, &pose.bone_positions)
                    {
                        responses.send(Response::Failed(err.to_string()));
                        return;
                    }
                    applied_pose = Some(pose.revision);
                }
                if request.pose.is_none() {
                    applied_pose = None;
                }
                gpu_scene.set_policy(request.policy);
                gpu_scene.set_pose_active(request.pose_active);
                gpu_scene.set_influence_view(request.influence_view);
                gpu_scene.set_skeleton_visible(request.skeleton);
                gpu_scene.set_skeleton_selected(request.selected_bone);
                let response = match renderer.render_with_overlay(
                    &gpu_scene,
                    &request.camera,
                    request.size.width.0 as u32,
                    request.size.height.0 as u32,
                    Background::DARK,
                    Overlay {
                        visible: request.skeleton,
                        selected: request.selected_bone,
                        // The inspector is for looking at bones inside opaque
                        // geometry, so the interactive overlay ignores depth.
                        depth_independent: true,
                    },
                ) {
                    Ok(frame) => Response::Frame {
                        generation: request.generation,
                        frame,
                    },
                    Err(err) => Response::Failed(err.to_string()),
                };
                let failed = matches!(response, Response::Failed(_));
                responses.send(response);
                if failed {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A burst of pose changes leaves one pending request, and it is the last
    /// one. This is what keeps rapid button presses from queuing work: the
    /// render thread wakes once per idle turn and takes the newest value.
    #[test]
    fn a_burst_of_pose_requests_keeps_only_the_latest() {
        let (sender, state) = LatestSender::new();
        for revision in 0..200u64 {
            assert!(sender.submit(revision), "submission {revision}");
        }
        assert_eq!(state.next(), Some(199));
        // Nothing is queued behind the value that was taken.
        drop(sender);
        assert_eq!(state.next(), None);
    }

    #[test]
    fn a_closed_request_queue_rejects_further_work() {
        let (sender, state) = LatestSender::new();
        assert!(sender.submit(1u64));
        drop(sender);
        assert_eq!(state.next(), None);
    }

    #[test]
    fn completed_frames_keep_only_the_newest_and_never_drop_lifecycle_messages() {
        let (queue, _receiver) = ResponseQueue::new();
        queue.send(Response::Ready {
            adapter: "adapter".into(),
            backend: "backend".into(),
        });
        for generation in 0..50 {
            queue.send(Response::Frame {
                generation,
                frame: Frame {
                    width: 1,
                    height: 1,
                    pixels: vec![generation as u8; 4],
                },
            });
        }
        queue.send(Response::Failed("later".into()));
        let first = queue.take().expect("a response");
        assert!(matches!(first, Response::Ready { .. }));
        let second = queue.take().expect("a response");
        match second {
            Response::Frame { generation, .. } => assert_eq!(generation, 49),
            Response::Failed(reason) => panic!("expected the newest frame, got {reason}"),
            Response::Ready { .. } => panic!("expected the newest frame, got the ready message"),
        }
        assert!(matches!(queue.take(), Some(Response::Failed(_))));
        assert_eq!(queue.len(), 0);
    }

    #[test]
    fn a_component_toggle_hides_every_mesh_it_owns() {
        let mut visibility = Visibility::new(4);
        // Two components: meshes 0..2 and 2..4.
        assert!(visibility.set_range(0..2, false));
        assert!(!visibility.mesh(0));
        assert!(!visibility.mesh(1));
        assert!(visibility.mesh(2), "the other component is untouched");
        assert!(!visibility.any(0..2));
        assert!(visibility.any(2..4));
    }

    #[test]
    fn a_mesh_toggle_touches_only_that_mesh() {
        let mut visibility = Visibility::new(3);
        assert!(visibility.set_mesh(1, false));
        assert!(visibility.mesh(0));
        assert!(!visibility.mesh(1));
        assert!(visibility.mesh(2));
        // The component stays partly visible, so it still reports shown.
        assert!(visibility.any(0..3));
        assert!(
            !visibility.set_mesh(1, false),
            "a repeated write changes nothing"
        );
    }

    #[test]
    fn visibility_covers_exactly_the_scene_meshes() {
        let mut visibility = Visibility::new(2);
        assert_eq!(visibility.flags().len(), 2);
        // A mesh index outside the scene never hides anything.
        assert!(!visibility.set_mesh(9, false));
        assert!(visibility.mesh(9), "an unknown mesh is treated as shown");
        assert!(visibility.set_all(false));
        assert!(
            !visibility.set_all(false),
            "a repeated write changes nothing"
        );
    }

    #[test]
    fn rapid_updates_keep_one_pending_state_and_return_the_latest() {
        let state = Arc::new(LatestState::new());
        for value in 0..1000 {
            assert!(state.submit(value));
            assert_eq!(state.pending_count(), 1);
        }
        assert_eq!(state.next(), Some(999));
        assert_eq!(state.pending_count(), 0);
    }

    #[test]
    fn closing_wakes_a_waiting_consumer() {
        let (sender, state) = LatestSender::<i32>::new();
        let (done, result) = std::sync::mpsc::channel();
        let waiting = thread::spawn(move || {
            done.send(state.next()).unwrap();
        });
        drop(sender);
        assert_eq!(result.recv_timeout(Duration::from_secs(1)).unwrap(), None);
        waiting.join().unwrap();
    }

    #[test]
    fn a_submit_after_close_is_rejected() {
        let (sender, state) = LatestSender::<i32>::new();
        drop(sender);
        assert!(!state.submit(1));
        assert_eq!(state.next(), None);
    }

    #[test]
    fn completed_responses_keep_one_frame_and_preserve_lifecycle_messages() {
        let (queue, _notifications) = ResponseQueue::new();
        queue.send(Response::Ready {
            adapter: "test".into(),
            backend: "test".into(),
        });
        queue.send(Response::Failed("stop".into()));
        for generation in 0..100 {
            queue.send(Response::Frame {
                generation,
                frame: Frame {
                    width: 1,
                    height: 1,
                    pixels: vec![0; 4],
                },
            });
        }
        assert!(queue.len() <= MAX_PENDING_RESPONSES);
        let mut ready = false;
        let mut failed = false;
        let mut latest_frame = None;
        while let Some(response) = queue.take() {
            match response {
                Response::Ready { .. } => ready = true,
                Response::Failed(_) => failed = true,
                Response::Frame { generation, .. } => latest_frame = Some(generation),
            }
        }
        assert!(ready);
        assert!(failed);
        assert_eq!(latest_frame, Some(99));
    }
}

#[cfg(test)]
mod visibility_tests {
    use super::Visibility;

    #[test]
    fn hiding_every_mesh_and_showing_them_again_keeps_the_per_mesh_choices() {
        let mut visibility = Visibility::new(3);
        visibility.set_mesh(1, false);
        let before = visibility.snapshot();
        assert!(visibility.set_all(false));
        assert!(!visibility.mesh(0) && !visibility.mesh(1) && !visibility.mesh(2));
        assert!(visibility.restore(&before));
        assert!(visibility.mesh(0));
        assert!(!visibility.mesh(1));
        assert!(visibility.mesh(2));
    }

    #[test]
    fn a_snapshot_of_a_different_scene_is_ignored() {
        let mut visibility = Visibility::new(2);
        assert!(!visibility.restore(&[false, false, false]));
        assert!(visibility.mesh(0) && visibility.mesh(1));
    }
}
