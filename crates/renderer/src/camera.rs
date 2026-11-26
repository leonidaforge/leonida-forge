//! Perspective orbit camera in RAGE space (Z up).

use std::f32::consts::{FRAC_PI_2, TAU};

use glam::camera::rh::{proj, view};
use glam::{Mat4, Vec3};

use lforge_scene::Aabb;

const MAX_PITCH: f32 = FRAC_PI_2 - 0.01;

/// A camera that orbits a target point. Distances are in model units.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OrbitCamera {
    pub target: Vec3,
    pub yaw: f32,
    pub pitch: f32,
    pub distance: f32,
    pub fov_y: f32,
    pub near: f32,
    pub far: f32,
    pub min_distance: f32,
    pub max_distance: f32,
}

impl Default for OrbitCamera {
    fn default() -> Self {
        Self {
            target: Vec3::ZERO,
            yaw: 0.65,
            pitch: 0.35,
            distance: 5.0,
            fov_y: 45f32.to_radians(),
            near: 0.01,
            far: 1000.0,
            min_distance: 0.01,
            max_distance: 100_000.0,
        }
    }
}

impl OrbitCamera {
    /// Frames the whole box, including its depth, in a viewport of `aspect`.
    pub fn framing(bounds: Aabb, aspect: f32) -> Self {
        let bounds = bounds.sanitized();
        let radius = bounds.radius().max(0.05);
        let aspect = if aspect.is_finite() && aspect > 0.0 {
            aspect
        } else {
            1.0
        };
        let mut camera = Self {
            target: bounds.center(),
            ..Self::default()
        };
        // A flat panel is nearly invisible from the default three-quarter
        // view; look across its thin axis instead.
        let size = bounds.size();
        if size.y < size.x.min(size.z) * 0.2 {
            camera.yaw = FRAC_PI_2;
            camera.pitch = 0.15;
        } else if size.z < size.x.min(size.y) * 0.2 {
            camera.pitch = 1.2;
        }
        let fov_x = 2.0 * ((camera.fov_y * 0.5).tan() * aspect).atan();
        let limiting = camera.fov_y.min(fov_x).max(1f32.to_radians());
        // A small margin keeps the silhouette off the viewport edges.
        camera.distance = radius / (limiting * 0.5).sin() * 1.15;
        camera.min_distance = radius * 0.02;
        camera.max_distance = radius * 500.0;
        camera.near = (camera.distance - radius * 2.0)
            .max(radius * 0.001)
            .max(0.0001);
        camera.far = (camera.distance + radius * 4.0).max(camera.near + radius * 8.0);
        camera
    }

    pub fn orbit(&mut self, delta_yaw: f32, delta_pitch: f32) {
        self.yaw = (self.yaw + delta_yaw).rem_euclid(TAU);
        self.pitch = (self.pitch + delta_pitch).clamp(-MAX_PITCH, MAX_PITCH);
    }

    /// Scales the distance to the target; factors below one move closer.
    pub fn zoom(&mut self, factor: f32) {
        if factor.is_finite() && factor >= 0.0 {
            self.distance = (self.distance * factor).clamp(self.min_distance, self.max_distance);
        }
    }

    /// Moves the target in the camera plane. `dx` and `dy` are pixels; the
    /// viewport height sets the scale so the model follows the pointer.
    pub fn pan(&mut self, dx: f32, dy: f32, viewport_height: f32) {
        if viewport_height <= 0.0 || !dx.is_finite() || !dy.is_finite() {
            return;
        }
        let forward = (self.target - self.eye()).normalize_or_zero();
        if forward == Vec3::ZERO {
            return;
        }
        let right = forward.cross(Vec3::Z).normalize_or_zero();
        let up = right.cross(forward).normalize_or_zero();
        let world_per_pixel = 2.0 * self.distance * (self.fov_y * 0.5).tan() / viewport_height;
        self.target += (-right * dx + up * dy) * world_per_pixel;
    }

    pub fn eye(&self) -> Vec3 {
        let (sin_yaw, cos_yaw) = self.yaw.sin_cos();
        let (sin_pitch, cos_pitch) = self.pitch.sin_cos();
        self.target + self.distance * Vec3::new(cos_pitch * cos_yaw, cos_pitch * sin_yaw, sin_pitch)
    }

    pub fn view(&self) -> Mat4 {
        view::look_at_mat4(self.eye(), self.target, Vec3::Z)
    }

    /// Clip space matches wgpu: Y up, depth in 0..1.
    pub fn projection(&self, aspect: f32) -> Mat4 {
        let aspect = if aspect.is_finite() && aspect > 0.0 {
            aspect
        } else {
            1.0
        };
        proj::directx::perspective(self.fov_y, aspect, self.near, self.far)
    }

    pub fn view_projection(&self, aspect: f32) -> Mat4 {
        self.projection(aspect) * self.view()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pitch_stays_below_the_poles() {
        let mut camera = OrbitCamera::default();
        camera.orbit(0.0, 10.0);
        assert_eq!(camera.pitch, MAX_PITCH);
        camera.orbit(0.0, -20.0);
        assert_eq!(camera.pitch, -MAX_PITCH);
    }

    #[test]
    fn yaw_wraps_around() {
        let mut camera = OrbitCamera {
            yaw: 0.0,
            ..Default::default()
        };
        camera.orbit(TAU + 1.0, 0.0);
        assert!((camera.yaw - 1.0).abs() < 1e-5);
    }

    #[test]
    fn zoom_is_clamped_around_the_initial_distance() {
        let mut camera = OrbitCamera::framing(
            Aabb {
                min: Vec3::splat(-1.0),
                max: Vec3::splat(1.0),
            },
            16.0 / 9.0,
        );
        let initial = camera.distance;
        camera.zoom(0.0);
        assert_eq!(camera.distance, camera.min_distance);
        camera.zoom(f32::INFINITY);
        assert_eq!(camera.distance, camera.min_distance);
        camera.zoom(1e9);
        assert_eq!(camera.distance, camera.max_distance);
        camera.zoom(initial / camera.max_distance);
        assert!((camera.distance - initial).abs() < 1e-3);
    }

    #[test]
    fn framing_puts_the_whole_box_inside_the_frustum() {
        let bounds = Aabb {
            min: Vec3::new(-2.0, -1.0, 0.0),
            max: Vec3::new(2.0, 1.0, 4.0),
        };
        let camera = OrbitCamera::framing(bounds, 16.0 / 9.0);
        let vp = camera.view_projection(16.0 / 9.0);
        for corner in [
            Vec3::new(-2.0, -1.0, 0.0),
            Vec3::new(2.0, 1.0, 4.0),
            Vec3::new(-2.0, 1.0, 4.0),
            Vec3::new(2.0, -1.0, 0.0),
        ] {
            let clip = vp * corner.extend(1.0);
            let ndc = clip.truncate() / clip.w;
            assert!((-1.0..=1.0).contains(&ndc.x), "{ndc}");
            assert!((-1.0..=1.0).contains(&ndc.y), "{ndc}");
            assert!((0.0..=1.0).contains(&ndc.z), "{ndc}");
        }
    }

    #[test]
    fn target_projects_to_viewport_center() {
        let camera = OrbitCamera::default();
        let clip = camera.view_projection(16.0 / 9.0) * camera.target.extend(1.0);
        let ndc = clip.truncate() / clip.w;
        assert!(ndc.x.abs() < 1e-5 && ndc.y.abs() < 1e-5);
        assert!((0.0..1.0).contains(&ndc.z));
    }

    #[test]
    fn pan_moves_the_target_perpendicular_to_the_view() {
        let mut camera = OrbitCamera::default();
        let before = camera.target;
        let eye_before = camera.eye();
        camera.pan(10.0, -5.0, 800.0);
        assert_ne!(camera.target, before);
        let moved = camera.target - before;
        let forward = (before - eye_before).normalize();
        assert!(moved.dot(forward).abs() < 1e-4);
    }
}
