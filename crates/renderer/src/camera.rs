use std::f32::consts::{FRAC_PI_2, TAU};

use glam::camera::rh::{proj, view};
use glam::{Mat4, Vec3};

const MAX_PITCH: f32 = FRAC_PI_2 - 0.01;
const MIN_DISTANCE: f32 = 1.5;
const MAX_DISTANCE: f32 = 50.0;

/// Perspective camera orbiting the origin.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct OrbitCamera {
    pub yaw: f32,
    pub pitch: f32,
    pub distance: f32,
    pub fov_y: f32,
}

impl Default for OrbitCamera {
    fn default() -> Self {
        Self {
            yaw: 0.6,
            pitch: 0.45,
            distance: 4.5,
            fov_y: 45f32.to_radians(),
        }
    }
}

impl OrbitCamera {
    pub fn orbit(&mut self, delta_yaw: f32, delta_pitch: f32) {
        self.yaw = (self.yaw + delta_yaw).rem_euclid(TAU);
        self.pitch = (self.pitch + delta_pitch).clamp(-MAX_PITCH, MAX_PITCH);
    }

    /// Scales the distance to the target; factors below 1 move closer.
    pub fn zoom(&mut self, factor: f32) {
        self.distance = (self.distance * factor).clamp(MIN_DISTANCE, MAX_DISTANCE);
    }

    pub fn eye(&self) -> Vec3 {
        let (sin_yaw, cos_yaw) = self.yaw.sin_cos();
        let (sin_pitch, cos_pitch) = self.pitch.sin_cos();
        self.distance * Vec3::new(cos_pitch * sin_yaw, sin_pitch, cos_pitch * cos_yaw)
    }

    pub fn view_projection(&self, aspect: f32) -> Mat4 {
        // wgpu clip space matches Direct3D: y up, depth in 0..1.
        let projection = proj::directx::perspective(self.fov_y, aspect, 0.1, 100.0);
        projection * view::look_at_mat4(self.eye(), Vec3::ZERO, Vec3::Y)
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
        camera.orbit(-2.0, 0.0);
        assert!((camera.yaw - (TAU - 1.0)).abs() < 1e-5);
    }

    #[test]
    fn zoom_is_clamped() {
        let mut camera = OrbitCamera::default();
        camera.zoom(0.0);
        assert_eq!(camera.distance, MIN_DISTANCE);
        camera.zoom(1000.0);
        assert_eq!(camera.distance, MAX_DISTANCE);
    }

    #[test]
    fn eye_is_at_distance_from_target() {
        let camera = OrbitCamera {
            yaw: 1.2,
            pitch: -0.7,
            distance: 7.0,
            ..Default::default()
        };
        assert!((camera.eye().length() - 7.0).abs() < 1e-5);
    }

    #[test]
    fn target_projects_to_viewport_center() {
        let camera = OrbitCamera::default();
        let clip = camera.view_projection(16.0 / 9.0) * Vec3::ZERO.extend(1.0);
        let ndc = clip.truncate() / clip.w;
        assert!(ndc.x.abs() < 1e-5 && ndc.y.abs() < 1e-5);
        assert!((0.0..1.0).contains(&ndc.z));
    }
}
