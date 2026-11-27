//! Vehicle-specific assembly helpers shared by the previewer and viewers.
//!
//! A vehicle body is a fragment whose skeleton carries wheel bones. The wheels
//! themselves are separate drawables in a shared wheel archive, so a preview
//! has to place them at the skeleton pivots. This module only reads the
//! skeleton and merges scenes; it does not decide material colours.

use glam::{Mat4, Vec3};
use lforge_scene::{Mesh, Scene};

/// One wheel pivot read from a vehicle skeleton.
#[derive(Debug, Clone, PartialEq)]
pub struct WheelMount {
    pub bone: &'static str,
    pub pivot: Vec3,
    pub is_right: bool,
    pub is_rear: bool,
}

/// The wheel bones a vehicle skeleton can carry, with their joaat hashes.
/// A model may use only the first four.
const WHEEL_BONES: [(u32, &str, bool, bool); 10] = [
    (0xC563_2281, "wheel_lf", false, false),
    (0x07F7_A965, "wheel_rf", true, false),
    (0x6512_E1D6, "wheel_lr", false, true),
    (0x638B_E088, "wheel_rr", true, true),
    (0x65A7_22CD, "wheel_lm1", false, true),
    (0xAD5C_9421, "wheel_rm1", true, true),
    (0x545B_8036, "wheel_lm2", false, true),
    (0xA903_0B6E, "wheel_rm2", true, true),
    (0xCA34_6BE2, "wheel_lm3", false, true),
    (0xF73D_A7E2, "wheel_rm3", true, true),
];

struct Joint {
    hash: u32,
    inverse_bind: Mat4,
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn system_pointer(bytes: &[u8], offset: usize) -> Option<usize> {
    let value = bytes.get(offset..offset + 8).map(|slice| {
        u64::from_le_bytes([
            slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
        ])
    })?;
    if (0x5000_0000..0x6000_0000).contains(&value) {
        Some((value - 0x5000_0000) as usize)
    } else {
        None
    }
}

fn inverse_bind(bytes: &[u8], offset: usize) -> Option<Mat4> {
    let mut values = [0.0f32; 16];
    for (index, value) in values.iter_mut().enumerate() {
        let slice = bytes.get(offset + index * 4..offset + index * 4 + 4)?;
        *value = f32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]);
        if index != 15 && !value.is_finite() {
            return None;
        }
    }
    if values[3] != 0.0 || values[7] != 0.0 || values[11] != 0.0 {
        return None;
    }
    Some(Mat4::from_cols_array(&[
        values[0], values[4], values[8], values[12], values[1], values[5], values[9], values[13],
        values[2], values[6], values[10], values[14], values[3], values[7], values[11], 1.0,
    ]))
}

/// Reads the skeleton at `header` and returns its joints.
fn read_skeleton(bytes: &[u8], header: usize) -> Option<Vec<Joint>> {
    let count = u16_at(bytes, header + 0x6c)? as usize;
    if count == 0 || count > 4096 || count != u16_at(bytes, header + 0x6e)? as usize {
        return None;
    }
    let bones = system_pointer(bytes, header + 0x28)?;
    let inverse_binds = system_pointer(bytes, header + 0x30)?;
    let parents = system_pointer(bytes, header + 0x40)?;
    let mut joints = Vec::with_capacity(count);
    for index in 0..count {
        let bone = bones + index * 0x50;
        let parent = u16_at(bytes, bone + 0x46)?;
        if u16_at(bytes, bone + 0x48)? as usize != index {
            return None;
        }
        if parent != u16::MAX && parent as usize >= count {
            return None;
        }
        let _ = parents; // Parent order is not needed to place wheels.
        let hash = u32_at(bytes, bone + 0x1c)?;
        let matrix = inverse_bind(bytes, inverse_binds + index * 64)?;
        joints.push(Joint {
            hash,
            inverse_bind: matrix,
        });
    }
    Some(joints)
}

/// Reads the wheel pivots from a drawable's direct skeleton.
pub fn wheel_mounts(system: &[u8], drawable_offset: usize) -> Vec<WheelMount> {
    let Some(header) = system_pointer(system, drawable_offset + 0x18) else {
        return Vec::new();
    };
    let Some(joints) = read_skeleton(system, header) else {
        return Vec::new();
    };
    let mut mounts = Vec::new();
    for joint in joints {
        let Some((_, bone, is_right, is_rear)) =
            WHEEL_BONES.iter().find(|(hash, ..)| *hash == joint.hash)
        else {
            continue;
        };
        let Some(bind) = joint.inverse_bind.try_inverse() else {
            continue;
        };
        let pivot = bind.row(3).truncate();
        if pivot.is_finite() {
            mounts.push(WheelMount {
                bone,
                pivot,
                is_right: *is_right,
                is_rear: *is_rear,
            });
        }
    }
    mounts
}

/// Appends `source` to `target`, keeping textures and materials distinct.
/// The source is placed by `transform`; its own mesh transforms are preserved.
pub fn append_scene(target: &mut Scene, source: &Scene, transform: Mat4) -> usize {
    let texture_base = target.textures.len();
    target.textures.extend(source.textures.iter().cloned());
    let material_base = target.materials.len();
    for material in &source.materials {
        let mut material = material.clone();
        material.diffuse = material.diffuse.map(|index| index + texture_base);
        material.normal = material.normal.map(|index| index + texture_base);
        material.specular = material.specular.map(|index| index + texture_base);
        // Mirroring a wheel reverses its triangle winding; drawing both sides
        // keeps the wheel visible without rewriting the index buffer.
        material.double_sided = true;
        target.materials.push(material);
    }
    for mesh in &source.meshes {
        let mut mesh: Mesh = mesh.clone();
        mesh.transform = transform * mesh.transform;
        for primitive in &mut mesh.primitives {
            primitive.material += material_base;
        }
        target.meshes.push(mesh);
    }
    if source.bounds != lforge_scene::Aabb::EMPTY {
        target.bounds = target
            .bounds
            .union(transformed_bounds(source.bounds, transform));
    }
    target.meshes.len()
}

fn transformed_bounds(bounds: lforge_scene::Aabb, transform: Mat4) -> lforge_scene::Aabb {
    let mut min = Vec3::splat(f32::INFINITY);
    let mut max = Vec3::splat(f32::NEG_INFINITY);
    for index in 0..8 {
        let corner = Vec3::new(
            if index & 1 == 0 {
                bounds.min.x
            } else {
                bounds.max.x
            },
            if index & 2 == 0 {
                bounds.min.y
            } else {
                bounds.max.y
            },
            if index & 4 == 0 {
                bounds.min.z
            } else {
                bounds.max.z
            },
        );
        let point = transform.transform_point3(corner);
        min = min.min(point);
        max = max.max(point);
    }
    lforge_scene::Aabb { min, max }
}

/// The source axis that should become the vehicle's X axle: the narrowest one.
pub fn axle_axis(bounds: lforge_scene::Aabb) -> usize {
    let size = bounds.sanitized().size();
    if size.x <= size.y && size.x <= size.z {
        0
    } else if size.y <= size.x && size.y <= size.z {
        1
    } else {
        2
    }
}

/// A transform that centres a wheel on its own bounds, scales it to
/// `diameter` metres and moves it to `mount`. The source's narrow axis becomes
/// the vehicle's X axis (the axle).
pub fn wheel_transform(source: &Scene, mount: &WheelMount, diameter: f32) -> Mat4 {
    wheel_transform_with_axis(source, mount, diameter, axle_axis(source.bounds))
}

/// The same transform with an explicit axle axis. Use this when a rim and a
/// tyre are merged first: the rim decides the axle, the combined bounds decide
/// the diameter.
pub fn wheel_transform_with_axis(
    source: &Scene,
    mount: &WheelMount,
    diameter: f32,
    axle: usize,
) -> Mat4 {
    wheel_transform_sized(source, mount, diameter, axle, 1.0)
}

/// The same transform with an extra scale along the axle. Pass `width < 1.0` to
/// narrow a tyre whose source is wider than the vehicle needs.
pub fn wheel_transform_sized(
    source: &Scene,
    mount: &WheelMount,
    diameter: f32,
    axle: usize,
    width: f32,
) -> Mat4 {
    let bounds = source.bounds.sanitized();
    let center = bounds.center();
    let size = bounds.size();
    let rotation = match axle {
        0 => Mat4::IDENTITY,
        1 => Mat4::from_rotation_z(std::f32::consts::FRAC_PI_2),
        _ => Mat4::from_rotation_y(std::f32::consts::FRAC_PI_2),
    };
    let scale = diameter / size.max_element().max(1e-4);
    let mirror = if mount.is_right { -1.0 } else { 1.0 };
    Mat4::from_translation(mount.pivot)
        * Mat4::from_scale(Vec3::new(mirror * width, 1.0, 1.0))
        * Mat4::from_scale(Vec3::splat(scale))
        * rotation
        * Mat4::from_translation(-center)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lforge_scene::Aabb;

    #[test]
    fn wheel_transform_centres_and_scales_the_source() {
        let source = Scene {
            bounds: Aabb {
                min: Vec3::new(-0.25, -0.5, -0.08),
                max: Vec3::new(0.25, 0.5, 0.08),
            },
            ..Scene::default()
        };
        let mount = WheelMount {
            bone: "wheel_lf",
            pivot: Vec3::new(-0.74, 1.29, -0.48),
            is_right: false,
            is_rear: false,
        };
        let transformed = wheel_transform(&source, &mount, 0.64);
        let centre = transformed.transform_point3(source.bounds.center());
        assert!((centre - mount.pivot).length() < 1e-5);
        let diameter = transformed.transform_vector3(Vec3::Y).length();
        assert!((diameter - 0.64).abs() < 1e-4);
        // The narrowest source axis becomes the axle (X).
        let axle = transformed
            .transform_vector3(Vec3::new(0.0, 0.0, source.bounds.size().z))
            .length();
        assert!(axle < 0.2);
    }

    #[test]
    fn width_scale_narrows_only_the_axle() {
        let source = Scene {
            bounds: Aabb {
                min: Vec3::new(-0.25, -0.5, -0.08),
                max: Vec3::new(0.25, 0.5, 0.08),
            },
            ..Scene::default()
        };
        let mount = WheelMount {
            bone: "wheel_lf",
            pivot: Vec3::ZERO,
            is_right: false,
            is_rear: false,
        };
        let full = wheel_transform_with_axis(&source, &mount, 0.64, 2);
        let narrow = wheel_transform_sized(&source, &mount, 0.64, 2, 0.5);
        let width = |transform: Mat4| {
            transform
                .transform_vector3(Vec3::new(0.0, 0.0, source.bounds.size().z))
                .length()
        };
        let height = |transform: Mat4| transform.transform_vector3(Vec3::Y).length();
        assert!((width(narrow) - width(full) * 0.5).abs() < 1e-4);
        assert!((height(narrow) - height(full)).abs() < 1e-4);
    }
}
