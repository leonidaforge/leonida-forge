//! GPU upload of a decoded scene.

use bytemuck::{Pod, Zeroable};
use glam::{Mat3, Mat4, Vec3};
use lforge_scene::{AlphaMode, Mesh, Scene, Vertex};
use wgpu::util::DeviceExt;

use crate::Error;
use crate::texture::{self, GpuTexture};

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct GpuVertex {
    position: [f32; 3],
    normal: [f32; 3],
    tangent: [f32; 4],
    uv0: [f32; 2],
    uv1: [f32; 2],
    color: [f32; 4],
}

impl GpuVertex {
    pub(crate) const ATTRIBUTES: [wgpu::VertexAttribute; 6] = wgpu::vertex_attr_array![
        0 => Float32x3,
        1 => Float32x3,
        2 => Float32x4,
        3 => Float32x2,
        4 => Float32x2,
        5 => Float32x4
    ];

    pub(crate) fn layout() -> wgpu::VertexBufferLayout<'static> {
        wgpu::VertexBufferLayout {
            array_stride: size_of::<Self>() as u64,
            step_mode: wgpu::VertexStepMode::Vertex,
            attributes: &Self::ATTRIBUTES,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct MaterialUniform {
    base_color: [f32; 4],
    /// bumpiness, alpha cutoff, normal map present, normal map is BC5.
    params: [f32; 4],
}

#[derive(Debug)]
pub(crate) struct GpuPrimitive {
    pub(crate) vertices: wgpu::Buffer,
    pub(crate) indices: wgpu::Buffer,
    pub(crate) index_count: u32,
    pub(crate) material: usize,
    pub(crate) center: Vec3,
    /// The scene mesh the primitive was uploaded from. Visibility is set per
    /// mesh, so hiding one component never re-reads or re-decodes anything.
    pub(crate) mesh: usize,
    pub(crate) visible: bool,
}

#[derive(Debug)]
pub(crate) struct GpuMaterial {
    pub(crate) bind_group: wgpu::BindGroup,
    pub(crate) alpha_mode: AlphaMode,
    pub(crate) double_sided: bool,
}

/// One overlay line vertex: a model-space position and a colour.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct OverlayVertex {
    pub(crate) position: [f32; 3],
    pub(crate) color: [f32; 4],
}

impl OverlayVertex {
    pub(crate) const ATTRIBUTES: [wgpu::VertexAttribute; 2] =
        wgpu::vertex_attr_array![0 => Float32x3, 1 => Float32x4];

    pub(crate) fn layout() -> wgpu::VertexBufferLayout<'static> {
        wgpu::VertexBufferLayout {
            array_stride: size_of::<Self>() as u64,
            step_mode: wgpu::VertexStepMode::Vertex,
            attributes: &Self::ATTRIBUTES,
        }
    }
}

/// The skeleton overlay of one uploaded scene.
///
/// The buffers hold model-space lines built from [`lforge_scene::Skeleton`].
/// Toggling visibility or changing the selection never rebuilds them: the
/// selection is a uniform range the overlay shader reads.
#[derive(Debug)]
pub(crate) struct GpuSkeleton {
    pub(crate) markers: wgpu::Buffer,
    pub(crate) marker_vertices: u32,
    pub(crate) connections: wgpu::Buffer,
    pub(crate) connection_vertices: u32,
    pub(crate) bone_count: usize,
    pub(crate) visible: bool,
    pub(crate) selected: Option<usize>,
}

/// A scene uploaded to one GPU device. Dropping it releases every buffer,
/// texture and bind group it owns.
#[derive(Debug)]
pub struct GpuScene {
    pub(crate) materials: Vec<GpuMaterial>,
    pub(crate) primitives: Vec<GpuPrimitive>,
    pub(crate) skeleton: Option<GpuSkeleton>,
    warnings: Vec<String>,
}

impl GpuScene {
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn is_empty(&self) -> bool {
        self.primitives.is_empty()
    }

    pub fn primitive_count(&self) -> usize {
        self.primitives.len()
    }

    /// Shows or hides every primitive uploaded from scene mesh `mesh`.
    ///
    /// The upload is unchanged; only the draw list consults the flag, so a
    /// visibility change costs one pass over the primitives.
    pub fn set_mesh_visible(&mut self, mesh: usize, visible: bool) {
        for primitive in &mut self.primitives {
            if primitive.mesh == mesh {
                primitive.visible = visible;
            }
        }
    }

    /// Whether at least one primitive of `mesh` is drawn.
    pub fn mesh_visible(&self, mesh: usize) -> bool {
        self.primitives
            .iter()
            .any(|primitive| primitive.mesh == mesh && primitive.visible)
    }

    /// Whether the scene carries a skeleton overlay.
    pub fn has_skeleton(&self) -> bool {
        self.skeleton.is_some()
    }

    pub fn skeleton_bone_count(&self) -> usize {
        self.skeleton
            .as_ref()
            .map_or(0, |skeleton| skeleton.bone_count)
    }

    /// Whether the skeleton overlay is drawn. The uploaded buffers are
    /// untouched.
    pub fn skeleton_visible(&self) -> bool {
        self.skeleton
            .as_ref()
            .is_some_and(|skeleton| skeleton.visible)
    }

    /// Shows or hides the skeleton overlay. This never re-uploads geometry.
    pub fn set_skeleton_visible(&mut self, visible: bool) {
        if let Some(skeleton) = &mut self.skeleton {
            skeleton.visible = visible;
        }
    }

    /// Highlights one bone in the overlay. This writes no GPU buffer.
    pub fn set_skeleton_selected(&mut self, selected: Option<usize>) {
        if let Some(skeleton) = &mut self.skeleton {
            skeleton.selected = selected.filter(|index| *index < skeleton.bone_count);
        }
    }

    pub fn skeleton_selected(&self) -> Option<usize> {
        self.skeleton
            .as_ref()
            .and_then(|skeleton| skeleton.selected)
    }

    pub(crate) fn upload(
        device: &wgpu::Device,
        queue: &wgpu::Queue,
        material_layout: &wgpu::BindGroupLayout,
        sampler: &wgpu::Sampler,
        fallback: &crate::FallbackTextures,
        scene: &Scene,
    ) -> Result<Self, Error> {
        let mut warnings = Vec::new();
        let mut textures: Vec<Option<GpuTexture>> = Vec::with_capacity(scene.textures.len());
        for source in &scene.textures {
            match texture::upload(device, queue, source) {
                Ok(uploaded) => textures.push(Some(uploaded)),
                Err(err) => {
                    warnings.push(format!("{}: {err}", source.name));
                    textures.push(None);
                }
            }
        }

        let mut materials = Vec::with_capacity(scene.materials.len().max(1));
        for material in &scene.materials {
            let fallback_diffuse = if material.missing_texture {
                &fallback.checker
            } else {
                &fallback.white
            };
            let diffuse = material
                .diffuse
                .and_then(|index| textures.get(index))
                .and_then(Option::as_ref)
                .map_or(&fallback_diffuse.view, |texture| &texture.view);
            let normal = material
                .normal
                .and_then(|index| textures.get(index))
                .and_then(Option::as_ref);
            let specular = material
                .specular
                .and_then(|index| textures.get(index))
                .and_then(Option::as_ref);
            let normal_bc5 = material
                .normal
                .and_then(|index| scene.textures.get(index))
                .is_some_and(|texture| texture.format == lforge_scene::TextureFormat::Bc5Unorm);
            let params = [
                material.bumpiness,
                if material.alpha_mode == AlphaMode::Mask {
                    0.5
                } else {
                    0.0
                },
                if normal.is_some() { 1.0 } else { 0.0 },
                if normal_bc5 { 1.0 } else { 0.0 },
            ];
            let uniform = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
                label: Some("material"),
                contents: bytemuck::bytes_of(&MaterialUniform {
                    base_color: material.base_color,
                    params,
                }),
                usage: wgpu::BufferUsages::UNIFORM,
            });
            let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("material"),
                layout: material_layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: uniform.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: wgpu::BindingResource::TextureView(diffuse),
                    },
                    wgpu::BindGroupEntry {
                        binding: 2,
                        resource: wgpu::BindingResource::TextureView(
                            normal.map_or(&fallback.normal.view, |texture| &texture.view),
                        ),
                    },
                    wgpu::BindGroupEntry {
                        binding: 3,
                        resource: wgpu::BindingResource::TextureView(
                            specular.map_or(&fallback.black.view, |texture| &texture.view),
                        ),
                    },
                    wgpu::BindGroupEntry {
                        binding: 4,
                        resource: wgpu::BindingResource::Sampler(sampler),
                    },
                ],
            });
            materials.push(GpuMaterial {
                bind_group,
                alpha_mode: material.alpha_mode,
                double_sided: material.double_sided,
            });
        }
        if materials.is_empty() {
            return Err(Error::Scene("scene has no materials".into()));
        }

        let mut primitives = Vec::new();
        for (index, mesh) in scene.meshes.iter().enumerate() {
            upload_mesh(device, index, mesh, &mut primitives);
        }
        if primitives.is_empty() {
            return Err(Error::Scene("scene has no drawable primitives".into()));
        }
        let skeleton = upload_skeleton(device, scene);
        Ok(Self {
            materials,
            primitives,
            skeleton,
            warnings,
        })
    }
}

/// Builds the overlay lines of a scene's skeleton, when it has one.
///
/// Markers come first, six vertices per bone, so the selection range is
/// `index * 6`. Parent-child connections follow. The marker length is a small
/// fraction of the skeleton's extent, so a tiny prop skeleton and a tall one
/// both stay visible.
fn upload_skeleton(device: &wgpu::Device, scene: &Scene) -> Option<GpuSkeleton> {
    let skeleton = scene.skeleton.as_ref()?;
    if skeleton.bones.is_empty() {
        return None;
    }
    let extent = skeleton.bounds().size().max_element().max(0.05);
    let marker = extent * 0.06;
    let connection_color = [0.15, 0.75, 0.95, 0.85];
    let marker_color = [0.35, 0.95, 1.0, 1.0];
    let mut markers = Vec::with_capacity(skeleton.bones.len() * 6);
    let mut connections = Vec::new();
    for bone in &skeleton.bones {
        let position = bone.model_position;
        for axis in [Vec3::X, Vec3::Y, Vec3::Z] {
            let end = position + axis * marker;
            markers.push(OverlayVertex {
                position: position.to_array(),
                color: marker_color,
            });
            markers.push(OverlayVertex {
                position: end.to_array(),
                color: marker_color,
            });
        }
        if let Some(parent) = bone
            .parent
            .and_then(|parent| skeleton.bone_position(parent))
        {
            connections.push(OverlayVertex {
                position: parent.to_array(),
                color: connection_color,
            });
            connections.push(OverlayVertex {
                position: position.to_array(),
                color: connection_color,
            });
        }
    }
    let marker_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("skeleton markers"),
        contents: bytemuck::cast_slice(&markers),
        usage: wgpu::BufferUsages::VERTEX,
    });
    let connection_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("skeleton connections"),
        contents: bytemuck::cast_slice(&connections),
        usage: wgpu::BufferUsages::VERTEX,
    });
    Some(GpuSkeleton {
        markers: marker_buffer,
        marker_vertices: markers.len() as u32,
        connections: connection_buffer,
        connection_vertices: connections.len() as u32,
        bone_count: skeleton.bones.len(),
        visible: false,
        selected: None,
    })
}

fn transform_vertex(vertex: &Vertex, transform: Mat4, normal_matrix: Mat3) -> GpuVertex {
    GpuVertex {
        position: transform
            .transform_point3(Vec3::from(vertex.position))
            .to_array(),
        normal: (normal_matrix * Vec3::from(vertex.normal))
            .normalize_or_zero()
            .to_array(),
        tangent: vertex.tangent.unwrap_or([0.0, 0.0, 0.0, 1.0]),
        uv0: vertex.uv0,
        uv1: vertex.uv1.unwrap_or([0.0, 0.0]),
        color: vertex.color,
    }
}

fn upload_mesh(device: &wgpu::Device, mesh_index: usize, mesh: &Mesh, out: &mut Vec<GpuPrimitive>) {
    let transform = mesh.transform;
    let normal_matrix = Mat3::from_mat4(transform).inverse().transpose();
    for primitive in &mesh.primitives {
        if primitive.vertices.is_empty() || primitive.indices.is_empty() {
            continue;
        }
        let vertices: Vec<GpuVertex> = primitive
            .vertices
            .iter()
            .map(|vertex| transform_vertex(vertex, transform, normal_matrix))
            .collect();
        let mut min = Vec3::splat(f32::INFINITY);
        let mut max = Vec3::splat(f32::NEG_INFINITY);
        for vertex in &vertices {
            let point = Vec3::from(vertex.position);
            min = min.min(point);
            max = max.max(point);
        }
        let center = if min.is_finite() && max.is_finite() {
            (min + max) * 0.5
        } else {
            Vec3::ZERO
        };
        let vertex_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some(&mesh.name),
            contents: bytemuck::cast_slice(&vertices),
            usage: wgpu::BufferUsages::VERTEX,
        });
        let index_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some(&mesh.name),
            contents: bytemuck::cast_slice(&primitive.indices),
            usage: wgpu::BufferUsages::INDEX,
        });
        out.push(GpuPrimitive {
            vertices: vertex_buffer,
            indices: index_buffer,
            index_count: primitive.indices.len() as u32,
            material: primitive.material,
            center,
            mesh: mesh_index,
            visible: true,
        });
    }
}
