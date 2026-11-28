//! GPU upload of a decoded scene.

use bytemuck::{Pod, Zeroable};
use glam::{Mat3, Mat4, Vec3};
use lforge_scene::{AlphaMode, Mesh, Scene, Vertex, VertexInfluences};
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

/// The skinned vertex: the static attributes plus the resolved influence
/// lanes. Only primitives with verified influences get this buffer.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct GpuSkinnedVertex {
    position: [f32; 3],
    normal: [f32; 3],
    tangent: [f32; 4],
    uv0: [f32; 2],
    uv1: [f32; 2],
    color: [f32; 4],
    joints: [u32; 4],
    weights: [f32; 4],
}

impl GpuSkinnedVertex {
    pub(crate) const ATTRIBUTES: [wgpu::VertexAttribute; 8] = wgpu::vertex_attr_array![
        0 => Float32x3,
        1 => Float32x3,
        2 => Float32x4,
        3 => Float32x2,
        4 => Float32x2,
        5 => Float32x4,
        6 => Uint32x4,
        7 => Float32x4
    ];

    pub(crate) fn layout() -> wgpu::VertexBufferLayout<'static> {
        wgpu::VertexBufferLayout {
            array_stride: size_of::<Self>() as u64,
            step_mode: wgpu::VertexStepMode::Vertex,
            attributes: &Self::ATTRIBUTES,
        }
    }
}

/// One probe vertex for the skinning verification path.
#[repr(C)]
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
pub struct SkinProbeVertex {
    pub position: [f32; 3],
    pub normal: [f32; 3],
    pub tangent: [f32; 4],
    pub joints: [u32; 4],
    pub weights: [f32; 4],
    /// 0 = position, 1 = normal, 2 = tangent. One point is drawn per mode.
    pub mode: u32,
}

/// The per-frame pose state read by the skinning shader.
#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct PoseUniform {
    pub highlight_bone: i32,
    pub view: u32,
    pub pad0: u32,
    pub pad1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct MaterialUniform {
    base_color: [f32; 4],
    /// bumpiness, alpha cutoff, normal map present, normal map is BC5.
    params: [f32; 4],
    /// metalness, roughness, emissive weight, spare.
    surface: [f32; 4],
}

/// The skinned vertex buffer of one primitive. The authored static buffer is
/// kept as well, so leaving pose mode never re-uploads anything.
#[derive(Debug)]
pub(crate) struct GpuSkin {
    pub(crate) vertices: wgpu::Buffer,
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
    /// Present only when the primitive carries verified, deformable influences.
    pub(crate) skin: Option<GpuSkin>,
    /// Whether the association was inferred rather than decoded. The policy
    /// decides whether such a primitive is drawn skinned.
    pub(crate) inferred: bool,
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
    /// Parents and marker length, kept so a pose can rebuild the lines without
    /// re-reading the scene.
    parents: Vec<Option<usize>>,
    marker: f32,
}

/// A scene uploaded to one GPU device. Dropping it releases every buffer,
/// texture and bind group it owns.
#[derive(Debug)]
pub struct GpuScene {
    pub(crate) materials: Vec<GpuMaterial>,
    pub(crate) primitives: Vec<GpuPrimitive>,
    pub(crate) skeleton: Option<GpuSkeleton>,
    pub(crate) joints: Option<wgpu::Buffer>,
    pub(crate) pose_uniform: Option<wgpu::Buffer>,
    pub(crate) pose_bind_group: Option<wgpu::BindGroup>,
    pub(crate) joint_count: usize,
    /// Whether influenced primitives are drawn through the skinned pipeline.
    pub(crate) pose_active: bool,
    /// Which associations may be drawn skinned.
    pub(crate) policy: lforge_scene::DeformationPolicy,
    /// `0` material shading, `1` selected-bone influence visualisation.
    pub(crate) view: u32,
    pub(crate) highlight_bone: Option<usize>,
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
        pose_layout: &wgpu::BindGroupLayout,
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
                    surface: [
                        material.metallic.clamp(0.0, 1.0),
                        material.roughness.clamp(0.02, 1.0),
                        material.emissive.max(0.0),
                        0.0,
                    ],
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
            upload_mesh(device, queue, index, mesh, scene, &mut primitives);
        }
        if primitives.is_empty() {
            return Err(Error::Scene("scene has no drawable primitives".into()));
        }
        let skeleton = upload_skeleton(device, scene);
        let joint_count = scene.skeleton.as_ref().map_or(0, |s| s.bones.len());
        let (joints, pose_uniform, pose_bind_group) = if joint_count > 0 {
            let joints = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("joint matrices"),
                size: (joint_count * size_of::<[[f32; 4]; 4]>()) as u64,
                usage: wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let identity = vec![Mat4::IDENTITY.to_cols_array(); joint_count];
            queue.write_buffer(&joints, 0, bytemuck::cast_slice(&identity));
            let pose_uniform = device.create_buffer(&wgpu::BufferDescriptor {
                label: Some("pose state"),
                size: size_of::<PoseUniform>() as u64,
                usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
                mapped_at_creation: false,
            });
            let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("pose"),
                layout: pose_layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: pose_uniform.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: joints.as_entire_binding(),
                    },
                ],
            });
            (Some(joints), Some(pose_uniform), Some(bind_group))
        } else {
            (None, None, None)
        };
        Ok(Self {
            materials,
            primitives,
            skeleton,
            joints,
            pose_uniform,
            pose_bind_group,
            joint_count,
            pose_active: false,
            policy: lforge_scene::DeformationPolicy::EXPLICIT,
            view: 0,
            highlight_bone: None,
            warnings,
        })
    }

    /// Whether any primitive can be drawn through the skinned pipeline.
    pub fn has_skin(&self) -> bool {
        self.joints.is_some()
            && self
                .primitives
                .iter()
                .any(|primitive| primitive.skin.is_some())
    }

    pub fn pose_active(&self) -> bool {
        self.pose_active
    }

    /// Which associations the skinned pipeline may draw.
    pub fn policy(&self) -> lforge_scene::DeformationPolicy {
        self.policy
    }

    /// Sets the deformation policy. This writes no buffer and rebuilds nothing:
    /// the draw list consults the policy per primitive, so switching it costs one
    /// frame and no upload.
    pub fn set_policy(&mut self, policy: lforge_scene::DeformationPolicy) {
        self.policy = policy;
    }

    /// Whether `primitive` is drawn through the skinned pipeline right now.
    pub(crate) fn draws_skinned(&self, primitive: &GpuPrimitive) -> bool {
        self.pose_active
            && primitive.skin.is_some()
            && (self.policy.include_inferred || !primitive.inferred)
    }

    /// Selects the skinned pipeline for influenced primitives. Turning it off
    /// returns to the authored buffers without uploading anything.
    pub fn set_pose_active(&mut self, active: bool) {
        self.pose_active = active && self.joints.is_some();
    }

    pub fn influence_view(&self) -> bool {
        self.view == 1
    }

    pub fn set_influence_view(&mut self, enabled: bool) {
        self.view = u32::from(enabled);
    }

    pub fn highlight_bone(&self) -> Option<usize> {
        self.highlight_bone
    }

    pub fn set_highlight_bone(&mut self, bone: Option<usize>) {
        self.highlight_bone = bone.filter(|index| *index < self.joint_count);
    }

    /// How many bone matrices the uploaded scene holds.
    pub fn joint_count(&self) -> usize {
        self.joint_count
    }

    /// Writes the current skinning matrices and posed bone positions. The
    /// authored vertex buffers are untouched, so a pose update costs one
    /// storage write and one small overlay rewrite.
    pub fn update_pose(
        &mut self,
        queue: &wgpu::Queue,
        matrices: &[Mat4],
        bone_positions: &[Vec3],
    ) -> Result<(), String> {
        let Some(joints) = &self.joints else {
            return Err("the scene carries no skeleton".into());
        };
        if matrices.len() > self.joint_count {
            return Err(format!(
                "{} matrices do not fit the {} uploaded bones",
                matrices.len(),
                self.joint_count
            ));
        }
        let mut data = Vec::with_capacity(self.joint_count * 16);
        for matrix in matrices {
            data.extend_from_slice(&matrix.to_cols_array());
        }
        for _ in matrices.len()..self.joint_count {
            data.extend_from_slice(&Mat4::IDENTITY.to_cols_array());
        }
        queue.write_buffer(joints, 0, bytemuck::cast_slice(&data));
        if let Some(skeleton) = &self.skeleton
            && bone_positions.len() == skeleton.bone_count
        {
            let (markers, connections) =
                overlay_lines(&skeleton.parents, skeleton.marker, bone_positions);
            queue.write_buffer(&skeleton.markers, 0, bytemuck::cast_slice(&markers));
            queue.write_buffer(&skeleton.connections, 0, bytemuck::cast_slice(&connections));
        }
        Ok(())
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
        usage: wgpu::BufferUsages::VERTEX | wgpu::BufferUsages::COPY_DST,
    });
    let connection_buffer = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
        label: Some("skeleton connections"),
        contents: bytemuck::cast_slice(&connections),
        usage: wgpu::BufferUsages::VERTEX | wgpu::BufferUsages::COPY_DST,
    });
    Some(GpuSkeleton {
        markers: marker_buffer,
        marker_vertices: markers.len() as u32,
        connections: connection_buffer,
        connection_vertices: connections.len() as u32,
        bone_count: skeleton.bones.len(),
        visible: false,
        selected: None,
        parents: skeleton.bones.iter().map(|bone| bone.parent).collect(),
        marker,
    })
}

/// Rebuilds the overlay line vertices for a set of bone positions.
fn overlay_lines(
    parents: &[Option<usize>],
    marker: f32,
    positions: &[Vec3],
) -> (Vec<OverlayVertex>, Vec<OverlayVertex>) {
    let marker_color = [0.35, 0.95, 1.0, 1.0];
    let connection_color = [0.15, 0.75, 0.95, 0.85];
    let mut markers = Vec::with_capacity(positions.len() * 6);
    let mut connections = Vec::new();
    for (index, position) in positions.iter().enumerate() {
        for axis in [Vec3::X, Vec3::Y, Vec3::Z] {
            markers.push(OverlayVertex {
                position: position.to_array(),
                color: marker_color,
            });
            markers.push(OverlayVertex {
                position: (position + axis * marker).to_array(),
                color: marker_color,
            });
        }
        if let Some(parent) = parents
            .get(index)
            .copied()
            .flatten()
            .and_then(|parent| positions.get(parent))
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
    (markers, connections)
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

fn upload_mesh(
    device: &wgpu::Device,
    queue: &wgpu::Queue,
    mesh_index: usize,
    mesh: &Mesh,
    scene: &Scene,
    out: &mut Vec<GpuPrimitive>,
) {
    let transform = mesh.transform;
    let normal_matrix = Mat3::from_mat4(transform).inverse().transpose();
    for (primitive_index, primitive) in mesh.primitives.iter().enumerate() {
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
        let influences = scene
            .influences_for(mesh_index, primitive_index)
            .filter(|influences| influences.deformable());
        // The skinned buffer is uploaded for an inferred association too, so the
        // policy can be switched at any time without re-uploading the scene; the
        // draw decision consults the policy per frame.
        let inferred = influences.is_some_and(|influences| influences.inferred());
        let skin = influences
            .map(|influences| upload_skin(device, queue, &mesh.name, &vertices, influences));
        out.push(GpuPrimitive {
            vertices: vertex_buffer,
            indices: index_buffer,
            index_count: primitive.indices.len() as u32,
            material: primitive.material,
            center,
            mesh: mesh_index,
            visible: true,
            skin,
            inferred,
        });
    }
}

fn upload_skin(
    device: &wgpu::Device,
    queue: &wgpu::Queue,
    name: &str,
    vertices: &[GpuVertex],
    influences: &VertexInfluences,
) -> GpuSkin {
    let skinned = vertices
        .iter()
        .zip(&influences.per_vertex)
        .map(|(vertex, lanes)| {
            let mut joints = [0u32; 4];
            let mut weights = [0.0f32; 4];
            for (lane, influence) in lanes.iter().enumerate() {
                joints[lane] = u32::from(influence.bone);
                weights[lane] = influence.weight;
            }
            GpuSkinnedVertex {
                position: vertex.position,
                normal: vertex.normal,
                tangent: vertex.tangent,
                uv0: vertex.uv0,
                uv1: vertex.uv1,
                color: vertex.color,
                joints,
                weights,
            }
        })
        .collect::<Vec<_>>();
    let buffer = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some(name),
        size: size_of_val(skinned.as_slice()) as u64,
        usage: wgpu::BufferUsages::VERTEX | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    queue.write_buffer(&buffer, 0, bytemuck::cast_slice(&skinned));
    GpuSkin { vertices: buffer }
}
