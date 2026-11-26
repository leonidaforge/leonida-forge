//! Renderer-independent scene data.
//!
//! Asset decoders produce these types; a graphics backend consumes them. The
//! crate has no graphics or UI dependency, so an offscreen exporter and the
//! desktop viewer can share one decoded scene model.

use glam::{Mat4, Vec3};

/// A vertex in RAGE model space (Z up, metres).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Vertex {
    pub position: [f32; 3],
    pub normal: [f32; 3],
    /// Tangent with the handedness in `w`; `None` when the mesh has no
    /// tangent stream. Normal mapping falls back to screen-space derivatives.
    pub tangent: Option<[f32; 4]>,
    pub uv0: [f32; 2],
    pub uv1: Option<[f32; 2]>,
    pub color: [f32; 4],
}

impl Vertex {
    pub const ATTRIBUTES: usize = 6;
}

/// A triangle list with one material.
#[derive(Debug, Clone, PartialEq)]
pub struct Primitive {
    pub material: usize,
    pub vertices: Vec<Vertex>,
    pub indices: Vec<u32>,
}

impl Primitive {
    /// Drops triangles with an index outside the vertex buffer or with
    /// repeated corners. A trailing partial triangle is dropped as well.
    pub fn validate_indices(&mut self) -> usize {
        let len = self.vertices.len() as u32;
        let before = self.indices.len() / 3;
        let mut valid = Vec::with_capacity(self.indices.len());
        for triangle in self.indices.as_chunks::<3>().0 {
            if triangle.iter().all(|index| *index < len)
                && triangle[0] != triangle[1]
                && triangle[1] != triangle[2]
                && triangle[0] != triangle[2]
            {
                valid.extend_from_slice(triangle);
            }
        }
        self.indices = valid;
        before - self.indices.len() / 3
    }
}

/// A mesh: primitives that share a local transform.
#[derive(Debug, Clone, PartialEq)]
pub struct Mesh {
    pub name: String,
    pub primitives: Vec<Primitive>,
    /// Local to model-space transform. Decoded drawables use the identity.
    pub transform: Mat4,
}

impl Mesh {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            primitives: Vec::new(),
            transform: Mat4::IDENTITY,
        }
    }
}

/// How a material treats alpha.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AlphaMode {
    #[default]
    Opaque,
    /// Alpha below 0.5 is discarded, the rest is opaque.
    Mask,
    /// Alpha is blended. Drawn after opaque geometry.
    Blend,
}

/// The semantic role of a bound texture, where one was established.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextureSemantic {
    Diffuse,
    Normal,
    Specular,
    /// The second specular slot. The viewer binds it but keeps the first
    /// specular map as the one the shader samples.
    Specular2,
    Unknown,
}

/// One texture parameter of a material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextureBinding {
    /// The material's parameter name hash.
    pub parameter: u32,
    /// Index into [`Scene::textures`].
    pub texture: usize,
    pub semantic: TextureSemantic,
}

/// A material as the renderer needs it. The decoder fills what the format
/// establishes and leaves the rest at neutral preview defaults.
#[derive(Debug, Clone, PartialEq)]
pub struct Material {
    pub name: String,
    pub base_color: [f32; 4],
    pub diffuse: Option<usize>,
    pub normal: Option<usize>,
    pub specular: Option<usize>,
    pub alpha_mode: AlphaMode,
    pub double_sided: bool,
    pub bumpiness: f32,
    pub uv_set: u32,
    /// A declared texture could not be resolved. The viewer shows a checker
    /// instead of presenting the material as fully textured.
    pub missing_texture: bool,
    pub bindings: Vec<TextureBinding>,
}

impl Default for Material {
    fn default() -> Self {
        Self {
            name: String::new(),
            base_color: [1.0; 4],
            diffuse: None,
            normal: None,
            specular: None,
            alpha_mode: AlphaMode::Opaque,
            double_sided: false,
            bumpiness: 1.0,
            uv_set: 0,
            missing_texture: false,
            bindings: Vec::new(),
        }
    }
}

/// A pixel format as decoded from the asset. Compressed formats carry the
/// block bytes in GPU order, so a compatible backend uploads them unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextureFormat {
    Rgba8Unorm,
    Rgba8UnormSrgb,
    Bgra8Unorm,
    Bgra8UnormSrgb,
    R8Unorm,
    Rg8Unorm,
    R16Unorm,
    Rgba16Unorm,
    R16Float,
    Rgba16Float,
    R32Float,
    Rgb10a2Unorm,
    Bc1Unorm,
    Bc1UnormSrgb,
    Bc3Unorm,
    Bc3UnormSrgb,
    Bc4Unorm,
    Bc5Unorm,
    Bc6hUf16,
    Bc7Unorm,
    Bc7UnormSrgb,
}

impl TextureFormat {
    /// Texels per block edge (1 for uncompressed formats).
    pub fn block_dim(self) -> u32 {
        match self {
            Self::Bc1Unorm
            | Self::Bc1UnormSrgb
            | Self::Bc3Unorm
            | Self::Bc3UnormSrgb
            | Self::Bc4Unorm
            | Self::Bc5Unorm
            | Self::Bc6hUf16
            | Self::Bc7Unorm
            | Self::Bc7UnormSrgb => 4,
            _ => 1,
        }
    }

    /// Bytes of one block (one texel for uncompressed formats).
    pub fn bytes_per_block(self) -> u32 {
        match self {
            Self::Rgba8Unorm | Self::Rgba8UnormSrgb | Self::Bgra8Unorm | Self::Bgra8UnormSrgb => 4,
            Self::R8Unorm => 1,
            Self::Rg8Unorm | Self::R16Unorm | Self::R16Float => 2,
            Self::Rgba16Unorm | Self::Rgba16Float => 8,
            Self::R32Float | Self::Rgb10a2Unorm => 4,
            Self::Bc1Unorm | Self::Bc1UnormSrgb | Self::Bc4Unorm => 8,
            Self::Bc3Unorm
            | Self::Bc3UnormSrgb
            | Self::Bc5Unorm
            | Self::Bc6hUf16
            | Self::Bc7Unorm
            | Self::Bc7UnormSrgb => 16,
        }
    }

    pub fn is_compressed(self) -> bool {
        self.block_dim() > 1
    }

    /// Whether the stored values are sRGB encoded.
    pub fn is_srgb(self) -> bool {
        matches!(
            self,
            Self::Rgba8UnormSrgb
                | Self::Bgra8UnormSrgb
                | Self::Bc1UnormSrgb
                | Self::Bc3UnormSrgb
                | Self::Bc7UnormSrgb
        )
    }

    /// Bytes needed for a surface of `width` x `height`, without mips.
    pub fn surface_bytes(self, width: u32, height: u32) -> Option<usize> {
        let dim = self.block_dim();
        let blocks_x = width.div_ceil(dim);
        let blocks_y = height.div_ceil(dim);
        let bytes = usize::try_from(blocks_x)
            .ok()?
            .checked_mul(usize::try_from(blocks_y).ok()?)?
            .checked_mul(self.bytes_per_block() as usize)?;
        Some(bytes)
    }
}

/// A decoded texture, already untiled. Only mip 0 is stored; the original
/// mip count is kept for diagnostics.
#[derive(Debug, Clone, PartialEq)]
pub struct Texture {
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub format: TextureFormat,
    /// Mip levels in the source. Only level 0 is present in `data`.
    pub source_mip_levels: u32,
    pub data: Vec<u8>,
    /// Where the texture came from, for diagnostics.
    pub source: String,
}

impl Texture {
    pub fn validate(&self) -> Result<(), String> {
        if self.width == 0 || self.height == 0 {
            return Err("texture has a zero dimension".into());
        }
        let expected = self
            .format
            .surface_bytes(self.width, self.height)
            .ok_or_else(|| "texture size overflows".to_string())?;
        if self.data.len() != expected {
            return Err(format!(
                "texture has {} bytes, {} x {} {:?} needs {}",
                self.data.len(),
                self.width,
                self.height,
                self.format,
                expected
            ));
        }
        Ok(())
    }

    /// Tightly packed RGBA8 mip 0. Compressed textures must be decoded first;
    /// the asset layer only calls this for formats it can expand.
    pub fn rgba8(&self) -> Option<Vec<u8>> {
        match self.format {
            TextureFormat::Rgba8Unorm | TextureFormat::Rgba8UnormSrgb => Some(self.data.clone()),
            TextureFormat::Bgra8Unorm | TextureFormat::Bgra8UnormSrgb => {
                let mut out = self.data.clone();
                for pixel in out.as_chunks_mut::<4>().0 {
                    pixel.swap(0, 2);
                }
                Some(out)
            }
            _ => None,
        }
    }
}

/// A diagnostic produced while decoding an asset. It never changes the
/// rendering result silently: the viewer shows the material as a fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub mesh: Option<String>,
    pub material: Option<String>,
    pub reference: Option<String>,
    pub reason: String,
}

impl Diagnostic {
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            mesh: None,
            material: None,
            reference: None,
            reason: reason.into(),
        }
    }

    pub fn with_material(mut self, material: impl Into<String>) -> Self {
        self.material = Some(material.into());
        self
    }

    pub fn with_mesh(mut self, mesh: impl Into<String>) -> Self {
        self.mesh = Some(mesh.into());
        self
    }

    pub fn with_reference(mut self, reference: impl Into<String>) -> Self {
        self.reference = Some(reference.into());
        self
    }
}

/// Axis-aligned bounds in model space.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Aabb {
    pub min: Vec3,
    pub max: Vec3,
}

impl Aabb {
    pub const EMPTY: Self = Self {
        min: Vec3::splat(f32::INFINITY),
        max: Vec3::splat(f32::NEG_INFINITY),
    };

    pub fn from_points(points: impl IntoIterator<Item = Vec3>) -> Self {
        let mut bounds = Self::EMPTY;
        for point in points {
            bounds = bounds.extend(point);
        }
        bounds
    }

    pub fn extend(self, point: Vec3) -> Self {
        Self {
            min: self.min.min(point),
            max: self.max.max(point),
        }
    }

    pub fn union(self, other: Self) -> Self {
        Self {
            min: self.min.min(other.min),
            max: self.max.max(other.max),
        }
    }

    pub fn is_empty(self) -> bool {
        self.min.x > self.max.x || self.min.y > self.max.y || self.min.z > self.max.z
    }

    pub fn is_finite(self) -> bool {
        self.min.is_finite() && self.max.is_finite()
    }

    pub fn center(self) -> Vec3 {
        if self.is_empty() {
            Vec3::ZERO
        } else {
            (self.min + self.max) * 0.5
        }
    }

    pub fn size(self) -> Vec3 {
        if self.is_empty() {
            Vec3::ZERO
        } else {
            self.max - self.min
        }
    }

    /// Radius of the sphere around [`Self::center`] that holds the box.
    pub fn radius(self) -> f32 {
        self.size().length() * 0.5
    }

    /// A finite box for display, even when the scene holds no vertices.
    pub fn sanitized(self) -> Self {
        if self.is_empty() || !self.is_finite() {
            Self {
                min: Vec3::splat(-0.5),
                max: Vec3::splat(0.5),
            }
        } else {
            let size = self.size();
            let pad = size.max_element().max(1.0) * 1e-5;
            Self {
                min: self.min - Vec3::splat(pad),
                max: self.max + Vec3::splat(pad),
            }
        }
    }
}

/// A complete renderable scene.
#[derive(Debug, Clone, PartialEq)]
pub struct Scene {
    pub meshes: Vec<Mesh>,
    pub materials: Vec<Material>,
    pub textures: Vec<Texture>,
    pub bounds: Aabb,
    pub diagnostics: Vec<Diagnostic>,
}

impl Default for Scene {
    fn default() -> Self {
        Self {
            meshes: Vec::new(),
            materials: Vec::new(),
            textures: Vec::new(),
            bounds: Aabb::EMPTY,
            diagnostics: Vec::new(),
        }
    }
}

impl Scene {
    pub fn new() -> Self {
        Self::default()
    }

    /// Computes bounds from the vertices, applying each mesh's transform.
    pub fn recompute_bounds(&mut self) {
        let mut bounds = Aabb::EMPTY;
        for mesh in &self.meshes {
            for primitive in &mesh.primitives {
                for vertex in &primitive.vertices {
                    let point = mesh.transform.transform_point3(Vec3::from(vertex.position));
                    bounds = bounds.extend(point);
                }
            }
        }
        self.bounds = bounds;
    }

    pub fn vertex_count(&self) -> usize {
        self.meshes
            .iter()
            .flat_map(|mesh| &mesh.primitives)
            .map(|primitive| primitive.vertices.len())
            .sum()
    }

    pub fn triangle_count(&self) -> usize {
        self.meshes
            .iter()
            .flat_map(|mesh| &mesh.primitives)
            .map(|primitive| primitive.indices.len() / 3)
            .sum()
    }

    /// Drops primitives whose material index or indices are out of range.
    pub fn validate(&mut self) -> Vec<Diagnostic> {
        let mut diagnostics = Vec::new();
        let materials = self.materials.len();
        for mesh in &mut self.meshes {
            let name = mesh.name.clone();
            for primitive in &mut mesh.primitives {
                if primitive.material >= materials {
                    diagnostics.push(
                        Diagnostic::new(format!(
                            "primitive refers to material {} of {}",
                            primitive.material, materials
                        ))
                        .with_mesh(name.clone()),
                    );
                    primitive.material = 0;
                }
                let dropped = primitive.validate_indices();
                if dropped > 0 {
                    diagnostics.push(
                        Diagnostic::new(format!(
                            "dropped {dropped} triangles with indices outside the vertex buffer"
                        ))
                        .with_mesh(name.clone()),
                    );
                }
            }
        }
        if self.materials.is_empty() {
            self.materials.push(Material::default());
        }
        self.meshes.retain_mut(|mesh| {
            mesh.primitives.retain(|primitive| {
                !primitive.vertices.is_empty() && !primitive.indices.is_empty()
            });
            !mesh.primitives.is_empty()
        });
        self.recompute_bounds();
        diagnostics
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn triangle(positions: [[f32; 3]; 3]) -> Primitive {
        Primitive {
            material: 0,
            vertices: positions
                .map(|position| Vertex {
                    position,
                    normal: [0.0, 0.0, 1.0],
                    tangent: None,
                    uv0: [0.0, 0.0],
                    uv1: None,
                    color: [1.0; 4],
                })
                .to_vec(),
            indices: vec![0, 1, 2],
        }
    }

    #[test]
    fn bounds_cover_every_vertex() {
        let mut scene = Scene::new();
        let mut mesh = Mesh::new("triangle");
        mesh.primitives.push(triangle([
            [0.0, 0.0, 0.0],
            [1.0, 0.0, 0.0],
            [0.0, 2.0, 3.0],
        ]));
        scene.meshes.push(mesh);
        scene.recompute_bounds();
        assert_eq!(scene.bounds.min, Vec3::ZERO);
        assert_eq!(scene.bounds.max, Vec3::new(1.0, 2.0, 3.0));
        assert_eq!(scene.bounds.center(), Vec3::new(0.5, 1.0, 1.5));
    }

    #[test]
    fn empty_bounds_sanitize_to_a_unit_box() {
        let bounds = Aabb::EMPTY.sanitized();
        assert!(bounds.is_finite());
        assert_eq!(bounds.size(), Vec3::ONE);
    }

    #[test]
    fn indices_outside_the_vertex_buffer_are_dropped() {
        let mut primitive = triangle([[0.0; 3], [1.0; 3], [2.0; 3]]);
        primitive.indices.extend([0, 1, 99, 0, 1]);
        assert_eq!(primitive.validate_indices(), 1);
        assert_eq!(primitive.indices, [0, 1, 2]);
    }

    #[test]
    fn surface_bytes_round_up_to_whole_blocks() {
        assert_eq!(TextureFormat::Bc1Unorm.surface_bytes(1, 1), Some(8));
        assert_eq!(TextureFormat::Bc7Unorm.surface_bytes(5, 9), Some(96));
        assert_eq!(TextureFormat::Rgba8Unorm.surface_bytes(3, 2), Some(24));
    }

    #[test]
    fn validation_replaces_a_missing_material_and_removes_empty_meshes() {
        let mut scene = Scene::new();
        let mut mesh = Mesh::new("empty");
        let mut primitive = triangle([[0.0; 3]; 3]);
        primitive.material = 7;
        mesh.primitives.push(primitive);
        scene.meshes.push(mesh);
        let diagnostics = scene.validate();
        assert_eq!(scene.materials.len(), 1);
        assert_eq!(scene.meshes[0].primitives[0].material, 0);
        assert!(diagnostics.iter().any(|d| d.reason.contains("material 7")));

        scene.meshes[0].primitives[0].indices.clear();
        scene.validate();
        assert!(scene.meshes.is_empty());
    }
}
