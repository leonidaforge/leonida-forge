//! Reusable wgpu renderer for decoded Leonida Forge scenes.
//!
//! The crate has no desktop or asset-decoding dependency. A caller uploads a
//! [`lforge_scene::Scene`], renders it to an offscreen RGBA8 sRGB target and
//! reads the pixels back. The same path serves the interactive viewer and a
//! future headless exporter; only the transport of the finished frame to a
//! window differs.
//!
//! Direct3D 12 is preferred on Windows. When no hardware adapter is available
//! the renderer asks for a fallback adapter (WARP on Windows). Block-compressed
//! textures are uploaded as stored when the adapter supports BC sampling and
//! are decoded to RGBA8 otherwise.

mod camera;
mod gpu_scene;
mod texture;

use std::fmt;
use std::sync::mpsc;

use bytemuck::{Pod, Zeroable};
use glam::Vec3;
use wgpu::util::DeviceExt;

pub use camera::OrbitCamera;
pub use gpu_scene::GpuScene;
pub use wgpu::AdapterInfo;

use lforge_scene::Scene;

const COLOR_FORMAT: wgpu::TextureFormat = wgpu::TextureFormat::Rgba8UnormSrgb;
const DEPTH_FORMAT: wgpu::TextureFormat = wgpu::TextureFormat::Depth32Float;
const BYTES_PER_PIXEL: u32 = 4;

#[derive(Debug)]
pub enum Error {
    Adapter(wgpu::RequestAdapterError),
    Device(wgpu::RequestDeviceError),
    Readback(wgpu::BufferAsyncError),
    Poll(wgpu::PollError),
    Texture(String),
    Scene(String),
    Target(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adapter(err) => write!(f, "no suitable GPU adapter: {err}"),
            Self::Device(err) => write!(f, "failed to create GPU device: {err}"),
            Self::Readback(err) => write!(f, "failed to read back frame: {err}"),
            Self::Poll(err) => write!(f, "failed to wait for GPU: {err}"),
            Self::Texture(reason) => write!(f, "texture error: {reason}"),
            Self::Scene(reason) => write!(f, "scene error: {reason}"),
            Self::Target(reason) => write!(f, "render target error: {reason}"),
        }
    }
}

impl std::error::Error for Error {}

/// The background of a rendered frame. Colours are linear RGBA.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Background {
    Color([f32; 4]),
    Transparent,
}

impl Background {
    pub const DARK: Self = Self::Color([0.012, 0.014, 0.018, 1.0]);

    fn clear(self) -> wgpu::Color {
        match self {
            Self::Color([r, g, b, a]) => wgpu::Color {
                r: f64::from(r),
                g: f64::from(g),
                b: f64::from(b),
                a: f64::from(a),
            },
            Self::Transparent => wgpu::Color {
                r: 0.0,
                g: 0.0,
                b: 0.0,
                a: 0.0,
            },
        }
    }
}

impl Default for Background {
    fn default() -> Self {
        Self::DARK
    }
}

/// A rendered frame as tightly packed RGBA8 sRGB rows, top row first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

impl Frame {
    /// The pixels in the renderer's native order (RGBA8 sRGB).
    pub fn rgba8(&self) -> &[u8] {
        &self.pixels
    }

    /// The same pixels as BGRA8, the order GPUI's `RenderImage` expects.
    pub fn to_bgra8(&self) -> Vec<u8> {
        let mut out = self.pixels.clone();
        for pixel in out.as_chunks_mut::<4>().0 {
            pixel.swap(0, 2);
        }
        out
    }

    pub fn pixel(&self, x: u32, y: u32) -> Option<[u8; 4]> {
        if x >= self.width || y >= self.height {
            return None;
        }
        let offset = ((y * self.width + x) * BYTES_PER_PIXEL) as usize;
        self.pixels
            .get(offset..offset + 4)
            .and_then(|pixel| pixel.try_into().ok())
    }
}

/// Options for one offscreen render.
#[derive(Debug, Clone, PartialEq)]
pub struct OffscreenOptions {
    pub width: u32,
    pub height: u32,
    pub background: Background,
    /// `None` frames the scene bounds automatically.
    pub camera: Option<OrbitCamera>,
    /// Whether to compute the camera from the scene when `camera` is `None`.
    pub frame_scene: bool,
}

impl OffscreenOptions {
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width,
            height,
            background: Background::DARK,
            camera: None,
            frame_scene: true,
        }
    }

    pub fn with_camera(mut self, camera: OrbitCamera) -> Self {
        self.camera = Some(camera);
        self
    }

    pub fn with_background(mut self, background: Background) -> Self {
        self.background = background;
        self
    }
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct CameraUniform {
    view_projection: [[f32; 4]; 4],
    camera_position: [f32; 4],
    light_direction: [f32; 4],
}

struct Target {
    width: u32,
    height: u32,
    color: wgpu::Texture,
    depth_view: wgpu::TextureView,
    readback: wgpu::Buffer,
    padded_bytes_per_row: u32,
}

/// A caller-owned GPU render target. Rendering into it never reads pixels
/// back; the caller can use the colour texture with its own device or copy it
/// later. Create it through [`Renderer::create_target`] so it belongs to the
/// renderer's device.
pub struct GpuTarget {
    width: u32,
    height: u32,
    format: wgpu::TextureFormat,
    color: wgpu::Texture,
    depth_view: wgpu::TextureView,
}

impl GpuTarget {
    pub fn width(&self) -> u32 {
        self.width
    }

    pub fn height(&self) -> u32 {
        self.height
    }

    pub fn format(&self) -> wgpu::TextureFormat {
        self.format
    }

    /// The colour texture. It is owned by this target and stays alive while
    /// the target does.
    pub fn color_texture(&self) -> &wgpu::Texture {
        &self.color
    }

    pub fn depth_view(&self) -> &wgpu::TextureView {
        &self.depth_view
    }

    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }
}

pub(crate) struct FallbackTextures {
    white: texture::GpuTexture,
    normal: texture::GpuTexture,
    black: texture::GpuTexture,
    checker: texture::GpuTexture,
}

/// A wgpu device, pipeline and readback target. Create one per viewer or per
/// exporter process; upload scenes through [`Renderer::upload_scene`] and
/// render them repeatedly.
pub struct Renderer {
    adapter_info: AdapterInfo,
    device: wgpu::Device,
    queue: wgpu::Queue,
    material_layout: wgpu::BindGroupLayout,
    camera: wgpu::Buffer,
    camera_bind_group: wgpu::BindGroup,
    sampler: wgpu::Sampler,
    pipelines: Pipelines,
    fallback: FallbackTextures,
    target: Option<Target>,
}

struct Pipelines {
    opaque: wgpu::RenderPipeline,
    opaque_double_sided: wgpu::RenderPipeline,
    blend: wgpu::RenderPipeline,
}

impl Renderer {
    /// Creates a renderer on the default adapter, falling back to a software
    /// adapter when necessary. Blocks until the device is ready.
    pub fn new() -> Result<Self, Error> {
        Self::with_options(RendererOptions::default())
    }

    pub fn with_options(options: RendererOptions) -> Result<Self, Error> {
        let mut descriptor = wgpu::InstanceDescriptor::new_without_display_handle();
        descriptor.backends = options.backends;
        let instance = wgpu::Instance::new(descriptor.with_env());
        let adapter = pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
            power_preference: options.power_preference,
            compatible_surface: None,
            force_fallback_adapter: options.force_fallback_adapter,
            ..Default::default()
        }))
        .or_else(|first| {
            if options.force_fallback_adapter {
                return Err(Error::Adapter(first));
            }
            pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions {
                power_preference: wgpu::PowerPreference::LowPower,
                compatible_surface: None,
                force_fallback_adapter: true,
                ..Default::default()
            }))
            .map_err(Error::Adapter)
        })?;
        let mut features = wgpu::Features::empty();
        if adapter
            .features()
            .contains(wgpu::Features::TEXTURE_COMPRESSION_BC)
        {
            features |= wgpu::Features::TEXTURE_COMPRESSION_BC;
        }
        let limits = wgpu::Limits::default().using_resolution(adapter.limits());
        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            label: Some("lforge-renderer"),
            required_features: features,
            required_limits: limits,
            ..Default::default()
        }))
        .map_err(Error::Device)?;

        let camera_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("camera"),
            entries: &[wgpu::BindGroupLayoutEntry {
                binding: 0,
                visibility: wgpu::ShaderStages::VERTEX_FRAGMENT,
                ty: wgpu::BindingType::Buffer {
                    ty: wgpu::BufferBindingType::Uniform,
                    has_dynamic_offset: false,
                    min_binding_size: None,
                },
                count: None,
            }],
        });
        let material_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("material"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                texture_entry(1),
                texture_entry(2),
                texture_entry(3),
                wgpu::BindGroupLayoutEntry {
                    binding: 4,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
            ],
        });
        let camera = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("camera"),
            size: size_of::<CameraUniform>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let camera_bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("camera"),
            layout: &camera_layout,
            entries: &[wgpu::BindGroupEntry {
                binding: 0,
                resource: camera.as_entire_binding(),
            }],
        });

        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("material"),
            address_mode_u: wgpu::AddressMode::Repeat,
            address_mode_v: wgpu::AddressMode::Repeat,
            address_mode_w: wgpu::AddressMode::Repeat,
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            mipmap_filter: wgpu::MipmapFilterMode::Nearest,
            anisotropy_clamp: 1,
            ..Default::default()
        });

        let shader = device.create_shader_module(wgpu::include_wgsl!("shader.wgsl"));
        let layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("scene"),
            bind_group_layouts: &[Some(&camera_layout), Some(&material_layout)],
            immediate_size: 0,
        });
        let pipelines = Pipelines {
            opaque: create_pipeline(&device, &layout, &shader, true, false, true),
            opaque_double_sided: create_pipeline(&device, &layout, &shader, false, false, true),
            blend: create_pipeline(&device, &layout, &shader, false, true, false),
        };
        let fallback = fallback_textures(&device, &queue);

        Ok(Self {
            adapter_info: adapter.get_info(),
            device,
            queue,
            material_layout,
            camera,
            camera_bind_group,
            sampler,
            pipelines,
            fallback,
            target: None,
        })
    }

    pub fn adapter_info(&self) -> &AdapterInfo {
        &self.adapter_info
    }

    /// Uploads a scene. The result owns the GPU buffers; dropping it releases
    /// them without affecting other scenes or this renderer.
    pub fn upload_scene(&self, scene: &Scene) -> Result<GpuScene, Error> {
        GpuScene::upload(
            &self.device,
            &self.queue,
            &self.material_layout,
            &self.sampler,
            &self.fallback,
            scene,
        )
    }

    fn update_camera(&self, camera: &OrbitCamera, width: u32, height: u32) {
        let aspect = width as f32 / height as f32;
        let uniforms = CameraUniform {
            view_projection: camera.view_projection(aspect).to_cols_array_2d(),
            camera_position: camera.eye().extend(1.0).to_array(),
            light_direction: Vec3::new(-0.4, -0.7, -0.6).normalize().extend(0.0).into(),
        };
        self.queue
            .write_buffer(&self.camera, 0, bytemuck::bytes_of(&uniforms));
    }

    fn encode_scene(
        &self,
        encoder: &mut wgpu::CommandEncoder,
        color_view: &wgpu::TextureView,
        depth_view: &wgpu::TextureView,
        scene: &GpuScene,
        camera: &OrbitCamera,
        background: Background,
    ) {
        let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
            label: Some("scene"),
            color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                view: color_view,
                depth_slice: None,
                resolve_target: None,
                ops: wgpu::Operations {
                    load: wgpu::LoadOp::Clear(background.clear()),
                    store: wgpu::StoreOp::Store,
                },
            })],
            depth_stencil_attachment: Some(wgpu::RenderPassDepthStencilAttachment {
                view: depth_view,
                depth_ops: Some(wgpu::Operations {
                    load: wgpu::LoadOp::Clear(1.0),
                    store: wgpu::StoreOp::Discard,
                }),
                stencil_ops: None,
            }),
            timestamp_writes: None,
            occlusion_query_set: None,
            multiview_mask: None,
        });
        pass.set_bind_group(0, &self.camera_bind_group, &[]);
        let camera_position = camera.eye();
        let mut order: Vec<usize> = (0..scene.primitives.len()).collect();
        order.sort_by(|&a, &b| {
            let a_primitive = &scene.primitives[a];
            let b_primitive = &scene.primitives[b];
            let a_blend =
                scene.materials[a_primitive.material].alpha_mode == lforge_scene::AlphaMode::Blend;
            let b_blend =
                scene.materials[b_primitive.material].alpha_mode == lforge_scene::AlphaMode::Blend;
            a_blend.cmp(&b_blend).then_with(|| {
                if a_blend {
                    let da = (a_primitive.center - camera_position).length_squared();
                    let db = (b_primitive.center - camera_position).length_squared();
                    db.total_cmp(&da)
                } else {
                    std::cmp::Ordering::Equal
                }
            })
        });
        let mut last_pipeline = None;
        for index in order {
            let primitive = &scene.primitives[index];
            let material = &scene.materials[primitive.material];
            let pipeline = if material.alpha_mode == lforge_scene::AlphaMode::Blend {
                &self.pipelines.blend
            } else if material.double_sided {
                &self.pipelines.opaque_double_sided
            } else {
                &self.pipelines.opaque
            };
            if last_pipeline != Some(pipeline as *const _) {
                pass.set_pipeline(pipeline);
                last_pipeline = Some(pipeline as *const _);
            }
            pass.set_bind_group(1, &material.bind_group, &[]);
            pass.set_vertex_buffer(0, primitive.vertices.slice(..));
            pass.set_index_buffer(primitive.indices.slice(..), wgpu::IndexFormat::Uint32);
            pass.draw_indexed(0..primitive.index_count, 0, 0..1);
        }
    }

    /// Creates a GPU target owned by this renderer's device. The colour
    /// format is the renderer's sRGB target format.
    pub fn create_target(&self, width: u32, height: u32) -> Result<GpuTarget, Error> {
        let max = self.device.limits().max_texture_dimension_2d;
        if width == 0 || height == 0 || width > max || height > max {
            return Err(Error::Target(format!(
                "{width} x {height} is outside 1..={max}"
            )));
        }
        let size = wgpu::Extent3d {
            width,
            height,
            depth_or_array_layers: 1,
        };
        let color = self.device.create_texture(&wgpu::TextureDescriptor {
            label: Some("gpu target color"),
            size,
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: COLOR_FORMAT,
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
            view_formats: &[],
        });
        let depth = self.device.create_texture(&wgpu::TextureDescriptor {
            label: Some("gpu target depth"),
            size,
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: DEPTH_FORMAT,
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            view_formats: &[],
        });
        Ok(GpuTarget {
            width,
            height,
            format: COLOR_FORMAT,
            color,
            depth_view: depth.create_view(&Default::default()),
        })
    }

    /// Renders an uploaded scene into a caller-owned GPU target. No GPU-to-CPU
    /// readback occurs.
    pub fn render_to_target(
        &self,
        scene: &GpuScene,
        camera: &OrbitCamera,
        target: &GpuTarget,
        background: Background,
    ) -> Result<(), Error> {
        let color_view = target.color.create_view(&Default::default());
        self.update_camera(camera, target.width, target.height);
        let mut encoder = self.device.create_command_encoder(&Default::default());
        self.encode_scene(
            &mut encoder,
            &color_view,
            &target.depth_view,
            scene,
            camera,
            background,
        );
        self.queue.submit([encoder.finish()]);
        Ok(())
    }

    /// Renders one frame of an uploaded scene and reads the pixels back.
    pub fn render(
        &mut self,
        scene: &GpuScene,
        camera: &OrbitCamera,
        width: u32,
        height: u32,
        background: Background,
    ) -> Result<Frame, Error> {
        let max = self.device.limits().max_texture_dimension_2d;
        let width = width.clamp(1, max);
        let height = height.clamp(1, max);
        if self
            .target
            .as_ref()
            .is_none_or(|target| (target.width, target.height) != (width, height))
        {
            self.target = Some(create_target(&self.device, width, height));
        }
        let target = self.target.as_ref().expect("target was just created");
        self.update_camera(camera, width, height);

        let color_view = target.color.create_view(&Default::default());
        let mut encoder = self.device.create_command_encoder(&Default::default());
        self.encode_scene(
            &mut encoder,
            &color_view,
            &target.depth_view,
            scene,
            camera,
            background,
        );
        encoder.copy_texture_to_buffer(
            target.color.as_image_copy(),
            wgpu::TexelCopyBufferInfo {
                buffer: &target.readback,
                layout: wgpu::TexelCopyBufferLayout {
                    offset: 0,
                    bytes_per_row: Some(target.padded_bytes_per_row),
                    rows_per_image: None,
                },
            },
            target.color.size(),
        );
        let submission = self.queue.submit([encoder.finish()]);

        let (sender, receiver) = mpsc::channel();
        target
            .readback
            .map_async(wgpu::MapMode::Read, .., move |result| {
                let _ = sender.send(result);
            });
        self.device
            .poll(wgpu::PollType::Wait {
                submission_index: Some(submission),
                timeout: None,
            })
            .map_err(Error::Poll)?;
        receiver
            .recv()
            .map_err(|_| Error::Readback(wgpu::BufferAsyncError))?
            .map_err(Error::Readback)?;

        let row_bytes = (width * BYTES_PER_PIXEL) as usize;
        let mut pixels = Vec::with_capacity(row_bytes * height as usize);
        {
            let mapped = target
                .readback
                .get_mapped_range(..)
                .map_err(|_| Error::Readback(wgpu::BufferAsyncError))?;
            for row in mapped.chunks(target.padded_bytes_per_row as usize) {
                pixels.extend_from_slice(&row[..row_bytes]);
            }
        }
        target.readback.unmap();

        Ok(Frame {
            width,
            height,
            pixels,
        })
    }

    /// Uploads `scene` and renders one frame. Use [`Renderer::upload_scene`]
    /// with [`Renderer::render`] to render the same scene repeatedly.
    pub fn render_offscreen(
        &mut self,
        scene: &Scene,
        options: &OffscreenOptions,
    ) -> Result<Frame, Error> {
        let gpu = self.upload_scene(scene)?;
        let aspect = options.width.max(1) as f32 / options.height.max(1) as f32;
        let camera = options.camera.unwrap_or_else(|| {
            if options.frame_scene {
                OrbitCamera::framing(scene.bounds, aspect)
            } else {
                OrbitCamera::default()
            }
        });
        self.render(
            &gpu,
            &camera,
            options.width,
            options.height,
            options.background,
        )
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RendererOptions {
    pub backends: wgpu::Backends,
    pub power_preference: wgpu::PowerPreference,
    pub force_fallback_adapter: bool,
}

impl Default for RendererOptions {
    fn default() -> Self {
        Self {
            backends: if cfg!(windows) {
                wgpu::Backends::DX12
            } else {
                wgpu::Backends::PRIMARY
            },
            power_preference: wgpu::PowerPreference::HighPerformance,
            force_fallback_adapter: false,
        }
    }
}

fn texture_entry(binding: u32) -> wgpu::BindGroupLayoutEntry {
    wgpu::BindGroupLayoutEntry {
        binding,
        visibility: wgpu::ShaderStages::FRAGMENT,
        ty: wgpu::BindingType::Texture {
            sample_type: wgpu::TextureSampleType::Float { filterable: true },
            view_dimension: wgpu::TextureViewDimension::D2,
            multisampled: false,
        },
        count: None,
    }
}

fn create_pipeline(
    device: &wgpu::Device,
    layout: &wgpu::PipelineLayout,
    shader: &wgpu::ShaderModule,
    cull: bool,
    blend: bool,
    depth_write: bool,
) -> wgpu::RenderPipeline {
    device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
        label: Some(if blend { "blend" } else { "opaque" }),
        layout: Some(layout),
        vertex: wgpu::VertexState {
            module: shader,
            entry_point: Some("vs_main"),
            compilation_options: Default::default(),
            buffers: &[Some(gpu_scene::GpuVertex::layout())],
        },
        primitive: wgpu::PrimitiveState {
            topology: wgpu::PrimitiveTopology::TriangleList,
            front_face: wgpu::FrontFace::Ccw,
            cull_mode: cull.then_some(wgpu::Face::Back),
            ..Default::default()
        },
        depth_stencil: Some(wgpu::DepthStencilState {
            format: DEPTH_FORMAT,
            depth_write_enabled: Some(depth_write),
            depth_compare: Some(wgpu::CompareFunction::Less),
            stencil: Default::default(),
            bias: Default::default(),
        }),
        multisample: Default::default(),
        fragment: Some(wgpu::FragmentState {
            module: shader,
            entry_point: Some("fs_main"),
            compilation_options: Default::default(),
            targets: &[Some(wgpu::ColorTargetState {
                format: COLOR_FORMAT,
                blend: blend.then_some(wgpu::BlendState::ALPHA_BLENDING),
                write_mask: wgpu::ColorWrites::ALL,
            })],
        }),
        multiview_mask: None,
        cache: None,
    })
}

fn create_target(device: &wgpu::Device, width: u32, height: u32) -> Target {
    let size = wgpu::Extent3d {
        width,
        height,
        depth_or_array_layers: 1,
    };
    let color = device.create_texture(&wgpu::TextureDescriptor {
        label: Some("frame color"),
        size,
        mip_level_count: 1,
        sample_count: 1,
        dimension: wgpu::TextureDimension::D2,
        format: COLOR_FORMAT,
        usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
        view_formats: &[],
    });
    let depth = device.create_texture(&wgpu::TextureDescriptor {
        label: Some("frame depth"),
        size,
        mip_level_count: 1,
        sample_count: 1,
        dimension: wgpu::TextureDimension::D2,
        format: DEPTH_FORMAT,
        usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
        view_formats: &[],
    });
    let padded_bytes_per_row =
        (width * BYTES_PER_PIXEL).next_multiple_of(wgpu::COPY_BYTES_PER_ROW_ALIGNMENT);
    let readback = device.create_buffer(&wgpu::BufferDescriptor {
        label: Some("frame readback"),
        size: u64::from(padded_bytes_per_row) * u64::from(height),
        usage: wgpu::BufferUsages::MAP_READ | wgpu::BufferUsages::COPY_DST,
        mapped_at_creation: false,
    });
    Target {
        width,
        height,
        color,
        depth_view: depth.create_view(&Default::default()),
        readback,
        padded_bytes_per_row,
    }
}

fn fallback_textures(device: &wgpu::Device, queue: &wgpu::Queue) -> FallbackTextures {
    FallbackTextures {
        white: solid(device, queue, "fallback white", [255, 255, 255, 255], true),
        normal: solid(
            device,
            queue,
            "fallback normal",
            [128, 128, 255, 255],
            false,
        ),
        black: solid(device, queue, "fallback black", [0, 0, 0, 255], false),
        checker: checker(device, queue),
    }
}

fn solid(
    device: &wgpu::Device,
    queue: &wgpu::Queue,
    label: &str,
    rgba: [u8; 4],
    srgb: bool,
) -> texture::GpuTexture {
    let format = if srgb {
        wgpu::TextureFormat::Rgba8UnormSrgb
    } else {
        wgpu::TextureFormat::Rgba8Unorm
    };
    let texture = device.create_texture_with_data(
        queue,
        &wgpu::TextureDescriptor {
            label: Some(label),
            size: wgpu::Extent3d {
                width: 1,
                height: 1,
                depth_or_array_layers: 1,
            },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format,
            usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
            view_formats: &[],
        },
        wgpu::util::TextureDataOrder::LayerMajor,
        &rgba,
    );
    texture::GpuTexture {
        view: texture.create_view(&Default::default()),
    }
}

fn checker(device: &wgpu::Device, queue: &wgpu::Queue) -> texture::GpuTexture {
    let size = 8u32;
    let mut pixels = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let bright = (x / 4 + y / 4) % 2 == 0;
            if bright {
                pixels.extend_from_slice(&[255, 0, 220, 255]);
            } else {
                pixels.extend_from_slice(&[32, 0, 40, 255]);
            }
        }
    }
    let texture = device.create_texture_with_data(
        queue,
        &wgpu::TextureDescriptor {
            label: Some("fallback checker"),
            size: wgpu::Extent3d {
                width: size,
                height: size,
                depth_or_array_layers: 1,
            },
            mip_level_count: 1,
            sample_count: 1,
            dimension: wgpu::TextureDimension::D2,
            format: wgpu::TextureFormat::Rgba8UnormSrgb,
            usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
            view_formats: &[],
        },
        wgpu::util::TextureDataOrder::LayerMajor,
        &pixels,
    );
    texture::GpuTexture {
        view: texture.create_view(&Default::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_pixel_is_row_major_from_the_top() {
        let frame = Frame {
            width: 2,
            height: 2,
            pixels: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        };
        assert_eq!(frame.pixel(0, 0), Some([1, 2, 3, 4]));
        assert_eq!(frame.pixel(1, 1), Some([13, 14, 15, 16]));
        assert_eq!(frame.pixel(2, 0), None);
        assert_eq!(frame.to_bgra8()[..4], [3, 2, 1, 4]);
    }

    #[test]
    fn transparent_background_clears_to_zero_alpha() {
        let color = Background::Transparent.clear();
        assert_eq!((color.r, color.g, color.b, color.a), (0.0, 0.0, 0.0, 0.0));
    }
}
