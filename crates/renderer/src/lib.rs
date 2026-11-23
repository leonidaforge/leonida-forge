//! Offscreen wgpu renderer for 3D viewports.
//!
//! Frames are rendered into an offscreen target and read back as tightly packed
//! BGRA8 sRGB pixels, so the renderer works without a window or surface.

mod camera;
mod mesh;

use std::fmt;
use std::sync::mpsc;

use bytemuck::{Pod, Zeroable};
use glam::Vec3;
use wgpu::util::DeviceExt;

pub use camera::OrbitCamera;
pub use wgpu::AdapterInfo;

const COLOR_FORMAT: wgpu::TextureFormat = wgpu::TextureFormat::Bgra8UnormSrgb;
const DEPTH_FORMAT: wgpu::TextureFormat = wgpu::TextureFormat::Depth32Float;
const BYTES_PER_PIXEL: u32 = 4;
const CLEAR_COLOR: wgpu::Color = wgpu::Color {
    r: 0.010,
    g: 0.011,
    b: 0.014,
    a: 1.0,
};

#[derive(Debug)]
pub enum Error {
    Adapter(wgpu::RequestAdapterError),
    Device(wgpu::RequestDeviceError),
    Readback(wgpu::BufferAsyncError),
    Poll(wgpu::PollError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Adapter(err) => write!(f, "no suitable GPU adapter: {err}"),
            Self::Device(err) => write!(f, "failed to create GPU device: {err}"),
            Self::Readback(err) => write!(f, "failed to read back frame: {err}"),
            Self::Poll(err) => write!(f, "failed to wait for GPU: {err}"),
        }
    }
}

impl std::error::Error for Error {}

/// A rendered frame as tightly packed BGRA8 sRGB rows.
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub pixels: Vec<u8>,
}

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Uniforms {
    view_projection: [[f32; 4]; 4],
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

pub struct Renderer {
    adapter_info: AdapterInfo,
    device: wgpu::Device,
    queue: wgpu::Queue,
    pipeline: wgpu::RenderPipeline,
    uniforms: wgpu::Buffer,
    bind_group: wgpu::BindGroup,
    vertices: wgpu::Buffer,
    indices: wgpu::Buffer,
    index_count: u32,
    target: Option<Target>,
}

impl Renderer {
    /// Creates a renderer on the default adapter. Blocks until the device is ready.
    ///
    /// Direct3D 12 is used on Windows; `WGPU_BACKEND` overrides the backend.
    pub fn new() -> Result<Self, Error> {
        let mut descriptor = wgpu::InstanceDescriptor::new_without_display_handle();
        if cfg!(windows) {
            descriptor.backends = wgpu::Backends::DX12;
        }
        let instance = wgpu::Instance::new(descriptor.with_env());
        let adapter =
            pollster::block_on(instance.request_adapter(&wgpu::RequestAdapterOptions::default()))
                .map_err(Error::Adapter)?;
        let (device, queue) = pollster::block_on(adapter.request_device(&wgpu::DeviceDescriptor {
            label: Some("lforge"),
            required_limits: wgpu::Limits::downlevel_defaults().using_resolution(adapter.limits()),
            ..Default::default()
        }))
        .map_err(Error::Device)?;

        let shader = device.create_shader_module(wgpu::include_wgsl!("shader.wgsl"));
        let uniforms = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("uniforms"),
            size: size_of::<Uniforms>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });
        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("uniforms"),
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
        let bind_group = device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some("uniforms"),
            layout: &bind_group_layout,
            entries: &[wgpu::BindGroupEntry {
                binding: 0,
                resource: uniforms.as_entire_binding(),
            }],
        });
        let layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("mesh"),
            bind_group_layouts: &[Some(&bind_group_layout)],
            immediate_size: 0,
        });
        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("mesh"),
            layout: Some(&layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: Some("vs_main"),
                compilation_options: Default::default(),
                buffers: &[Some(wgpu::VertexBufferLayout {
                    array_stride: size_of::<mesh::Vertex>() as u64,
                    step_mode: wgpu::VertexStepMode::Vertex,
                    attributes: &mesh::Vertex::ATTRIBUTES,
                })],
            },
            primitive: wgpu::PrimitiveState {
                cull_mode: Some(wgpu::Face::Back),
                ..Default::default()
            },
            depth_stencil: Some(wgpu::DepthStencilState {
                format: DEPTH_FORMAT,
                depth_write_enabled: Some(true),
                depth_compare: Some(wgpu::CompareFunction::Less),
                stencil: Default::default(),
                bias: Default::default(),
            }),
            multisample: Default::default(),
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: Some("fs_main"),
                compilation_options: Default::default(),
                targets: &[Some(COLOR_FORMAT.into())],
            }),
            multiview_mask: None,
            cache: None,
        });

        let (vertex_data, index_data) = mesh::cube();
        let vertices = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("cube vertices"),
            contents: bytemuck::cast_slice(&vertex_data),
            usage: wgpu::BufferUsages::VERTEX,
        });
        let indices = device.create_buffer_init(&wgpu::util::BufferInitDescriptor {
            label: Some("cube indices"),
            contents: bytemuck::cast_slice(&index_data),
            usage: wgpu::BufferUsages::INDEX,
        });

        Ok(Self {
            adapter_info: adapter.get_info(),
            device,
            queue,
            pipeline,
            uniforms,
            bind_group,
            vertices,
            indices,
            index_count: index_data.len() as u32,
            target: None,
        })
    }

    pub fn adapter_info(&self) -> &AdapterInfo {
        &self.adapter_info
    }

    /// Renders one frame. Blocks until the pixels are read back.
    ///
    /// The size is clamped to the device's texture limits.
    pub fn render(
        &mut self,
        width: u32,
        height: u32,
        camera: &OrbitCamera,
    ) -> Result<Frame, Error> {
        let max = self.device.limits().max_texture_dimension_2d;
        let (width, height) = (width.clamp(1, max), height.clamp(1, max));
        if self
            .target
            .as_ref()
            .is_none_or(|target| (target.width, target.height) != (width, height))
        {
            self.target = Some(create_target(&self.device, width, height));
        }
        let target = self.target.as_ref().expect("target was just created");

        let uniforms = Uniforms {
            view_projection: camera
                .view_projection(width as f32 / height as f32)
                .to_cols_array_2d(),
            light_direction: Vec3::new(-0.4, -0.8, -0.5).normalize().extend(0.0).into(),
        };
        self.queue
            .write_buffer(&self.uniforms, 0, bytemuck::bytes_of(&uniforms));

        let color_view = target.color.create_view(&Default::default());
        let mut encoder = self.device.create_command_encoder(&Default::default());
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("mesh"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &color_view,
                    depth_slice: None,
                    resolve_target: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(CLEAR_COLOR),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: Some(wgpu::RenderPassDepthStencilAttachment {
                    view: &target.depth_view,
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
            pass.set_pipeline(&self.pipeline);
            pass.set_bind_group(0, &self.bind_group, &[]);
            pass.set_vertex_buffer(0, self.vertices.slice(..));
            pass.set_index_buffer(self.indices.slice(..), wgpu::IndexFormat::Uint16);
            pass.draw_indexed(0..self.index_count, 0, 0..1);
        }
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
            .expect("map callback runs before poll returns")
            .map_err(Error::Readback)?;

        let row_bytes = (width * BYTES_PER_PIXEL) as usize;
        let mut pixels = Vec::with_capacity(row_bytes * height as usize);
        {
            let mapped = target
                .readback
                .get_mapped_range(..)
                .expect("readback buffer is mapped");
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
}

fn create_target(device: &wgpu::Device, width: u32, height: u32) -> Target {
    let size = wgpu::Extent3d {
        width,
        height,
        depth_or_array_layers: 1,
    };
    let color = device.create_texture(&wgpu::TextureDescriptor {
        label: Some("viewport color"),
        size,
        mip_level_count: 1,
        sample_count: 1,
        dimension: wgpu::TextureDimension::D2,
        format: COLOR_FORMAT,
        usage: wgpu::TextureUsages::RENDER_ATTACHMENT | wgpu::TextureUsages::COPY_SRC,
        view_formats: &[],
    });
    let depth = device.create_texture(&wgpu::TextureDescriptor {
        label: Some("viewport depth"),
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
        label: Some("viewport readback"),
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
