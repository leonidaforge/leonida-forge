// Skeleton overlay. Receives model-space lines from the scene layer; it never
// reads a skeleton record.

struct Camera {
    view_projection: mat4x4<f32>,
    camera_position: vec4<f32>,
    light_direction: vec4<f32>,
}

struct Highlight {
    // First and last vertex of the selected bone's markers in the marker pass.
    start: u32,
    count: u32,
    pad0: u32,
    pad1: u32,
}

@group(0) @binding(0)
var<uniform> camera: Camera;
@group(1) @binding(0)
var<uniform> highlight: Highlight;

struct OverlayInput {
    @location(0) position: vec3<f32>,
    @location(1) color: vec4<f32>,
}

struct OverlayOutput {
    @builtin(position) clip_position: vec4<f32>,
    @location(0) color: vec4<f32>,
}

@vertex
fn vs_overlay(input: OverlayInput, @builtin(vertex_index) index: u32) -> OverlayOutput {
    var output: OverlayOutput;
    output.clip_position = camera.view_projection * vec4<f32>(input.position, 1.0);
    var color = input.color;
    if (highlight.count > 0u && index >= highlight.start && index < highlight.start + highlight.count) {
        color = vec4<f32>(1.0, 0.72, 0.15, 1.0);
    }
    output.color = color;
    return output;
}

@fragment
fn fs_overlay(input: OverlayOutput) -> @location(0) vec4<f32> {
    return input.color;
}
