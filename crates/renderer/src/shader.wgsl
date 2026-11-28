// The static scene shader. The camera, the material and the shading model come
// from shading.wgsl, which is concatenated before this file; only the vertex
// stage and the entry points live here.

struct VertexInput {
    @location(0) position: vec3<f32>,
    @location(1) normal: vec3<f32>,
    @location(2) tangent: vec4<f32>,
    @location(3) uv0: vec2<f32>,
    @location(4) uv1: vec2<f32>,
    @location(5) color: vec4<f32>,
}

struct VertexOutput {
    @builtin(position) clip_position: vec4<f32>,
    @location(0) world_position: vec3<f32>,
    @location(1) normal: vec3<f32>,
    @location(2) tangent: vec4<f32>,
    @location(3) uv: vec2<f32>,
    @location(4) color: vec4<f32>,
}

@vertex
fn vs_main(input: VertexInput) -> VertexOutput {
    var output: VertexOutput;
    output.clip_position = camera.view_projection * vec4<f32>(input.position, 1.0);
    output.world_position = input.position;
    output.normal = input.normal;
    output.tangent = input.tangent;
    output.uv = input.uv0;
    output.color = input.color;
    return output;
}

@fragment
fn fs_main(input: VertexOutput, @builtin(front_facing) front_facing: bool) -> @location(0) vec4<f32> {
    return shade(input.world_position, input.normal, input.tangent, input.uv, front_facing);
}
