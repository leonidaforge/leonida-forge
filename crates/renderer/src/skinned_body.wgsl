// The skinned counterpart of shader.wgsl. The camera, the material and the
// shading model come from shading.wgsl and the skinning helpers from
// skinning.wgsl, both concatenated before this file. Only the vertex stage and
// the influence-view branch live here, so posed geometry is shaded by exactly
// the same model as authored geometry.

struct SkinnedVertexInput {
    @location(0) position: vec3<f32>,
    @location(1) normal: vec3<f32>,
    @location(2) tangent: vec4<f32>,
    @location(3) uv0: vec2<f32>,
    @location(4) uv1: vec2<f32>,
    @location(5) color: vec4<f32>,
    @location(6) joints: vec4<u32>,
    @location(7) weights: vec4<f32>,
}

struct VertexOutput {
    @builtin(position) clip_position: vec4<f32>,
    @location(0) world_position: vec3<f32>,
    @location(1) normal: vec3<f32>,
    @location(2) tangent: vec4<f32>,
    @location(3) uv: vec2<f32>,
    @location(4) color: vec4<f32>,
    @location(5) highlight: f32,
}

@vertex
fn vs_skinned(input: SkinnedVertexInput) -> VertexOutput {
    var output: VertexOutput;
    let position = skin_position(input.position, input.joints, input.weights);
    output.clip_position = camera.view_projection * vec4<f32>(position, 1.0);
    output.world_position = position;
    output.normal = safe_direction(
        skin_direction(input.normal, input.joints, input.weights),
        input.normal,
    );
    output.tangent = vec4<f32>(
        safe_direction(
            skin_direction(input.tangent.xyz, input.joints, input.weights),
            input.tangent.xyz,
        ),
        input.tangent.w,
    );
    output.uv = input.uv0;
    output.color = input.color;
    if (pose_state.view == 1u) {
        output.highlight = highlight_weight(input.joints, input.weights);
    } else {
        output.highlight = 0.0;
    }
    return output;
}

@fragment
fn fs_skinned(input: VertexOutput, @builtin(front_facing) front_facing: bool) -> @location(0) vec4<f32> {
    if (pose_state.view == 1u) {
        let weight = clamp(input.highlight, 0.0, 1.0);
        var colour = mix(vec3<f32>(0.16, 0.16, 0.18), vec3<f32>(1.0, 0.28, 0.05), sqrt(weight));
        if (weight > 0.999) {
            colour = vec3<f32>(1.0, 0.95, 0.15);
        }
        return vec4<f32>(colour, 1.0);
    }
    return shade(input.world_position, input.normal, input.tangent, input.uv, front_facing);
}
