struct Camera {
    view_projection: mat4x4<f32>,
    camera_position: vec4<f32>,
    light_direction: vec4<f32>,
}

@group(0) @binding(0)
var<uniform> camera: Camera;

struct Material {
    base_color: vec4<f32>,
    // x = bumpiness, y = alpha cutoff, z = normal map present, w = BC5 normal
    params: vec4<f32>,
}

@group(1) @binding(0)
var<uniform> material: Material;
@group(1) @binding(1)
var diffuse_texture: texture_2d<f32>;
@group(1) @binding(2)
var normal_texture: texture_2d<f32>;
@group(1) @binding(3)
var specular_texture: texture_2d<f32>;
@group(1) @binding(4)
var texture_sampler: sampler;

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

fn sample_normal(input: VertexOutput) -> vec3<f32> {
    let geometric = normalize(input.normal);
    if (material.params.z < 0.5) {
        return geometric;
    }
    let tangent_length = length(input.tangent.xyz);
    if (tangent_length < 0.5) {
        return geometric;
    }
    let tangent = normalize(input.tangent.xyz);
    let bitangent = normalize(cross(geometric, tangent)) * input.tangent.w;
    let encoded = textureSample(normal_texture, texture_sampler, input.uv).xyz * 2.0 - vec3<f32>(1.0);
    var local = encoded;
    if (material.params.w > 0.5) {
        local.z = sqrt(max(0.0, 1.0 - local.x * local.x - local.y * local.y));
    }
    local.y = -local.y;
    let normal = tangent * local.x + bitangent * local.y + geometric * local.z;
    return normalize(normal);
}

@fragment
fn fs_main(input: VertexOutput, @builtin(front_facing) front_facing: bool) -> @location(0) vec4<f32> {
    let base_sample = textureSample(diffuse_texture, texture_sampler, input.uv);
    let alpha = base_sample.a * material.base_color.a;
    if (material.params.y > 0.0 && alpha < material.params.y) {
        discard;
    }

    var normal = sample_normal(input);
    if (!front_facing) {
        normal = -normal;
    }
    let light = normalize(-camera.light_direction.xyz);
    let fill = normalize(vec3<f32>(-light.y, light.x, 0.25));
    let view = normalize(camera.camera_position.xyz - input.world_position);
    let diffuse = max(dot(normal, light), 0.0);
    let fill_diffuse = max(dot(normal, fill), 0.0) * 0.18;
    let half_vector = normalize(light + view);
    let specular_sample = textureSample(specular_texture, texture_sampler, input.uv).rgb;
    let specular = pow(max(dot(normal, half_vector), 0.0), 48.0) * specular_sample * 0.35;

    let tint = material.base_color.rgb * base_sample.rgb;
    let lit = tint * (0.32 + 0.78 * diffuse + fill_diffuse) + specular;
    return vec4<f32>(lit, alpha);
}
