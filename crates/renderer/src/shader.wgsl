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
    // x = metalness, y = roughness, z = emissive weight, w = spare
    surface: vec4<f32>,
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

// A studio backdrop sampled by reflection: bright above, dark below, with a
// long soft key panel so painted panels pick up a highlight along the shoulder.
fn studio(direction: vec3<f32>) -> vec3<f32> {
    let up = clamp(direction.y * 0.5 + 0.5, 0.0, 1.0);
    let sky = mix(vec3<f32>(0.05, 0.05, 0.06), vec3<f32>(0.62, 0.68, 0.82), up);
    let panel = pow(max(dot(direction, normalize(vec3<f32>(-0.4, 0.62, 0.68))), 0.0), 6.0);
    let strip = pow(max(dot(direction, normalize(vec3<f32>(0.75, 0.35, -0.55))), 0.0), 22.0);
    return sky + vec3<f32>(1.0, 0.97, 0.92) * panel * 0.9 + vec3<f32>(0.55, 0.65, 0.85) * strip;
}

fn distribution(n_dot_h: f32, roughness: f32) -> f32 {
    let alpha = max(roughness * roughness, 0.002);
    let alpha2 = alpha * alpha;
    let denominator = n_dot_h * n_dot_h * (alpha2 - 1.0) + 1.0;
    return alpha2 / (3.14159265 * denominator * denominator);
}

fn geometry_term(n_dot_v: f32, n_dot_l: f32, roughness: f32) -> f32 {
    let k = (roughness + 1.0) * (roughness + 1.0) / 8.0;
    let view = n_dot_v / (n_dot_v * (1.0 - k) + k);
    let light = n_dot_l / (n_dot_l * (1.0 - k) + k);
    return view * light;
}

fn fresnel_schlick(cosine: f32, f0: vec3<f32>) -> vec3<f32> {
    return f0 + (vec3<f32>(1.0) - f0) * pow(clamp(1.0 - cosine, 0.0, 1.0), 5.0);
}

fn aces(color: vec3<f32>) -> vec3<f32> {
    let a = 2.51;
    let b = 0.03;
    let c = 2.43;
    let d = 0.59;
    let e = 0.14;
    return clamp((color * (a * color + b)) / (color * (c * color + d) + e), vec3<f32>(0.0), vec3<f32>(1.0));
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
    return normalize(mix(geometric, normalize(normal), clamp(material.params.x, 0.0, 1.0)));
}

fn direct(
    normal: vec3<f32>,
    view: vec3<f32>,
    n_dot_v: f32,
    light_dir: vec3<f32>,
    light_color: vec3<f32>,
    diffuse_albedo: vec3<f32>,
    f0: vec3<f32>,
    roughness: f32,
) -> vec3<f32> {
    let n_dot_l = max(dot(normal, light_dir), 0.0);
    if (n_dot_l <= 0.0) {
        return vec3<f32>(0.0);
    }
    let half_vector = normalize(light_dir + view);
    let n_dot_h = max(dot(normal, half_vector), 0.0);
    let v_dot_h = max(dot(view, half_vector), 0.0);
    let d = distribution(n_dot_h, roughness);
    let g = geometry_term(n_dot_v, n_dot_l, roughness);
    let f = fresnel_schlick(v_dot_h, f0);
    let specular = d * g * f / (4.0 * n_dot_v * n_dot_l + 1e-4);
    return (diffuse_albedo * 0.31830988 + specular) * light_color * n_dot_l;
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
    let view = normalize(camera.camera_position.xyz - input.world_position);
    let n_dot_v = max(dot(normal, view), 1e-4);

    // A specular map marks glossy panels; it sharpens the highlight instead of
    // replacing the base roughness.
    let specular_sample = textureSample(specular_texture, texture_sampler, input.uv).rgb;
    let gloss = max(max(specular_sample.r, specular_sample.g), specular_sample.b);
    let roughness = clamp(material.surface.y * mix(1.0, 0.35, gloss), 0.03, 1.0);
    let metallic = clamp(material.surface.x, 0.0, 1.0);

    let albedo = material.base_color.rgb * base_sample.rgb;
    let diffuse_albedo = albedo * (1.0 - metallic);
    let f0 = mix(vec3<f32>(0.04), albedo, metallic);

    let key_dir = normalize(-camera.light_direction.xyz);
    let fill_dir = normalize(vec3<f32>(-0.55, 0.35, 0.75));
    let rim_dir = normalize(vec3<f32>(0.2, -0.35, -0.9));
    var color = vec3<f32>(0.0);
    color += direct(normal, view, n_dot_v, key_dir, vec3<f32>(1.0, 0.97, 0.92) * 3.1, diffuse_albedo, f0, roughness);
    color += direct(normal, view, n_dot_v, fill_dir, vec3<f32>(0.45, 0.55, 0.78) * 0.85, diffuse_albedo, f0, roughness);
    color += direct(normal, view, n_dot_v, rim_dir, vec3<f32>(0.6, 0.72, 1.0) * 1.15, diffuse_albedo, f0, roughness);

    // Hemisphere ambient stands in for the sky and the floor bounce.
    let hemi = mix(vec3<f32>(0.04, 0.04, 0.05), vec3<f32>(0.26, 0.31, 0.40), clamp(normal.y * 0.5 + 0.5, 0.0, 1.0));
    color += diffuse_albedo * hemi;

    // Reflections: paint and glass pick up the backdrop, matte trim barely does.
    let reflected = reflect(-view, normal);
    let environment = studio(reflected);
    let fresnel = fresnel_schlick(n_dot_v, f0);
    color += environment * fresnel * mix(0.55, 0.10, roughness);
    let clear_coat = metallic * (1.0 - roughness) * 0.35;
    color += environment * clear_coat * pow(1.0 - n_dot_v, 2.0);

    color += albedo * material.surface.z;
    return vec4<f32>(aces(color), alpha);
}
