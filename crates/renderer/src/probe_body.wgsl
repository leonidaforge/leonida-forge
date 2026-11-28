// Verification probe: evaluates the shared skinning functions for a
// caller-supplied vertex set and writes position, normal and tangent per
// vertex. It runs as a compute pass so the result does not depend on point or
// quad rasterisation rules.

struct ProbeInput {
    position: vec4<f32>,
    normal: vec4<f32>,
    tangent: vec4<f32>,
    joints: vec4<u32>,
    weights: vec4<f32>,
}

@group(0) @binding(0) var<storage, read> probes: array<ProbeInput>;
@group(0) @binding(1) var<storage, read_write> results: array<vec4<f32>>;

@compute @workgroup_size(64)
fn probe_main(@builtin(global_invocation_id) id: vec3<u32>) {
    let index = id.x;
    if (index >= arrayLength(&results)) {
        return;
    }
    let vertex = index / 3u;
    let mode = index % 3u;
    let input = probes[vertex];
    if (mode == 0u) {
        let position = skin_position(input.position.xyz, input.joints, input.weights);
        results[index] = vec4<f32>(position, 1.0);
    } else if (mode == 1u) {
        let normal = safe_direction(
            skin_direction(input.normal.xyz, input.joints, input.weights),
            input.normal.xyz,
        );
        results[index] = vec4<f32>(normal, 1.0);
    } else {
        let tangent = safe_direction(
            skin_direction(input.tangent.xyz, input.joints, input.weights),
            input.tangent.xyz,
        );
        results[index] = vec4<f32>(tangent, input.tangent.w);
    }
}
