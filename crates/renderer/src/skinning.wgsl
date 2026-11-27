// Shared skinning maths. Included by the rendering shader and by the
// verification probe, so both evaluate the same function.

struct PoseState {
    // -1 disables the influence view.
    highlight_bone: i32,
    // 0 = material, 1 = influence visualisation.
    view: u32,
    _pad0: u32,
    _pad1: u32,
}

@group(2) @binding(0) var<uniform> pose_state: PoseState;
@group(2) @binding(1) var<storage, read> joint_matrices: array<mat4x4<f32>>;

fn identity_matrix() -> mat4x4<f32> {
    return mat4x4<f32>(
        vec4<f32>(1.0, 0.0, 0.0, 0.0),
        vec4<f32>(0.0, 1.0, 0.0, 0.0),
        vec4<f32>(0.0, 0.0, 1.0, 0.0),
        vec4<f32>(0.0, 0.0, 0.0, 1.0),
    );
}

// The decoder validated every active index against the uploaded bone count.
// arrayLength keeps a malformed buffer from reading outside the binding.
fn safe_joint(index: u32) -> mat4x4<f32> {
    let count = arrayLength(&joint_matrices);
    if (count == 0u) {
        return identity_matrix();
    }
    return joint_matrices[min(index, count - 1u)];
}

fn skin_position(position: vec3<f32>, joints: vec4<u32>, weights: vec4<f32>) -> vec3<f32> {
    var out = vec3<f32>(0.0);
    for (var lane = 0u; lane < 4u; lane = lane + 1u) {
        let weight = weights[lane];
        if (weight > 0.0) {
            out = out + (safe_joint(joints[lane]) * vec4<f32>(position, 1.0)).xyz * weight;
        }
    }
    return out;
}

// Directions ignore translation. A rotation keeps the handedness, so the
// tangent's w component is carried through unchanged by the caller.
fn rotation_of(matrix: mat4x4<f32>) -> mat3x3<f32> {
    return mat3x3<f32>(matrix[0].xyz, matrix[1].xyz, matrix[2].xyz);
}

fn skin_direction(direction: vec3<f32>, joints: vec4<u32>, weights: vec4<f32>) -> vec3<f32> {
    var out = vec3<f32>(0.0);
    for (var lane = 0u; lane < 4u; lane = lane + 1u) {
        let weight = weights[lane];
        if (weight > 0.0) {
            out = out + (rotation_of(safe_joint(joints[lane])) * direction) * weight;
        }
    }
    return out;
}

// The summed weight of the highlighted bone on one vertex.
fn highlight_weight(joints: vec4<u32>, weights: vec4<f32>) -> f32 {
    let bone = pose_state.highlight_bone;
    if (bone < 0) {
        return 0.0;
    }
    var total = 0.0;
    for (var lane = 0u; lane < 4u; lane = lane + 1u) {
        if (joints[lane] == u32(bone)) {
            total = total + weights[lane];
        }
    }
    return total;
}
