# Skinning

How a verified influence set becomes deformed geometry in this repository, and
how the desktop viewer exposes it. The format side, meaning which bytes carry the
influences and what the indices mean, is documented in the research repository
under `formats/resources/skeletons/`.

## Layers

| Layer | Location | Responsibility |
| ----- | -------- | -------------- |
| Decoder | `crates/model/src/influence.rs` | Reads slots 6 and 8, identifies the index encoding, validates every active index, and reports what it cannot read |
| Scene data | `crates/scene/src/skin.rs` | `VertexInfluences`, `SkinningMatrices`, `deform_primitive`, deformed bounds |
| Pose | `crates/scene/src/pose.rs` | Per-bone local deltas, hierarchy evaluation, reference pose |
| Renderer | `crates/renderer` | Skinned pipelines, joint-matrix buffer, influence view, compute probe |
| Desktop | `apps/desktop/src/viewers` | Pose session, panel controls, pose-aware framing |
| Consumer | `examples/skinning-consumer` | An external caller of the above, with no game path |

`lforge-scene` does not depend on the renderer or on GPUI, so the pose and the CPU
reference can be used and tested without a window or a device.

## Pose conventions

```text
R_local = R_bind_local * R_delta        delta rotation in the bone's own axes
t_local = t_bind_local + t_delta        delta translation in the parent's axes
G_pose[i] = compose(parent chain)       R_model = R_parent * R_local
                                        t_model = t_parent + R_parent * t_local
S[i] = G_pose[i] * inverse_bind[i]
p' = sum_k w_k * S[i_k] * p_authored
```

`Pose::set_rotation` stores the delta, `Pose::globals` resolves the hierarchy and
rejects a non-finite value, a cycle or an out-of-range parent, and
`SkinningMatrices::build` multiplies each posed transform by the stored
inverse-bind matrix. `deform_primitive` always starts from the authored vertices,
so evaluating a pose twice does not compound.

Normals and tangents use the rotation part of the same matrices, because every
supported bone has identity scale. A blended direction that collapses to zero
falls back to the authored direction and is counted, in the CPU path and in both
shader paths.

## Renderer

A primitive with verified, deformable influences gets a second vertex buffer that
carries the static attributes plus four joint indices and four weights. The
authored buffer is kept, so leaving pose mode never uploads anything again. Joint
matrices live in a storage buffer at bind group 2, rewritten per pose change;
`GpuScene::update_pose` also rewrites the overlay lines so the skeleton follows
the pose.

The skinned pipelines differ from the static ones only in the vertex shader.
`skinning.wgsl` holds the shared maths and is concatenated into both
`skinned_body.wgsl` and the compute probe `probe_body.wgsl`, so the verification
probe evaluates the same functions the raster path does.

`Renderer::probe_skinning` evaluates positions, normals and tangents for a caller's
vertex set and reads the results back. It is used by tests, by the desktop
deformation harness and by the consumer example. Interactive rendering never reads
back vertices.

## Influence view

With `view = 1` the skinned fragment shader ignores materials and colours the
surface by the summed weight of the highlighted bone: neutral grey at zero,
orange through the weight range, yellow at full weight. Primitives without a
verified influence set are drawn through the static pipeline and keep their
materials, so "no verified influence" is visibly different from "verified zero
weight". Changing the highlighted bone writes sixteen bytes of uniform and never
touches a buffer.

## Desktop pose inspector

`viewers::pose::PoseSession` holds the deltas, the Euler angles the panel shows,
the display mode and the influence view. It is UI-independent and tested without a
window. `Viewport` owns the session and caches one `PoseFrame` per revision; a
frame carries the matrices, the posed bone positions and two flags. The render
thread applies it, so a pose change never re-uploads a scene, never re-decodes a
resource and never queues: the request channel keeps one pending value and the
newest request wins.

Leaving pose mode sends one reference frame, because the joint matrices and the
overlay lines would otherwise stay at the last pose.

`Reset View` frames the deformed bounds while the posed display is active, and the
authored bounds otherwise. The interactive frame loop never computes posed bounds
and never reads back vertices.

Both the model viewer and the dictionary viewer show the same POSE panel from
`viewers/pose_panel.rs`. A dictionary member replacement builds a new `Viewport`,
so a pose cannot outlive the member it belongs to.

## Tests and harnesses

| Test | Covers |
| ---- | ------ |
| `crates/scene/src/pose.rs` tests | Delta composition, multiple roots, cycle and scale rejection, reference pose |
| `crates/scene/src/skin.rs` tests | LBS against hand-computed matrices, collapsed normals, deformed bounds, pose-dependent framing |
| `crates/model/src/influence/tests.rs` | The five encodings, weight totals, range rejection, inferred single-bone |
| `crates/renderer/tests/skinning.rs` | GPU against CPU for positions, normals and tangents; a 596-bone palette; the influence view; a tangent-free primitive rendered through both pipelines |
| `apps/desktop` `reports_deformation_measurements` | Real chains: propagation, per-root independence, CPU/GPU and pixel comparison, reset, timings, memory, previews |

The desktop harness is ignored by default. Run it with `LF_DEFORM_CASES` naming a
case list, `LF_TEST_GAME_ROOT`, `LF_TEST_EXECUTABLE` and optionally `LF_DEFORM_OUT`.

## Consumer example

```text
cargo run -p skinning-consumer -- --resource <decoded resource> \
    [--member <index>] [--bone <index|name>] [--degrees <deg>] \
    [--translate x,y,z] [--compare] [--render <file.png>]
```

It reads resource bytes, not archives, so it holds no installation path. It
decodes with `lforge-model`, poses with `lforge-scene`, optionally compares the GPU
probe with the CPU reference and optionally writes one PNG.

## Limits

- Linear blend skinning only. No dual-quaternion path exists.
- Non-identity scale is refused rather than composed.
- A pose is entered by hand. No animation clip, playback or blending is decoded.
- A geometry whose weights do not sum to 255 or 127 is reported and not deformed.
- An inferred single-bone association is marked as inferred and counted
  separately in the panel.
