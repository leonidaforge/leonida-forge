//! GPU tests for the skeleton overlay. The scene is synthetic: a red quad in
//! the z = 0 plane and two cyan bones behind it at z = -0.5.

use glam::{Quat, Vec3};
use lforge_renderer::{Background, Frame, OffscreenOptions, OrbitCamera, Overlay, Renderer};
use lforge_scene::{Bone, Material, Mesh, Primitive, Scene, Skeleton, Vertex};

fn renderer() -> Option<Renderer> {
    match Renderer::new() {
        Ok(renderer) => Some(renderer),
        Err(err) => {
            eprintln!("SKIP: no GPU adapter: {err}");
            None
        }
    }
}

fn vertex(position: [f32; 3]) -> Vertex {
    Vertex {
        position,
        normal: [0.0, 0.0, 1.0],
        tangent: None,
        uv0: [0.0, 0.0],
        uv1: None,
        color: [1.0; 4],
    }
}

fn quad() -> Primitive {
    Primitive {
        material: 0,
        vertices: vec![
            vertex([-1.0, -1.0, 0.0]),
            vertex([1.0, -1.0, 0.0]),
            vertex([1.0, 1.0, 0.0]),
            vertex([-1.0, 1.0, 0.0]),
        ],
        indices: vec![0, 1, 2, 0, 2, 3],
    }
}

fn bone(index: usize, parent: Option<usize>, position: Vec3) -> Bone {
    Bone {
        name: Some(format!("bone_{index}")),
        index,
        parent,
        identifier: Some(index as u32 + 1),
        identifier16: Some(index as u16 + 1),
        local_translation: position,
        local_rotation: Quat::IDENTITY,
        local_scale: Vec3::ONE,
        model_rotation: Quat::IDENTITY,
        model_position: position,
        inverse_bind: None,
    }
}

fn scene_with_skeleton() -> Scene {
    let mut scene = Scene::new();
    scene.materials.push(Material {
        name: "red".into(),
        base_color: [0.9, 0.1, 0.1, 1.0],
        ..Material::default()
    });
    let mut mesh = Mesh::new("quad");
    mesh.primitives.push(quad());
    scene.meshes.push(mesh);
    scene.skeleton = Some(Skeleton {
        bones: vec![
            bone(0, None, Vec3::new(-0.4, 0.0, -0.5)),
            bone(1, Some(0), Vec3::new(0.4, 0.0, -0.5)),
        ],
        roots: vec![0],
        max_depth: 2,
    });
    scene.validate();
    scene
}

fn camera(scene: &Scene) -> OrbitCamera {
    OrbitCamera::framing(scene.bounds, 4.0 / 3.0)
}

fn differing(a: &Frame, b: &Frame) -> usize {
    let a = a.pixels.as_chunks::<4>().0;
    let b = b.pixels.as_chunks::<4>().0;
    a.iter().zip(b).filter(|(a, b)| a != b).count()
}

fn cyan_pixels(frame: &Frame) -> usize {
    frame
        .pixels
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|pixel| pixel[0] < 220 && pixel[1] > 200 && pixel[2] > 200)
        .count()
}

fn orange_pixels(frame: &Frame) -> usize {
    frame
        .pixels
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|pixel| pixel[0] > 220 && pixel[1] > 120 && pixel[1] < 240 && pixel[2] < 140)
        .count()
}

fn render(renderer: &mut Renderer, scene: &Scene, overlay: Overlay) -> Frame {
    renderer
        .render_offscreen(
            scene,
            &OffscreenOptions::new(320, 240)
                .with_camera(camera(scene))
                .with_background(Background::DARK)
                .with_overlay(overlay),
        )
        .expect("render")
}
#[test]
fn the_overlay_is_absent_by_default() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let scene = scene_with_skeleton();
    let default = render(&mut renderer, &scene, Overlay::NONE);
    assert_eq!(cyan_pixels(&default), 0);
    assert_eq!(orange_pixels(&default), 0);
}

#[test]
fn a_depth_independent_overlay_draws_over_opaque_geometry() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let scene = scene_with_skeleton();
    let plain = render(&mut renderer, &scene, Overlay::NONE);
    let overlay = render(&mut renderer, &scene, Overlay::skeleton(None, true));
    assert!(
        differing(&plain, &overlay) > 20,
        "the overlay changed {} pixels",
        differing(&plain, &overlay)
    );
    assert!(
        cyan_pixels(&overlay) > 10,
        "the overlay drew {} cyan pixels",
        cyan_pixels(&overlay)
    );
}

#[test]
fn a_depth_tested_overlay_is_hidden_by_the_mesh() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let scene = scene_with_skeleton();
    let plain = render(&mut renderer, &scene, Overlay::NONE);
    let overlay = render(&mut renderer, &scene, Overlay::skeleton(None, false));
    assert_eq!(
        differing(&plain, &overlay),
        0,
        "a bone behind the quad must stay hidden"
    );
}

#[test]
fn hiding_the_mesh_reveals_a_depth_tested_overlay() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let scene = scene_with_skeleton();
    let plain = render(&mut renderer, &scene, Overlay::NONE);
    let mut gpu = renderer.upload_scene(&scene).expect("upload");
    assert!(gpu.has_skeleton());
    assert!(!gpu.skeleton_visible());
    assert_eq!(gpu.skeleton_bone_count(), 2);
    gpu.set_skeleton_visible(true);
    assert!(gpu.skeleton_visible());
    for mesh in 0..scene.meshes.len() {
        gpu.set_mesh_visible(mesh, false);
    }
    let framed = renderer
        .render(&gpu, &camera(&scene), 320, 240, Background::DARK)
        .expect("render");
    assert!(
        differing(&plain, &framed) > 0,
        "the skeleton is the only visible object"
    );
    assert!(cyan_pixels(&framed) > 0);
}

#[test]
fn the_selected_bone_is_highlighted() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let scene = scene_with_skeleton();
    let none = render(&mut renderer, &scene, Overlay::skeleton(None, true));
    let selected = render(&mut renderer, &scene, Overlay::skeleton(Some(1), true));
    assert!(orange_pixels(&none) == 0);
    assert!(
        orange_pixels(&selected) > 2,
        "the selected bone drew {} orange pixels",
        orange_pixels(&selected)
    );
    assert!(
        cyan_pixels(&selected) < cyan_pixels(&none),
        "the selected bone's markers are no longer drawn in the bone colour"
    );
    assert!(differing(&none, &selected) > 0);
}

#[test]
fn the_overlay_renders_into_a_caller_owned_target() {
    let Some(renderer) = renderer() else {
        return;
    };
    let scene = scene_with_skeleton();
    let gpu = renderer.upload_scene(&scene).expect("upload");
    let target = renderer.create_target(64, 48).expect("target");
    renderer
        .render_to_target_with(
            &gpu,
            &camera(&scene),
            &target,
            Background::DARK,
            Overlay::skeleton(Some(0), true),
        )
        .expect("render to target");
}
