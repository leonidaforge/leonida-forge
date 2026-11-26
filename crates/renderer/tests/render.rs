//! GPU tests. On a machine without a compatible adapter the renderer asks
//! for the platform's software adapter; if even that is unavailable the test
//! prints a skip line and returns. Such a return is not a rendering pass.

use lforge_renderer::{Background, Frame, GpuScene, OffscreenOptions, OrbitCamera, Renderer};
use lforge_scene::{
    Aabb, AlphaMode, Material, Mesh, Primitive, Scene, Texture, TextureFormat, Vertex,
};

fn renderer() -> Option<Renderer> {
    match Renderer::new() {
        Ok(renderer) => Some(renderer),
        Err(err) => {
            eprintln!("SKIP: no GPU adapter: {err}");
            None
        }
    }
}

fn vertex(position: [f32; 3], uv: [f32; 2]) -> Vertex {
    Vertex {
        position,
        normal: [0.0, 0.0, 1.0],
        tangent: None,
        uv0: uv,
        uv1: None,
        color: [1.0; 4],
    }
}

/// A quad in the XY plane facing +Z.
fn quad(material: usize) -> Primitive {
    Primitive {
        material,
        vertices: vec![
            vertex([-1.0, -1.0, 0.0], [0.0, 0.0]),
            vertex([1.0, -1.0, 0.0], [1.0, 0.0]),
            vertex([1.0, 1.0, 0.0], [1.0, 1.0]),
            vertex([-1.0, 1.0, 0.0], [0.0, 1.0]),
        ],
        indices: vec![0, 1, 2, 0, 2, 3],
    }
}

fn colored_quad(material: usize) -> Primitive {
    let mut primitive = quad(material);
    for vertex in &mut primitive.vertices {
        vertex.normal = [0.0, 0.0, 1.0];
    }
    primitive
}

fn checker_texture() -> Texture {
    let mut data = Vec::new();
    for y in 0..8 {
        for x in 0..8 {
            if (x / 2 + y / 2) % 2 == 0 {
                data.extend_from_slice(&[255, 40, 40, 255]);
            } else {
                data.extend_from_slice(&[40, 40, 255, 255]);
            }
        }
    }
    Texture {
        name: "checker".into(),
        width: 8,
        height: 8,
        format: TextureFormat::Rgba8UnormSrgb,
        source_mip_levels: 1,
        data,
        source: "synthetic".into(),
    }
}

fn textured_scene() -> Scene {
    let mut scene = Scene::new();
    scene.textures.push(checker_texture());
    scene.materials.push(Material {
        name: "checker".into(),
        diffuse: Some(0),
        ..Material::default()
    });
    let mut mesh = Mesh::new("quad");
    mesh.primitives.push(quad(0));
    scene.meshes.push(mesh);
    scene.validate();
    scene
}

fn colored_scene() -> Scene {
    let mut scene = Scene::new();
    scene.materials.push(Material {
        name: "red".into(),
        base_color: [0.9, 0.1, 0.1, 1.0],
        ..Material::default()
    });
    let mut mesh = Mesh::new("quad");
    mesh.primitives.push(colored_quad(0));
    scene.meshes.push(mesh);
    scene.validate();
    scene
}

fn background(frame: &Frame) -> [u8; 4] {
    frame.pixel(0, 0).expect("corner pixel")
}

fn center(frame: &Frame) -> [u8; 4] {
    frame
        .pixel(frame.width / 2, frame.height / 2)
        .expect("center pixel")
}

#[test]
fn renders_a_synthetic_mesh_over_the_background() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let scene = colored_scene();
    let camera = OrbitCamera::framing(scene.bounds, 4.0 / 3.0);
    let frame = renderer
        .render_offscreen(
            &scene,
            &OffscreenOptions::new(96, 72)
                .with_camera(camera)
                .with_background(Background::DARK),
        )
        .expect("render");
    assert_eq!((frame.width, frame.height), (96, 72));
    assert_eq!(frame.pixels.len(), 96 * 72 * 4);
    assert_ne!(center(&frame), background(&frame));
    let center = center(&frame);
    assert!(center[0] > center[2], "the red material should dominate");
}

#[test]
fn renders_a_textured_mesh() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let scene = textured_scene();
    let camera = OrbitCamera::framing(scene.bounds, 1.0);
    let frame = renderer
        .render_offscreen(
            &scene,
            &OffscreenOptions::new(64, 64)
                .with_camera(camera)
                .with_background(Background::DARK),
        )
        .expect("render");
    let center = center(&frame);
    assert!(
        center[0] > center[1] || center[2] > center[1],
        "the checker colours should reach the centre: {center:?}"
    );
    assert_ne!(center, background(&frame));
}

#[test]
fn multiple_meshes_and_materials_share_one_scene() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let mut scene = Scene::new();
    scene.materials.push(Material {
        name: "red".into(),
        base_color: [0.9, 0.1, 0.1, 1.0],
        ..Material::default()
    });
    scene.materials.push(Material {
        name: "blue".into(),
        base_color: [0.1, 0.1, 0.9, 1.0],
        ..Material::default()
    });
    let mut left = Mesh::new("left");
    let mut left_primitive = colored_quad(0);
    for vertex in &mut left_primitive.vertices {
        vertex.position[0] -= 1.1;
    }
    left.primitives.push(left_primitive);
    let mut right = Mesh::new("right");
    let mut right_primitive = colored_quad(1);
    for vertex in &mut right_primitive.vertices {
        vertex.position[0] += 1.1;
    }
    right.primitives.push(right_primitive);
    scene.meshes.push(left);
    scene.meshes.push(right);
    scene.validate();

    let camera = OrbitCamera::framing(scene.bounds, 2.0);
    let frame = renderer
        .render_offscreen(
            &scene,
            &OffscreenOptions::new(120, 60)
                .with_camera(camera)
                .with_background(Background::DARK),
        )
        .expect("render");
    let mut red = 0;
    let mut blue = 0;
    for y in 0..frame.height {
        for x in 0..frame.width {
            let pixel = frame.pixel(x, y).expect("pixel");
            if pixel[0] > pixel[2].saturating_add(20) {
                red += 1;
            }
            if pixel[2] > pixel[0].saturating_add(20) {
                blue += 1;
            }
        }
    }
    assert!(red > 0, "the red mesh is drawn");
    assert!(blue > 0, "the blue mesh is drawn");
}

#[test]
fn offscreen_rendering_can_be_repeated_without_a_window() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let scene = textured_scene();
    let options = OffscreenOptions::new(32, 24);
    let first = renderer.render_offscreen(&scene, &options).expect("first");
    let second = renderer.render_offscreen(&scene, &options).expect("second");
    assert_eq!(first, second, "the same scene renders deterministically");
    assert_eq!((first.width, first.height), (32, 24));
}

#[test]
fn a_scene_can_be_rendered_again_after_another_upload() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let first = renderer
        .upload_scene(&colored_scene())
        .expect("first upload");
    let second = renderer
        .upload_scene(&textured_scene())
        .expect("second upload");
    let camera = OrbitCamera::framing(
        Aabb {
            min: [-1.0, -1.0, -0.1].into(),
            max: [1.0, 1.0, 0.1].into(),
        },
        1.0,
    );
    assert!(
        renderer
            .render(&first, &camera, 32, 32, Background::DARK)
            .is_ok()
    );
    assert!(
        renderer
            .render(&second, &camera, 32, 32, Background::DARK)
            .is_ok()
    );
    drop(first);
    let third: GpuScene = renderer.upload_scene(&colored_scene()).expect("third");
    assert!(
        renderer
            .render(&third, &camera, 32, 32, Background::DARK)
            .is_ok()
    );
}

#[test]
fn transparent_background_keeps_zero_alpha() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let scene = colored_scene();
    let frame = renderer
        .render_offscreen(
            &scene,
            &OffscreenOptions::new(32, 32).with_background(Background::Transparent),
        )
        .expect("render");
    let corner = frame.pixel(0, 0).expect("corner");
    assert_eq!(corner[3], 0, "the clear alpha stays transparent");
    let center = frame.pixel(16, 16).expect("centre");
    assert_eq!(center[3], 255, "opaque geometry writes alpha 1");
}

#[test]
fn resizing_updates_the_target_and_aspect_ratio() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let scene = colored_scene();
    let camera = OrbitCamera::default();
    let gpu = renderer.upload_scene(&scene).unwrap();
    let wide = renderer
        .render(&gpu, &camera, 80, 40, Background::DARK)
        .expect("wide");
    let tall = renderer
        .render(&gpu, &camera, 40, 80, Background::DARK)
        .expect("tall");
    assert_eq!((wide.width, wide.height), (80, 40));
    assert_eq!((tall.width, tall.height), (40, 80));
    assert_eq!(wide.pixels.len(), 80 * 40 * 4);
    assert_eq!(tall.pixels.len(), 40 * 80 * 4);
}

#[test]
fn blend_material_is_supported() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let mut scene = colored_scene();
    scene.materials[0].alpha_mode = AlphaMode::Blend;
    scene.materials[0].base_color = [0.9, 0.1, 0.1, 0.5];
    let frame = renderer
        .render_offscreen(
            &scene,
            &OffscreenOptions::new(32, 32).with_background(Background::Transparent),
        )
        .expect("render");
    let center = center(&frame);
    assert!(center[3] > 0 && center[3] < 255, "{center:?}");
}

#[test]
fn a_missing_texture_uses_the_checker_fallback() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let mut scene = Scene::new();
    scene.materials.push(Material {
        name: "missing".into(),
        missing_texture: true,
        ..Material::default()
    });
    let mut mesh = Mesh::new("quad");
    mesh.primitives.push(quad(0));
    scene.meshes.push(mesh);
    scene.validate();
    let frame = renderer
        .render_offscreen(&scene, &OffscreenOptions::new(64, 64))
        .expect("render");
    let mut found = false;
    for pixel in frame.pixels.as_chunks::<4>().0 {
        if pixel[0] > 150 && pixel[2] > 150 && pixel[1] < 100 {
            found = true;
            break;
        }
    }
    assert!(found, "the checker fallback is visible");
}

#[test]
fn an_empty_scene_is_reported() {
    let Some(renderer) = renderer() else {
        return;
    };
    let mut scene = Scene::new();
    scene.materials.push(Material::default());
    let err = renderer.upload_scene(&scene).expect_err("empty scene");
    assert!(err.to_string().contains("primitive"));
}

#[test]
fn renders_into_a_gpu_target_without_readback() {
    let Some(renderer) = renderer() else {
        return;
    };
    let scene = colored_scene();
    let camera = OrbitCamera::framing(scene.bounds, 1.0);
    let target = renderer.create_target(48, 32).expect("target");
    assert_eq!(target.size(), (48, 32));
    assert_eq!(target.width(), 48);
    assert_eq!(target.height(), 32);
    let gpu = renderer.upload_scene(&scene).expect("upload");
    // A GPU-only render has no Frame result: it never copies to the CPU.
    renderer
        .render_to_target(&gpu, &camera, &target, Background::DARK)
        .expect("render to target");
    assert_eq!(target.color_texture().width(), 48);
    assert_eq!(target.color_texture().height(), 32);
}

#[test]
fn a_zero_sized_gpu_target_is_rejected() {
    let Some(renderer) = renderer() else {
        return;
    };
    assert!(renderer.create_target(0, 16).is_err());
    assert!(renderer.create_target(16, 0).is_err());
}

fn solid_bc1_texture(width: u32, height: u32) -> Texture {
    // BC1: red endpoint, every selector picks it.
    let block = [0x00u8, 0xF8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut data = Vec::new();
    for _ in 0..width.div_ceil(4) * height.div_ceil(4) {
        data.extend_from_slice(&block);
    }
    Texture {
        name: format!("bc1-{width}x{height}"),
        width,
        height,
        format: TextureFormat::Bc1Unorm,
        source_mip_levels: 1,
        data,
        source: "synthetic".into(),
    }
}

#[test]
fn bc3_srgb_texture_uploads_and_samples() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    let mut scene = Scene::new();
    scene.textures.push(Texture {
        name: "bc3-srgb".into(),
        width: 4,
        height: 4,
        format: TextureFormat::Bc3UnormSrgb,
        source_mip_levels: 1,
        data: vec![
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
        source: "synthetic".into(),
    });
    scene.materials.push(Material {
        name: "bc3-srgb".into(),
        diffuse: Some(0),
        ..Material::default()
    });
    let mut mesh = Mesh::new("quad");
    mesh.primitives.push(quad(0));
    scene.meshes.push(mesh);
    scene.validate();
    let frame = renderer
        .render_offscreen(&scene, &OffscreenOptions::new(64, 64))
        .expect("render");
    let center = center(&frame);
    assert!(
        center[0] > 150 && center[1] < 100 && center[2] < 100,
        "{center:?}"
    );
}

#[test]
fn small_compressed_textures_upload_and_sample() {
    let Some(mut renderer) = renderer() else {
        return;
    };
    for (width, height) in [(1, 1), (4, 1), (13, 1), (4, 4), (5, 3), (17, 9)] {
        let mut scene = Scene::new();
        scene.textures.push(solid_bc1_texture(width, height));
        scene.materials.push(Material {
            name: "bc1".into(),
            diffuse: Some(0),
            ..Material::default()
        });
        let mut mesh = Mesh::new("quad");
        mesh.primitives.push(quad(0));
        scene.meshes.push(mesh);
        scene.validate();
        let frame = renderer
            .render_offscreen(&scene, &OffscreenOptions::new(64, 64))
            .unwrap_or_else(|err| panic!("{width}x{height}: {err}"));
        let center = center(&frame);
        assert!(
            center[0] > 150 && center[1] < 100 && center[2] < 100,
            "{width}x{height}: {center:?}"
        );
    }
}
