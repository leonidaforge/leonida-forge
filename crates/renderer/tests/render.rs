//! Requires a GPU adapter. On machines without one, set `WGPU_BACKEND` to a
//! backend with a software implementation (WARP is part of Direct3D 12).

use lforge_renderer::{OrbitCamera, Renderer};

fn pixel(frame: &lforge_renderer::Frame, x: u32, y: u32) -> [u8; 4] {
    let offset = ((y * frame.width + x) * 4) as usize;
    frame.pixels[offset..offset + 4].try_into().unwrap()
}

#[test]
fn renders_cube_over_background() {
    let mut renderer = Renderer::new().expect("renderer");
    // 67 * 4 bytes is not a multiple of the 256-byte copy alignment, so rows are padded.
    let frame = renderer.render(67, 45, &OrbitCamera::default()).unwrap();

    assert_eq!((frame.width, frame.height), (67, 45));
    assert_eq!(frame.pixels.len(), 67 * 45 * 4);

    let background = pixel(&frame, 0, 0);
    assert_eq!(pixel(&frame, 66, 0), background);
    assert_eq!(pixel(&frame, 0, 44), background);
    assert_eq!(pixel(&frame, 66, 44), background);
    assert_ne!(pixel(&frame, 33, 22), background);
}

#[test]
fn resizes_and_clamps_empty_sizes() {
    let mut renderer = Renderer::new().expect("renderer");
    let camera = OrbitCamera::default();
    assert_eq!(
        renderer.render(32, 32, &camera).unwrap().pixels.len(),
        32 * 32 * 4
    );

    let frame = renderer.render(0, 0, &camera).unwrap();
    assert_eq!((frame.width, frame.height), (1, 1));
    assert_eq!(frame.pixels.len(), 4);
}
