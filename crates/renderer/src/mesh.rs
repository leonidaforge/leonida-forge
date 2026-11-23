use bytemuck::{Pod, Zeroable};

#[repr(C)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub(crate) struct Vertex {
    position: [f32; 3],
    normal: [f32; 3],
    color: [f32; 3],
}

impl Vertex {
    pub(crate) const ATTRIBUTES: [wgpu::VertexAttribute; 3] =
        wgpu::vertex_attr_array![0 => Float32x3, 1 => Float32x3, 2 => Float32x3];
}

/// Unit cube centered at the origin with one flat color per face.
pub(crate) fn cube() -> (Vec<Vertex>, Vec<u16>) {
    // [normal, tangent u, tangent v, linear color]; u × v points along the normal.
    #[rustfmt::skip]
    let faces: [[[f32; 3]; 4]; 6] = [
        [[1., 0., 0.], [0., 0., -1.], [0., 1., 0.], [0.80, 0.22, 0.18]],
        [[-1., 0., 0.], [0., 0., 1.], [0., 1., 0.], [0.20, 0.55, 0.80]],
        [[0., 1., 0.], [1., 0., 0.], [0., 0., -1.], [0.85, 0.75, 0.25]],
        [[0., -1., 0.], [1., 0., 0.], [0., 0., 1.], [0.45, 0.45, 0.50]],
        [[0., 0., 1.], [1., 0., 0.], [0., 1., 0.], [0.25, 0.70, 0.35]],
        [[0., 0., -1.], [-1., 0., 0.], [0., 1., 0.], [0.70, 0.35, 0.75]],
    ];

    let mut vertices = Vec::with_capacity(24);
    let mut indices = Vec::with_capacity(36);
    for [normal, u, v, color] in faces {
        let base = vertices.len() as u16;
        for (su, sv) in [(-1., -1.), (1., -1.), (1., 1.), (-1., 1.)] {
            let position = std::array::from_fn(|i| 0.5 * (normal[i] + su * u[i] + sv * v[i]));
            vertices.push(Vertex {
                position,
                normal,
                color,
            });
        }
        indices.extend([0, 1, 2, 0, 2, 3].map(|i| base + i));
    }
    (vertices, indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use glam::Vec3;

    #[test]
    fn faces_wind_counter_clockwise_seen_from_outside() {
        let (vertices, indices) = cube();
        for triangle in indices.chunks(3) {
            let [a, b, c] = [0, 1, 2].map(|i| Vec3::from(vertices[triangle[i] as usize].position));
            let face_normal = (b - a).cross(c - a).normalize();
            let normal = Vec3::from(vertices[triangle[0] as usize].normal);
            assert!(face_normal.dot(normal) > 0.999);
        }
    }

    #[test]
    fn vertices_lie_on_the_unit_cube() {
        let (vertices, _) = cube();
        for vertex in vertices {
            assert!(vertex.position.iter().all(|c| c.abs() == 0.5));
        }
    }
}
