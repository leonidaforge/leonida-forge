use super::*;
use lforge_rage9::dictionary::SlotState;

#[test]
fn a_member_name_hash_covers_the_name_without_its_final_extension() {
    let joaat = lforge_rage9::rpf::names::joaat;
    assert_eq!(
        DictionaryMember::hash_of_name("farlod_structures_03.#dr"),
        joaat(b"farlod_structures_03")
    );
    assert_ne!(
        DictionaryMember::hash_of_name("farlod_structures_03.#dr"),
        joaat(b"farlod_structures_03.#dr")
    );
    assert_eq!(
        DictionaryMember::hash_of_name("noextension"),
        joaat(b"noextension")
    );
    // Only the final extension is removed, not the first one.
    assert_eq!(DictionaryMember::hash_of_name("a.b.c"), joaat(b"a.b"));
}

fn vertex_buffer() -> VertexBuffer {
    VertexBuffer {
        at: 0,
        elements: 0xD0 / 4,
        unit: 4,
        word_0e: 9,
        word_10: 0x1601,
        graphics: 0,
        layout: None,
        vertex_count: 4,
        packed_flags: 0,
        declared_bytes: 0xD0,
        attribute_bytes: 0,
        layout_end: 0,
        prefix_gap: 0,
        attributes: vec![
            lforge_rage9::drawable::Attribute {
                slot: 0,
                offset: 0x80,
                size: 8,
                format: 0x10,
            },
            lforge_rage9::drawable::Attribute {
                slot: 4,
                offset: 0xA0,
                size: 4,
                format: 0x29,
            },
            lforge_rage9::drawable::Attribute {
                slot: 16,
                offset: 0xB0,
                size: 4,
                format: 0x26,
            },
            lforge_rage9::drawable::Attribute {
                slot: 24,
                offset: 0xC0,
                size: 4,
                format: 0x1c,
            },
        ],
        declarations: vec![
            lforge_rage9::drawable::Declaration {
                slot: 0,
                format: 0x42,
                offset: 0x80,
                matches_layout: true,
            },
            lforge_rage9::drawable::Declaration {
                slot: 1,
                format: 0x26,
                offset: 0xC0,
                matches_layout: true,
            },
            lforge_rage9::drawable::Declaration {
                slot: 2,
                format: 0x21,
                offset: 0xA0,
                matches_layout: true,
            },
            lforge_rage9::drawable::Declaration {
                slot: 3,
                format: 0x28,
                offset: 0xB0,
                matches_layout: true,
            },
        ],
        declaration_end: None,
    }
}

fn index_view() -> IndexView {
    IndexView {
        at: 0,
        clusters: 1,
        count_a: 2,
        count_b: 4,
        count_word: 0,
        low_byte: 0,
        high_byte: 0,
        elements: 16,
        unit: 4,
        graphics: 0x100,
        range: None,
        in_bounds: true,
        header: None,
        header_matches: None,
        constant: None,
    }
}

fn quad_graphics() -> Vec<u8> {
    let mut g = vec![0u8; 0x200];
    g[0..4].copy_from_slice(&0x4042u32.to_le_bytes());
    // slot 0 position at 0x80, slot 2 normal at 0xA0, slot 3 UV at 0xB0,
    // slot 1 colour at 0xC0.
    for (slot, offset, format) in [
        (0u32, 0x80u32, 0x42u8),
        (2, 0xA0, 0x21),
        (3, 0xB0, 0x28),
        (1, 0xC0, 0x26),
    ] {
        let word = ((offset / 2) << 8) | u32::from(format);
        let at = 4 * slot as usize;
        g[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    for (index, value) in [0.0f32, 0.0, 0.0].iter().enumerate() {
        g[0x60 + index * 4..0x64 + index * 4].copy_from_slice(&value.to_le_bytes());
    }
    for (index, value) in [1.0f32 / 256.0, 1.0 / 256.0, 1.0 / 256.0]
        .iter()
        .enumerate()
    {
        g[0x70 + index * 4..0x74 + index * 4].copy_from_slice(&value.to_le_bytes());
    }
    g[0x6C..0x70].copy_from_slice(&2u32.to_le_bytes());
    let corners = [(0u64, 0u64, 0u64), (1, 0, 0), (1, 1, 0), (0, 1, 0)];
    for (index, (x, y, z)) in corners.iter().enumerate() {
        let q = ((x & 0xFFFF) << 16) | ((y & 0xFFFF) << 32) | ((z & 0xFFFF) << 48);
        let at = 0x80 + index * 8;
        g[at..at + 8].copy_from_slice(&q.to_le_bytes());
    }
    let normal = 0x8000_0000u32 | 511 | (511 << 10);
    for index in 0..4 {
        g[0xA0 + index * 4..0xA4 + index * 4].copy_from_slice(&normal.to_le_bytes());
    }
    for (index, (u, v)) in [(0i16, 0i16), (8192, 0), (8192, 8192), (0, 8192)]
        .iter()
        .enumerate()
    {
        let at = 0xB0 + index * 4;
        g[at..at + 2].copy_from_slice(&u.to_le_bytes());
        g[at + 2..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    for index in 0..4 {
        g[0xC0 + index * 4..0xC4 + index * 4].copy_from_slice(&[255, 128, 64, 255]);
    }
    // Meshlet index buffer at 0x100.
    g[0x100..0x102].copy_from_slice(&1u16.to_le_bytes());
    g[0x104..0x108].copy_from_slice(&2u32.to_le_bytes());
    g[0x108..0x10C].copy_from_slice(&4u32.to_le_bytes());
    // Descriptor: remap start 0 at +0x04, triangle start 0 at +0x06.
    let tri0 = 0x100 + 0x1C;
    let words = [(1u32 << 7) | (2 << 14), (2 << 7) | (3 << 14)];
    for (index, word) in words.iter().enumerate() {
        let at = tri0 + index * 4;
        g[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    let remap = 0x100 + 0x24;
    for (index, value) in [0u16, 1, 2, 3].iter().enumerate() {
        let at = remap + index * 2;
        g[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }
    g
}

#[test]
fn decodes_a_synthetic_quad() {
    let graphics = quad_graphics();
    let mut diagnostics = Vec::new();
    let (primitive, influence) = decode_mesh(
        &graphics,
        &vertex_buffer(),
        &index_view(),
        None,
        &mut diagnostics,
    )
    .expect("quad decodes");
    assert!(matches!(influence, InfluenceDecode::NotDeclared));
    assert_eq!(primitive.vertices.len(), 4);
    assert_eq!(primitive.indices, [0, 1, 2, 0, 2, 3]);
    assert_eq!(primitive.vertices[1].position, [1.0, 0.0, 0.0]);
    assert_eq!(primitive.vertices[2].position, [1.0, 1.0, 0.0]);
    assert!((primitive.vertices[0].uv0[0] - 0.0).abs() < 1e-6);
    assert!((primitive.vertices[2].uv0[0] - 1.0).abs() < 1e-6);
    assert!(primitive.vertices[0].normal[2] > 0.99);
}

#[test]
fn an_index_outside_the_vertex_buffer_is_dropped() {
    let mut graphics = quad_graphics();
    // Second triangle's third corner remaps to vertex 3; redirect the remap
    // entry to an index outside the buffer.
    let remap = 0x100 + 0x24 + 3 * 2;
    graphics[remap..remap + 2].copy_from_slice(&99u16.to_le_bytes());
    let mut diagnostics = Vec::new();
    let (primitive, _) = decode_mesh(
        &graphics,
        &vertex_buffer(),
        &index_view(),
        None,
        &mut diagnostics,
    )
    .expect("one triangle remains");
    assert_eq!(primitive.indices, [0, 1, 2]);
    assert!(diagnostics.iter().any(|d| d.reason.contains("dropped")));
}

#[test]
fn an_empty_or_non_drawable_resource_is_rejected() {
    assert!(!is_drawable(&[], &[]));
    assert!(decode(&[], &[], &NoTextures).is_err());
}

#[test]
fn a_resource_boundary_is_found_from_a_graphics_pointer_and_marker() {
    let mut bytes = vec![0u8; 0x200];
    // Page-map system pointer and one graphics pointer to offset zero.
    bytes[0x08..0x10].copy_from_slice(&0x5000_0100u64.to_le_bytes());
    bytes[0x18..0x20].copy_from_slice(&0x6000_0000u64.to_le_bytes());
    bytes.extend_from_slice(&0x4042u32.to_le_bytes());
    bytes.resize(0x300, 0);
    let split = split_resource(&bytes).expect("split");
    assert_eq!(split.system_len, 0x200);
    assert!(split.support >= 1);
}

#[test]
fn a_resource_without_graphics_markers_is_not_split() {
    let mut bytes = vec![0u8; 0x200];
    bytes[0x08..0x10].copy_from_slice(&0x5000_0100u64.to_le_bytes());
    assert!(split_resource(&bytes).is_none());
    assert_eq!(
        split_resource_reason(&bytes),
        Err(LayoutProblem::NoMarkers),
        "an inferred split says why it could not be made"
    );
}

#[test]
fn a_marker_without_a_graphics_pointer_is_not_split() {
    let mut bytes = vec![0u8; 0x200];
    bytes[0x08..0x10].copy_from_slice(&0x5000_0100u64.to_le_bytes());
    bytes.extend_from_slice(&0x4042u32.to_le_bytes());
    bytes.resize(0x300, 0);
    assert_eq!(
        split_resource_reason(&bytes),
        Err(LayoutProblem::NoCandidates)
    );
}

#[test]
fn a_resource_that_is_too_short_to_split_says_so() {
    assert_eq!(
        split_resource_reason(&[0u8; 0x20]),
        Err(LayoutProblem::NotAResource)
    );
}

#[test]
fn two_equally_supported_boundaries_are_reported_as_ambiguous() {
    let mut bytes = vec![0u8; 0x200];
    bytes[0x08..0x10].copy_from_slice(&0x5000_0100u64.to_le_bytes());
    // Two graphics pointers and two markers. Each pointer reaches a marker for a
    // different boundary and no boundary is supported twice, so none of them is
    // evidence.
    bytes[0x18..0x20].copy_from_slice(&0x6000_0000u64.to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&0x6000_0040u64.to_le_bytes());
    bytes.extend_from_slice(&0x4042u32.to_le_bytes());
    bytes.resize(0x300, 0);
    bytes[0x2C0..0x2C4].copy_from_slice(&0x4042u32.to_le_bytes());
    let problem = split_resource_reason(&bytes).expect_err("the boundaries tie");
    let LayoutProblem::Ambiguous(splits) = problem else {
        panic!("a tie is reported as ambiguous, not as a missing candidate");
    };
    assert!(
        splits.len() >= 2,
        "both supported boundaries are named: {splits:?}"
    );
    let described = LayoutProblem::Ambiguous(splits).describe();
    assert!(described.contains("ambiguous"), "{described}");
    assert!(
        described.contains("0x"),
        "the boundaries are named: {described}"
    );
}

#[test]
fn texture_semantics_are_taken_from_the_parameter_hashes() {
    assert_eq!(semantic(DIFFUSE_TEX), TextureSemantic::Diffuse);
    assert_eq!(semantic(DIFFUSE_TEX2), TextureSemantic::Diffuse);
    assert_eq!(semantic(BUMP_TEX), TextureSemantic::Normal);
    assert_eq!(semantic(SPECULAR_TEX), TextureSemantic::Specular);
    assert_eq!(semantic(SPECULAR_TEX2), TextureSemantic::Specular2);
    assert_eq!(semantic(0x1234_5678), TextureSemantic::Unknown);
}

fn shader(bucket: u8) -> Shader {
    Shader {
        at: 0,
        shader_hash: 0xBCF0_3FC1,
        marker: 0x6D65_7461,
        texture_parameters: 1,
        total_parameters: 1,
        word_06: 0x800,
        slots: 1,
        bound_slots: 1,
        flags: [0, 0, 0, 0, bucket, 0, 0, 0],
        parameters: vec![drawable::Parameter {
            index: 0,
            name_hash: DIFFUSE_TEX,
            packed: 0,
            class: 0,
            slot: 0,
            texture: true,
        }],
        slot_states: vec![drawable::Slot {
            index: 0,
            state: SlotState::Bound,
            key: Some(0x0123_4567_89AB_CDEF),
            hash32: Some(0x1122_3344),
        }],
    }
}

fn build(shader: &Shader, provider: &dyn TextureProvider) -> (Material, Scene, Vec<Diagnostic>) {
    let mut scene = Scene::new();
    let mut diagnostics = Vec::new();
    let embedded = HashMap::new();
    let mut embedded_indices = HashMap::new();
    let mut texture_bindings = Vec::new();
    let mut external_indices = HashMap::new();
    let material = {
        let mut context = MaterialContext {
            provider,
            graphics: &[],
            embedded: &embedded,
            embedded_indices: &mut embedded_indices,
            texture_bindings: &mut texture_bindings,
            external_indices: &mut external_indices,
            scene: &mut scene,
            diagnostics: &mut diagnostics,
        };
        build_material(shader, 0, &mut context)
    };
    (material, scene, diagnostics)
}

#[test]
fn a_missing_texture_is_a_fallback_with_a_diagnostic() {
    let (material, scene, diagnostics) = build(&shader(0), &NoTextures);
    assert!(material.missing_texture);
    assert!(material.diffuse.is_none());
    assert!(scene.textures.is_empty());
    assert!(diagnostics.iter().any(|d| d.reason.contains("not present")));
    assert!(
        diagnostics
            .iter()
            .any(|d| d.reference.as_deref() == Some("0x0123456789ABCDEF"))
    );
}

#[test]
fn a_missing_texture_keeps_its_binding_report() {
    let mut scene = Scene::new();
    let mut diagnostics = Vec::new();
    let embedded = HashMap::new();
    let mut embedded_indices = HashMap::new();
    let mut external_indices = HashMap::new();
    let mut texture_bindings = Vec::new();
    let shader = shader(0);
    let mut context = MaterialContext {
        provider: &NoTextures,
        graphics: &[],
        embedded: &embedded,
        embedded_indices: &mut embedded_indices,
        external_indices: &mut external_indices,
        texture_bindings: &mut texture_bindings,
        scene: &mut scene,
        diagnostics: &mut diagnostics,
    };
    build_material(&shader, 0, &mut context);
    assert_eq!(texture_bindings.len(), 1);
    assert_eq!(texture_bindings[0].key64, 0x0123_4567_89AB_CDEF);
    assert_eq!(texture_bindings[0].texture, None);
    assert_eq!(texture_bindings[0].status, TextureBindingStatus::Missing);
}

struct OneTexture(SourceLevel);

impl TextureProvider for OneTexture {
    fn resolve(&self, _reference: &TextureReference) -> TextureResolution {
        TextureResolution::Resolved(ResolvedTexture {
            level: self.0.clone(),
            source: "test".into(),
        })
    }
}

#[test]
fn a_resolved_texture_is_bound_once_and_deduplicated() {
    let texture = SourceLevel {
        width: 1,
        height: 1,
        level: 0,
        format: lforge_texture::pixel_format(28),
        data: vec![255, 255, 255, 255],
        swizzled: false,
    };
    let mut scene = Scene::new();
    let mut diagnostics = Vec::new();
    let mut external = HashMap::new();
    let shader = shader(0);
    let provider = OneTexture(texture);
    let embedded = HashMap::new();
    let mut embedded_indices = HashMap::new();
    let mut texture_bindings = Vec::new();
    let (material, second) = {
        let mut context = MaterialContext {
            provider: &provider,
            graphics: &[],
            embedded: &embedded,
            embedded_indices: &mut embedded_indices,
            texture_bindings: &mut texture_bindings,
            external_indices: &mut external,
            scene: &mut scene,
            diagnostics: &mut diagnostics,
        };
        let material = build_material(&shader, 0, &mut context);
        let second = build_material(&shader, 0, &mut context);
        (material, second)
    };
    assert_eq!(material.diffuse, Some(0));
    assert!(!material.missing_texture);
    assert_eq!(scene.textures.len(), 1);
    assert_eq!(material.bindings[0].semantic, TextureSemantic::Diffuse);
    assert_eq!(second.diffuse, Some(0));
    assert_eq!(scene.textures.len(), 1);
}

#[test]
fn alpha_buckets_and_double_sided_are_read_from_the_shader_record() {
    assert_eq!(alpha_mode(&shader(0)), AlphaMode::Opaque);
    assert_eq!(alpha_mode(&shader(0x08)), AlphaMode::Mask);
    assert_eq!(alpha_mode(&shader(0x02)), AlphaMode::Blend);
    assert_eq!(alpha_mode(&shader(0x40)), AlphaMode::Blend);
    let (material, _, _) = build(&shader(0x04), &NoTextures);
    assert!(material.double_sided);
}

fn shader_with_parameters(hashes: &[u32]) -> Shader {
    let mut shader = shader(0);
    shader.texture_parameters = hashes.len() as u8;
    shader.total_parameters = hashes.len() as u16;
    shader.slots = hashes.len() as u32;
    shader.bound_slots = hashes.len() as u32;
    shader.parameters = hashes
        .iter()
        .enumerate()
        .map(|(index, &name_hash)| drawable::Parameter {
            index: index as u16,
            name_hash,
            packed: 0,
            class: 0,
            slot: index as u32,
            texture: true,
        })
        .collect();
    shader.slot_states = hashes
        .iter()
        .enumerate()
        .map(|(index, _)| drawable::Slot {
            index: index as u16,
            state: SlotState::Bound,
            key: Some(0x0123_4567_89AB_CDEF + index as u64),
            hash32: Some(0x1122_3344),
        })
        .collect();
    shader
}

#[test]
fn specular_tex_fills_the_sampled_slot_and_tex2_stays_distinct() {
    let level = SourceLevel {
        width: 1,
        height: 1,
        level: 0,
        format: lforge_texture::pixel_format(28),
        data: vec![255, 255, 255, 255],
        swizzled: false,
    };
    let provider = OneTexture(level);
    let mut scene = Scene::new();
    let mut diagnostics = Vec::new();
    let embedded = HashMap::new();
    let mut embedded_indices = HashMap::new();
    let mut texture_bindings = Vec::new();
    let mut external_indices = HashMap::new();
    let shader = shader_with_parameters(&[SPECULAR_TEX2, SPECULAR_TEX]);
    let material = {
        let mut context = MaterialContext {
            provider: &provider,
            graphics: &[],
            embedded: &embedded,
            embedded_indices: &mut embedded_indices,
            texture_bindings: &mut texture_bindings,
            external_indices: &mut external_indices,
            scene: &mut scene,
            diagnostics: &mut diagnostics,
        };
        build_material(&shader, 0, &mut context)
    };
    assert_eq!(material.specular, Some(1));
    assert_eq!(
        material
            .bindings
            .iter()
            .map(|binding| binding.semantic)
            .collect::<Vec<_>>(),
        vec![TextureSemantic::Specular2, TextureSemantic::Specular]
    );
    assert!(!material.missing_texture);
}

#[test]
fn geometry_completeness_distinguishes_complete_from_partial() {
    assert_eq!(
        geometry_completeness(0, 1, 0, 3, 3, 0),
        GeometryCompleteness::Complete
    );
    assert!(matches!(
        geometry_completeness(0x80, 1, 0, 3, 3, 0),
        GeometryCompleteness::Partial { .. }
    ));
    assert!(matches!(
        geometry_completeness(0, 2, 0, 3, 3, 0),
        GeometryCompleteness::Partial { .. }
    ));
    assert!(matches!(
        geometry_completeness(0, 1, 1, 3, 3, 0),
        GeometryCompleteness::Partial { .. }
    ));
    assert!(matches!(
        geometry_completeness(0, 1, 0, 3, 2, 1),
        GeometryCompleteness::Partial { .. }
    ));
    assert!(matches!(
        geometry_completeness(0, 1, 0, 3, 2, 0),
        GeometryCompleteness::Partial { .. }
    ));
}

#[test]
fn texture_completeness_is_separate_from_geometry() {
    assert_eq!(texture_completeness(0, true), TextureCompleteness::Complete);
    assert_eq!(
        texture_completeness(0, false),
        TextureCompleteness::NotReferenced
    );
    assert_eq!(
        texture_completeness(2, true),
        TextureCompleteness::Partial { missing: 2 }
    );
}

#[test]
fn format_78_maps_to_bc3_srgb() {
    let level = SourceLevel {
        width: 4,
        height: 4,
        level: 0,
        format: lforge_texture::pixel_format(78),
        data: vec![0u8; 16],
        swizzled: false,
    };
    let texture = texture_from_source(level, "format 78".into()).unwrap();
    assert_eq!(texture.format, TextureFormat::Bc3UnormSrgb);
}

#[test]
fn a_non_fragment_is_not_decoded_as_one() {
    let system = vec![0u8; 0x200];
    let graphics = vec![0u8; 0x100];
    assert!(!is_fragment(&system, &graphics));
    assert!(decode_fragment(&system, &graphics, &NoTextures).is_err());
}

/// Manual verification against a real installation. The test is ignored by
/// default and reads only caller-supplied paths.
///
/// `LF_TEST_FRAGMENT` is one decoded fragment resource and
/// `LF_TEST_FRAGMENT_SPLIT` its system-segment length in bytes.
#[test]
#[ignore = "requires LF_TEST_FRAGMENT and LF_TEST_FRAGMENT_SPLIT"]
fn a_real_fragment_decodes_into_assembled_components() {
    let path = std::env::var("LF_TEST_FRAGMENT").expect("LF_TEST_FRAGMENT");
    let split: usize = std::env::var("LF_TEST_FRAGMENT_SPLIT")
        .expect("LF_TEST_FRAGMENT_SPLIT")
        .parse()
        .expect("a byte count");
    let bytes = std::fs::read(path).expect("the fragment resource");
    let (system, graphics) = bytes.split_at(split);
    assert!(is_fragment(system, graphics));
    let decoded = decode_fragment(system, graphics, &NoTextures).expect("a decoded fragment");
    assert!(!decoded.components.is_empty());
    assert_eq!(decoded.components.len(), 1);
    let component = &decoded.components[0];
    assert_eq!(
        component.drawable_at,
        decoded.report.header.drawable as usize
    );
    // One component is one member drawable. Its meshes are that drawable's
    // models, so a component holds a range of meshes and never one mesh.
    assert_eq!(component.meshes, 0..decoded.scene.meshes.len());
    assert!(decoded.scene.meshes.len() >= decoded.components.len());
    assert!(component.vertices > 0);
    assert!(decoded.scene.bounds.is_finite());
    eprintln!(
        "{}: {} component(s), {} mesh(es), {} vertices, {} triangles, {} material(s), geometry {:?}",
        component.name.as_deref().unwrap_or("fragment"),
        decoded.components.len(),
        decoded.scene.meshes.len(),
        component.vertices,
        component.triangles,
        decoded.scene.materials.len(),
        decoded.completeness
    );
}
