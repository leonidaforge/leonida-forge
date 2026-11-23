use super::*;

/// System data of `len` bytes with a page map at `map_at` declaring
/// `system` and `graphics` pages.
fn system(len: usize, map_at: usize, system: u8, graphics: u8) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    bytes[8..16].copy_from_slice(&(SYSTEM_BASE + map_at as u64).to_le_bytes());
    bytes[map_at + 8] = system;
    bytes[map_at + 9] = graphics;
    bytes
}

fn put(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

#[test]
fn decodes_pointers() {
    assert_eq!(Pointer::decode(0x5000_0040), Some(Pointer::System(0x40)));
    assert_eq!(
        Pointer::decode(0x6FFF_FFF0),
        Some(Pointer::Graphics(0x0FFF_FFF0))
    );
    assert_eq!(Pointer::decode(0x4FFF_FFFF), None);
    assert_eq!(Pointer::decode(0x7000_0000), None);
    // The upper half must be zero.
    assert_eq!(Pointer::decode(0x1_5000_0000), None);
}

#[test]
fn recognises_the_start_of_system_data() {
    let head = system(64, 32, 1, 0);
    assert_eq!(page_map_offset(&head), Some(32));
    assert_eq!(page_map_offset(&head[..15]), None);

    let mut vtable = head.clone();
    vtable[0] = 1;
    assert_eq!(page_map_offset(&vtable), None);
    let mut graphics = head.clone();
    put(&mut graphics, 8, GRAPHICS_BASE + 32);
    assert_eq!(page_map_offset(&graphics), None);
    let mut inside_header = head;
    put(&mut inside_header, 8, SYSTEM_BASE + 8);
    assert_eq!(page_map_offset(&inside_header), None);
}

#[test]
fn reads_the_tag_only_after_its_marker() {
    let mut head = system(64, 32, 1, 0);
    assert_eq!(tag(&head), None);
    head[0x10..0x14].copy_from_slice(b"0DRP");
    head[0x14] = 0x7A;
    assert_eq!(tag(&head), Some(0x7A));
    assert_eq!(tag(&head[..0x14]), None);
}

#[test]
fn parses_page_maps_and_rejects_malformed_ones() {
    let mut bytes = vec![0u8; 16 + 3 * 8];
    bytes[8] = 1;
    bytes[9] = 2;
    let map = PageMap::parse(0x100, &bytes).unwrap();
    assert_eq!(
        map,
        PageMap {
            offset: 0x100,
            system_pages: 1,
            graphics_pages: 2
        }
    );
    assert_eq!(map.byte_len(), 40);

    assert_eq!(PageMap::parse(0, &bytes[..39]), Err(PageMapError::Outside));
    assert_eq!(PageMap::parse(0, &bytes[..15]), Err(PageMapError::Outside));
    for at in [0, 7, 10, 15, 16, 39] {
        let mut bad = bytes.clone();
        bad[at] = 1;
        assert_eq!(PageMap::parse(0, &bad), Err(PageMapError::NonZero), "{at}");
    }
    let mut none = bytes;
    none[8] = 0;
    assert_eq!(PageMap::parse(0, &none), Err(PageMapError::NoSystemPage));
}

#[test]
fn split_streams_form_one_page() {
    assert_eq!(group_pages(&[]), Vec::<(u32, u64)>::new());
    assert_eq!(
        group_pages(&[0x4A0, 0x41_0000]),
        [(1, 0x4A0), (1, 0x41_0000)]
    );
    assert_eq!(
        group_pages(&[0x400, SPLIT_LEN, 0x60_0000, 0x4000]),
        [(1, 0x400), (2, SPLIT_LEN + 0x60_0000), (1, 0x4000)]
    );
    assert_eq!(
        group_pages(&[SPLIT_LEN, SPLIT_LEN, 1]),
        [(3, 2 * SPLIT_LEN + 1)]
    );
    // Only exactly SPLIT_LEN continues; 64 KiB pages do not.
    assert_eq!(
        group_pages(&[0x1_0000, 0x2CB0]),
        [(1, 0x1_0000), (1, 0x2CB0)]
    );
}

#[test]
fn a_resource_with_one_page_per_segment_is_complete() {
    let mut sys = system(0x100, 0xD0, 1, 1);
    put(&mut sys, 0x20, SYSTEM_BASE + 0xD0);
    put(&mut sys, 0x30, GRAPHICS_BASE + 0x3000);
    let graphics = vec![0xAB; 0x4000];
    let layout = analyze(&[&sys, &graphics]).unwrap();
    assert_eq!(layout.status(), Status::Complete, "{:?}", layout.issues());
    assert_eq!(layout.segment_len(Segment::System), 0x100);
    assert_eq!(layout.segment_len(Segment::Graphics), 0x4000);
    assert_eq!(layout.stream_count(), 2);
    assert_eq!(
        layout.pointers,
        Pointers {
            system: 2,
            graphics: 1,
            system_outside: 0,
            graphics_outside: 0,
            checked: true
        }
    );
}

#[test]
fn a_system_only_resource_ignores_what_follows() {
    let sys = system(0x80, 0x60, 1, 0);
    let unrelated = vec![1u8; 0x60];
    let layout = analyze(&[&sys, &unrelated]).unwrap();
    assert_eq!(layout.status(), Status::Complete);
    assert_eq!(layout.pages.len(), 1);
    assert_eq!(layout.segment_len(Segment::Graphics), 0);
}

#[test]
fn missing_graphics_pages_make_a_resource_partial() {
    let mut sys = system(0x100, 0xC0, 1, 2);
    // A pointer into the missing second page.
    put(&mut sys, 0x20, GRAPHICS_BASE + 0x2_0000);
    let first = vec![0u8; 0x2_0000];
    let layout = analyze(&[&sys, &first]).unwrap();
    assert_eq!(layout.status(), Status::Partial);
    let issues = layout.issues();
    assert!(issues.contains(&Issue::MissingPages {
        segment: Segment::Graphics,
        declared: 2,
        found: 1
    }));
    assert!(issues.contains(&Issue::PointersOutside {
        system: 0,
        graphics: 1
    }));
    // System data alone is never complete when graphics pages are declared.
    let layout = analyze(&[&sys]).unwrap();
    assert_eq!(layout.status(), Status::Partial);
    assert_eq!(layout.segment_len(Segment::Graphics), 0);
}

#[test]
fn the_page_map_may_be_in_a_later_system_page() {
    let mut sys = system(0x1_0000 + 0x100, 0x1_0040, 2, 1);
    put(&mut sys, 0x20, SYSTEM_BASE + 0x1_0080);
    let (first, second) = sys.split_at(0x1_0000);
    let graphics = vec![0u8; 0x800];
    let layout = analyze(&[first, second, &graphics]).unwrap();
    assert_eq!(layout.status(), Status::Complete, "{:?}", layout.issues());
    assert_eq!(
        layout
            .pages
            .iter()
            .map(|p| (p.segment, p.len))
            .collect::<Vec<_>>(),
        [
            (Segment::System, 0x1_0000),
            (Segment::System, 0x100),
            (Segment::Graphics, 0x800)
        ]
    );
}

#[test]
fn a_page_map_beyond_the_declared_system_pages_is_rejected() {
    // One system page is declared, but the map lies in the second stream.
    let sys = system(0x1_0000 + 0x100, 0x1_0040, 1, 1);
    let (first, second) = sys.split_at(0x1_0000);
    let layout = analyze(&[first, second]).unwrap();
    assert_eq!(layout.page_map, Err(PageMapError::Outside));
    assert_eq!(layout.status(), Status::Unverified);
    assert_eq!(layout.pages.len(), 1);
}

#[test]
fn a_page_map_past_the_data_leaves_a_candidate() {
    let mut sys = vec![0u8; 0x40];
    put(&mut sys, 8, SYSTEM_BASE + 0x1000);
    let layout = analyze(&[&sys]).unwrap();
    assert_eq!(layout.page_map, Err(PageMapError::Outside));
    assert_eq!(layout.status(), Status::Unverified);
    assert_eq!(layout.issues(), [Issue::PageMap(PageMapError::Outside)]);
}

#[test]
fn rejects_data_that_does_not_start_like_a_resource() {
    assert_eq!(analyze(&[]), None);
    assert_eq!(analyze(&[b"<?xml version=\"1.0\"?>"]), None);
    assert_eq!(analyze(&[&[0u8; 8]]), None);
}

#[test]
fn pages_of_multi_page_segments_must_fit_the_size_pattern() {
    let sys = system(0x80, 0x40, 1, 2);
    let ok = analyze(&[&sys, &vec![0; 0x2_0000], &vec![0; 0x7000]]).unwrap();
    assert_eq!(ok.status(), Status::Complete);

    // The second stream is not a tail page: two neighbouring files, not one
    // resource's pages.
    let wrong = analyze(&[&sys, &vec![0; 0x1_8000], &vec![0; 0x2_0000]]).unwrap();
    assert_eq!(wrong.status(), Status::Unverified);
    assert_eq!(
        wrong.issues(),
        [
            Issue::PageSize {
                segment: Segment::Graphics,
                page: 0
            },
            Issue::PageSize {
                segment: Segment::Graphics,
                page: 1
            }
        ]
    );
}

#[test]
fn pointer_like_values_outside_are_only_a_warning() {
    let mut sys = system(0x80, 0x40, 1, 1);
    // A hash followed by four zero bytes reads like a system pointer.
    put(&mut sys, 0x20, 0x5C74_C225);
    let layout = analyze(&[&sys, &[0; 0x100]]).unwrap();
    assert_eq!(layout.status(), Status::Complete);
    assert_eq!(
        layout.issues(),
        [Issue::PointersOutside {
            system: 1,
            graphics: 0
        }]
    );
}

#[test]
fn feeding_in_pieces_gives_the_same_layout() {
    let mut sys = system(0x200, 0x1D0, 1, 1);
    for at in (0x20..0x1D0).step_by(16) {
        put(&mut sys, at, GRAPHICS_BASE + at as u64);
    }
    let pages = [(1, 0x200), (1, 0x400)];
    let whole = {
        let mut builder = Builder::new(&sys).unwrap();
        builder.feed(&sys);
        builder.finish(&pages)
    };
    for piece in [1, 3, 7, 9, 0x1D5] {
        let mut builder = Builder::new(&sys).unwrap();
        for chunk in sys.chunks(piece) {
            builder.feed(chunk);
        }
        assert_eq!(builder.finish(&pages), whole, "pieces of {piece}");
    }
    assert_eq!(whole.status(), Status::Complete);
    assert_eq!(whole.pointers.graphics, 27);
}

#[test]
fn split_graphics_pages_count_as_one_page() {
    let sys = system(0x80, 0x40, 1, 1);
    let mut builder = Builder::new(&sys).unwrap();
    builder.feed(&sys);
    let pages = group_pages(&[0x80, SPLIT_LEN, 0x60_0000]);
    let layout = builder.finish(&pages);
    assert_eq!(layout.status(), Status::Complete);
    assert_eq!(layout.stream_count(), 3);
    assert_eq!(layout.segment_len(Segment::Graphics), SPLIT_LEN + 0x60_0000);
}

#[test]
fn too_many_pointer_like_values_are_not_all_checked() {
    let len = (MAX_POINTERS + 8) * 8;
    let mut sys = system(len, len - 0x20, 1, 0);
    for at in (16..len - 0x20).step_by(8) {
        put(&mut sys, at, SYSTEM_BASE);
    }
    let layout = analyze(&[&sys]).unwrap();
    assert!(!layout.pointers.checked);
    assert_eq!(layout.pointers.system as usize, MAX_POINTERS);
}
