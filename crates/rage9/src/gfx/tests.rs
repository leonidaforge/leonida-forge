//! Synthetic GFx payloads. None of these bytes come from the game.

use super::*;

fn u16v(value: u16) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn u32v(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

/// A tag record, short or long form.
fn tag(code: u16, body: &[u8]) -> Vec<u8> {
    let mut out = if body.len() >= 0x3F {
        u16v((code << 6) | 0x3F)
    } else {
        u16v((code << 6) | body.len() as u16)
    };
    if body.len() >= 0x3F {
        out.extend_from_slice(&u32v(body.len() as u32));
    }
    out.extend_from_slice(body);
    out
}

/// A payload with a RECT of `nbits`, the frame header and `tags`.
fn payload(nbits: u8, tags: &[u8]) -> Vec<u8> {
    let rect_len = (5 + 4 * usize::from(nbits)).div_ceil(8);
    let mut rect = vec![0u8; rect_len];
    rect[0] = nbits << 3;
    let mut bytes = b"GFX".to_vec();
    bytes.push(VERSION);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&rect);
    bytes.extend_from_slice(&0x1E00u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(tags);
    let len = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&len.to_le_bytes());
    bytes
}

/// A frame with no drawn content: ShowFrame then End.
fn empty_frame() -> Vec<u8> {
    let mut tags = tag(SHOW_FRAME, &[]);
    tags.extend_from_slice(&tag(END, &[]));
    tags
}

fn parse(bytes: &[u8]) -> Result<Document, Error> {
    super::parse(bytes, &Limits::default(), &AtomicBool::new(false))
}

#[test]
fn parses_a_minimal_movie() {
    let bytes = payload(0, &empty_frame());
    let document = parse(&bytes).unwrap();
    assert_eq!(document.header.version, VERSION);
    assert_eq!(document.header.declared_len as usize, bytes.len());
    assert_eq!(document.header.rect_len, 1);
    assert_eq!(document.header.nbits, 0);
    assert_eq!(document.header.frame_rate, 0x1E00);
    assert_eq!(document.header.frame_count, 1);
    assert_eq!(document.header.tag_start, 8 + 1 + 4);
    assert_eq!(document.top_level, 2);
    assert_eq!(document.max_depth, 0);
    assert_eq!(document.end, bytes.len());
    let codes: Vec<u16> = document.tags.iter().map(|tag| tag.code).collect();
    assert_eq!(codes, [SHOW_FRAME, END]);
    assert!(document.tags.iter().all(|tag| tag.length == 0));
}

#[test]
fn accepts_short_and_long_tag_forms() {
    let short = vec![0xAA; 10];
    let long = vec![0xBB; 0x100];
    let mut tags = tag(1000, &short);
    tags.extend_from_slice(&tag(2000, &long));
    tags.extend_from_slice(&tag(SHOW_FRAME, &[]));
    tags.extend_from_slice(&tag(END, &[]));
    let bytes = payload(16, &tags);
    let document = parse(&bytes).unwrap();
    assert_eq!(document.tags[0].length, 10);
    assert_eq!(document.tags[1].length, 0x100);
    assert_eq!(document.tags[1].body.len(), 0x100);
    assert_eq!(document.top_level, 4);
}

#[test]
fn walks_the_nested_stream_of_tag_39() {
    let mut nested = u16v(0x1111);
    nested.extend_from_slice(&u16v(0x2222));
    nested.extend_from_slice(&tag(7, &[0x33; 4]));
    nested.extend_from_slice(&tag(END, &[]));
    let mut tags = tag(NESTED_TAG, &nested);
    tags.extend_from_slice(&tag(SHOW_FRAME, &[]));
    tags.extend_from_slice(&tag(END, &[]));
    let bytes = payload(14, &tags);
    let document = parse(&bytes).unwrap();
    assert_eq!(document.top_level, 3);
    assert_eq!(document.max_depth, 1);
    let nested_codes: Vec<u16> = document
        .tags
        .iter()
        .filter(|tag| tag.depth == 1)
        .map(|tag| tag.code)
        .collect();
    assert_eq!(nested_codes, [7, END]);
}

#[test]
fn enforces_the_nesting_limit() {
    let mut body = tag(END, &[]);
    for _ in 0..=Limits::default().max_depth {
        let mut next = u16v(0);
        next.extend_from_slice(&u16v(0));
        next.extend_from_slice(&body);
        body = tag(NESTED_TAG, &next);
    }
    body.extend_from_slice(&tag(SHOW_FRAME, &[]));
    body.extend_from_slice(&tag(END, &[]));
    let bytes = payload(15, &body);
    let err = parse(&bytes).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Limit);
}

#[test]
fn rejects_a_truncated_tag_header_or_body() {
    let tags = u16v(0x1F);
    let bytes = payload(16, &tags);
    let err = parse(&bytes).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Truncated);

    // An extended length whose `u32` is cut off.
    let mut tags = u16v((10 << 6) | 0x3F);
    tags.push(0);
    let err = parse(&payload(16, &tags)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Truncated);

    // A body longer than the payload.
    let mut tags = u16v((10 << 6) | 0x3F);
    tags.extend_from_slice(&u32v(0x400));
    let err = parse(&payload(16, &tags)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Truncated);
}

#[test]
fn rejects_a_rect_that_overruns_the_payload() {
    // A header that declares nbits 255 leaves no room for the RECT.
    let mut bytes = b"GFX".to_vec();
    bytes.push(VERSION);
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.push(0xF8);
    bytes.extend_from_slice(&[0; 10]);
    let len = bytes.len() as u32;
    bytes[4..8].copy_from_slice(&len.to_le_bytes());
    let err = parse(&bytes).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Truncated);
}

#[test]
fn rejects_other_versions_and_length_mismatches() {
    for version in [41u8, 43] {
        let mut bytes = payload(16, &empty_frame());
        bytes[3] = version;
        let err = parse(&bytes).unwrap_err();
        assert_eq!(err.kind, ErrorKind::UnsupportedVersion);
        assert!(err.message.contains(&version.to_string()));
    }
    let mut bytes = payload(16, &empty_frame());
    bytes[4..8].copy_from_slice(&0u32.to_le_bytes());
    let err = parse(&bytes).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Length);
}

#[test]
fn requires_a_zero_length_end_tag_last() {
    let bytes = payload(16, &tag(SHOW_FRAME, &[]));
    let err = parse(&bytes).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Unterminated);

    let mut tags = tag(SHOW_FRAME, &[]);
    tags.extend_from_slice(&tag(END, &[]));
    tags.extend_from_slice(&tag(7, &[]));
    let bytes = payload(16, &tags);
    let err = parse(&bytes).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Unterminated);

    let mut tags = tag(SHOW_FRAME, &[]);
    tags.extend_from_slice(&tag(END, &[0]));
    let err = parse(&payload(16, &tags)).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Unterminated);
}

#[test]
fn rejects_a_foreign_or_short_payload() {
    assert_eq!(parse(b"GF").unwrap_err().kind, ErrorKind::NotGfx);
    assert_eq!(parse(b"GFX").unwrap_err().kind, ErrorKind::TooShort);
    // The version byte is separate from the identifier.
    assert_eq!(
        parse(b"GFX42").unwrap_err().kind,
        ErrorKind::UnsupportedVersion
    );
    assert_eq!(
        parse(b"GFXX").unwrap_err().kind,
        ErrorKind::UnsupportedVersion
    );
}

#[test]
fn stops_when_cancelled() {
    let cancel = AtomicBool::new(true);
    let err = super::parse(&payload(16, &empty_frame()), &Limits::default(), &cancel).unwrap_err();
    assert_eq!(err.kind, ErrorKind::Cancelled);
}
