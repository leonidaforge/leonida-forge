use std::io::{self, Read, Seek, SeekFrom};
use std::sync::atomic::AtomicBool;

use memchr::memmem;

use crate::{CHUNK, Error, check, stream_len};

/// Parses hex bytes such as `52 50 46 37` or `52504637`. Each
/// whitespace-separated group needs an even number of digits.
pub fn parse_hex_pattern(text: &str) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    for group in text.split_whitespace() {
        if let Some(c) = group.chars().find(|c| !c.is_ascii_hexdigit()) {
            return Err(format!("'{c}' in '{group}' is not a hexadecimal digit"));
        }
        if group.len() % 2 != 0 {
            return Err(format!("'{group}' has an odd number of hex digits"));
        }
        for pair in group.as_bytes().chunks(2) {
            let pair = std::str::from_utf8(pair).expect("ASCII hex digits");
            bytes.push(u8::from_str_radix(pair, 16).expect("validated hex digits"));
        }
    }
    if bytes.is_empty() {
        return Err("the pattern is empty".to_string());
    }
    Ok(bytes)
}

fn empty_pattern() -> Error {
    io::Error::new(io::ErrorKind::InvalidInput, "the pattern is empty").into()
}

/// Fills `buf` from `offset`. The caller keeps the range within the data.
fn read_window(reader: &mut (impl Read + Seek), offset: u64, buf: &mut [u8]) -> io::Result<()> {
    reader.seek(SeekFrom::Start(offset))?;
    reader.read_exact(buf)
}

/// Finds the first match that starts at or after `from`.
pub fn find_next(
    reader: &mut (impl Read + Seek),
    pattern: &[u8],
    from: u64,
    cancel: &AtomicBool,
) -> Result<Option<u64>, Error> {
    if pattern.is_empty() {
        return Err(empty_pattern());
    }
    let len = stream_len(reader)?;
    let overlap = pattern.len() - 1;
    let finder = memmem::Finder::new(pattern);
    let mut buf = vec![0; CHUNK + overlap];
    let mut start = from;
    while start < len && len - start >= pattern.len() as u64 {
        check(cancel)?;
        let n = usize::try_from(len - start).map_or(buf.len(), |rest| rest.min(buf.len()));
        read_window(reader, start, &mut buf[..n])?;
        if let Some(ix) = finder.find(&buf[..n]) {
            return Ok(Some(start + ix as u64));
        }
        // Keep the last `overlap` bytes so matches across windows are found.
        start += (n - overlap) as u64;
    }
    Ok(None)
}

/// Finds the last match that starts before `before`.
pub fn find_previous(
    reader: &mut (impl Read + Seek),
    pattern: &[u8],
    before: u64,
    cancel: &AtomicBool,
) -> Result<Option<u64>, Error> {
    if pattern.is_empty() {
        return Err(empty_pattern());
    }
    let len = stream_len(reader)?;
    let overlap = pattern.len() - 1;
    let finder = memmem::FinderRev::new(pattern);
    let mut buf = vec![0; CHUNK + overlap];
    // A match starting just before `before` ends `overlap` bytes after it.
    let mut end = len.min(before.saturating_add(overlap as u64));
    if before == 0 {
        return Ok(None);
    }
    while end >= pattern.len() as u64 {
        check(cancel)?;
        let start = end.saturating_sub(buf.len() as u64);
        let n = (end - start) as usize;
        read_window(reader, start, &mut buf[..n])?;
        if let Some(ix) = finder.rfind(&buf[..n]) {
            return Ok(Some(start + ix as u64));
        }
        if start == 0 {
            break;
        }
        end = start + overlap as u64;
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::Sparse;
    use std::io::Cursor;

    fn not_cancelled() -> AtomicBool {
        AtomicBool::new(false)
    }

    fn all_forward(data: &[u8], pattern: &[u8]) -> Vec<u64> {
        let mut reader = Cursor::new(data.to_vec());
        let mut found = Vec::new();
        let mut from = 0;
        while let Some(at) = find_next(&mut reader, pattern, from, &not_cancelled()).unwrap() {
            found.push(at);
            from = at + 1;
        }
        found
    }

    fn all_backward(data: &[u8], pattern: &[u8]) -> Vec<u64> {
        let mut reader = Cursor::new(data.to_vec());
        let mut found = Vec::new();
        let mut before = data.len() as u64;
        while let Some(at) = find_previous(&mut reader, pattern, before, &not_cancelled()).unwrap()
        {
            found.push(at);
            before = at;
        }
        found
    }

    #[test]
    fn parses_hex_patterns() {
        assert_eq!(
            parse_hex_pattern("52 50 46 37"),
            Ok(vec![0x52, 0x50, 0x46, 0x37])
        );
        assert_eq!(
            parse_hex_pattern("52504637"),
            Ok(vec![0x52, 0x50, 0x46, 0x37])
        );
        assert_eq!(parse_hex_pattern("  ab\tCD  "), Ok(vec![0xAB, 0xCD]));
        assert!(parse_hex_pattern("").unwrap_err().contains("empty"));
        assert!(parse_hex_pattern("   ").is_err());
        assert!(parse_hex_pattern("5 2").unwrap_err().contains("odd"));
        assert!(parse_hex_pattern("ABC").is_err());
        assert!(parse_hex_pattern("0x52").unwrap_err().contains("'x'"));
        assert!(parse_hex_pattern("ZZ").is_err());
        assert!(parse_hex_pattern("é1").is_err());
    }

    #[test]
    fn finds_matches_forward_and_backward() {
        let data = b"abcabcXabc";
        assert_eq!(all_forward(data, b"abc"), [0, 3, 7]);
        assert_eq!(all_backward(data, b"abc"), [7, 3, 0]);
        assert_eq!(all_forward(b"aaaa", b"aa"), [0, 1, 2]);
        assert_eq!(all_backward(b"aaaa", b"aa"), [2, 1, 0]);
        assert!(all_forward(data, b"xyz").is_empty());
        assert!(all_backward(data, b"abcabcXabcd").is_empty());
    }

    #[test]
    fn start_positions_are_respected() {
        let mut data = Cursor::new(b"abcabc".to_vec());
        let cancel = not_cancelled();
        assert_eq!(find_next(&mut data, b"abc", 4, &cancel).unwrap(), None);
        assert_eq!(find_next(&mut data, b"abc", 100, &cancel).unwrap(), None);
        assert_eq!(
            find_next(&mut data, b"abc", u64::MAX, &cancel).unwrap(),
            None
        );
        assert_eq!(
            find_previous(&mut data, b"abc", 3, &cancel).unwrap(),
            Some(0)
        );
        assert_eq!(find_previous(&mut data, b"abc", 0, &cancel).unwrap(), None);
        assert_eq!(
            find_previous(&mut data, b"abc", u64::MAX, &cancel).unwrap(),
            Some(3)
        );
    }

    #[test]
    fn empty_data_and_patterns() {
        let mut data = Cursor::new(Vec::new());
        let cancel = not_cancelled();
        assert_eq!(find_next(&mut data, b"a", 0, &cancel).unwrap(), None);
        assert_eq!(find_previous(&mut data, b"a", 0, &cancel).unwrap(), None);
        assert!(find_next(&mut data, b"", 0, &cancel).is_err());
        assert!(find_previous(&mut data, b"", 0, &cancel).is_err());
    }

    #[test]
    fn finds_matches_across_window_boundaries() {
        let pattern = b"RPF7-boundary";
        let len = CHUNK * 3;
        // Where the first forward window ends and the first backward one starts.
        let forward_edge = CHUNK + pattern.len() - 1;
        let backward_edge = len - forward_edge;
        for edge in [forward_edge, backward_edge] {
            for shift in 0..=pattern.len() {
                let at = edge - shift;
                let mut data = vec![0u8; len];
                data[at..at + pattern.len()].copy_from_slice(pattern);
                assert_eq!(all_forward(&data, pattern), [at as u64], "at {at}");
                assert_eq!(all_backward(&data, pattern), [at as u64], "at {at}");
            }
        }
        // Near the start of the data, where backward windows run out.
        let mut data = vec![0u8; CHUNK * 2 + 5];
        data[CHUNK + 3..CHUNK + 3 + pattern.len()].copy_from_slice(pattern);
        data[1..1 + pattern.len()].copy_from_slice(pattern);
        assert_eq!(all_backward(&data, pattern), [CHUNK as u64 + 3, 1]);
        assert_eq!(all_forward(&data, pattern), [1, CHUNK as u64 + 3]);
    }

    #[test]
    fn finds_matches_beyond_four_gib() {
        let at = 6 * 1024 * 1024 * 1024 + 5;
        let mut data = Sparse {
            len: at + 1024,
            patches: vec![(at, b"Test".to_vec())],
            pos: 0,
        };
        let cancel = not_cancelled();
        let near = at - 3 * CHUNK as u64;
        assert_eq!(
            find_next(&mut data, b"Test", near, &cancel).unwrap(),
            Some(at)
        );
        assert_eq!(
            find_previous(&mut data, b"Test", at + 1024, &cancel).unwrap(),
            Some(at)
        );
        assert_eq!(
            find_next(&mut data, b"Test", at + 1, &cancel).unwrap(),
            None
        );
    }

    #[test]
    fn searches_can_be_cancelled() {
        let mut data = Cursor::new(vec![0u8; 64]);
        let cancel = AtomicBool::new(true);
        assert!(matches!(
            find_next(&mut data, b"x", 0, &cancel),
            Err(Error::Cancelled)
        ));
        assert!(matches!(
            find_previous(&mut data, b"x", 64, &cancel),
            Err(Error::Cancelled)
        ));
    }
}
