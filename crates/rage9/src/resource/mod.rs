//! RAGE resources: a system segment of CPU structures followed by a graphics
//! segment of GPU data, each made of one or more pages.
//!
//! What is checked here was observed in GTA VI data and matches the RPF7 and
//! RPF8 resource layouts; none of it is confirmed by game code:
//!
//! - System data starts with a zero `u64` and, at +8, a system pointer to the
//!   page map.
//! - Pointers are `u64` values `0x5xxxxxxx` (system) or `0x6xxxxxxx`
//!   (graphics) whose low 28 bits are an offset into the concatenated pages of
//!   that segment.
//! - The page map is 16 bytes with the system and graphics page counts at +8
//!   and +9, followed by one zeroed 8-byte slot per page.
//! - As stored, each page is its own zlib stream, system pages first. Pages
//!   longer than [`SPLIT_LEN`] are split into streams of that length.
//!
//! Page sizes are not stored in the resource. They come from the stream
//! lengths, so a missing page can be detected but not its size.

#[cfg(test)]
mod tests;

use crate::Status;

pub const SYSTEM_BASE: u64 = 0x5000_0000;
pub const GRAPHICS_BASE: u64 = 0x6000_0000;
const OFFSET_MASK: u64 = 0x0FFF_FFFF;
pub const PAGE_MAP_HEADER_LEN: u32 = 16;
/// In a segment of several pages, every page but the last is a multiple of
/// this and the last is at most this long.
pub const PAGE_UNIT: u64 = 0x1_0000;
/// Inflated length of every stream of a split page except the last.
pub const SPLIT_LEN: u64 = 0x200_0000;
/// The longest possible page map: two counts of at most 255 pages.
const MAX_MAP_LEN: usize = PAGE_MAP_HEADER_LEN as usize + 8 * 2 * u8::MAX as usize;
/// Pointer-like values kept per resource for the range check.
const MAX_POINTERS: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pointer {
    System(u32),
    Graphics(u32),
}

impl Pointer {
    pub fn decode(value: u64) -> Option<Self> {
        let offset = (value & OFFSET_MASK) as u32;
        match value >> 28 {
            5 => Some(Pointer::System(offset)),
            6 => Some(Pointer::Graphics(offset)),
            _ => None,
        }
    }
}

fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

/// The page map offset of system data that starts with `head`, if `head` has
/// the shape of a resource: a zero `u64`, then a system pointer past both.
pub fn page_map_offset(head: &[u8]) -> Option<u32> {
    if u64_at(head, 0)? != 0 {
        return None;
    }
    match Pointer::decode(u64_at(head, 8)?)? {
        Pointer::System(offset) if offset >= PAGE_MAP_HEADER_LEN => Some(offset),
        _ => None,
    }
}

/// The byte after `0DRP` at +0x10, a marker some resources carry. Its
/// meaning is not known.
pub fn tag(head: &[u8]) -> Option<u8> {
    if head.get(0x10..0x14)? == b"0DRP" {
        head.get(0x14).copied()
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageMap {
    /// Offset in the system data.
    pub offset: u32,
    pub system_pages: u8,
    pub graphics_pages: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageMapError {
    /// The map is not inside the system data that was found.
    Outside,
    /// A byte other than the page counts is not zero.
    NonZero,
    /// No system page is declared, so none can hold the map.
    NoSystemPage,
}

impl PageMapError {
    pub fn describe(self) -> &'static str {
        match self {
            PageMapError::Outside => "the page map is outside the recovered system data",
            PageMapError::NonZero => "the page map has unexpected non-zero bytes",
            PageMapError::NoSystemPage => "the page map declares no system page",
        }
    }
}

impl PageMap {
    pub fn byte_len(&self) -> u32 {
        PAGE_MAP_HEADER_LEN + 8 * (u32::from(self.system_pages) + u32::from(self.graphics_pages))
    }

    pub fn pages(&self, segment: Segment) -> u8 {
        match segment {
            Segment::System => self.system_pages,
            Segment::Graphics => self.graphics_pages,
        }
    }

    /// Parses the map from `bytes`, which start at `offset` in the system
    /// data. The page slots are filled in at runtime. As stored, they and the
    /// other header bytes have been zero in every observed resource, so
    /// anything else is rejected.
    pub fn parse(offset: u32, bytes: &[u8]) -> Result<Self, PageMapError> {
        let header = bytes
            .get(..PAGE_MAP_HEADER_LEN as usize)
            .ok_or(PageMapError::Outside)?;
        let map = PageMap {
            offset,
            system_pages: header[8],
            graphics_pages: header[9],
        };
        let all = bytes
            .get(..map.byte_len() as usize)
            .ok_or(PageMapError::Outside)?;
        if all
            .iter()
            .enumerate()
            .any(|(at, &byte)| byte != 0 && !(8..10).contains(&at))
        {
            return Err(PageMapError::NonZero);
        }
        if map.system_pages == 0 {
            return Err(PageMapError::NoSystemPage);
        }
        Ok(map)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Segment {
    System,
    Graphics,
}

impl Segment {
    pub fn name(self) -> &'static str {
        match self {
            Segment::System => "system",
            Segment::Graphics => "graphics",
        }
    }
}

/// One page as stored: consecutive streams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Page {
    pub segment: Segment,
    pub stream_count: u32,
    /// Inflated length.
    pub len: u64,
}

/// Groups the inflated lengths of consecutive streams into pages: a stream
/// of exactly [`SPLIT_LEN`] continues into the next one. Returns the stream
/// count and length of each page.
pub fn group_pages(stream_lens: &[u64]) -> Vec<(u32, u64)> {
    let mut pages: Vec<(u32, u64)> = Vec::new();
    let mut open = false;
    for &len in stream_lens {
        match pages.last_mut() {
            Some(page) if open => {
                page.0 += 1;
                page.1 += len;
            }
            _ => pages.push((1, len)),
        }
        open = len == SPLIT_LEN;
    }
    pages
}

/// 8-byte aligned values in the system data that decode as pointers.
/// Hashes, strings and fill patterns can look like pointers too, so values
/// outside the data are a warning, not proof of a missing page.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Pointers {
    pub system: u32,
    pub graphics: u32,
    pub system_outside: u32,
    pub graphics_outside: u32,
    /// Whether every value was checked. Very large system data has more
    /// pointer-like values than are kept.
    pub checked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Issue {
    PageMap(PageMapError),
    /// Fewer pages were found than the page map declares.
    MissingPages {
        segment: Segment,
        declared: u8,
        found: u8,
    },
    /// A page of a segment with several pages breaks the size pattern
    /// described at [`PAGE_UNIT`].
    PageSize {
        segment: Segment,
        page: u8,
    },
    /// Pointer-like values point past the end of their segment.
    PointersOutside {
        system: u32,
        graphics: u32,
    },
}

impl Issue {
    pub fn describe(&self) -> String {
        match *self {
            Issue::PageMap(err) => err.describe().to_string(),
            Issue::MissingPages {
                segment,
                declared,
                found,
            } => format!("{found} of {declared} {} pages found", segment.name()),
            Issue::PageSize { segment, page } => format!(
                "the size of {} page {} does not fit the pattern of multi-page segments",
                segment.name(),
                u32::from(page) + 1
            ),
            Issue::PointersOutside { system, graphics } => format!(
                "{system} system and {graphics} graphics pointer-like values point past the reconstructed data"
            ),
        }
    }
}

/// What could be established about one resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub page_map: Result<PageMap, PageMapError>,
    /// System pages, then graphics pages. Without a valid page map, only the
    /// first stream group, which holds the start of the system data.
    pub pages: Vec<Page>,
    pub pointers: Pointers,
    pub tag: Option<u8>,
}

impl Layout {
    pub fn segment_pages(&self, segment: Segment) -> impl Iterator<Item = &Page> {
        self.pages
            .iter()
            .filter(move |page| page.segment == segment)
    }

    pub fn segment_len(&self, segment: Segment) -> u64 {
        self.segment_pages(segment).map(|page| page.len).sum()
    }

    pub fn stream_count(&self) -> u32 {
        self.pages.iter().map(|page| page.stream_count).sum()
    }

    pub fn issues(&self) -> Vec<Issue> {
        let map = match self.page_map {
            Ok(map) => map,
            Err(err) => return vec![Issue::PageMap(err)],
        };
        let mut issues = Vec::new();
        for segment in [Segment::System, Segment::Graphics] {
            let pages: Vec<&Page> = self.segment_pages(segment).collect();
            let declared = map.pages(segment);
            if pages.len() < usize::from(declared) {
                issues.push(Issue::MissingPages {
                    segment,
                    declared,
                    found: pages.len() as u8,
                });
                continue;
            }
            let last = pages.len().saturating_sub(1);
            for (ix, page) in pages.iter().enumerate().filter(|_| pages.len() > 1) {
                let fits = if ix == last {
                    page.len <= PAGE_UNIT
                } else {
                    page.len % PAGE_UNIT == 0
                };
                if !fits {
                    issues.push(Issue::PageSize {
                        segment,
                        page: ix as u8,
                    });
                }
            }
        }
        let pointers = self.pointers;
        if pointers.system_outside > 0 || pointers.graphics_outside > 0 {
            issues.push(Issue::PointersOutside {
                system: pointers.system_outside,
                graphics: pointers.graphics_outside,
            });
        }
        issues
    }

    /// How much of the resource is accounted for, independent of whether its
    /// streams inflated completely:
    ///
    /// - Complete: the page map is valid, every declared page was found and
    ///   page sizes fit the observed pattern.
    /// - Partial: the page map is valid, but declared pages are missing.
    /// - Unverified: the page map could not be validated, or page sizes do
    ///   not fit the pattern.
    ///
    /// Pointer-like values outside the data do not change the status: in
    /// GTA VI data most of them are 32-bit hashes followed by four zero
    /// bytes.
    pub fn status(&self) -> Status {
        let issues: Vec<Issue> = self
            .issues()
            .into_iter()
            .filter(|issue| !matches!(issue, Issue::PointersOutside { .. }))
            .collect();
        if issues.is_empty() {
            Status::Complete
        } else if self.page_map.is_ok()
            && issues
                .iter()
                .any(|issue| matches!(issue, Issue::MissingPages { .. }))
        {
            Status::Partial
        } else {
            Status::Unverified
        }
    }
}

/// Builds a [`Layout`] from the inflated system data, fed in order, and the
/// page groups of the streams that hold the resource and what follows it.
pub struct Builder {
    map_offset: u32,
    tag: Option<u8>,
    pos: u64,
    map_bytes: Vec<u8>,
    carry: Vec<u8>,
    system: Vec<u32>,
    graphics: Vec<u32>,
    overflow: bool,
}

impl Builder {
    /// `head` is the start of the system data. `None` if it does not have
    /// the shape of a resource.
    pub fn new(head: &[u8]) -> Option<Self> {
        Some(Self {
            map_offset: page_map_offset(head)?,
            tag: tag(head),
            pos: 0,
            map_bytes: Vec::new(),
            carry: Vec::with_capacity(8),
            system: Vec::new(),
            graphics: Vec::new(),
            overflow: false,
        })
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        let map_start = u64::from(self.map_offset);
        let map_end = map_start + MAX_MAP_LEN as u64;
        let end = self.pos + bytes.len() as u64;
        if self.pos < map_end && end > map_start {
            let from = map_start.saturating_sub(self.pos) as usize;
            let to = (map_end.min(end) - self.pos) as usize;
            self.map_bytes.extend_from_slice(&bytes[from..to]);
        }

        let mut rest = bytes;
        if !self.carry.is_empty() {
            let take = (8 - self.carry.len()).min(rest.len());
            self.carry.extend_from_slice(&rest[..take]);
            rest = &rest[take..];
            if self.carry.len() == 8 {
                let value = u64::from_le_bytes(self.carry[..].try_into().expect("8 bytes"));
                self.carry.clear();
                self.note(value);
            }
        }
        let (words, remainder) = rest.as_chunks::<8>();
        for word in words {
            self.note(u64::from_le_bytes(*word));
        }
        self.carry.extend_from_slice(remainder);
        self.pos = end;
    }

    fn note(&mut self, value: u64) {
        let Some(pointer) = Pointer::decode(value) else {
            return;
        };
        if self.system.len() + self.graphics.len() >= MAX_POINTERS {
            self.overflow = true;
            return;
        }
        match pointer {
            Pointer::System(offset) => self.system.push(offset),
            Pointer::Graphics(offset) => self.graphics.push(offset),
        }
    }

    /// The page map, once the bytes that hold it have been fed.
    pub fn page_map(&self) -> Option<Result<PageMap, PageMapError>> {
        match PageMap::parse(self.map_offset, &self.map_bytes) {
            Err(PageMapError::Outside) => None,
            other => Some(other),
        }
    }

    /// Whether the system pages fed so far are all there is to feed: the
    /// page map is known and as many pages as it declares have been fed, or
    /// it is invalid.
    pub fn has_system(&self, pages_fed: usize) -> bool {
        match self.page_map() {
            Some(Ok(map)) => pages_fed >= usize::from(map.system_pages),
            Some(Err(_)) => true,
            None => false,
        }
    }

    /// Assigns `pages`, the stream groups from [`group_pages`] starting with
    /// the first system page, to segments. The data fed must be the system
    /// pages up to where [`Builder::has_system`] became true, or all pages
    /// if it never did.
    pub fn finish(self, pages: &[(u32, u64)]) -> Layout {
        let first = |page_map| Layout {
            page_map,
            pages: pages
                .first()
                .map(|&(stream_count, len)| Page {
                    segment: Segment::System,
                    stream_count,
                    len,
                })
                .into_iter()
                .collect(),
            pointers: Pointers::default(),
            tag: self.tag,
        };
        let map = match self.page_map() {
            Some(Ok(map)) => map,
            Some(Err(err)) => return first(Err(err)),
            None => return first(Err(PageMapError::Outside)),
        };
        let system = usize::from(map.system_pages);
        let graphics = usize::from(map.graphics_pages);
        let found: Vec<Page> = pages
            .iter()
            .take(system + graphics)
            .enumerate()
            .map(|(ix, &(stream_count, len))| Page {
                segment: if ix < system {
                    Segment::System
                } else {
                    Segment::Graphics
                },
                stream_count,
                len,
            })
            .collect();
        let system_len: u64 = found.iter().take(system).map(|page| page.len).sum();
        if u64::from(map.offset) + u64::from(map.byte_len()) > system_len {
            return first(Err(PageMapError::Outside));
        }
        let graphics_len: u64 = found.iter().skip(system).map(|page| page.len).sum();
        let pointers = Pointers {
            system: self.system.len() as u32,
            graphics: self.graphics.len() as u32,
            system_outside: self
                .system
                .iter()
                .filter(|&&offset| u64::from(offset) >= system_len)
                .count() as u32,
            graphics_outside: self
                .graphics
                .iter()
                .filter(|&&offset| u64::from(offset) >= graphics_len)
                .count() as u32,
            checked: !self.overflow && self.pos == system_len,
        };
        Layout {
            page_map: Ok(map),
            pages: found,
            pointers,
            tag: self.tag,
        }
    }
}

/// Reconstructs a resource from its inflated streams in storage order,
/// starting with the first system stream. Streams after the resource are
/// ignored. `None` if the first stream does not start like a resource.
pub fn analyze(streams: &[&[u8]]) -> Option<Layout> {
    let mut builder = Builder::new(streams.first()?)?;
    let lens: Vec<u64> = streams.iter().map(|stream| stream.len() as u64).collect();
    let pages = group_pages(&lens);
    let mut next = 0;
    for (fed, &(count, _)) in pages.iter().enumerate() {
        if builder.has_system(fed) {
            break;
        }
        for stream in &streams[next..next + count as usize] {
            builder.feed(stream);
        }
        next += count as usize;
    }
    Some(builder.finish(&pages))
}
