//! One row of the table of contents, read once.

use std::ops::Range;

use lforge_binary::Source;

use super::transform::CipherDescriptor;
use super::{
    ChunkTable, Error, Location, Metadata, Payload, PayloadSource, StreamTransform, invalid,
};

/// A field of a row: `Ok(None)` if the row has no value for it, `Err` with
/// the reason if the value is malformed.
pub type Field<T> = Result<Option<T>, String>;

/// The fields of one row. Values are as stored. Their meaning is only
/// interpreted where it is established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The row index. It identifies the entry within this metadata only.
    pub row: u32,
    /// Payload offset, sizes, type ID, compression mode and record layout.
    pub location: Field<Location>,
    pub name_hash: Field<u64>,
    pub name_key: Field<u32>,
    pub chunks: Field<ChunkTable>,
    pub payload_transform: Result<bool, String>,
    /// The descriptor the payload transform initializes its cipher with, when
    /// the row carries one.
    pub payload_cipher: Field<CipherDescriptor>,
    /// The alternate source the payload is read through. `None` for the main
    /// source.
    pub read_source: Field<u32>,
    /// Where the stored payload data ends, from the archive header's declared
    /// trailing region. `None` when the metadata was built from decoded bytes.
    pub payload_end: Option<u64>,
}

fn reason(err: Error) -> String {
    match err {
        Error::Invalid(reason) => reason,
        other => other.to_string(),
    }
}

impl Entry {
    pub(super) fn read(metadata: &Metadata, row: u32) -> Self {
        Self {
            row,
            location: metadata.location_record(row).map_err(reason),
            name_hash: metadata.name_hash(row).map_err(reason),
            name_key: metadata.name_key(row).map_err(reason),
            chunks: metadata.chunk_table(row).map_err(reason),
            payload_transform: metadata.payload_transform(row).map_err(reason),
            payload_cipher: metadata.payload_cipher(row).map_err(reason),
            read_source: metadata.read_source(row).map_err(reason),
            payload_end: metadata.payload_end(),
        }
    }

    pub fn type_id(&self) -> Option<u8> {
        Some(self.location.as_ref().ok()?.as_ref()?.type_id)
    }

    fn malformed(&self, field: &str, reason: &str) -> Error {
        invalid(format!("row {}: malformed {field}: {reason}", self.row))
    }

    /// The archive-relative range of an entry stored as it is: from its
    /// payload offset, its logical size, as the engine reads a nested archive.
    /// Fails with [`Error::Encoded`] for an entry that is compressed, chunked
    /// or behind the payload transform. The range is not checked against a
    /// source; [`Entry::raw_source`] does that.
    pub fn raw_range(&self) -> Result<Range<u64>, Error> {
        let row = self.row;
        let location = match &self.location {
            Ok(Some(location)) => *location,
            Ok(None) => return Err(invalid(format!("row {row} has no location record"))),
            Err(reason) => return Err(self.malformed("location record", reason)),
        };
        let chunked = match &self.chunks {
            Ok(chunks) => chunks.is_some(),
            Err(reason) => return Err(self.malformed("chunk table", reason)),
        };
        let transformed = match &self.payload_transform {
            Ok(transformed) => *transformed,
            Err(reason) => return Err(self.malformed("payload transform flag", reason)),
        };
        let encoding = if location.is_compressed() {
            Some("compressed")
        } else if chunked {
            Some("in chunks")
        } else if transformed {
            Some("behind the payload transform")
        } else {
            None
        };
        if let Some(encoding) = encoding {
            return Err(Error::Encoded { row, encoding });
        }
        if location.logical_len > location.stored_len {
            return Err(invalid(format!(
                "entry {row} is stored as it is, but its logical size {:#x} exceeds its stored size {:#x}",
                location.logical_len, location.stored_len
            )));
        }
        let start = location.payload_offset;
        let end = start
            .checked_add(location.logical_len)
            .ok_or_else(|| invalid(format!("the range of entry {row} overflows")))?;
        Ok(start..end)
    }

    /// The source the entry's stored bytes are read through: `main`, or
    /// `alternates[i]` for read source `i`. An alternate that is missing or
    /// `None` fails with [`Error::ReadSource`] rather than falling back to
    /// `main`.
    fn read_through<'s>(
        &self,
        main: &'s Source,
        alternates: &'s [Option<Source>],
    ) -> Result<&'s Source, Error> {
        match &self.read_source {
            Ok(None) => Ok(main),
            Ok(Some(index)) => usize::try_from(*index)
                .ok()
                .and_then(|i| alternates.get(i)?.as_ref())
                .ok_or(Error::ReadSource {
                    row: self.row,
                    index: *index,
                }),
            Err(reason) => Err(self.malformed("read source", reason)),
        }
    }

    /// The bytes of an entry stored as it is, as a view of the source it is
    /// read through: `main`, or `alternates[i]` for read source `i`. The range is the same in
    /// every source.
    pub fn raw_source(
        &self,
        main: &Source,
        alternates: &[Option<Source>],
    ) -> Result<Source, Error> {
        let row = self.row;
        let range = self.raw_range()?;
        self.check_payload_end(row, range.end)?;
        let source = self.read_through(main, alternates)?;
        if range.end > source.len() {
            return Err(invalid(format!(
                "entry {row} ends at {:#x}, after the end of the archive ({:#x})",
                range.end,
                source.len()
            )));
        }
        Ok(source.slice(range.start, range.end - range.start)?)
    }

    /// Rejects a payload range that crosses the start of the trailing region
    /// the archive header declares.
    fn check_payload_end(&self, row: u32, end: u64) -> Result<(), Error> {
        match self.payload_end {
            Some(tail) if end > tail => Err(invalid(format!(
                "entry {row} ends at {end:#x}, after the start of the trailing region ({tail:#x})"
            ))),
            _ => Ok(()),
        }
    }

    /// The source the entry's stored bytes are read through: `main`, or
    /// `alternates[i]` for read source `i`.
    pub(crate) fn source<'a>(
        &self,
        main: &'a Source,
        alternates: &'a [Option<Source>],
    ) -> Result<&'a Source, Error> {
        self.read_through(main, alternates)
    }

    /// The contents of the entry, decoded where that is supported.
    ///
    /// The engine's order applies: an entry behind the payload transform is
    /// refused; with a chunk table, each chunk's method decides and the
    /// entry's compression mode is not used; without one, mode 0 is the
    /// stored bytes ([`Entry::raw_source`]) and mode 1 one raw DEFLATE
    /// stream. Other modes fail with [`Error::Undecodable`]. Stored bytes are
    /// read through `main` or `alternates[i]` as for [`Entry::raw_source`].
    pub fn payload(&self, main: &Source, alternates: &[Option<Source>]) -> Result<Payload, Error> {
        self.payload_with(main, alternates, None)
    }

    /// The contents of an entry behind the payload transform, decoded with
    /// `transform`. The bytes are transformed while they are read, so a large
    /// entry is never materialized whole.
    pub fn transformed_payload(
        &self,
        main: &Source,
        alternates: &[Option<Source>],
        transform: StreamTransform,
    ) -> Result<Payload, Error> {
        self.payload_with(main, alternates, Some(transform))
    }

    fn payload_with(
        &self,
        main: &Source,
        alternates: &[Option<Source>],
        transform: Option<StreamTransform>,
    ) -> Result<Payload, Error> {
        let row = self.row;
        let location = match &self.location {
            Ok(Some(location)) => *location,
            Ok(None) => return Err(invalid(format!("row {row} has no location record"))),
            Err(reason) => return Err(self.malformed("location record", reason)),
        };
        match &self.payload_transform {
            Ok(false) if transform.is_some() => {
                return Err(invalid(format!("row {row} has no payload transform field")));
            }
            Ok(true) if transform.is_none() => {
                return Err(Error::Encoded {
                    row,
                    encoding: "behind the payload transform",
                });
            }
            Ok(_) => {}
            Err(reason) => return Err(self.malformed("payload transform flag", reason)),
        }
        let wrap = |source: Source| match &transform {
            Some(transform) => PayloadSource::transformed(source, transform.clone()),
            None => PayloadSource::plain(source),
        };
        let table = match &self.chunks {
            Ok(table) => table.as_ref(),
            Err(reason) => return Err(self.malformed("chunk table", reason)),
        };
        if table.is_none() {
            match location.mode {
                0 => {
                    return self
                        .raw_source(main, alternates)
                        .map(|source| Payload::stored(wrap(source)));
                }
                1 => {}
                2 => {
                    return Err(Error::Undecodable {
                        row,
                        reason: "compression mode 2 fails in the engine".to_string(),
                    });
                }
                mode => {
                    return Err(Error::Undecodable {
                        row,
                        reason: format!("compression mode {mode} has no known codec"),
                    });
                }
            }
        }
        let source = self.read_through(main, alternates)?;
        let end = location
            .payload_offset
            .checked_add(location.stored_len)
            .ok_or_else(|| invalid(format!("the range of entry {row} overflows")))?;
        self.check_payload_end(row, end)?;
        if end > source.len() {
            return Err(invalid(format!(
                "the stored bytes of entry {row} end at {end:#x}, after the end of the archive \
                 ({:#x})",
                source.len()
            )));
        }
        let stored = wrap(source.slice(location.payload_offset, location.stored_len)?);
        match table {
            Some(table) => Payload::chunked(row, stored, location.logical_len, table),
            None => Ok(Payload::deflate(stored, location.logical_len)),
        }
    }
}
