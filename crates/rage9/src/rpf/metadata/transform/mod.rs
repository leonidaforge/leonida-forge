//! The cipher layer of the validation chain: cipher descriptors, the cipher
//! type table, CBC chaining and the span runner.
//!
//! The block operation of algorithm 0x10 is specific to the executable and is
//! not implemented here, and no key material is included. The engine's key
//! lookup is not reproduced either: a [`CipherSource`] decides which block
//! operation a key identifier gets. Without a source for real archives, this
//! module cannot decrypt them.
//!
//! Behavior follows the cryptography research for executable build e95020b2.

use std::fmt;
use std::ops::Range;

use super::{array, u16_at, u32_at};

pub const BLOCK_LEN: usize = 16;
pub type Block = [u8; BLOCK_LEN];

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Cipher types 13 to 15, on which the engine traps.
    InvalidType(u16),
    /// An algorithm that was not analyzed.
    Unsupported {
        kind: u16,
        algorithm: u8,
    },
    /// The source has no static descriptor for this index.
    NoStaticDescriptor(u8),
    /// The source has no block operation for this key identifier.
    NoKey(u32),
    /// A CBC input whose length is not a multiple of the block length.
    Unaligned(usize),
    OutOfBounds {
        span: Range<usize>,
        len: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidType(kind) => write!(f, "invalid cipher type {kind}"),
            Error::Unsupported { kind, algorithm } => write!(
                f,
                "cipher type {kind} selects algorithm {algorithm:#x}, which is not supported"
            ),
            Error::NoStaticDescriptor(index) => write!(f, "no static cipher descriptor {index}"),
            Error::NoKey(key_id) => write!(f, "no key for key identifier {key_id:#x}"),
            Error::Unaligned(len) => {
                write!(
                    f,
                    "{len} bytes are not a multiple of the {BLOCK_LEN}-byte block"
                )
            }
            Error::OutOfBounds { span, len } => {
                write!(f, "span {span:#x?} lies outside {len:#x} bytes")
            }
        }
    }
}

impl std::error::Error for Error {}

/// A cipher descriptor, from the executable, from `B` sub-block 1, or from an
/// entry's payload-transform field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CipherDescriptor {
    pub key_id: u32,
    /// The cipher type.
    pub kind: u16,
    /// For algorithm 0x10, the initial IV. For algorithm 0x11, the base the
    /// counter starts from; that algorithm's block operation is not
    /// implemented here.
    pub parameter: Block,
}

impl CipherDescriptor {
    pub const LEN: usize = 0x16;

    pub fn parse(bytes: &[u8]) -> Option<Self> {
        Some(Self {
            key_id: u32_at(bytes, 0x00)?,
            kind: u16_at(bytes, 0x04)?,
            parameter: array(bytes, 0x06)?,
        })
    }

    /// Whether the span runner finalizes after every span, which makes each
    /// span start from the initial IV.
    pub fn resets_per_span(&self) -> bool {
        matches!(self.kind, 3..=5)
    }
}

/// The cipher type of the executable's static descriptor `index`, which is
/// `hdr[0x2E] >> 1`.
pub fn static_kind(index: u8) -> u16 {
    match index {
        4 => 16,
        1 => 3,
        _ => 0,
    }
}

/// The stored range a payload transform covers, from the stream fields of the
/// entry's transform descriptor.
///
/// The descriptor carries four `u64` fields, at `+0x18`, `+0x20`, `+0x28` and
/// `+0x30`. Writing `a`, `b`, `c` and `t` for those fields, the covered stored
/// positions of a stream of `len` bytes are
///
/// - every position below `a + b`,
/// - the first `b` bytes of each later buffer, where the buffers start at
///   `a + b + c` and repeat every `b + c` bytes, and
/// - the last `t` bytes of the stream.
///
/// The `a = 0` shapes cover a contiguous range from 0: `c = 0` makes the
/// buffers abut. Positions are relative to the first chunk byte, so the
/// stored 16-byte prefix of encoding 2 is outside the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StreamRange {
    leading: u64,
    gap: u64,
    length: u64,
    step: u64,
    tail: u64,
}

impl StreamRange {
    /// The shortest descriptor value that holds all four stream fields.
    pub const MIN_LEN: usize = 0x38;

    /// `None` when the value is shorter than the stream fields, a field sum
    /// overflows, or the fields describe no covered position at all. An empty
    /// coverage means the descriptor cannot be verified, so it is refused
    /// rather than treated as a plaintext stream.
    pub fn parse(value: &[u8]) -> Option<Self> {
        let a = u64_at(value, 0x18)?;
        let b = u64_at(value, 0x20)?;
        let c = u64_at(value, 0x28)?;
        let t = u64_at(value, 0x30)?;
        let leading = a.checked_add(b)?;
        let step = b.checked_add(c)?;
        if step == 0 || (leading == 0 && b == 0 && t == 0) {
            return None;
        }
        Some(Self {
            leading,
            gap: c,
            length: b,
            step,
            tail: t,
        })
    }

    /// Whether the stored position `offset` of a stream of `stream_len` bytes
    /// is transformed.
    pub fn covers(&self, offset: u64, stream_len: u64) -> bool {
        if self.tail != 0 && offset >= stream_len.saturating_sub(self.tail) {
            return true;
        }
        if offset < self.leading {
            return true;
        }
        let Some(after_leading) = offset.checked_sub(self.leading) else {
            return false;
        };
        let Some(from_first) = after_leading.checked_sub(self.gap) else {
            return false;
        };
        from_first % self.step < self.length
    }

    /// The length of the leading region.
    pub fn leading(&self) -> u64 {
        self.leading
    }

    /// The gap between the leading region and the first later buffer.
    pub fn gap(&self) -> u64 {
        self.gap
    }

    /// The length of each later buffer.
    pub fn length(&self) -> u64 {
        self.length
    }

    /// The distance between later buffer starts.
    pub fn step(&self) -> u64 {
        self.step
    }

    /// The length of the trailing region.
    pub fn tail(&self) -> u64 {
        self.tail
    }

    /// Whether the range covers every stored position.
    pub fn is_whole(&self) -> bool {
        self.gap == 0 && self.length == self.step
    }

    #[cfg(test)]
    pub(crate) fn from_parts(
        leading: u64,
        gap: u64,
        length: u64,
        step: u64,
        tail: u64,
    ) -> Option<Self> {
        (step != 0).then_some(Self {
            leading,
            gap,
            length,
            step,
            tail,
        })
    }
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let low = u32_at(bytes, offset)?;
    let high = u32_at(bytes, offset.checked_add(4)?)?;
    Some(u64::from(low) | (u64::from(high) << 32))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// Algorithm 0. Every operation succeeds without touching the data.
    Identity,
    /// Algorithm 0x10, CBC decryption.
    Cbc,
    /// Algorithm 1, 2, 0x11 or 0x12, none of which was analyzed.
    Untraced(u8),
}

impl Algorithm {
    /// Maps a cipher type through the engine's 19-entry type table.
    pub fn of(kind: u16) -> Result<Self, Error> {
        Ok(match kind {
            0 | 9 | 19.. => Algorithm::Identity,
            3..=5 | 10..=12 | 16 => Algorithm::Cbc,
            1 => Algorithm::Untraced(1),
            2 => Algorithm::Untraced(2),
            17 => Algorithm::Untraced(0x11),
            6..=8 | 18 => Algorithm::Untraced(0x12),
            13..=15 => return Err(Error::InvalidType(kind)),
        })
    }

    /// The algorithm identifier the engine's key selector carries. This is a
    /// property of the algorithm family, not of the cipher type that selected
    /// it: cipher types 3, 4, 5, 10, 11, 12 and 16 all carry `0x10`.
    pub fn id(self) -> u8 {
        match self {
            Algorithm::Identity => 0,
            Algorithm::Cbc => 0x10,
            Algorithm::Untraced(id) => id,
        }
    }
}

/// Decryption of one block under a fixed key.
pub trait BlockDecrypt {
    fn decrypt_block(&self, block: &mut Block);
}

/// What the engine takes from the executable rather than from the archive.
pub trait CipherSource {
    type Block: BlockDecrypt;

    /// The key identifier and parameter of static descriptor `index`. Its
    /// cipher type is [`CipherSource::static_kind`].
    fn static_descriptor(&self, index: u8) -> Option<(u32, Block)>;

    /// The cipher type of static descriptor `index`. The default returns the
    /// current build's [`static_kind`] mapping, so existing sources need not
    /// implement it; a recognized source overrides it with the type read from
    /// the executable.
    fn static_kind(&self, index: u8) -> Option<u16> {
        Some(static_kind(index))
    }

    /// The algorithm 0x10 block operation for `key_id`.
    fn cbc_block(&self, key_id: u32) -> Option<Self::Block>;

    /// The block operation for `key_id` under cipher type `kind`. The default
    /// ignores `kind` and calls [`CipherSource::cbc_block`]; a recognized
    /// source overrides it to select the block by the type's algorithm.
    fn cbc_block_for(&self, kind: u16, key_id: u32) -> Option<Self::Block> {
        let _ = kind;
        self.cbc_block(key_id)
    }
}

/// CBC decryption in place. The IV carries over between updates until
/// [`Cbc::reset`].
#[derive(Debug, Clone)]
pub struct Cbc<B> {
    block: B,
    initial: Block,
    iv: Block,
}

impl<B: BlockDecrypt> Cbc<B> {
    pub fn new(block: B, iv: Block) -> Self {
        Self {
            block,
            initial: iv,
            iv,
        }
    }

    /// Fails before changing `data` or the IV if the length is not a
    /// multiple of the block length.
    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        if !data.len().is_multiple_of(BLOCK_LEN) {
            return Err(Error::Unaligned(data.len()));
        }
        for block in data.as_chunks_mut::<BLOCK_LEN>().0 {
            let stored = *block;
            self.block.decrypt_block(block);
            for (byte, iv) in block.iter_mut().zip(&self.iv) {
                *byte ^= iv;
            }
            self.iv = stored;
        }
        Ok(())
    }

    pub fn reset(&mut self) {
        self.iv = self.initial;
    }
}

enum State<B> {
    Identity,
    Cbc(Cbc<B>),
}

/// A cipher initialized from a descriptor.
pub struct Cipher<B> {
    resets_per_span: bool,
    state: State<B>,
}

impl<B: BlockDecrypt> Cipher<B> {
    /// `block` supplies the block operation for the descriptor's key
    /// identifier. It is called only for algorithm 0x10. The engine also looks
    /// up a key for algorithm 0, which is not modelled.
    pub fn new(
        descriptor: &CipherDescriptor,
        block: impl FnOnce(u32) -> Option<B>,
    ) -> Result<Self, Error> {
        let state = match Algorithm::of(descriptor.kind)? {
            Algorithm::Identity => State::Identity,
            Algorithm::Cbc => {
                let block = block(descriptor.key_id).ok_or(Error::NoKey(descriptor.key_id))?;
                State::Cbc(Cbc::new(block, descriptor.parameter))
            }
            Algorithm::Untraced(algorithm) => {
                return Err(Error::Unsupported {
                    kind: descriptor.kind,
                    algorithm,
                });
            }
        };
        Ok(Self {
            resets_per_span: descriptor.resets_per_span(),
            state,
        })
    }

    pub fn update(&mut self, data: &mut [u8]) -> Result<(), Error> {
        match &mut self.state {
            State::Identity => Ok(()),
            State::Cbc(cbc) => cbc.update(data),
        }
    }

    /// The engine's `final`. It resets the IV and cannot fail for the
    /// implemented algorithms.
    pub fn finish(&mut self) {
        if let State::Cbc(cbc) = &mut self.state {
            cbc.reset();
        }
    }

    /// Processes `spans` of `buffer` in order, as the engine's span runner
    /// does. All spans are checked before any byte changes.
    pub fn run(&mut self, buffer: &mut [u8], spans: &[Range<usize>]) -> Result<(), Error> {
        let block_aligned = matches!(self.state, State::Cbc(_));
        for span in spans {
            if span.start > span.end || span.end > buffer.len() {
                return Err(Error::OutOfBounds {
                    span: span.clone(),
                    len: buffer.len(),
                });
            }
            if block_aligned && !span.len().is_multiple_of(BLOCK_LEN) {
                return Err(Error::Unaligned(span.len()));
            }
        }
        for span in spans {
            self.update(&mut buffer[span.clone()])?;
            if self.resets_per_span {
                self.finish();
            }
        }
        self.finish();
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests;
