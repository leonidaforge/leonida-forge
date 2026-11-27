//! GTA VI RAGE formats: RPF9 archives, the resources stored in them, and the
//! sibling containers and payload encodings found in archive rows.

pub mod adat;
pub mod catalog;
pub mod dictionary;
pub mod drawable;
pub mod drawable_dictionary;
pub mod edup;
pub mod fragment;
pub mod gfx;
pub mod kb2;
pub mod psin;
pub mod rbf0;
pub mod rds5;
pub mod resource;
pub mod rpf;
pub mod skeleton;

/// How much of a recovered file or resource is known to be accounted for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// For plain files, a known signature and a final short chunk. For
    /// resources, see [`resource::Layout::status`].
    Complete,
    /// Identified, but its end or some of its pages were not found.
    Partial,
    /// What was found cannot be established as a whole file or resource.
    Unverified,
}

impl Status {
    pub fn name(self) -> &'static str {
        match self {
            Status::Complete => "complete",
            Status::Partial => "partial",
            Status::Unverified => "unverified",
        }
    }
}
