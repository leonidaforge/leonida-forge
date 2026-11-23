//! GTA VI RAGE formats: RPF9 archives and the resources stored in them.

pub mod resource;
pub mod rpf;

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
