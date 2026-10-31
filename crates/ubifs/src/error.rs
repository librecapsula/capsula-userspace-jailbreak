//! Crate error types.

use core::fmt;

/// A UBIFS parse/build error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// A node is absent (an empty LEB, an out-of-bounds offset, etc.).
    MissingData(String),
    /// Bad magic or node type.
    BadNode(String),
    /// A checksum mismatch.
    BadCrc(String),
    /// Geometry or parameters are invalid or incompatible.
    BadGeometry(String),
    /// A key or entry was not found.
    NotFound(String),
    /// The operation does not apply to an object of this type.
    NotADirectory(String),
    /// Input data does not fit or contradicts format limits.
    Overflow(String),
    /// The requested feature is not supported (e.g. encrypted images).
    Unsupported(String),
    /// Anything else, with a message.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::MissingData(m) => write!(f, "missing data: {m}"),
            Error::BadNode(m) => write!(f, "bad node: {m}"),
            Error::BadCrc(m) => write!(f, "bad crc: {m}"),
            Error::BadGeometry(m) => write!(f, "bad geometry: {m}"),
            Error::NotFound(m) => write!(f, "not found: {m}"),
            Error::NotADirectory(m) => write!(f, "not a directory: {m}"),
            Error::Overflow(m) => write!(f, "overflow: {m}"),
            Error::Unsupported(m) => write!(f, "unsupported: {m}"),
            Error::Other(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Crate result type.
pub type Result<T> = core::result::Result<T, Error>;

pub(crate) fn other<T>(msg: impl Into<String>) -> Result<T> {
    Err(Error::Other(msg.into()))
}
