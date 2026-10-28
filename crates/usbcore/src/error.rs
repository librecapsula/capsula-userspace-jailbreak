//! USB transport error types (shared by the vendor protocol crates).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Device not found / has disappeared.
    #[error("usb device not found")]
    DeviceNotFound,
    #[error("multiple matching USB devices; connect only one device")]
    MultipleDevices,
    /// USB transport error.
    #[error("usb: {0}")]
    Usb(String),
    /// Bytes in the caller buffer are valid even though this completion failed.
    #[error("bulk read failed after {transferred} bytes: {reason}")]
    PartialRead { transferred: usize, reason: String },
    /// I/O error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

impl From<nusb::Error> for Error {
    fn from(e: nusb::Error) -> Self {
        Error::Usb(e.to_string())
    }
}

impl From<nusb::transfer::TransferError> for Error {
    fn from(e: nusb::transfer::TransferError) -> Self {
        Error::Usb(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
