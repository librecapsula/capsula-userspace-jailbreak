//! amlogic error types: the protocol and its USB transport.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Device not found / has disappeared (e.g. the u-boot download
    /// window closed before identify).
    #[error("amlogic device not found")]
    DeviceNotFound,
    #[error("multiple Amlogic devices; connect only one device")]
    MultipleDevices,
    /// USB transport error.
    #[error("usb: {0}")]
    Usb(String),
    /// Bytes in the caller buffer are valid even though this completion
    /// failed (a partial bulk read: keep the prefix, propagate the error).
    #[error("bulk read failed after {transferred} bytes: {reason}")]
    PartialRead { transferred: usize, reason: String },
    #[error("invalid protocol response: {0}")]
    InvalidResponse(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("command status did not finish within 60 seconds")]
    CommandTimeout,
    /// The device reports `PWD_REQ=1` and has not accepted a password.
    #[error("device requires a password before burning commands (PWD_REQ=1)")]
    PasswordRequired,
    /// A bulk command (AM_REQ_BULKCMD / TPL command) was answered with an
    /// error text instead of `success`.
    #[error("device rejected the command: {0}")]
    CommandFailed(String),
    /// A media transfer (download/upload) was rejected: the reply was
    /// neither `OK!!` nor `Continue:`.
    #[error("media transfer failed: {0}")]
    MediaFailed(String),
    /// A command string is too long for the 64-byte EP0 buffer.
    #[error("command too long (max 63 chars): {0}")]
    CommandTooLong(String),
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
