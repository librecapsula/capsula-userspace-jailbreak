//! rockusb error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    /// Device not found / has disappeared.
    #[error("rockchip device not found")]
    DeviceNotFound,
    /// USB transport error.
    #[error("usb: {0}")]
    Usb(String),
    /// Device returned an invalid CSW (signature or tag mismatch).
    #[error("invalid device response (CSW)")]
    BadResponse,
    /// Command completed with an error status in the CSW.
    #[error("device rejected the command (status={0:#x})")]
    CommandFailed(u8),
    /// The loader file is not a valid BOOT/LDR container.
    #[error("loader: {0}")]
    Loader(String),
    /// The device is in the wrong mode for this operation.
    #[error("wrong device mode: {0}")]
    WrongMode(String),
    /// A bulk transfer got no answer within the timeout — the device
    /// stopped responding (a wedged loader). Carries the details needed
    /// to analyze the hang: what was being transferred, on which
    /// endpoint, and for how long there was no answer.
    #[error("{what}: нет ответа от устройства за {waited:?} (ep {endpoint:#x}, {len} байт) — похоже, завис лоадер")]
    Timeout {
        what: String,
        endpoint: u8,
        len: usize,
        waited: std::time::Duration,
    },
    /// I/O error (loader files etc.).
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
