//! Вшитый лоадер: подписанный BOOT-контейнер (DDR init 0x471 + usbplug
//! 0x472), извлечённый из OTA Capsule-14 44.90. Один лоадер на все
//! поддерживаемые платы — во всех актуальных прошивках rk3308 это одна
//! и та же сборка.
//!
//! Лоадер зашит в бинарник; сеть инструменту не нужна.

use rockusb::{Error as UsbError, LoaderContainer};
use std::sync::OnceLock;

/// The signed loader, byte-exact from the Capsule-14 OTA 44.90.
const LOADER_BIN: &[u8] = include_bytes!("../../../resources/loader/loader.bin");

static LOADER: OnceLock<Result<LoaderContainer, String>> = OnceLock::new();

/// The embedded loader, parsed and CRC32-verified once per process.
pub fn embedded() -> Result<LoaderContainer, UsbError> {
    LOADER
        .get_or_init(|| LoaderContainer::parse(LOADER_BIN.to_vec()).map_err(|e| e.to_string()))
        .clone()
        .map_err(UsbError::Loader)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded loader must be the signed RK3308 usbplug the
    /// MaskROM download expects.
    #[test]
    fn embedded_loader_parses() {
        let c = embedded().expect("вшитый лоадер должен разбираться");
        assert!(c.is_signed, "лоадер подписан");
        assert!(!c.is_newidb, "форм-фактор BOOT, не LDR");
        // rc4_flag != 0 means RC4 is disabled for the download
        assert!(!c.is_rc4on, "rc4_flag=1 -> RC4 отключён");
        assert_eq!(c.chiptype.to_le_bytes(), *b"8033", "чип rk3308");
        // MaskROM download stages: DDR init (0x471) and usbplug (0x472)
        let stages = c.download_stages();
        assert!(stages.len() >= 2, "нужны стадии 471+472");
        assert_eq!(stages.first().unwrap().0, 0x471);
        assert_eq!(stages.last().unwrap().0, 0x472);
        let total: usize = stages.iter().map(|(_, _, d, _)| d.len()).sum();
        assert!(total > 0 && total < c.data.len());
    }
}
