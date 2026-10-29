//! MaskROM stage (BootROM, 2207:330e without iProduct): the DownloadBoot
//! protocol. Port of rock_maskrom_upload_memory / download from xrock.

use crate::error::Result;
use crate::loader_container::LoaderContainer;
use crate::transport::Transport;
use crate::util::{crc16_xrock, Rc4};

const CHUNK: usize = 4096;

/// Stage codes (wIndex of the control request).
pub const CODE_471: u16 = 0x0471; // DDR init / TPL
pub const CODE_472: u16 = 0x0472; // usbplug

pub struct MaskRomSession<T: Transport> {
    transport: T,
}

impl<T: Transport> MaskRomSession<T> {
    pub fn new(transport: T) -> Self {
        MaskRomSession { transport }
    }

    /// Upload a buffer for a stage code (0x471/0x472). Port of
    /// rock_maskrom_upload_memory: optional RC4, the len%4096 == 4095/4094
    /// edge cases, CRC16-CCITT appended big-endian, sent in 4096-byte
    /// chunks by control transfers.
    pub fn upload_memory(&mut self, code: u16, buf: &[u8], rc4: bool) -> Result<()> {
        let mut len = buf.len();
        let mut buffer = vec![0u8; len + 5];
        buffer[..len].copy_from_slice(buf);
        if rc4 {
            Rc4::new(&Rc4::ROCKCHIP_KEY).apply(&mut buffer[..len]);
        }
        let mut pend = false;
        match len % CHUNK {
            4095 => len += 1,    // append one zero byte (the buffer is zeroed)
            4094 => pend = true, // after the payload: a separate 1-byte packet
            _ => {}
        }
        let crc = crc16_xrock(0xffff, &buffer[..len]);
        buffer[len] = (crc >> 8) as u8;
        buffer[len + 1] = (crc & 0xff) as u8;
        len += 2;

        let mut total = 0usize;
        while total < len {
            let n = (len - total).min(CHUNK);
            self.transport
                .control_out(0x0c, 0, code, &buffer[total..total + n])?;
            total += n;
        }
        if pend {
            self.transport.control_out(0x0c, 0, code, &[0u8; 1])?;
        }
        Ok(())
    }

    /// `xrock download <loader>`: parse the BOOT container and upload its
    /// 471/472 stages in order, with the per-entry delays. RC4 follows
    /// the container flag (rc4_flag == 0 -> enabled, as in xrock).
    ///
    /// The flash is NOT touched: everything goes to RAM. After usbplug
    /// starts, the device re-enumerates (330e + iProduct "USB-MSC").
    pub fn download(&mut self, container: &LoaderContainer) -> Result<()> {
        for (code, name, data, delay_ms) in container.download_stages() {
            log::info!(
                "DownloadBoot: stage {code:#06x} ({name}, {} bytes)",
                data.len()
            );
            self.upload_memory(code, data, container.is_rc4on)?;
            if delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(delay_ms as u64));
            }
        }
        Ok(())
    }
}
