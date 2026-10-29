//! Loader stage: usbplug (330d, or 330e+USB-MSC) — the rockusb protocol
//! over bulk CBW/CSW. Port of rock.c from xrock (CBW fields bit-for-bit).
//!
//! CBW (31 bytes): 'USBC' BE, tag BE, dCBWDataTransferLength LE,
//! flag 0x80=IN/0x00=OUT, lun=0, cmdlen 6|10,
//! command {opcode, subcode, address BE32, reserved, size BE16, reserved}.
//! CSW (13 bytes): 'USBS' BE, tag, residue LE, status (0 = ok).
//!
//! Compatibility note: READ_SDRAM/WRITE_SDRAM are sent with length=0
//! (usbplug ignores the field and goes by size); READ_LBA/WRITE_LBA with
//! length = sectors*512. Reproduced literally from rock.c.

use crate::error::{Error, Result};
use crate::transport::Transport;

pub mod opcode {
    pub const TEST_UNIT_READY: u8 = 0x00;
    pub const READ_FLASH_ID: u8 = 0x01;
    pub const READ_LBA: u8 = 0x14;
    pub const WRITE_LBA: u8 = 0x15;
    pub const ERASE_SYSDISK: u8 = 0x16;
    pub const READ_SDRAM: u8 = 0x17;
    pub const WRITE_SDRAM: u8 = 0x18;
    pub const EXEC_SDRAM: u8 = 0x19;
    pub const READ_FLASH_INFO: u8 = 0x1a;
    pub const READ_CHIP_INFO: u8 = 0x1b;
    pub const ERASE_LBA: u8 = 0x25;
    pub const READ_CAPABILITY: u8 = 0xaa;
    pub const RESET_DEVICE: u8 = 0xff;
}

/// RESET_DEVICE subcode: 0x03 — MaskROM, 0x00 — normal reboot.
pub const RESET_SUBCODE_MASKROM: u8 = 0x03;
pub const RESET_SUBCODE_NORMAL: u8 = 0x00;

const CBW_LEN: usize = 31;
const CSW_LEN: usize = 13;
/// Max sectors per flash R/W command (rock.c).
pub const LBA_CHUNK: u32 = 16384;
/// Max bytes per RAM R/W command (rock.c).
pub const MEM_CHUNK: usize = 16384;

/// Flash details (rock_flash_detect: READ_FLASH_INFO + READ_FLASH_ID).
#[derive(Debug, Clone)]
pub struct FlashInfo {
    pub sector_total: u32,
    pub block_size: u16,
    pub page_size: u8,
    pub ecc_bits: u8,
    pub access_time: u8,
    pub manufacturer_id: u8,
    pub chip_select: u8,
    pub id: [u8; 5],
}

/// A raw rockusb command; the fields mirror rock.c (length and
/// direction are explicit: usbplug is picky about them).
struct RawCommand {
    opcode: u8,
    subcode: u8,
    address: u32,
    size: u16,
    cmdlen: u8,
    /// dCBWDataTransferLength.
    length: u32,
    flag_in: bool,
}

pub struct LoaderSession<T: Transport> {
    transport: T,
    ep_in: u8,
    ep_out: u8,
    tag: u32,
}

impl<T: Transport> LoaderSession<T> {
    pub fn new(transport: T, ep_in: u8, ep_out: u8) -> Self {
        LoaderSession {
            transport,
            ep_in,
            ep_out,
            tag: 0x5a5a_0000,
        }
    }

    fn next_tag(&mut self) -> [u8; 4] {
        self.tag = self.tag.wrapping_add(1);
        self.tag.to_be_bytes()
    }

    /// Send the CBW, run the data phase (read into buf / write payload),
    /// verify the CSW (signature, tag, status).
    fn exec(
        &mut self,
        cmd: &RawCommand,
        payload_out: Option<&[u8]>,
        buf_in: Option<&mut [u8]>,
    ) -> Result<()> {
        let tag = self.next_tag();
        let mut cbw = [0u8; CBW_LEN];
        cbw[0..4].copy_from_slice(b"USBC");
        cbw[4..8].copy_from_slice(&tag);
        cbw[8..12].copy_from_slice(&cmd.length.to_le_bytes());
        cbw[12] = if cmd.flag_in { 0x80 } else { 0x00 };
        cbw[14] = cmd.cmdlen;
        cbw[15] = cmd.opcode;
        cbw[16] = cmd.subcode;
        cbw[17..21].copy_from_slice(&cmd.address.to_be_bytes());
        // usb_command_t: address(2..6), reserved6(6), size(7..9) -> CBW 22..24
        cbw[22..24].copy_from_slice(&cmd.size.to_be_bytes());

        self.transport.bulk_write(self.ep_out, &cbw)?;
        if let Some(data) = payload_out {
            self.transport.bulk_write(self.ep_out, data)?;
        }
        if let Some(buf) = buf_in {
            self.transport.bulk_read(self.ep_in, buf)?;
        }
        self.read_csw(&tag)
    }

    fn read_csw(&mut self, tag: &[u8; 4]) -> Result<()> {
        let mut csw = [0u8; CSW_LEN];
        self.transport.bulk_read(self.ep_in, &mut csw)?;
        if &csw[0..4] != b"USBS" || csw[4..8] != *tag {
            return Err(Error::BadResponse);
        }
        if csw[8..12] != [0, 0, 0, 0] {
            log::debug!("rockusb: residue != 0: {:?}", &csw[8..12]);
        }
        if csw[12] != 0 {
            return Err(Error::CommandFailed(csw[12]));
        }
        Ok(())
    }

    /// TEST_UNIT_READY: is the rockusb protocol alive.
    pub fn ready(&mut self) -> Result<()> {
        self.exec(
            &RawCommand {
                opcode: opcode::TEST_UNIT_READY,
                subcode: 0,
                address: 0,
                size: 0,
                cmdlen: 6,
                length: 0,
                flag_in: true,
            },
            None,
            None,
        )
    }

    /// READ_CHIP_INFO (16 bytes) — loader version.
    pub fn chip_info(&mut self) -> Result<[u8; 16]> {
        let mut buf = [0u8; 16];
        self.exec(
            &RawCommand {
                opcode: opcode::READ_CHIP_INFO,
                subcode: 0,
                address: 0,
                size: 0,
                cmdlen: 6,
                length: 16,
                flag_in: true,
            },
            None,
            Some(&mut buf),
        )?;
        Ok(buf)
    }

    /// READ_CAPABILITY (8 bytes).
    pub fn capability(&mut self) -> Result<[u8; 8]> {
        let mut buf = [0u8; 8];
        self.exec(
            &RawCommand {
                opcode: opcode::READ_CAPABILITY,
                subcode: 0,
                address: 0,
                size: 0,
                cmdlen: 6,
                length: 8,
                flag_in: true,
            },
            None,
            Some(&mut buf),
        )?;
        Ok(buf)
    }

    /// READ_FLASH_INFO (11 bytes) + READ_FLASH_ID (5 bytes).
    pub fn flash_detect(&mut self) -> Result<FlashInfo> {
        let mut buf = [0u8; 11];
        self.exec(
            &RawCommand {
                opcode: opcode::READ_FLASH_INFO,
                subcode: 0,
                address: 0,
                size: 0,
                cmdlen: 6,
                length: 11,
                flag_in: true,
            },
            None,
            Some(&mut buf),
        )?;
        let mut id = [0u8; 5];
        self.exec(
            &RawCommand {
                opcode: opcode::READ_FLASH_ID,
                subcode: 0,
                address: 0,
                size: 0,
                cmdlen: 6,
                length: 5,
                flag_in: true,
            },
            None,
            Some(&mut id),
        )?;
        Ok(FlashInfo {
            sector_total: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
            block_size: u16::from_le_bytes([buf[4], buf[5]]),
            page_size: buf[6],
            ecc_bits: buf[7],
            access_time: buf[8],
            manufacturer_id: buf[9],
            chip_select: buf[10],
            id,
        })
    }

    /// RESET_DEVICE. subcode 0x00 — normal boot, 0x03 — MaskROM.
    /// The device re-enumerates afterwards; a communication error on the
    /// final phase is normal — not suppressed, but the caller may ignore.
    pub fn reset(&mut self, subcode: u8) -> Result<()> {
        self.exec(
            &RawCommand {
                opcode: opcode::RESET_DEVICE,
                subcode,
                address: 0,
                size: 0,
                cmdlen: 6,
                length: 0,
                flag_in: false,
            },
            None,
            None,
        )
    }

    /// Read RAM (READ_SDRAM): `xrock dump` / `xrock read`. length=0
    /// (as in rock.c), MEM_CHUNK-sized chunks.
    pub fn read_mem(&mut self, addr: u32, buf: &mut [u8]) -> Result<()> {
        let mut off = 0usize;
        while off < buf.len() {
            let n = (buf.len() - off).min(MEM_CHUNK);
            self.exec(
                &RawCommand {
                    opcode: opcode::READ_SDRAM,
                    subcode: 0,
                    address: addr + off as u32,
                    size: n as u16,
                    cmdlen: 10,
                    length: 0,
                    flag_in: true,
                },
                None,
                Some(&mut buf[off..off + n]),
            )?;
            off += n;
        }
        Ok(())
    }

    /// Write RAM (WRITE_SDRAM): `xrock write`. **Writes into device RAM** —
    /// used for the usbplug read-limit patch during backup.
    pub fn write_mem(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        let mut off = 0usize;
        while off < data.len() {
            let n = (data.len() - off).min(MEM_CHUNK);
            self.exec(
                &RawCommand {
                    opcode: opcode::WRITE_SDRAM,
                    subcode: 0,
                    address: addr + off as u32,
                    size: n as u16,
                    cmdlen: 10,
                    length: 0,
                    flag_in: false,
                },
                Some(&data[off..off + n]),
                None,
            )?;
            off += n;
        }
        Ok(())
    }

    /// Erase an LBA range (ERASE_LBA), chunked. **Destructive.**
    pub fn erase_lba(&mut self, sector: u32, count: u32) -> Result<()> {
        let mut sec = sector;
        let mut cnt = count;
        while cnt > 0 {
            let n = cnt.min(LBA_CHUNK);
            self.exec(
                &RawCommand {
                    opcode: opcode::ERASE_LBA,
                    subcode: 0,
                    address: sec,
                    size: n as u16,
                    cmdlen: 10,
                    length: 0,
                    flag_in: false,
                },
                None,
                None,
            )?;
            sec += n;
            cnt -= n;
        }
        Ok(())
    }

    /// Read flash by LBA (READ_LBA): `xrock flash read`; buf.len() must
    /// be a multiple of 512, chunks of LBA_CHUNK sectors, length = n*512.
    pub fn read_lba(&mut self, sector: u32, buf: &mut [u8]) -> Result<()> {
        if !buf.len().is_multiple_of(512) {
            return Err(Error::Loader(
                "read_lba: size must be a multiple of 512".into(),
            ));
        }
        let total = (buf.len() / 512) as u32;
        let mut done = 0u32;
        while done < total {
            let n = (total - done).min(LBA_CHUNK);
            let off = done as usize * 512;
            self.exec(
                &RawCommand {
                    opcode: opcode::READ_LBA,
                    subcode: 0,
                    address: sector + done,
                    size: n as u16,
                    cmdlen: 10,
                    length: n * 512,
                    flag_in: true,
                },
                None,
                Some(&mut buf[off..off + n as usize * 512]),
            )?;
            done += n;
        }
        Ok(())
    }

    /// Write flash by LBA (WRITE_LBA): `xrock flash write`. **Destructive
    /// to the flash** — only call from explicit write pipelines.
    pub fn write_lba(&mut self, sector: u32, data: &[u8]) -> Result<()> {
        if !data.len().is_multiple_of(512) {
            return Err(Error::Loader(
                "write_lba: size must be a multiple of 512".into(),
            ));
        }
        let total = (data.len() / 512) as u32;
        let mut done = 0u32;
        while done < total {
            let n = (total - done).min(LBA_CHUNK);
            let off = done as usize * 512;
            self.exec(
                &RawCommand {
                    opcode: opcode::WRITE_LBA,
                    subcode: 0,
                    address: sector + done,
                    size: n as u16,
                    cmdlen: 10,
                    length: n * 512,
                    flag_in: false,
                },
                Some(&data[off..off + n as usize * 512]),
                None,
            )?;
            done += n;
        }
        Ok(())
    }
}
