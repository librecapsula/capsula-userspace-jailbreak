//! Partition write path: the vendor `mwrite` flow (update.c
//! `do_cmd_mwrtie`, tools/update-macos) over the burning gadget.

use crate::error::{Error, Result};
use crate::nand::{NAND_SIZE, PAGE_SIZE};
use crate::transport::Transport;
use crate::{AmlogicSession, MEDIA_CHUNK};
use std::io::Read;

/// Размер куска флэшер-записи (flasher.sh MWRITE_CHUNK=8 МиБ уменьшен
/// до бюджета окна: стена ~250–350 мс убивает сессию на кусках
/// крупнее 1 МиБ — то же измерение, что задало READ_STAGE).
pub const NAND_WRITE_CHUNK: usize = 0x10_0000;

impl<T: Transport> AmlogicSession<T> {
    /// Один кусок флэшер-записи (flasher.sh `write_big_to_flash`):
    /// отправить `len` байт из `data` в ОЗУ по адресу `ram` — постановка
    /// `download mem` через TPL-канал (статус сразу), media-пакеты,
    /// `download get_status` — и затем `nand write` куска во флеш по
    /// логическому смещению `off`.
    ///
    /// Кусок атомарен настолько, насколько это даёт устройство: если
    /// сессия умирает в media-потоке или на `nand write`, состояние
    /// куска во флеше неопределено — вызывающий повторяет ТОТ ЖЕ кусок
    /// после стирания остатка диапазона (перепрограммирование частично
    /// запрограммированной страницы портит её, поэтому повтор всегда
    /// идёт после `nand erase`, см. jb-core `write_data_pass`).
    pub fn write_nand_chunk<R: Read>(
        &mut self,
        ram: u32,
        off: u32,
        len: usize,
        data: &mut R,
    ) -> Result<()> {
        if len == 0
            || !len.is_multiple_of(PAGE_SIZE as usize)
            || len > NAND_WRITE_CHUNK
            || ram as u64 + len as u64 > 0x0190_0000
            || !off.is_multiple_of(PAGE_SIZE)
            || off as u64 + len as u64 > NAND_SIZE as u64
        {
            return Err(Error::InvalidArgument(format!(
                "write chunk out of geometry: ram {ram:#x} off {off:#x} len {len:#x}"
            )));
        }
        let status = self.tpl_cmd(&format!("download mem {ram:#x} normal {len:#x}"))?;
        log::debug!("amlogic: download mem armed: {status}");
        let mut buf = vec![0u8; MEDIA_CHUNK];
        let mut sent = 0usize;
        let mut seq = 0u32;
        while sent < len {
            let want = (len - sent).min(MEDIA_CHUNK);
            let chunk = &mut buf[..want];
            data.read_exact(chunk).map_err(|e| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("image source ended after {sent:#x} of {len:#x} bytes: {e}"),
                ))
            })?;
            self.write_media(chunk, seq)?;
            sent += want;
            seq += 1;
        }
        // устройство дописало кусок в ОЗУ
        let status = self.bulk_cmd("download get_status")?;
        log::debug!("amlogic: download mem get_status: {status}");
        // запись куска во флеш по логическому смещению (u-boot сам
        // обходит бед-блоки)
        self.bulk_cmd(&format!("echo; nand write {ram:#x} {off:#x} {len:#x}"))?;
        Ok(())
    }
}

impl<T: Transport> AmlogicSession<T> {
    /// Write a partition image exactly the way the vendor tool does:
    ///
    /// 1. `download store <part> normal <total>` is armed on the **TPL
    ///    channel** (AM_REQ_TPL_CMD with wIndex=1, then AM_REQ_TPL_STAT):
    ///    the gadget accepts the arm immediately and answers `success`
    ///    BEFORE any media moves. A bulkcmd arm cannot be used here —
    ///    its status only arrives once the whole image has been written,
    ///    so the transfer could not be monitored (and the vendor tool
    ///    does not do it either);
    /// 2. the image streams as [`MEDIA_CHUNK`] media packets
    ///    (AM_REQ_WRITE_MEDIA + bulk-OUT + `OK!!` per block, three
    ///    attempts per block, `Continue:32` honored, 12-minute ack
    ///    budget per attempt);
    /// 3. the closing `download get_status` burning command (bulkcmd)
    ///    completes when the device has flushed the staged image to
    ///    NAND; its final status is the write verdict.
    ///
    /// `total` is the exact image size; the last packet may be short
    /// (the device counts received bytes against the armed total, and
    /// the spec caps the block size, not the tail).
    pub fn write_store<R: Read>(
        &mut self,
        part: &str,
        total: usize,
        data: &mut R,
        progress: &dyn Fn(usize),
    ) -> Result<()> {
        let (_, _, physical) = crate::partition(part)
            .ok_or_else(|| Error::InvalidArgument(format!("unknown partition {part:?}")))?;
        if total == 0 || total > physical as usize {
            return Err(Error::InvalidArgument(format!(
                "partition {part}: write size {total:#x} outside 1..={physical:#x}"
            )));
        }
        let status = self.tpl_cmd(&format!("download store {part} normal {total:#x}"))?;
        log::debug!("amlogic: download store {part} armed: {status}");
        let mut buf = vec![0u8; MEDIA_CHUNK];
        let mut sent = 0usize;
        let mut seq = 0u32;
        while sent < total {
            let want = (total - sent).min(MEDIA_CHUNK);
            let chunk = &mut buf[..want];
            data.read_exact(chunk).map_err(|e| {
                Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    format!("image source ended after {sent:#x} of {total:#x} bytes: {e}"),
                ))
            })?;
            self.write_media(chunk, seq)?;
            sent += want;
            seq += 1;
            progress(sent);
        }
        let status = self.bulk_cmd("download get_status")?;
        log::debug!("amlogic: download store {part}: get_status {status}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{req, MockTransport, Step};

    fn command(text: &str) -> Vec<u8> {
        let mut payload = vec![0; 64];
        payload[..text.len()].copy_from_slice(text.as_bytes());
        payload
    }

    /// Vendor media head: attempt, length, add_sum at 0x08, chunk index
    /// at 0x0c, algorithm 0xef + announced ack length at 0x10.
    fn media_head(attempt: u32, len: usize, seq: u32, sum: u32) -> Vec<u8> {
        let mut head = vec![0u8; 0x20];
        head[0..4].copy_from_slice(&attempt.to_le_bytes());
        head[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        head[8..12].copy_from_slice(&sum.to_le_bytes());
        head[12..16].copy_from_slice(&seq.to_le_bytes());
        head[16..18].copy_from_slice(&0x00efu16.to_le_bytes());
        head[18..20].copy_from_slice(&0x0100u16.to_le_bytes());
        head
    }

    fn ok_reply() -> Vec<u8> {
        let mut r = vec![0u8; 64];
        r[..7].copy_from_slice(b"success");
        r
    }

    /// data < MEDIA_CHUNK with a short tail packet + final get_status.
    #[test]
    fn write_store_streams_media_packets_with_short_tail() {
        let payload: Vec<u8> = (0..MEDIA_CHUNK + 100).map(|i| (i % 253) as u8).collect();
        let steps = vec![
            // the vendor arm: TPL channel, wIndex=1, immediate "success"
            Step::ControlOut(
                req::TPL_CMD,
                0,
                1,
                command(&format!("download store data normal {:#x}", payload.len())),
            ),
            Step::ControlIn(req::TPL_STAT, 0, 0, ok_reply()),
            // seq 0: full 64 KiB block
            Step::ControlOut(
                req::WRITE_MEDIA,
                1,
                0xffff,
                media_head(0, MEDIA_CHUNK, 0, crate::add_sum(&payload[..MEDIA_CHUNK])),
            ),
            Step::BulkOut(payload[..MEDIA_CHUNK].to_vec()),
            Step::BulkIn(b"OK!!\0".to_vec()),
            // seq 1: short tail of 100 bytes
            Step::ControlOut(
                req::WRITE_MEDIA,
                1,
                0xffff,
                media_head(0, 100, 1, crate::add_sum(&payload[MEDIA_CHUNK..])),
            ),
            Step::BulkOut(payload[MEDIA_CHUNK..].to_vec()),
            Step::BulkIn(b"OK!!\0".to_vec()),
            // the vendor closing command flushes the image to NAND
            Step::ControlOut(req::BULKCMD, 0, 2, command("download get_status")),
            Step::BulkIn(b"success\0".to_vec()),
        ];
        let mut s = AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02);
        let mut src = std::io::Cursor::new(payload.clone());
        let seen = std::cell::RefCell::new(0usize);
        s.write_store("data", payload.len(), &mut src, &|n| *seen.borrow_mut() = n)
            .unwrap();
        assert_eq!(*seen.borrow(), payload.len());
        assert_eq!(s.transport().pos, s.transport().steps.len());
    }

    /// A rejected block is retried up to three attempts, then fails.
    #[test]
    fn write_store_fails_after_three_rejected_blocks() {
        let payload = vec![0x5a; MEDIA_CHUNK];
        let mut steps = vec![
            Step::ControlOut(
                req::TPL_CMD,
                0,
                1,
                command(&format!("download store data normal {:#x}", MEDIA_CHUNK)),
            ),
            Step::ControlIn(req::TPL_STAT, 0, 0, ok_reply()),
        ];
        for attempt in 0..3 {
            steps.push(Step::ControlOut(
                req::WRITE_MEDIA,
                1,
                0xffff,
                media_head(attempt, MEDIA_CHUNK, 0, crate::add_sum(&payload)),
            ));
            steps.push(Step::BulkOut(payload.clone()));
            steps.push(Step::BulkIn(b"failed: bad block\0".to_vec()));
        }
        let mut s = AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02);
        let mut src = std::io::Cursor::new(payload);
        let err = s
            .write_store("data", MEDIA_CHUNK, &mut src, &|_| {})
            .unwrap_err();
        assert!(matches!(err, Error::MediaFailed(_)), "{err}");
        assert_eq!(s.transport().pos, s.transport().steps.len());
    }

    /// Size checks happen before anything touches USB.
    #[test]
    fn write_store_validates_part_and_size() {
        let mut s = AmlogicSession::new(MockTransport::new(vec![]), 0x81, 0x02);
        let mut src = std::io::Cursor::new(vec![0u8; 16]);
        assert!(matches!(
            s.write_store("nope", 16, &mut src, &|_| {}),
            Err(Error::InvalidArgument(_))
        ));
        // the physical map of "data" is 0x4e0_0000
        assert!(matches!(
            s.write_store("data", 0x4e0_0001, &mut src, &|_| {}),
            Err(Error::InvalidArgument(_))
        ));
        assert!(matches!(
            s.write_store("data", 0, &mut src, &|_| {}),
            Err(Error::InvalidArgument(_))
        ));
        assert_eq!(s.transport().pos, 0);
    }

    /// One flasher-style chunk: TPL arm + media + get_status + nand write.
    #[test]
    fn write_nand_chunk_flows_like_the_vendor_mwrite() {
        let chunk_len = 0x2_0000;
        let payload: Vec<u8> = (0..chunk_len).map(|i| (i % 249) as u8).collect();
        let mut steps = vec![
            Step::ControlOut(
                req::TPL_CMD,
                0,
                1,
                command(&format!("download mem 0x1080000 normal {chunk_len:#x}")),
            ),
            Step::ControlIn(req::TPL_STAT, 0, 0, ok_reply()),
        ];
        // one 64 KiB media packet per chunk_len/0x10000
        for seq in 0..(chunk_len / crate::MEDIA_CHUNK) {
            let part = &payload[seq * crate::MEDIA_CHUNK..(seq + 1) * crate::MEDIA_CHUNK];
            steps.push(Step::ControlOut(
                req::WRITE_MEDIA,
                1,
                0xffff,
                media_head(0, crate::MEDIA_CHUNK, seq as u32, crate::add_sum(part)),
            ));
            steps.push(Step::BulkOut(part.to_vec()));
            steps.push(Step::BulkIn(b"OK!!\0".to_vec()));
        }
        steps.push(Step::ControlOut(
            req::BULKCMD,
            0,
            2,
            command("download get_status"),
        ));
        steps.push(Step::BulkIn(b"success\0".to_vec()));
        steps.push(Step::ControlOut(
            req::BULKCMD,
            0,
            2,
            command("echo; nand write 0x1080000 0xb200000 0x20000"),
        ));
        steps.push(Step::BulkIn(b"success\0".to_vec()));
        let mut s = AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02);
        let mut src = std::io::Cursor::new(payload);
        s.write_nand_chunk(0x0108_0000, 0x0b20_0000, chunk_len, &mut src)
            .unwrap();
        assert_eq!(s.transport().pos, s.transport().steps.len());
    }

    /// Geometry checks happen before anything touches USB.
    #[test]
    fn write_nand_chunk_validates_geometry() {
        let mut s = AmlogicSession::new(MockTransport::new(vec![]), 0x81, 0x02);
        let mut src = std::io::Cursor::new(vec![0u8; 16]);
        // not page-aligned
        assert!(matches!(
            s.write_nand_chunk(0x108_0000, 0x0b20_0001, 16, &mut src),
            Err(Error::InvalidArgument(_))
        ));
        // over the chunk cap
        assert!(matches!(
            s.write_nand_chunk(0x108_0000, 0x0b20_0000, NAND_WRITE_CHUNK + 2048, &mut src),
            Err(Error::InvalidArgument(_))
        ));
        assert_eq!(s.transport().pos, 0);
    }
}
