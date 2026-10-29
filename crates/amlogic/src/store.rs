//! Partition write path: the `download store` media stream (spec §16.2).

use crate::error::{Error, Result};
use crate::transport::Transport;
use crate::{AmlogicSession, MEDIA_CHUNK};
use std::io::Read;

impl<T: Transport> AmlogicSession<T> {
    /// Write a partition image through the burning-command media
    /// stream — the mirror of [`AmlogicSession::upload_store_to`]:
    ///
    /// 1. `download store <part> normal <total>` arms the transfer (the
    ///    command's own status only arrives when the whole image has
    ///    been received and written, so the arm is sent without waiting
    ///    — see `upload mem` in [`AmlogicSession::upload_read`] for the
    ///    read-side counterpart of this rule);
    /// 2. the image streams as [`MEDIA_CHUNK`] media packets
    ///    (AM_REQ_WRITE_MEDIA + bulk-OUT + `OK!!` per block, three
    ///    attempts per block, `Continue:32` honored);
    /// 3. the final `success` of the arm command confirms the store
    ///    write.
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
        self.send_bulk_cmd(&format!("download store {part} normal {total:#x}"))?;
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
        let status = self.wait_bulk_status()?;
        log::debug!("amlogic: download store {part} {total:#x}: {status}");
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

    fn media_head(attempt: u32, len: usize, seq: u32, sum: u32) -> Vec<u8> {
        let mut head = vec![0u8; 0x20];
        head[0..4].copy_from_slice(&attempt.to_le_bytes());
        head[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        head[8..12].copy_from_slice(&(seq << 4).to_le_bytes());
        head[12..16].copy_from_slice(&sum.to_le_bytes());
        head[16..20].copy_from_slice(&0x0100_00efu32.to_le_bytes());
        head
    }

    /// data < MEDIA_CHUNK with a short tail packet + final status.
    #[test]
    fn write_store_streams_media_packets_with_short_tail() {
        let payload: Vec<u8> = (0..MEDIA_CHUNK + 100).map(|i| (i % 253) as u8).collect();
        let steps = vec![
            Step::ControlOut(
                req::BULKCMD,
                0,
                2,
                command(&format!("download store data normal {:#x}", payload.len())),
            ),
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
            // the arm command completes after the image was written
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
        let mut steps = vec![Step::ControlOut(
            req::BULKCMD,
            0,
            2,
            command(&format!("download store data normal {:#x}", MEDIA_CHUNK)),
        )];
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

    /// A short image source is an error, not a silent partial write.
    #[test]
    fn write_store_rejects_short_image_source() {
        let payload = vec![7u8; MEDIA_CHUNK];
        let steps = vec![
            Step::ControlOut(
                req::BULKCMD,
                0,
                2,
                command(&format!(
                    "download store data normal {:#x}",
                    MEDIA_CHUNK * 2
                )),
            ),
            Step::ControlOut(
                req::WRITE_MEDIA,
                1,
                0xffff,
                media_head(0, MEDIA_CHUNK, 0, crate::add_sum(&payload)),
            ),
            Step::BulkOut(payload.clone()),
            Step::BulkIn(b"OK!!\0".to_vec()),
        ];
        let mut s = AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02);
        let mut src = std::io::Cursor::new(payload);
        let err = s
            .write_store("data", MEDIA_CHUNK * 2, &mut src, &|_| {})
            .unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err}");
        assert!(err.to_string().contains("ended after"));
        assert_eq!(s.transport().pos, s.transport().steps.len());
    }
}
