//! The Amlogic update (USB burning) protocol client.
//!
//! The same vendor-request protocol serves both download stages that
//! enumerate as `1b8e:c003`: the BootROM (IPL) and the u-boot USB-burning
//! gadget ("optimus", AM_REQ_* in `drivers/usb/gadget/v2_burning/`).
//! Wire format cross-checked against the device side (u-boot 2015.01
//! `v2_usb_tool/usb_pcd.c`) and the pyamlboot host implementation.
//!
//! All memory here is the SoC DRAM/registers address space; storage
//! access goes through textual burning commands (`download`/`upload`)
//! executed by the u-boot gadget.

use crate::error::{Error, Result};
use crate::soc::SocId;
use crate::{add_sum, req};
use std::io::Write;
use std::thread::sleep;
use std::time::{Duration, Instant};
use usbcore::Transport;

/// u16 block count per control transfer (pyamlboot MAX_LARGE_BLOCK_COUNT).
const MAX_LARGE_BLOCKS: usize = 0xffff;
/// Data block per `download` media packet (the burning tool's 64 KiB).
pub const MEDIA_CHUNK: usize = 0x10000;
/// Ack buffer length for media transfers (pyamlboot ackLen).
pub const MEDIA_ACK_LEN: usize = 0x200;
/// Bulk reply length of bulkcmd/tpl status (AM_BULK_REPLY_LEN).
pub const BULK_REPLY_LEN: usize = 512;
/// The device truncates a bulkcmd payload at 64 bytes silently; keep
/// the string + NUL within that (flasher.sh BULKCMD_MAX = 63).
pub const BULKCMD_MAX: usize = 63;
/// Device-side transfer slot of the upload stream (u-boot v2_burning
/// `OPTIMUS_DOWNLOAD_SLOT_SZ`, 64 KiB): per AM_REQ_UPLOAD request the
/// buffer manager announces `min(left of the armed command, this slot)`
/// in the 16-byte EP0 head and pushes exactly that on bulk IN.
pub const UPLOAD_SLOT: usize = 0x1_0000;
/// NAND staging size of the raw-range dump: one `nand read` moves this
/// much NAND->DRAM, then a single `upload mem` arm streams it to the
/// host in device-paced bursts.
pub const NAND_STAGE: usize = 256 * 1024;
/// Pause between `Continue:32` media acknowledgements (spec §16.2).
const MEDIA_CONTINUE_PAUSE: Duration = Duration::from_millis(500);
/// Pause between `Continue:34` burning-command polls (spec §15.2).
const COMMAND_CONTINUE_PAUSE: Duration = Duration::from_secs(3);
/// Fallback pause for another `Continue:xx` code.
const CONTINUE_PAUSE: Duration = Duration::from_millis(50);
/// Overall status deadline; the spec gives a 60 s TPL status window.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(60);
/// Identify is a 5 s request (spec §18).
const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(5);
/// EP0 memory read/write are 5 s requests (spec §18).
const MEMORY_TIMEOUT: Duration = Duration::from_secs(5);
/// Run waits for the device-side memory handler (spec §18).
const RUN_TIMEOUT: Duration = Duration::from_secs(50);
/// Large memory transfers are 50 s requests (spec §18).
const LARGE_TIMEOUT: Duration = Duration::from_secs(50);
/// TPL command is a 50 s request (spec §18).
const TPL_CMD_TIMEOUT: Duration = Duration::from_secs(50);
/// TPL status is a 60 s request (spec §18).
const TPL_STAT_TIMEOUT: Duration = Duration::from_secs(60);
/// A burning command may run for 50 s before its first status (spec §18).
const BULK_CMD_TIMEOUT: Duration = Duration::from_secs(50);
/// Media read/write are 5 s requests (spec §18).
const MEDIA_TIMEOUT: Duration = Duration::from_secs(5);
/// One bulk status read after the command is already running: short
/// enough to notice a dead pipe, long enough for a normal reply.
const STATUS_TIMEOUT: Duration = Duration::from_secs(5);
/// Password authentication is an 8 s request (spec §18).
const PASSWORD_TIMEOUT: Duration = Duration::from_secs(8);

/// A session with an Amlogic SoC in a USB download mode.
pub struct AmlogicSession<T: Transport> {
    transport: T,
    ep_in: u8,
    ep_out: u8,
}

impl<T: Transport> AmlogicSession<T> {
    /// Access the underlying transport (tests and advanced callers).
    pub fn transport(&self) -> &T {
        &self.transport
    }
}

impl AmlogicSession<usbcore::NusbTransport> {
    /// USB port reset (see [`usbcore::NusbTransport::reset`]): the
    /// session handle dies, the device re-enumerates into a fresh
    /// download window. Part of the automatic dump cycle.
    pub fn reset(&self) -> Result<()> {
        Ok(self.transport.reset()?)
    }

    /// Open the only `1b8e:c003` device and claim interface 0.
    /// Refuse an ambiguous bus before opening either board.
    pub fn open() -> Result<Self> {
        let t = usbcore::NusbTransport::open_unique(crate::USB_VID_AMLOGIC, crate::USB_PID_UPDATE)?;
        let (ep_in, ep_out) = (t.ep_in, t.ep_out);
        Ok(AmlogicSession::new(t, ep_in, ep_out))
    }
}

impl<T: Transport> AmlogicSession<T> {
    pub fn new(transport: T, ep_in: u8, ep_out: u8) -> Self {
        AmlogicSession {
            transport,
            ep_in,
            ep_out,
        }
    }

    /// EP0 vendor IN (control_in) helper with the 5 s memory timeout.
    fn ctrl_in(&mut self, request: u8, value: u16, index: u16, buf: &mut [u8]) -> Result<usize> {
        self.ctrl_in_timeout(request, value, index, buf, MEMORY_TIMEOUT)
    }

    /// EP0 vendor IN (control_in) with an operation-specific timeout.
    fn ctrl_in_timeout(
        &mut self,
        request: u8,
        value: u16,
        index: u16,
        buf: &mut [u8],
        timeout: Duration,
    ) -> Result<usize> {
        Ok(self
            .transport
            .control_in_timeout(request, value, index, buf, timeout)?)
    }

    /// EP0 vendor OUT (control_out) helper with the 5 s memory timeout.
    fn ctrl_out(&mut self, request: u8, value: u16, index: u16, data: &[u8]) -> Result<()> {
        self.ctrl_out_timeout(request, value, index, data, MEMORY_TIMEOUT)
    }

    /// EP0 vendor OUT (control_out) with an operation-specific timeout.
    fn ctrl_out_timeout(
        &mut self,
        request: u8,
        value: u16,
        index: u16,
        data: &[u8],
        timeout: Duration,
    ) -> Result<()> {
        Ok(self
            .transport
            .control_out_timeout(request, value, index, data, timeout)?)
    }

    /// Identify the device (AM_REQ_IDENTIFY_HOST): protocol version and
    /// boot stage. Call promptly while the download window is open;
    /// its lifetime depends on the board's bootloader.
    pub fn identify(&mut self) -> Result<SocId> {
        let mut buf = [0u8; 8];
        let n = self.ctrl_in_timeout(req::IDENTIFY_HOST, 0, 0, &mut buf, IDENTIFY_TIMEOUT)?;
        if !(4..=buf.len()).contains(&n) || buf[..4].iter().all(|&b| b == 0) {
            return Err(Error::InvalidResponse(format!(
                "invalid identify reply ({n} bytes)"
            )));
        }
        SocId::parse(&buf[..n])
            .ok_or_else(|| Error::InvalidResponse("identify reply too short".into()))
    }

    /// Identify a session; only TPL supports the burning-command prime.
    /// A device that still demands a password refuses the prime instead
    /// of burning the window on commands it will reject.
    pub fn identify_and_prime(&mut self) -> Result<SocId> {
        let soc = self.identify()?;
        if soc.stage() == crate::Stage::Tpl {
            if soc.need_password() == Some(true) && soc.password_ok() != Some(true) {
                return Err(Error::PasswordRequired);
            }
            self.prime()?;
        }
        Ok(soc)
    }

    /// Send the password (AM_REQ_PASSWORD): `wValue` is the 16-bit sum
    /// of the bytes, `wIndex` is zero, the data is 1..64 bytes
    /// (spec §10). The caller re-identifies and checks
    /// [`SocId::password_ok`]; the vendor tool allows two attempts.
    pub fn send_password(&mut self, password: &[u8]) -> Result<()> {
        if password.is_empty() || password.len() > 64 {
            return Err(Error::InvalidArgument(format!(
                "password length {} outside 1..=64",
                password.len()
            )));
        }
        let sum = password
            .iter()
            .fold(0u16, |sum, &byte| sum.wrapping_add(byte as u16));
        self.ctrl_out_timeout(req::PASSWORD, sum, 0, password, PASSWORD_TIMEOUT)
    }

    /// Write up to 64 bytes to memory (AM_REQ_WRITE_MEM).
    pub fn write_memory(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        assert!(data.len() <= 64, "chunk must be <= 64 bytes");
        self.ctrl_out(req::WRITE_MEM, (addr >> 16) as u16, addr as u16, data)
    }

    /// Write data to memory in 64-byte EP0 chunks (AM_REQ_WRITE_MEM).
    pub fn write_memory_chunks(&mut self, addr: u32, data: &[u8]) -> Result<()> {
        for (i, chunk) in data.chunks(64).enumerate() {
            self.write_memory(addr + (i * 64) as u32, chunk)?;
        }
        Ok(())
    }

    /// Read up to 64 bytes from memory (AM_REQ_READ_MEM); returns the
    /// bytes actually received.
    pub fn read_memory(&mut self, addr: u32, buf: &mut [u8]) -> Result<usize> {
        assert!(buf.len() <= 64, "chunk must be <= 64 bytes");
        self.ctrl_in(req::READ_MEM, (addr >> 16) as u16, addr as u16, buf)
    }

    /// Read data from memory in 64-byte EP0 chunks (AM_REQ_READ_MEM).
    /// Fills `buf` completely; fails if the device answers short.
    pub fn read_memory_chunks(&mut self, addr: u32, buf: &mut [u8]) -> Result<()> {
        for (i, chunk) in buf.chunks_mut(64).enumerate() {
            let n = self.read_memory(addr + (i * 64) as u32, chunk)?;
            if n != chunk.len() {
                return Err(Error::Usb(format!(
                    "short read at {:#x} ({n} of {} bytes)",
                    addr + (i * 64) as u32,
                    chunk.len()
                )));
            }
        }
        Ok(())
    }

    /// Run code at `addr` (AM_REQ_RUN_IN_ADDR). With `keep_power` the
    /// flag bit asks newer BootROMs to leave the USB phy powered across
    /// the jump (the BL2/TPL loading chain needs it to keep talking).
    pub fn run(&mut self, addr: u32, keep_power: bool) -> Result<()> {
        let data = if keep_power {
            addr | crate::FLAG_KEEP_POWER_ON
        } else {
            addr
        };
        self.ctrl_out_timeout(
            req::RUN_IN_ADDR,
            (addr >> 16) as u16,
            addr as u16,
            &data.to_le_bytes(),
            RUN_TIMEOUT,
        )
    }

    /// Large memory write (AM_REQ_WR_LARGE_MEM): one control transfer
    /// announces the transfer, the payload follows on the bulk-OUT pipe
    /// in `block_len` blocks (device-side cap 0x1000 per block). The
    /// last block MAY be shorter (§13.3); the header carries the actual
    /// transfer length, its add_sum checksum and the block size.
    pub fn write_large_memory(&mut self, addr: u32, data: &[u8], block_len: usize) -> Result<()> {
        assert!((1..=0x1000).contains(&block_len), "block_len 1..0x1000");
        let mut off = 0usize;
        while off < data.len() {
            let blocks = (data.len() - off).div_ceil(block_len).min(MAX_LARGE_BLOCKS);
            let len = (data.len() - off).min(blocks * block_len);
            let mut head = [0u8; 16];
            head[0..4].copy_from_slice(&(addr + off as u32).to_le_bytes());
            head[4..8].copy_from_slice(&(len as u32).to_le_bytes());
            head[8..12].copy_from_slice(&(add_sum(&data[off..off + len]) & 0xffff).to_le_bytes());
            head[12..16].copy_from_slice(&(block_len as u32).to_le_bytes());
            self.ctrl_out_timeout(
                req::WR_LARGE_MEM,
                block_len as u16,
                blocks as u16,
                &head,
                LARGE_TIMEOUT,
            )?;
            for b in 0..blocks {
                let start = off + b * block_len;
                let end = (start + block_len).min(data.len());
                if start >= end {
                    break;
                }
                self.transport.bulk_write(self.ep_out, &data[start..end])?;
            }
            off += len;
        }
        Ok(())
    }

    /// Large memory read (AM_REQ_RD_LARGE_MEM): mirror of
    /// [`write_large_memory`], payload arrives on the bulk-IN pipe.
    /// Reliable on the BootROM stage; the u-boot burning gadget of the
    /// old 2015.01 tree mishandles this request — there prefer
    /// [`AmlogicSession::upload_read`] (bulkcmd `upload mem`).
    /// The length need not be a multiple of the block size (§13.2).
    pub fn read_large_memory(&mut self, addr: u32, buf: &mut [u8], block_len: usize) -> Result<()> {
        assert!((1..=0x1000).contains(&block_len), "block_len 1..0x1000");
        let mut off = 0usize;
        while off < buf.len() {
            let blocks = (buf.len() - off).div_ceil(block_len).min(MAX_LARGE_BLOCKS);
            let len = (buf.len() - off).min(blocks * block_len);
            let mut head = [0u8; 16];
            head[0..4].copy_from_slice(&(addr + off as u32).to_le_bytes());
            head[4..8].copy_from_slice(&(len as u32).to_le_bytes());
            // A read has no payload to checksum; the block size is the
            // wValue mirror required by §13.1.
            head[12..16].copy_from_slice(&(block_len as u32).to_le_bytes());
            self.ctrl_out_timeout(
                req::RD_LARGE_MEM,
                block_len as u16,
                blocks as u16,
                &head,
                LARGE_TIMEOUT,
            )?;
            self.transport
                .bulk_read(self.ep_in, &mut buf[off..off + len])?;
            off += len;
        }
        Ok(())
    }

    /// Execute a textual burning command via AM_REQ_BULKCMD and return
    /// the final status text. The u-boot gadget runs the string through
    /// its burning dispatcher (`optimus_working`). The status is
    /// `success` when the command completed, `Continue:xx` while it is
    /// still running (polled with a pause), anything else is the error
    /// text.
    pub fn bulk_cmd(&mut self, cmd: &str) -> Result<String> {
        self.bulk_cmd_timeout(cmd, BULK_CMD_TIMEOUT)
    }

    /// [`bulk_cmd`](Self::bulk_cmd) with an explicit first-status
    /// deadline; the prime needs the short pipe detector, not the 50 s
    /// burning-command window.
    fn bulk_cmd_timeout(&mut self, cmd: &str, first_status: Duration) -> Result<String> {
        self.send_bulk_cmd(cmd)?;
        self.wait_bulk_status_timeout(first_status)
    }

    /// Send a bulk command without waiting for the status.
    ///
    /// Wire format of the reference flasher: the command + NUL rides a
    /// full 64-byte zero-padded payload, and the string itself is capped
    /// at 63 chars (the device truncates at 64 silently and then
    /// answers half a command with a syntax error nobody reports).
    pub fn send_bulk_cmd(&mut self, cmd: &str) -> Result<()> {
        if cmd.as_bytes().contains(&0) {
            return Err(Error::InvalidArgument("command contains NUL".into()));
        }
        if cmd.len() > BULKCMD_MAX {
            return Err(Error::CommandTooLong(cmd.to_string()));
        }
        let mut payload = [0u8; 64];
        payload[..cmd.len()].copy_from_slice(cmd.as_bytes());
        self.ctrl_out_timeout(req::BULKCMD, 0, 2, &payload, BULK_CMD_TIMEOUT)
    }

    /// Sacrificial command right after identify: the first bulkcmd of a
    /// session can lose its leading bytes (flasher.sh `prime_bulk`), and
    /// on a freshly caught device the bulk pipes may not be ready yet
    /// (IOKit kIOUSBUnknownPipeErr) — so this retries until the bulk
    /// path answers. The semantic result is ignored either way. A
    /// failure here means the session is unusable: continuing would
    /// burn the window on commands whose status nobody can read, so it
    /// is an error and the caller reconnects (the reference flasher
    /// fails the whole run on a failed prime).
    pub fn prime(&mut self) -> Result<()> {
        for attempt in 0..8 {
            match self.bulk_cmd_timeout("echo", MEMORY_TIMEOUT) {
                // the pipe works — the reply text is meaningless here
                Ok(_) | Err(Error::CommandFailed(_)) => return Ok(()),
                Err(e @ Error::Usb(_)) => {
                    if attempt == 7 {
                        return Err(e);
                    }
                    sleep(Duration::from_millis(50));
                }
                Err(e) => return Err(e),
            }
        }
        unreachable!()
    }

    /// Poll the bulk status until the running command finishes.
    /// `Continue:xx` means "still executing". A command may take up to
    /// 50 s before its first status; later polls use the 5 s pipe
    /// detector. The overall deadline is [`COMMAND_TIMEOUT`].
    pub fn wait_bulk_status(&mut self) -> Result<String> {
        self.wait_bulk_status_timeout(BULK_CMD_TIMEOUT)
    }

    fn wait_bulk_status_timeout(&mut self, first_status: Duration) -> Result<String> {
        let start = Instant::now();
        let mut first = true;
        poll_status(
            || {
                let timeout = if first { first_status } else { STATUS_TIMEOUT };
                first = false;
                self.read_bulk_reply_timeout(timeout)
            },
            || start.elapsed(),
            sleep,
        )
    }

    /// One 512-byte bulk-IN status reply, NUL-trimmed. Read UP TO 512 in
    /// one transfer: the reference flasher tolerates short replies, and
    /// blocking for the full frame after a short packet (e.g. a
    /// `Continue:34` tick) wedges the pipe — the exact session-killer
    /// of the earlier revisions.
    pub fn read_bulk_reply(&mut self) -> Result<String> {
        self.read_bulk_reply_timeout(STATUS_TIMEOUT)
    }

    fn read_bulk_reply_timeout(&mut self, timeout: Duration) -> Result<String> {
        let mut buf = [0u8; BULK_REPLY_LEN];
        let n = self
            .transport
            .bulk_read_upto_timeout(self.ep_in, &mut buf, timeout)?;
        if n == 0 || n > buf.len() {
            return Err(Error::InvalidResponse(format!(
                "invalid bulk status length: {n}"
            )));
        }
        let text = nul_trim(&buf[..n]);
        log::debug!("amlogic: bulk reply {n}b: {text}");
        Ok(text)
    }

    /// Execute a command via AM_REQ_TPL_CMD (subcode 1) and fetch the
    /// result with AM_REQ_TPL_STAT (a 64-byte EP0 reply instead of the
    /// bulk one). The burning tool uses this channel for `download`.
    pub fn tpl_cmd(&mut self, cmd: &str) -> Result<String> {
        if cmd.as_bytes().contains(&0) {
            return Err(Error::InvalidArgument("command contains NUL".into()));
        }
        let mut payload = [0u8; 64];
        if cmd.len() + 1 > payload.len() {
            return Err(Error::CommandTooLong(cmd.to_string()));
        }
        payload[..cmd.len()].copy_from_slice(cmd.as_bytes());
        self.ctrl_out_timeout(req::TPL_CMD, 0, 1, &payload, TPL_CMD_TIMEOUT)?;
        self.tpl_stat()
    }

    /// Fetch the TPL command result (AM_REQ_TPL_STAT), polling within
    /// the same 60-second status deadline as bulk commands.
    pub fn tpl_stat(&mut self) -> Result<String> {
        let start = Instant::now();
        poll_status(
            || {
                let mut buf = [0u8; 0x40];
                let n = self.ctrl_in_timeout(req::TPL_STAT, 0, 0, &mut buf, TPL_STAT_TIMEOUT)?;
                if n == 0 || n > buf.len() {
                    return Err(Error::InvalidResponse(format!(
                        "invalid TPL status length: {n}"
                    )));
                }
                Ok(nul_trim(&buf[..n]))
            },
            || start.elapsed(),
            sleep,
        )
    }

    /// One `download` media packet (AM_REQ_WRITE_MEDIA): `data` (at most
    /// [`MEDIA_CHUNK`], zero-padded is not applied — pass whole packets)
    /// is streamed over bulk-OUT with an add_sum checksum, then the
    /// device acknowledges on bulk-IN with `OK!!`. Prerequisite: a
    /// `download <store|mem|dtb> <part> <type> <total_size>` command has
    /// armed the transfer.
    pub fn write_media(&mut self, data: &[u8], seq: u32) -> Result<()> {
        assert!(data.len() <= MEDIA_CHUNK, "packet must be <= MEDIA_CHUNK");
        if data.is_empty() {
            return Err(Error::InvalidArgument("empty media packet".into()));
        }
        // Spec §16.2: attempt 0..2, block length, seq << 4, checksum,
        // then `ef 00 00 01`, then zero padding. Retry a rejected block
        // up to three times; `Continue:32` means "wait and read again".
        let mut last = String::new();
        for attempt in 0..3u32 {
            let mut head = [0u8; 0x20];
            head[0..4].copy_from_slice(&attempt.to_le_bytes());
            head[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
            head[8..12].copy_from_slice(&(seq << 4).to_le_bytes());
            head[12..16].copy_from_slice(&add_sum(data).to_le_bytes());
            head[16..20].copy_from_slice(&0x0100_00efu32.to_le_bytes());
            self.ctrl_out_timeout(req::WRITE_MEDIA, 1, 0xffff, &head, MEDIA_TIMEOUT)?;
            self.transport.bulk_write(self.ep_out, data)?;
            loop {
                let ack = self.read_bulk_reply()?;
                if ack.starts_with("Continue:") {
                    log::info!("amlogic: {ack} — waiting");
                    sleep(MEDIA_CONTINUE_PAUSE);
                    continue;
                }
                if ack.starts_with("OK!!") {
                    return Ok(());
                }
                last = ack;
                break;
            }
            if attempt < 2 {
                log::warn!(
                    "media block {seq} rejected ({last:?}); retrying (attempt {})",
                    attempt + 1
                );
            }
        }
        Err(Error::MediaFailed(last))
    }

    /// Stream a whole buffer as `download` media packets of
    /// [`MEDIA_CHUNK`] (sequence numbers from 0).
    pub fn write_media_all(&mut self, mut data: &[u8]) -> Result<()> {
        let mut seq = 0u32;
        while !data.is_empty() {
            let n = data.len().min(MEDIA_CHUNK);
            self.write_media(&data[..n], seq)?;
            data = &data[n..];
            seq += 1;
        }
        Ok(())
    }

    /// One AM_REQ_UPLOAD burst of the armed `upload ...` stream.
    ///
    /// Device side (usb_pcd.c `do_vendor_out_complete` AM_REQ_UPLOAD):
    /// wValue/wIndex are IGNORED — the 16-byte EP0 head announces how
    /// much the device pushes on bulk IN for THIS request:
    /// `min(left of the armed command, UPLOAD_SLOT)`, and the gadget
    /// streams exactly that much. The host must read exactly the
    /// announced amount: reading less leaves the tail in the pipe and
    /// every following burst drifts until the gadget stalls (the "pipe
    /// overrun" of the pre-0.4 revisions), reading more stalls on
    /// read_exact. `hint` only feeds the vendor tool's 4 KiB page
    /// accounting in wIndex — wire fidelity, no effect on the device.
    pub fn upload_fetch(&mut self, hint: usize) -> Result<(Vec<u8>, [u8; 16])> {
        self.upload_fetch_bounded(hint, UPLOAD_SLOT)
    }

    fn upload_fetch_bounded(
        &mut self,
        hint: usize,
        remaining: usize,
    ) -> Result<(Vec<u8>, [u8; 16])> {
        let (head, size) = self.upload_head(hint, remaining)?;
        let mut data = Vec::with_capacity(size);
        self.read_upload_payload(size, &mut data, &|_| {}, false)?;
        Ok((data, head))
    }

    fn upload_head(&mut self, hint: usize, remaining: usize) -> Result<([u8; 16], usize)> {
        let want = hint.clamp(1, UPLOAD_SLOT);
        let blocks = (want.div_ceil(0x1000)) as u16;
        let mut head = [0u8; 16];
        let n = self.ctrl_in_timeout(req::READ_MEDIA, 0x1000, blocks, &mut head, MEDIA_TIMEOUT)?;
        if n != 16 {
            return Err(Error::InvalidResponse(format!(
                "short upload head: {n} of 16 bytes (session dead?)"
            )));
        }
        // [4..8] is what this burst will carry (do_vendor_in_complete
        // copies it into bulk_data_len); a garbage head means a dead
        // or desynchronized session.
        let left = u32::from_le_bytes(head[4..8].try_into().unwrap()) as usize;
        if left > UPLOAD_SLOT || left > remaining {
            return Err(Error::InvalidResponse(format!(
                "upload head announces {left:#x} bytes for {remaining:#x} remaining (slot {UPLOAD_SLOT:#x})"
            )));
        }
        Ok((head, left))
    }

    /// Deliver every completed USB read immediately, so a later link
    /// failure cannot discard the already received prefix.
    fn read_upload_payload(
        &mut self,
        size: usize,
        out: &mut dyn Write,
        progress: &dyn Fn(usize),
        allow_empty: bool,
    ) -> Result<usize> {
        let mut buf = [0u8; UPLOAD_SLOT];
        let mut received = 0;
        while received < size {
            let want = size - received;
            let (n, failure) = match self.transport.bulk_read_upto(self.ep_in, &mut buf[..want]) {
                Ok(n) => (n, None),
                Err(error @ usbcore::Error::PartialRead { transferred, .. }) => {
                    (transferred, Some(error))
                }
                Err(error) => return Err(error.into()),
            };
            // The gadget announces the burst before staging storage data.
            // A staging failure deliberately sends a ZLP to stop upload.
            // Only a store stream with complete previous bursts may keep it
            // as a short image; RAM and truncated bursts must still fail.
            if n == 0 && received == 0 && failure.is_none() && allow_empty {
                return Ok(0);
            }
            if n == 0 || n > want {
                return Err(Error::InvalidResponse(format!(
                    "upload payload: got {n} bytes for {want} remaining"
                )));
            }
            out.write_all(&buf[..n])?;
            received += n;
            progress(received);
            if let Some(error) = failure {
                return Err(error.into());
            }
        }
        Ok(received)
    }

    /// Stream an armed `upload ...` command to completion: sequential
    /// [`upload_fetch`](Self::upload_fetch) bursts until `total` bytes
    /// are collected or the device announces an empty burst (the stream
    /// ended early — bad blocks shorten NAND-backed uploads). Returns
    /// what arrived; exact callers check the length themselves.
    pub(crate) fn receive_upload(
        &mut self,
        total: usize,
        stop: &dyn Fn() -> bool,
        progress: &dyn Fn(usize),
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(total.min(1 << 20));
        self.receive_upload_to(total, stop, &mut out, progress, false)?;
        Ok(out)
    }

    fn receive_upload_to(
        &mut self,
        total: usize,
        stop: &dyn Fn() -> bool,
        out: &mut dyn Write,
        progress: &dyn Fn(usize),
        allow_short_payload: bool,
    ) -> Result<usize> {
        let mut received = 0;
        while received < total {
            if stop() {
                break;
            }
            let (head, size) = self.upload_head(total - received, total - received)?;
            if size == 0 {
                break;
            }
            let actual = self.read_upload_payload(size, out, &|n| progress(received + n), allow_short_payload && received > 0)
                .map_err(|error| match error {
                    Error::InvalidResponse(detail) => Error::InvalidResponse(format!(
                        "{detail}; stream offset {received:#x} (burst start), announced {size:#x}, total {total:#x}, head={head:02x?}"
                    )),
                    other => other,
                })?;
            if actual == 0 {
                log::warn!("store upload stopped with a ZLP at {received:#x} of {total:#x}; keeping a short image (announced {size:#x})");
                break;
            }
            received += actual;
        }
        Ok(received)
    }

    /// u-boot gadget stage: read DRAM via the `upload mem <addr> normal
    /// <size>` burning command + AM_REQ_UPLOAD bursts (works around the
    /// old tree's broken AM_REQ_RD_LARGE_MEM). One arm for the whole
    /// `size`, streamed in device-paced [`UPLOAD_SLOT`] bursts.
    pub fn upload_read(&mut self, addr: u32, size: usize) -> Result<Vec<u8>> {
        if size == 0 || size > 0x80_0000 {
            return Err(Error::Usb(format!(
                "upload mem size {size:#x} out of 1..=0x800000"
            )));
        }
        let cmd = format!("upload mem {addr:#x} normal {size:#x}");
        self.send_bulk_cmd(&cmd)?;
        // the command completes once the payload is staged; the data
        // itself arrives via upload_fetch bursts
        let status = self.wait_bulk_status()?;
        log::debug!("upload armed: {status}");
        self.finish_dram_read(addr, size, &|_| {})
    }

    /// Read a DRAM range (one `upload mem` arm + device-paced bursts).
    pub fn read_dram(
        &mut self,
        addr: u32,
        size: usize,
        progress: &dyn Fn(usize),
    ) -> Result<Vec<u8>> {
        if size == 0 || size > 0x80_0000 {
            return Err(Error::Usb(format!(
                "upload mem size {size:#x} out of 1..=0x800000"
            )));
        }
        self.send_bulk_cmd(&format!("upload mem {addr:#x} normal {size:#x}"))?;
        let status = self.wait_bulk_status()?;
        log::debug!("upload armed: {status}");
        self.finish_dram_read(addr, size, progress)
    }

    fn finish_dram_read(
        &mut self,
        addr: u32,
        size: usize,
        progress: &dyn Fn(usize),
    ) -> Result<Vec<u8>> {
        let data = self.receive_upload(size, &|| false, progress)?;
        if data.len() != size {
            return Err(Error::InvalidResponse(format!(
                "upload mem {addr:#x}: got {:#x} of {size:#x} bytes",
                data.len()
            )));
        }
        Ok(data)
    }

    /// `nand read <ram> <off> <len>` — raw-offset NAND read into DRAM
    /// (the logical layout: u-boot skips bad blocks). Sent with the
    /// reference flasher's `echo; ` prefix. Pair with
    /// [`AmlogicSession::read_dram`] to bring the data to the host.
    pub fn nand_read(&mut self, ram: u32, off: u32, len: usize) -> Result<()> {
        self.bulk_cmd(&format!("echo; nand read {ram:#x} {off:#x} {len:#x}"))
            .map(|_| ())
    }

    /// Dump a raw NAND range through DRAM (flasher.sh
    /// `read_big_from_flash`): a `nand read` stages up to
    /// [`NAND_STAGE`] in RAM, then ONE `upload mem` arm streams the
    /// stage to the host in device-paced bursts (the reference flasher's
    /// mechanics: the device announces every burst in the upload head,
    /// the host just consumes exactly what is announced).
    ///
    /// Error split: a `nand read` REJECTED by the device (`failed:`,
    /// a bad block after the good prefix) does NOT necessarily mean the
    /// staging buffer was not written: the live A113X gadget fills the
    /// whole range and still answers `failed:` when it skipped a bad
    /// block. The stage is uploaded in both cases. An entirely unchanged
    /// sentinel buffer is rejected; otherwise uploaded bytes are preserved
    /// without guessing a valid length from their contents. A failed status
    /// is logged because NAND completeness remains uncertain.
    /// A TRANSPORT error is the session dying
    /// and propagates to the caller, which reconnects and retries the
    /// same range.
    pub fn read_nand_range(
        &mut self,
        off: u32,
        len: usize,
        progress: &dyn Fn(usize),
    ) -> Result<Vec<u8>> {
        self.read_nand_range_until(off, len, progress, &|| false)
    }

    /// [`read_nand_range`] with a cooperative stop: `stop` is polled
    /// before every burst, so a caller riding a short-lived window
    /// can exit cleanly mid-stage and finish the command it needs
    /// before the window closes.
    pub fn read_nand_range_until(
        &mut self,
        off: u32,
        len: usize,
        progress: &dyn Fn(usize),
        stop: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>> {
        let mut out = vec![0u8; len];
        let mut total = 0usize; // bytes received across all stages
        while total < len {
            if stop() {
                break;
            }
            let stage = (len - total).min(NAND_STAGE);
            // the `echo; ` prefix routes the command through the u-boot
            // shell, exactly as the reference flasher sends it (the
            // burning dispatcher must not intercept it)
            self.bulk_cmd(&format!(
                "echo; mw.b {:#x} 0xa5 {stage:#x}",
                crate::RAM_SCRATCH
            ))?;
            // A bad-block `failed:` does not prove the buffer is empty:
            // keep the status and upload the stage anyway.
            let read_failure = match self.nand_read(crate::RAM_SCRATCH, off + total as u32, stage) {
                Ok(()) => None,
                Err(e @ Error::CommandFailed(_)) => Some(e),
                // anything else is the session dying
                Err(other) => return Err(other),
            };
            // arm the whole stage once; the bursts below are paced by
            // the device (announced in the upload head)
            self.send_bulk_cmd(&format!(
                "upload mem {:#x} normal {stage:#x}",
                crate::RAM_SCRATCH
            ))?;
            self.wait_bulk_status()?;
            let mut staged = 0usize;
            while staged < stage {
                if stop() {
                    break;
                }
                // pacing knob for the load-kill diagnosis: a pause
                // between bursts tells apart a device-side FIFO overrun
                // (death tracks the burst rate) from a hard device timer
                // (death tracks wall time regardless of pacing)
                if let Ok(ms) = std::env::var("AML_BURST_DELAY_MS") {
                    if let Ok(ms) = ms.parse::<u64>() {
                        if ms > 0 && staged > 0 {
                            sleep(Duration::from_millis(ms));
                        }
                    }
                }
                let (chunk, _head) = self.upload_fetch_bounded(stage - staged, stage - staged)?;
                if chunk.is_empty() {
                    return Err(Error::Usb(format!(
                        "upload mem: stream ended after {staged:#x} of {stage:#x} bytes"
                    )));
                }
                out[total + staged..total + staged + chunk.len()].copy_from_slice(&chunk);
                staged += chunk.len();
            }

            // A suffix of 0xa5 is ambiguous: it may be real NAND data,
            // not untouched staging RAM. Never infer a byte count from
            // its contents. Preserve every uploaded byte once the buffer
            // changed; a rejected command still leaves NAND completeness
            // uncertain and must remain visible in the diagnostic log.
            let unchanged = staged > 0 && out[total..total + staged].iter().all(|&b| b == 0xa5);
            if let Some(error) = read_failure {
                if unchanged {
                    if stop() {
                        break;
                    }
                    if total == 0 {
                        return Err(error);
                    }
                    log::warn!(
                        "nand read rejected at {:#x} (+{total:#x} of {len:#x}): {error} \
                         — keeping the prefix",
                        off + total as u32
                    );
                    break;
                }
                log::warn!(
                    "nand read at {:#x} reported {error}; preserving all {staged:#x} \
                     uploaded bytes without trimming; NAND completeness is uncertain",
                    off + total as u32
                );
            }

            // a successful read that left the sentinel untouched did
            // not happen at all (usb_pcd/flasher.sh guard)
            if staged == stage && out[total..total + stage].iter().all(|&b| b == 0xa5) {
                return Err(Error::Usb(format!(
                    "nand read {:#x}: the staging buffer still holds the sentinel — \
                     the read did not happen",
                    off + total as u32
                )));
            }
            total += staged;
            progress(total);
            if staged < stage {
                break; // stopped mid-stage
            }
        }
        out.truncate(total);
        Ok(out)
    }

    /// Collect a partition upload in memory. An explicit zero upload
    /// head returns a short stream with a warning; it does not establish
    /// the cause of the short read. Prefer [`Self::upload_store_to`]
    /// for long reads or when the prefix must survive a transport error.
    pub fn upload_store(
        &mut self,
        part: &str,
        total: usize,
        progress: &dyn Fn(usize),
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(total.min(1 << 20));
        self.upload_store_to(part, total, &mut out, progress)?;
        Ok(out)
    }

    /// Stream a known partition into a writer using at most one 64 KiB
    /// payload buffer. A zero upload head is a short stream, not proof
    /// of a bad block. A boundary ZLP after complete bursts is also kept
    /// as a short image: the gadget uses it when storage staging fails.
    /// Transport and writer errors propagate, leaving
    /// completed writes in `out`; the caller decides how to retain them.
    pub fn upload_store_to(
        &mut self,
        part: &str,
        total: usize,
        out: &mut dyn Write,
        progress: &dyn Fn(usize),
    ) -> Result<usize> {
        let (_, _, size) = crate::partition(part)
            .ok_or_else(|| Error::InvalidArgument(format!("unknown partition {part:?}")))?;
        if total > size as usize {
            return Err(Error::InvalidArgument(format!(
                "partition {part}: size {total:#x} exceeds {size:#x}"
            )));
        }
        if total == 0 {
            return Ok(0);
        }
        self.bulk_cmd(&format!("upload store {part} normal {total:#x}"))?;
        let received = self.receive_upload_to(total, &|| false, out, progress, true)?;
        if received < total {
            log::warn!("upload store {part}: stream ended at {received:#x} of {total:#x} bytes");
        }
        Ok(received)
    }

    /// Fill memory words (AM_REQ_FILL_MEM): (addr, value) pairs.
    pub fn fill_memory(&mut self, pairs: &[(u32, u32)]) -> Result<()> {
        let mut data = Vec::with_capacity(pairs.len() * 8);
        for (addr, value) in pairs {
            data.extend_from_slice(&addr.to_le_bytes());
            data.extend_from_slice(&value.to_le_bytes());
        }
        self.ctrl_out(req::FILL_MEM, 0, 0, &data)
    }
}

/// Trim trailing NULs of a fixed-size reply buffer.
fn nul_trim(buf: &[u8]) -> String {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).into_owned()
}

fn poll_status(
    mut read: impl FnMut() -> Result<String>,
    mut elapsed: impl FnMut() -> Duration,
    mut pause: impl FnMut(Duration),
) -> Result<String> {
    loop {
        if elapsed() >= COMMAND_TIMEOUT {
            return Err(Error::CommandTimeout);
        }
        let text = read()?;
        let spent = elapsed();
        if spent >= COMMAND_TIMEOUT {
            return Err(Error::CommandTimeout);
        }
        if text.starts_with("Continue:") {
            log::info!("amlogic: {text} — waiting");
            let wait = if text.starts_with("Continue:32") {
                MEDIA_CONTINUE_PAUSE
            } else if text.starts_with("Continue:34") {
                COMMAND_CONTINUE_PAUSE
            } else {
                CONTINUE_PAUSE
            };
            pause(wait.min(COMMAND_TIMEOUT - spent));
        } else if text.starts_with("success") {
            return Ok(text);
        } else {
            return Err(Error::CommandFailed(text));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn continuous_status_hits_total_deadline() {
        let elapsed = Cell::new(Duration::ZERO);
        let reads = Cell::new(0);
        let result = poll_status(
            || {
                reads.set(reads.get() + 1);
                Ok(if elapsed.get() > Duration::from_secs(60) {
                    "success".into()
                } else {
                    "Continue:34".into()
                })
            },
            || elapsed.get(),
            |delay| elapsed.set(elapsed.get() + delay),
        );
        assert!(matches!(result, Err(Error::CommandTimeout)));
        assert_eq!(elapsed.get(), Duration::from_secs(60));
        assert_eq!(reads.get(), 20);
    }

    #[test]
    fn late_status_success_does_not_escape_deadline() {
        let elapsed = Cell::new(Duration::ZERO);
        let result = poll_status(
            || {
                elapsed.set(Duration::from_secs(61));
                Ok("success".into())
            },
            || elapsed.get(),
            |_| unreachable!("a late reply must not trigger another pause"),
        );
        assert!(matches!(result, Err(Error::CommandTimeout)));
    }
}
