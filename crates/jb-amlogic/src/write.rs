//! The chunked partition write (flasher.sh `write_big_to_flash`
//! mechanics): erase, then per chunk — an identify keepalive,
//! `download mem` into RAM (the TPL channel) + media packets +
//! `download get_status`, and one `nand write` at the logical offset.
//!
//! THE ERASE/WRITE ARITHMETIC MISMATCH (measured live, 2026-11-01): in
//! this u-boot `nand write`/`nand read` count the length over the
//! LOGICAL space (bad blocks are skipped, the same space `store size`
//! reports), while `nand erase` takes a PHYSICAL address range — it
//! skips bad blocks on the way but does not extend the range. Inside a
//! partition with bad blocks, an erase of the image size covers fewer
//! PEBs than the write lays down: the tail keeps stale erase headers
//! with an old image sequence number, and UBI refuses to attach ("bad
//! image sequence number ... in PEB ...") — the stock system then
//! reformats the partition ("default file-system created") and falls
//! into factory mode. Therefore the erase ALWAYS covers the full
//! physical partition range: after the write every physical PEB is
//! either ours or clean 0xFF (free for UBI), whatever the write's own
//! skip-bad arithmetic does.
//!
//! A session death mid-chunk leaves that chunk's flash state
//! undefined, and reprogramming a partially programmed page corrupts
//! it — so any retry starts with the FULL erase and writes from zero.
//! The write fits one session (~13 s for the whole data partition),
//! which makes the all-or-nothing restart cheap.

use amlogic::store::NAND_WRITE_CHUNK;
use amlogic::{nand, AmlogicSession, Transport};
use anyhow::ensure;
use std::io::{Read, Seek, SeekFrom};

/// The state of the chunked partition write (lives between windows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteState {
    /// Image bytes acknowledged by `nand write` (the status was
    /// received). Reset to zero by every full erase.
    pub written: usize,
    /// The partition must be (re-)erased before writing: the initial
    /// state, and the state after any session death — a retry always
    /// starts with the full erase (see the module docs).
    pub need_erase: bool,
}

impl WriteState {
    pub fn fresh() -> Self {
        WriteState {
            written: 0,
            need_erase: true,
        }
    }
}

/// One write pass: erase the FULL physical partition range (if due)
/// and write the image in chunks of [`NAND_WRITE_CHUNK`] — each chunk:
/// identify-keepalive, `download mem` into RAM (the TPL channel) +
/// media packets + `download get_status` + `nand write` at the logical
/// offset. The pass lasts until the end of the image or until the
/// session dies (no artificial budgets). `erase_len` is the PHYSICAL
/// partition size (the erase arithmetic is physical — see the module
/// docs). Returns `true` when the image is written in full; `Ok(false)`
/// — the session died: reconnect the board and call again (state in
/// `st`; the retry re-erases and restarts from zero); disk/source
/// errors are `Err`.
pub fn write_data_pass<T: Transport>(
    s: &mut AmlogicSession<T>,
    image: &mut (impl Read + Seek),
    off: u32,
    erase_len: u32,
    total: usize,
    st: &mut WriteState,
    progress: &dyn Fn(usize),
) -> anyhow::Result<bool> {
    let page = nand::PAGE_SIZE as usize;
    ensure!(
        total > 0 && total.is_multiple_of(page),
        "размер образа некратен странице"
    );
    ensure!(
        off.is_multiple_of(page as u32),
        "смещение записи некратно странице"
    );
    ensure!(
        erase_len >= total as u32 && (off + erase_len) <= nand::NAND_SIZE,
        "erase-диапазон не накрывает образ или выходит за NAND"
    );
    if st.need_erase {
        // The full physical range, not the image remainder: stale PEBs
        // with an old image sequence number make UBI refuse the whole
        // partition (see the module docs). Whatever has been written
        // before is erased along with it — the write restarts from
        // zero.
        if let Err(e) = s.nand_erase(off, erase_len) {
            log::warn!("amlogic: nand erase {off:#x}+{erase_len:#x} не дожился (окно?): {e}");
            return Ok(false);
        }
        st.need_erase = false;
        st.written = 0;
    }
    let mut buf = vec![0u8; NAND_WRITE_CHUNK];
    while st.written < total {
        // keepalive: identify resets the gadget idle timer before a
        // chunk (the nand write that follows is silent on the device)
        if let Err(e) = s.identify() {
            log::warn!("amlogic: identify не дожился (окно?): {e}");
            return Ok(false);
        }
        let n = (total - st.written).min(NAND_WRITE_CHUNK);
        image.seek(SeekFrom::Start(st.written as u64))?;
        image.read_exact(&mut buf[..n])?;
        let mut cursor = std::io::Cursor::new(&buf[..n]);
        if let Err(e) = s.write_nand_chunk(
            amlogic::RAM_SCRATCH,
            off + st.written as u32,
            n,
            &mut cursor,
        ) {
            log::warn!(
                "amlogic: кусок {:#x} не дожился (окно?): {e}",
                off + st.written as u32
            );
            // the chunk's flash state is undefined — the retry erases
            // the whole partition and starts over
            st.need_erase = true;
            return Ok(false);
        }
        st.written += n;
        progress(st.written);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use amlogic::req;
    use amlogic::{MockTransport, Step};

    fn command(text: &str) -> Vec<u8> {
        let mut payload = vec![0; 64];
        payload[..text.len()].copy_from_slice(text.as_bytes());
        payload
    }

    fn ok_64() -> Vec<u8> {
        let mut r = vec![0u8; 64];
        r[..7].copy_from_slice(b"success");
        r
    }

    fn ok_512() -> Vec<u8> {
        let mut r = vec![0u8; amlogic::BULK_REPLY_LEN];
        r[..7].copy_from_slice(b"success");
        r
    }

    fn media_head(len: usize, seq: u32, sum: u32) -> Vec<u8> {
        let mut head = vec![0u8; 0x20];
        head[0..4].copy_from_slice(&0u32.to_le_bytes());
        head[4..8].copy_from_slice(&(len as u32).to_le_bytes());
        head[8..12].copy_from_slice(&seq.to_le_bytes());
        head[12..16].copy_from_slice(&sum.to_le_bytes());
        head[16..18].copy_from_slice(&0x00efu16.to_le_bytes());
        head[18..20].copy_from_slice(&0x0100u16.to_le_bytes());
        head
    }

    const OFF: u32 = 0x0b20_0000;
    /// 256 КиБ: один кусок NAND_WRITE_CHUNK.
    const TOTAL: usize = 0x4_0000;
    /// Полный физический диапазон «раздела» больше образа — параметр
    /// должен дойти до команды erase без пересчёта.
    const ERASE_LEN: u32 = 0x8_0000;

    fn identify_step() -> Step {
        Step::ControlIn(req::IDENTIFY_HOST, 0, 0, vec![0, 7, 0, 16])
    }

    fn chunk_steps(image: &[u8], off: u32, total: usize) -> Vec<Step> {
        let mut steps = vec![
            Step::ControlOut(
                req::TPL_CMD,
                0,
                1,
                command(&format!("download mem 0x1080000 normal {total:#x}")),
            ),
            Step::ControlIn(req::TPL_STAT, 0, 0, ok_64()),
        ];
        for seq in 0..(total / amlogic::MEDIA_CHUNK) {
            let part = &image[seq * amlogic::MEDIA_CHUNK..(seq + 1) * amlogic::MEDIA_CHUNK];
            steps.push(Step::ControlOut(
                req::WRITE_MEDIA,
                1,
                0xffff,
                media_head(amlogic::MEDIA_CHUNK, seq as u32, amlogic::add_sum(part)),
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
        steps.push(Step::BulkIn(ok_512()));
        steps.push(Step::ControlOut(
            req::BULKCMD,
            0,
            2,
            command(&format!("echo; nand write 0x1080000 {off:#x} {total:#x}")),
        ));
        steps.push(Step::BulkIn(ok_512()));
        steps
    }

    fn erase_step() -> Vec<Step> {
        vec![
            Step::ControlOut(
                req::BULKCMD,
                0,
                2,
                command(&format!("echo; nand erase {OFF:#x} {ERASE_LEN:#x}")),
            ),
            Step::BulkIn(ok_512()),
        ]
    }

    /// Полный проход: erase всего физического диапазона + keepalive +
    /// кусок (TPL arm + media-пакеты + get_status + nand write).
    #[test]
    fn write_data_pass_completes_a_range() {
        let image = vec![0x5au8; TOTAL];
        let mut steps = erase_step();
        steps.push(identify_step());
        steps.extend(chunk_steps(&image, OFF, TOTAL));
        let mut s = AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02);
        let mut src = std::io::Cursor::new(image);
        let mut st = WriteState::fresh();
        let done =
            write_data_pass(&mut s, &mut src, OFF, ERASE_LEN, TOTAL, &mut st, &|_| {}).unwrap();
        assert!(done);
        assert_eq!((st.written, st.need_erase), (TOTAL, false));
        assert_eq!(s.transport().pos, s.transport().steps.len());
    }

    /// Смерть посреди куска: следующий проход ПОВТОРЯЕТ полный erase
    /// (состояние флеша неопределено, перезапись нестёртого портит
    /// страницы) и пишет с нуля.
    #[test]
    fn restart_after_a_mid_chunk_death_repeats_the_full_erase() {
        let image = vec![0x22u8; TOTAL];
        // проход 1: erase прошёл, кусок умер на media-фазе (сразу после
        // TPL arm) — состояние куска во флеше неопределено
        let mut steps = erase_step();
        steps.push(identify_step());
        steps.push(Step::ControlOut(
            req::TPL_CMD,
            0,
            1,
            command(&format!("download mem 0x1080000 normal {TOTAL:#x}")),
        ));
        steps.push(Step::ControlIn(req::TPL_STAT, 0, 0, ok_64()));
        let mut s = AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02);
        let mut src = std::io::Cursor::new(image.clone());
        let mut st = WriteState::fresh();
        let done =
            write_data_pass(&mut s, &mut src, OFF, ERASE_LEN, TOTAL, &mut st, &|_| {}).unwrap();
        assert!(!done);
        assert_eq!((st.written, st.need_erase), (0, true));

        // проход 2: полный erase ещё раз, писать с нуля
        steps = erase_step();
        steps.push(identify_step());
        steps.extend(chunk_steps(&image, OFF, TOTAL));
        let mut s = AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02);
        let mut src = std::io::Cursor::new(image);
        let done =
            write_data_pass(&mut s, &mut src, OFF, ERASE_LEN, TOTAL, &mut st, &|_| {}).unwrap();
        assert!(done);
        assert_eq!(st.written, TOTAL);
        assert_eq!(s.transport().pos, s.transport().steps.len());
    }

    /// Erase-диапазон, который не накрывает образ, отвергается до
    /// первого касания USB.
    #[test]
    fn rejects_erase_range_that_does_not_cover_the_image() {
        let mut s = AmlogicSession::new(MockTransport::new(vec![]), 0x81, 0x02);
        let mut src = std::io::Cursor::new(vec![0u8; TOTAL]);
        let mut st = WriteState::fresh();
        let err = write_data_pass(
            &mut s,
            &mut src,
            OFF,
            (TOTAL - 2048) as u32,
            TOTAL,
            &mut st,
            &|_| {},
        )
        .expect_err("short erase range must be rejected");
        assert!(err.to_string().contains("erase-диапазон"), "{err}");
        assert_eq!(s.transport().pos, 0);
    }
}
