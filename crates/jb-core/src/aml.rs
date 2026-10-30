//! Доменные операции для Amlogic-мин Capsula (A113X): съём окружения
//! u-boot, чекпоинт-захват NAND по окнам и многоконная запись раздела
//! по образцу flasher.sh. Протокол — крейт `amlogic`; CLI-сценарии — в
//! бэкенде jb-cli.

pub mod backup;

use amlogic::store::NAND_WRITE_CHUNK;
use amlogic::{nand, AmlogicSession, Transport};
use anyhow::{anyhow, ensure};
use std::io::{Read, Seek, SeekFrom};
use std::time::{Duration, Instant};

/// Снять сырой буфер текстового экспорта окружения u-boot. Ответы
/// bulkcmd уходят в serial-консоль, поэтому окружение экспортируется в
/// DRAM и вычитывается оттуда по USB (flasher.sh `capture_env`). Буфер
/// заранее зануляется — иначе хвост понесёт 0x55-стену memory-теста
/// BL2.
pub fn capture_env_raw<T: Transport>(s: &mut AmlogicSession<T>) -> anyhow::Result<Vec<u8>> {
    s.bulk_cmd(&format!(
        "echo; mw.b {:#x} 0 {:#x}",
        amlogic::ENV_ADDR,
        amlogic::ENV_SIZE
    ))
    .map_err(|e| anyhow!("mw.b: {e}"))?;
    s.bulk_cmd(&format!("echo; env export -t {:#x}", amlogic::ENV_ADDR))
        .map_err(|e| anyhow!("env export: {e}"))?;
    let buf = s
        .read_dram(amlogic::ENV_ADDR, amlogic::ENV_SIZE, &|_| {})
        .map_err(|e| anyhow!("чтение окружения из DRAM: {e}"))?;
    Ok(buf)
}

/// Декодировать снимок окружения как текст.
pub fn capture_env<T: Transport>(s: &mut AmlogicSession<T>) -> anyhow::Result<String> {
    let buf = capture_env_raw(s)?;
    let end = buf
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| anyhow!("текст окружения не завершён NUL"))?;
    Ok(String::from_utf8_lossy(&buf[..end])
        .trim_matches('\u{55}')
        .trim_end()
        .to_string())
}

/// Состояние многоконной записи раздела (живёт между окнами).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteState {
    /// Байт образа, подтверждённых `nand write` (статус получен).
    pub written: usize,
    /// Остаток диапазона требует стирания перед следующим куском:
    /// смерть окна посреди `nand write` оставляет состояние куска
    /// неопределённым, а перепрограммирование частично записанной
    /// страницы портит её — повтор всегда идёт после `nand erase`
    /// остатка, как перезапуск записи во flasher.sh.
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

/// Один проход окна записи (flasher.sh `write_big_to_flash`, кусками):
/// стереть остаток диапазона (если нужен) и записать сколько успеет
/// кусков по [`NAND_WRITE_CHUNK`] — каждый кусок: `download mem` в ОЗУ
/// (TPL-канал) + media-пакеты + `download get_status` + `nand write` по
/// смещению. Возвращает `true`, когда образ записан целиком;
/// `Ok(false)` — окно исчерпано: плату надо переподключить и вызвать
/// снова (смерть сессии — нормальный конец окна, состояние в `st`);
/// ошибки диска/источника — `Err`.
pub fn write_data_pass<T: Transport>(
    s: &mut AmlogicSession<T>,
    image: &mut (impl Read + Seek),
    off: u32,
    total: usize,
    st: &mut WriteState,
    progress: &dyn Fn(usize),
    budget: Duration,
) -> anyhow::Result<bool> {
    let page = nand::PAGE_SIZE as usize;
    ensure!(total > 0 && total.is_multiple_of(page), "размер образа некратен странице");
    ensure!(off.is_multiple_of(page as u32), "смещение записи некратно странице");
    let start = Instant::now();
    if st.need_erase {
        // стирается только несделанный остаток: подтверждённые куски
        // не трогаются
        let erase_off = off + st.written as u32;
        let erase_len = (total - st.written).next_multiple_of(page) as u32;
        if let Err(e) = s.nand_erase(erase_off, erase_len) {
            log::warn!("amlogic: nand erase {erase_off:#x}+{erase_len:#x} не дожился (окно?): {e}");
            return Ok(false);
        }
        st.need_erase = false;
    }
    let mut buf = vec![0u8; NAND_WRITE_CHUNK];
    while st.written < total {
        if start.elapsed() >= budget {
            return Ok(false);
        }
        let n = (total - st.written).min(NAND_WRITE_CHUNK);
        image.seek(SeekFrom::Start(st.written as u64))?;
        image.read_exact(&mut buf[..n])?;
        let mut cursor = std::io::Cursor::new(&buf[..n]);
        if let Err(e) =
            s.write_nand_chunk(amlogic::RAM_SCRATCH, off + st.written as u32, n, &mut cursor)
        {
            log::warn!(
                "amlogic: кусок {:#x} не дожился (окно?): {e}",
                off + st.written as u32
            );
            // состояние куска во флеше неопределено — перед повтором
            // стираем остаток
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
        head[8..12].copy_from_slice(&sum.to_le_bytes());
        head[12..16].copy_from_slice(&seq.to_le_bytes());
        head[16..18].copy_from_slice(&0x00efu16.to_le_bytes());
        head[18..20].copy_from_slice(&0x0100u16.to_le_bytes());
        head
    }

    const OFF: u32 = 0x0b20_0000;
    /// 256 КиБ: один кусок NAND_WRITE_CHUNK.
    const TOTAL: usize = 0x4_0000;

    /// Полный проход: erase + кусок (TPL arm + 4 media-пакета +
    /// get_status + nand write).
    #[test]
    fn write_data_pass_completes_a_range() {
        let image = vec![0x5au8; TOTAL];
        let mut steps = vec![
            Step::ControlOut(
                req::BULKCMD,
                0,
                2,
                command(&format!("echo; nand erase {OFF:#x} {TOTAL:#x}")),
            ),
            Step::BulkIn(ok_512()),
            Step::ControlOut(
                req::TPL_CMD,
                0,
                1,
                command(&format!("download mem 0x1080000 normal {TOTAL:#x}")),
            ),
            Step::ControlIn(req::TPL_STAT, 0, 0, ok_64()),
        ];
        for seq in 0..(TOTAL / amlogic::MEDIA_CHUNK) {
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
            command(&format!("echo; nand write 0x1080000 {OFF:#x} {TOTAL:#x}")),
        ));
        steps.push(Step::BulkIn(ok_512()));
        let mut s = AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02);
        let mut src = std::io::Cursor::new(image);
        let mut st = WriteState::fresh();
        let done = write_data_pass(
            &mut s,
            &mut src,
            OFF,
            TOTAL,
            &mut st,
            &|_| {},
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(done);
        assert_eq!((st.written, st.need_erase), (TOTAL, false));
        assert_eq!(s.transport().pos, s.transport().steps.len());
    }

    /// Нулевой бюджет: erase уходит, куски не начинаются; второй
    /// проход с нормальным бюджетом НЕ повторяет erase (need_erase
    /// уже снят) и дописывает диапазон.
    #[test]
    fn write_data_pass_budget_end_then_resume() {
        let image = vec![0x11u8; TOTAL];
        let steps = vec![
            Step::ControlOut(
                req::BULKCMD,
                0,
                2,
                command(&format!("echo; nand erase {OFF:#x} {TOTAL:#x}")),
            ),
            Step::BulkIn(ok_512()),
        ];
        let mut s = AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02);
        let mut src = std::io::Cursor::new(image.clone());
        let mut st = WriteState::fresh();
        let done = write_data_pass(
            &mut s, &mut src, OFF, TOTAL, &mut st, &|_| {}, Duration::ZERO,
        )
        .unwrap();
        assert!(!done);
        assert_eq!((st.written, st.need_erase), (0, false));

        // возобновление: erase уже не шлётся
        let mut steps = vec![
            Step::ControlOut(
                req::TPL_CMD,
                0,
                1,
                command(&format!("download mem 0x1080000 normal {TOTAL:#x}")),
            ),
            Step::ControlIn(req::TPL_STAT, 0, 0, ok_64()),
        ];
        for seq in 0..(TOTAL / amlogic::MEDIA_CHUNK) {
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
            command(&format!("echo; nand write 0x1080000 {OFF:#x} {TOTAL:#x}")),
        ));
        steps.push(Step::BulkIn(ok_512()));
        let mut s = AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02);
        let mut src = std::io::Cursor::new(image);
        let done = write_data_pass(
            &mut s,
            &mut src,
            OFF,
            TOTAL,
            &mut st,
            &|_| {},
            Duration::from_secs(60),
        )
        .unwrap();
        assert!(done);
        assert_eq!(st.written, TOTAL);
    }

    /// Смерть сессии посреди куска: Ok(false) + need_erase — следующий
    /// проход повторяет erase остатка, а не перепрограммирует
    /// неопределённый кусок.
    #[test]
    fn write_data_pass_marks_erase_after_a_mid_chunk_death() {
        let image = vec![0x22u8; TOTAL];
        let steps = vec![Step::ControlOut(
            req::BULKCMD,
            0,
            2,
            command(&format!("echo; nand erase {OFF:#x} {TOTAL:#x}")),
        )];
        // сценарий обрывается сразу после erase — первый же кусок умрёт
        let mut s = AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02);
        let mut src = std::io::Cursor::new(image);
        let mut st = WriteState::fresh();
        let done = write_data_pass(
            &mut s, &mut src, OFF, TOTAL, &mut st, &|_| {}, Duration::from_secs(60),
        )
        .unwrap();
        assert!(!done);
        assert_eq!((st.written, st.need_erase), (0, true));
    }
}
