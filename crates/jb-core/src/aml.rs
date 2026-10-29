//! Доменные операции для Amlogic-мин Capsula (A113X): съём окружения
//! u-boot и полный однопроходный захват NAND. Протокол — крейт
//! `amlogic`; сценарий записи userdata живёт в бэкенде jb-cli.

pub mod backup;

use amlogic::{AmlogicSession, Transport};
use anyhow::anyhow;

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
