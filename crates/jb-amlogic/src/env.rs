//! Capturing the u-boot environment of the Mini — the device identity
//! (the `deviceid` key) and the boot state live there.

use amlogic::{AmlogicSession, Transport};
use anyhow::anyhow;

/// Capture the raw text export of the u-boot environment. bulkcmd
/// replies go to the serial console, so the environment is exported
/// into DRAM and read back over USB (flasher.sh `capture_env`). The
/// buffer is zeroed first — otherwise the tail carries the 0x55 wall
/// of the BL2 memory test.
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

/// Decode an environment snapshot as text.
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
