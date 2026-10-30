//! Чекпоинт-захват A113X по окнам (flasher.sh-модель): у стокового
//! u-boot одно download-окно ~250–350 мс на включение, поэтому полный
//! захват не помещается в одну сессию архитектурно. Каждый
//! [`capture_pass`] снимает сколько успеет в пределах бюджета окна и
//! сохраняет чекпоинт на диск (манифест + `.partial`-файлы — и есть
//! состояние); исчерпанное окно возвращает [`Pass::Interrupted`], и
//! вызывающий просит переподключить плату, ждёт её на шине и
//! продолжает с остановившегося смещения.
//!
//! Чтение — как у flasher.sh: `nand read <ram> <off> <n>` (shell) +
//! `upload mem` (стрим) по смещениям логического пространства, что и
//! делает возможным докачку: `upload store` возобновлению по смещению
//! не подлежит. Манифест (`manifest.json`) аутентифицирует сохранённые
//! файлы; формат каталога — `backup/amlogic-<время>-<pid>-<n>/` со
//! схемой 1, у каждого запуска свой каталог.

use crate::backup_store::{file_sha256, safe_capture_name, CaptureDirectory};
use crate::session::{Progress, ProgressFn};
use amlogic::{nand, AmlogicSession, Transport};
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Кусок чтения одного окна. Замер на живой плате (октябрь 2026):
/// стена окна ~250–350 мс от открытия убивает сессию посреди
/// `nand read` на 2 МиБ (в захват не падает ни байта), а 1 МиБ
/// (`nand read` ≈ 70 мс + стрим ≈ 40 мс) помещается. Бюджет
/// проверяется между кусками.
pub const READ_STAGE: usize = 0x10_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Running,
    Failed,
    Complete,
    Warnings,
}

/// Итог одного прохода окна.
#[derive(Debug)]
pub enum Pass {
    /// Всё снято, манифест сфинализирован и проверен.
    Done(BackupReport),
    /// Окно исчерпано (бюджет или смерть сессии); чекпоинт сохранён —
    /// переподключите плату и вызовите [`capture_pass`] снова.
    Interrupted(String),
}

#[derive(Debug)]
pub struct BackupReport {
    pub path: PathBuf,
    pub status: Status,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileRecord {
    name: String,
    expected: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    physical_size: Option<u64>,
    actual: u64,
    sha256: String,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: u32,
    profile: String,
    nand_size: u32,
    page_size: u32,
    oob_size: u32,
    device_read_passes: u32,
    status: Status,
    files: Vec<FileRecord>,
    error: Option<String>,
}
struct Layout<'a> {
    partitions: &'a [(&'a str, u32, u32)],
    reserved: &'a [(&'a str, u32, u32)],
    nand_size: u32,
}
fn a113x() -> Layout<'static> {
    Layout {
        partitions: amlogic::PARTITIONS,
        reserved: nand::RESERVED,
        nand_size: nand::NAND_SIZE,
    }
}

/// Устройство в рамках одного окна. Все методы короткие; ошибки
/// транспорта — нормальный конец окна, их перехватывает `drive`.
trait Device {
    fn partition_size(&mut self, name: &str, physical: usize) -> anyhow::Result<usize>;
    fn env(&mut self) -> anyhow::Result<Vec<u8>>;
    /// Прочитать диапазон NAND в `out` начиная со смещения `off`
    /// (главное пространство). `len` — в байтах ФАЙЛА: для raw=false
    /// это главные байты, для raw=true — байты вместе с OOB
    /// (`страница+OOB`-кратно); `off` всегда в главных байтах.
    /// stop проверяется между кусками; возвращает дописанные байты
    /// файла.
    fn read_range(
        &mut self,
        off: u32,
        len: usize,
        raw: bool,
        out: &mut dyn Write,
        progress: &dyn Fn(usize),
        stop: &dyn Fn() -> bool,
    ) -> anyhow::Result<usize>;
}
impl<T: Transport> Device for AmlogicSession<T> {
    fn partition_size(&mut self, name: &str, _physical: usize) -> anyhow::Result<usize> {
        Ok(self.partition_readable_size(name)?)
    }
    fn env(&mut self) -> anyhow::Result<Vec<u8>> {
        super::capture_env_raw(self)
    }
    fn read_range(
        &mut self,
        off: u32,
        len: usize,
        raw: bool,
        out: &mut dyn Write,
        progress: &dyn Fn(usize),
        stop: &dyn Fn() -> bool,
    ) -> anyhow::Result<usize> {
        let file_page = if raw {
            nand::raw_bytes(nand::PAGE_SIZE)?
        } else {
            nand::PAGE_SIZE as usize
        };
        ensure!(len.is_multiple_of(file_page), "некратный странице кусок чтения");
        let stage_cap = if raw {
            nand::raw_bytes(READ_STAGE as u32)?
        } else {
            READ_STAGE
        };
        let mut appended = 0usize;
        while appended < len {
            if stop() {
                break;
            }
            let stage = (len - appended).min(stage_cap);
            // главный диапазон этого куска (для raw — пересчёт из
            // файловых страниц)
            let (main_off, main_len) = if raw {
                (
                    off + (appended / file_page * nand::PAGE_SIZE as usize) as u32,
                    stage / file_page * nand::PAGE_SIZE as usize,
                )
            } else {
                (off + appended as u32, stage)
            };
            let chunk = if raw {
                self.read_raw_nand_chunk(main_off, main_len as u32)?
            } else {
                self.read_nand_chunk(main_off, main_len as u32)?
            };
            out.write_all(&chunk)?;
            appended += chunk.len();
            progress(appended);
        }
        Ok(appended)
    }
}

/// Создать каталог захвата и стартовый манифест; каталог возвращается
/// вызывающему и переоткрывается каждым [`capture_pass`].
pub fn start(parent: &Path) -> anyhow::Result<PathBuf> {
    start_with(parent, &a113x())
}

fn start_with(parent: &Path, layout: &Layout<'_>) -> anyhow::Result<PathBuf> {
    let dir = CaptureDirectory::create(parent, "amlogic")?;
    let m = Manifest {
        schema: 1,
        profile: "capsula-mini-a113x".into(),
        nand_size: layout.nand_size,
        page_size: nand::PAGE_SIZE,
        oob_size: nand::OOB_SIZE,
        device_read_passes: 1,
        status: Status::Running,
        files: vec![],
        error: None,
    };
    save_manifest(&dir, &m)?;
    Ok(dir.path().into())
}

/// Один проход окна: продолжить захват из чекпоинта в `dir_path`.
/// `budget` — настенные часы окна (от входа в функцию); по их
/// исчерпанию или на ошибке транспорта возвращается
/// [`Pass::Interrupted`] с сохранённым чекпоинтом.
pub fn capture_pass<T: Transport>(
    session: &mut AmlogicSession<T>,
    dir_path: &Path,
    progress: ProgressFn,
    budget: Duration,
) -> anyhow::Result<Pass> {
    let dir = CaptureDirectory::open(dir_path)?;
    let mut m: Manifest = serde_json::from_slice(&std::fs::read(dir_path.join("manifest.json"))?)
        .context("манифест захвата не читается")?;
    ensure!(
        m.schema == 1 && m.profile == "capsula-mini-a113x",
        "неподдерживаемая схема захвата"
    );
    ensure!(
        m.status == Status::Running,
        "захват уже завершён, продолжать нечего"
    );
    let start = Instant::now();
    let stop = || start.elapsed() >= budget;
    let outcome = drive(session, &dir, &mut m, progress, &stop, &a113x());
    match outcome {
        Ok(()) => {
            m.status = if m.files.iter().any(|f| f.actual != f.expected) {
                Status::Warnings
            } else {
                Status::Complete
            };
            validate(dir.path(), &m, &a113x())?;
            let sums = m
                .files
                .iter()
                .map(|f| format!("{}  {}\n", f.sha256, f.name))
                .collect::<String>();
            dir.write_file("SHA256SUMS.txt", sums.as_bytes())?;
            save_manifest(&dir, &m)?;
            Ok(Pass::Done(BackupReport {
                path: dir.path().into(),
                status: m.status,
            }))
        }
        Err(DriveError::Window(reason)) => {
            save_manifest(&dir, &m)?;
            Ok(Pass::Interrupted(reason))
        }
        Err(DriveError::Fatal(error)) => {
            m.status = Status::Failed;
            m.error = Some(format!("{error:#}"));
            save_manifest(&dir, &m)?;
            Err(error)
        }
    }
}

/// Ошибки прохода: конец окна (норма, чекпоинт сохраняется) против
/// фатальной (диск/манифест — статус Failed).
enum DriveError {
    Window(String),
    Fatal(anyhow::Error),
}
impl DriveError {
    fn fatal<E: Into<anyhow::Error>>(e: E) -> Self {
        DriveError::Fatal(e.into())
    }
}

fn find_record<'a>(m: &'a Manifest, base: &str) -> Option<&'a FileRecord> {
    let partial = format!("{base}.partial");
    m.files
        .iter()
        .find(|f| f.name == base || f.name == partial)
}

fn partial_len(dir: &CaptureDirectory, partial: &str) -> u64 {
    std::fs::symlink_metadata(dir.path().join(partial))
        .map(|md| md.len())
        .unwrap_or(0)
}

/// Чекпоинт-запись по факту на диске: хеш + фактический размер;
/// полный файл публикуется (`.partial` → итоговое имя). Идемпотентна:
/// уже опубликованный файл переотмечается без переименования.
fn record(
    dir: &CaptureDirectory,
    m: &mut Manifest,
    base: &str,
    expected: u64,
    physical_size: Option<u64>,
) -> anyhow::Result<()> {
    let partial = format!("{base}.partial");
    let published = std::fs::symlink_metadata(dir.path().join(base)).is_ok();
    let actual = if published {
        std::fs::symlink_metadata(dir.path().join(base))?.len()
    } else {
        partial_len(dir, &partial)
    };
    ensure!(actual <= expected, "файл {base} больше ожидаемого");
    ensure!(
        published || std::fs::symlink_metadata(dir.path().join(&partial))?.is_file(),
        "нет файла чекпоинта {partial}"
    );
    let source = if published { base } else { &partial };
    let hash = file_sha256(&dir.path().join(source))?;
    let rec = FileRecord {
        name: if actual == expected {
            base.to_string()
        } else {
            partial.clone()
        },
        expected,
        physical_size,
        actual,
        sha256: hash,
    };
    match m
        .files
        .iter()
        .position(|f| f.name == base || f.name == partial)
    {
        Some(i) => m.files[i] = rec,
        None => m.files.push(rec),
    }
    if actual == expected && !published {
        dir.publish_partial(&partial, base)?;
    }
    save_manifest(dir, m)
}

fn bytes(dir: &CaptureDirectory, m: &mut Manifest, name: &str, data: &[u8]) -> anyhow::Result<()> {
    let partial = format!("{name}.partial");
    let mut f = dir.create_file(&partial)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    record(dir, m, name, data.len() as u64, None)
}

fn environment_text(raw: &[u8]) -> anyhow::Result<&str> {
    ensure!(raw.len() == amlogic::ENV_SIZE, "короткий снимок окружения");
    let end = raw
        .iter()
        .position(|b| *b == 0)
        .context("окружение не завершено NUL")?;
    let text = std::str::from_utf8(&raw[..end]).context("окружение не в UTF-8")?;
    ensure!(
        text.lines().any(|line| line
            .split_once('=')
            .is_some_and(|(key, _)| !key.is_empty() && !key.chars().any(char::is_whitespace))),
        "некорректный экспорт окружения: нет записей key=value"
    );
    Ok(text)
}

/// Описание одного элемента захвата (раздел, reserved, сырой дамп).
struct Item<'a> {
    base: &'a str,
    label: &'a str,
    expected: u64,
    off: u32,
    raw: bool,
    physical: Option<u64>,
}

/// Один элемент захвата: докачать от чекпоинта до конца или до конца
/// бюджета.
fn capture_item(
    dev: &mut impl Device,
    dir: &CaptureDirectory,
    m: &mut Manifest,
    progress: ProgressFn,
    stop: &dyn Fn() -> bool,
    item: Item<'_>,
) -> Result<(), DriveError> {
    let Item {
        base,
        label,
        expected,
        off,
        raw,
        physical,
    } = item;
    // Уже готово (включая «полный, но не опубликованный» с прошлого
    // окна) — только публикуем.
    if let Some(r) = find_record(m, base) {
        if r.actual == r.expected {
            record(dir, m, base, expected, physical)
                .map_err(DriveError::Fatal)?;
            return Ok(());
        }
    }
    if stop() {
        return Err(DriveError::Window(format!(
            "окно исчерпано перед {label}"
        )));
    }
    let partial = format!("{base}.partial");
    let cur = partial_len(dir, &partial);
    if find_record(m, base).is_none() {
        if cur == 0 {
            // create_new: первый кусок этого элемента
            dir.create_file(&partial).map_err(DriveError::fatal)?;
        }
        record(dir, m, base, expected, physical).map_err(DriveError::Fatal)?;
    }
    progress(Progress::TransferStart {
        name: label.into(),
        bytes: expected,
    });
    // смещение устройства в главных байтах; длина — в файловых байтах
    let raw_page = nand::raw_bytes(nand::PAGE_SIZE).map_err(DriveError::fatal)? as u64;
    let dev_off = if raw {
        off + (cur / raw_page * nand::PAGE_SIZE as u64) as u32
    } else {
        off + cur as u32
    };
    let read = (|| -> Result<(), DriveError> {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.path().join(&partial))
            .map_err(|e| DriveError::Fatal(e.into()))?;
        let got = dev.read_range(
            dev_off,
            (expected - cur) as usize,
            raw,
            &mut f,
            &|n| {
                progress(Progress::TransferProgress {
                    name: label.into(),
                    done: cur + n as u64,
                    total: expected,
                })
            },
            stop,
        );
        // принятый префикс синхронизируется даже при ошибке USB
        let synced = f.sync_all();
        match (got, synced) {
            (Ok(_), Ok(())) => Ok(()),
            (Ok(_), Err(e)) | (_, Err(e)) => Err(DriveError::Fatal(e.into())),
            (Err(dev_err), Ok(())) => Err(DriveError::Window(format!(
                "{label}: чтение прервано (окно?): {dev_err:#}"
            ))),
        }
    })();
    match read {
        Ok(()) => {}
        // конец окна: чекпоинт префикса всё равно фиксируется
        Err(e @ DriveError::Window(_)) => {
            let _ = record(dir, m, base, expected, physical);
            return Err(e);
        }
        Err(e) => return Err(e),
    }
    // чекпоинт по факту на диске: и после успеха, и после смерти окна
    let on_disk = partial_len(dir, &partial);
    record(dir, m, base, expected, physical).map_err(DriveError::Fatal)?;
    progress(Progress::TransferDone {
        name: label.into(),
    });
    if on_disk < expected {
        Err(DriveError::Window(format!(
            "{label}: снято {on_disk:#x} из {expected:#x} — окно исчерпано"
        )))
    } else {
        Ok(())
    }
}

fn drive(
    dev: &mut impl Device,
    dir: &CaptureDirectory,
    m: &mut Manifest,
    progress: ProgressFn,
    stop: &dyn Fn() -> bool,
    layout: &Layout<'_>,
) -> Result<(), DriveError> {
    // 1. Окружение — раз на захват, до разделов.
    if find_record(m, "env.txt").is_none() {
        if stop() {
            return Err(DriveError::Window("окно исчерпано перед окружением".into()));
        }
        progress(Progress::Step("Amlogic: съём окружения u-boot".into()));
        let env = dev.env().map_err(|e| {
            DriveError::Window(format!("съём окружения не удался (окно?): {e:#}"))
        })?;
        if env.len() != amlogic::ENV_SIZE {
            return Err(DriveError::fatal(anyhow::anyhow!("короткий снимок окружения")));
        }
        bytes(dir, m, "env-export.bin", &env).map_err(DriveError::Fatal)?;
        let text = environment_text(&env).map_err(DriveError::Fatal)?;
        bytes(dir, m, "env.txt", text.as_bytes()).map_err(DriveError::Fatal)?;
    }

    // 2. Разделы — по логической ёмкости (store size), докачка по
    // смещениям `nand read` (бед-блоки u-boot обходит сам).
    for &(name, off, size) in layout.partitions {
        let base = format!("{name}.bin");
        let expected = match find_record(m, &base) {
            Some(r) => r.expected,
            None => {
                if stop() {
                    return Err(DriveError::Window(format!(
                        "окно исчерпано перед опросом размера {name}"
                    )));
                }
                let readable = dev.partition_size(name, size as usize).map_err(|e| {
                    DriveError::Window(format!("запрос логического размера {name}: {e:#}"))
                })?;
                if !(readable > 0 && readable <= size as usize) {
                    return Err(DriveError::Window(format!(
                        "некорректный логический размер {name} ({readable:#x})"
                    )));
                }
                readable as u64
            }
        };
        if expected < size as u64 {
            progress(Progress::Step(format!(
                "Amlogic: {name} логический размер {expected:#x}, физический {size:#x} \
                 (бед-блоки исключены)"
            )));
        }
        capture_item(
            dev,
            dir,
            m,
            progress,
            stop,
            Item {
                base: &base,
                label: name,
                expected,
                off,
                raw: false,
                physical: Some(size as u64),
            },
        )?;
    }

    // 3. Зарезервированные области — по адресам (device-уникальны).
    for &(name, off, size) in layout.reserved {
        let base = format!("reserved-{name}.bin");
        progress(Progress::Step(format!(
            "Amlogic: зарезервированная область {name}"
        )));
        capture_item(
            dev,
            dir,
            m,
            progress,
            stop,
            Item {
                base: &base,
                label: &base,
                expected: size as u64,
                off,
                raw: false,
                physical: None,
            },
        )?;
    }

    // 4. Полный сырой дамп с OOB — постранично, докачка по страницам.
    let expected_raw = nand::raw_bytes(layout.nand_size).map_err(DriveError::fatal)? as u64;
    progress(Progress::Step("Amlogic: полный сырой дамп NAND".into()));
    capture_item(
        dev,
        dir,
        m,
        progress,
        stop,
        Item {
            base: "nand-full.raw.bin",
            label: "nand-full.raw.bin",
            expected: expected_raw,
            off: 0,
            raw: true,
            physical: None,
        },
    )?;
    Ok(())
}

/// Проверить записанный инвентарь, геометрию, размеры и контрольные
/// суммы на диске — без обращения к USB.
pub fn verify(path: &Path) -> anyhow::Result<BackupReport> {
    let m = verify_layout(path, &a113x())?;
    Ok(BackupReport {
        path: path.into(),
        status: m.status,
    })
}
fn verify_layout(path: &Path, layout: &Layout<'_>) -> anyhow::Result<Manifest> {
    ensure!(
        std::fs::symlink_metadata(path)?.file_type().is_dir(),
        "захват — не каталог"
    );
    let mp = path.join("manifest.json");
    let meta = std::fs::symlink_metadata(&mp)?;
    ensure!(
        meta.file_type().is_file() && meta.len() <= 1024 * 1024,
        "некорректный файл манифеста"
    );
    let m: Manifest = serde_json::from_slice(&std::fs::read(mp)?)?;
    validate(path, &m, layout)?;
    Ok(m)
}
fn validate(path: &Path, m: &Manifest, layout: &Layout<'_>) -> anyhow::Result<()> {
    ensure!(
        m.schema == 1
            && m.profile == "capsula-mini-a113x"
            && m.nand_size == layout.nand_size
            && m.page_size == nand::PAGE_SIZE
            && m.oob_size == nand::OOB_SIZE
            && m.device_read_passes == 1,
        "неподдерживаемая геометрия/схема захвата"
    );
    ensure!(
        matches!(m.status, Status::Complete | Status::Warnings) && m.error.is_none(),
        "захват не завершился"
    );
    let mut expected = std::collections::BTreeMap::new();
    expected.insert("env-export.bin".into(), (amlogic::ENV_SIZE as u64, false));
    // Текстовый экспорт выводится локально и ограничен бинарным
    // окружением.
    expected.insert("env.txt".into(), (0, false));
    for &(name, _, size) in layout.partitions {
        expected.insert(format!("{name}.bin"), (size as u64, true));
    }
    for &(name, _, size) in layout.reserved {
        expected.insert(format!("reserved-{name}.bin"), (size as u64, false));
    }
    expected.insert(
        "nand-full.raw.bin".into(),
        (nand::raw_bytes(layout.nand_size)? as u64, false),
    );
    let mut short = false;
    for file in &m.files {
        safe_capture_name(&file.name)?;
        let name = file.name.strip_suffix(".partial").unwrap_or(&file.name);
        let (size, can_short) = expected
            .remove(name)
            .context("неожиданный/дублирующийся файл захвата")?;
        if name == "env.txt" {
            ensure!(
                file.expected < amlogic::ENV_SIZE as u64,
                "переполнен текст окружения"
            );
        } else if let Some(physical) = file.physical_size {
            ensure!(
                can_short && physical == size && file.expected > 0 && file.expected <= physical,
                "некорректный физический/логический размер {name}"
            );
        } else {
            ensure!(file.expected == size, "неожиданный размер {name}");
        }
        ensure!(
            file.physical_size.is_none() || can_short,
            "физический размер у не-раздела {name}"
        );
        let partial = file.actual < file.expected;
        ensure!(
            file.actual <= file.expected && (!partial || can_short),
            "некорректный размер захвата {name}"
        );
        ensure!(
            file.name.ends_with(".partial") == partial,
            "некорректный статус частичного файла"
        );
        short |= partial;
        let p = path.join(&file.name);
        let meta = std::fs::symlink_metadata(&p)?;
        ensure!(
            meta.file_type().is_file() && meta.len() == file.actual,
            "некорректный файл захвата {}",
            file.name
        );
        ensure!(
            file_sha256(&p)? == file.sha256,
            "контрольная сумма {} не сошлась",
            file.name
        );
    }
    ensure!(expected.is_empty(), "в захвате нет части файлов инвентаря");
    let env = std::fs::read(path.join("env-export.bin"))?;
    let text = environment_text(&env)?;
    ensure!(
        std::fs::read(path.join("env.txt"))? == text.as_bytes(),
        "текст окружения отличается от сырого экспорта"
    );
    ensure!(
        (m.status == Status::Warnings) == short,
        "несогласованный статус завершения"
    );
    Ok(())
}

fn save_manifest(dir: &CaptureDirectory, m: &Manifest) -> anyhow::Result<()> {
    dir.replace_file("manifest.json", &serde_json::to_vec_pretty(m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const PARTS: &[(&str, u32, u32)] = &[("boot", 0, 8)];
    const REGIONS: &[(&str, u32, u32)] = &[("keys", 8, 4)];
    fn layout() -> Layout<'static> {
        Layout {
            partitions: PARTS,
            reserved: REGIONS,
            nand_size: 4096,
        }
    }
    struct Fake {
        calls: RefCell<Vec<String>>,
        fail: bool,
        environment: Option<Vec<u8>>,
        readable: Option<usize>,
        /// Сколько байт ФАЙЛА отдаёт read_range за один вызов
        /// (короткий ответ = окно умерло посреди элемента).
        chunk: usize,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail: false,
                environment: None,
                readable: None,
                chunk: usize::MAX,
            }
        }
    }
    impl Device for Fake {
        fn partition_size(&mut self, name: &str, _physical: usize) -> anyhow::Result<usize> {
            self.calls.borrow_mut().push(format!("size:{name}"));
            Ok(self.readable.unwrap_or(8))
        }
        fn env(&mut self) -> anyhow::Result<Vec<u8>> {
            self.calls.borrow_mut().push("env".into());
            Ok(self.environment.clone().unwrap_or_else(|| {
                let mut data = vec![0; amlogic::ENV_SIZE];
                data[..4].copy_from_slice(b"a=b\n");
                data
            }))
        }
        fn read_range(
            &mut self,
            off: u32,
            len: usize,
            raw: bool,
            out: &mut dyn Write,
            _: &dyn Fn(usize),
            _: &dyn Fn() -> bool,
        ) -> anyhow::Result<usize> {
            self.calls.borrow_mut().push(format!("read:{off}:{raw}"));
            anyhow::ensure!(!self.fail, "USB disconnected");
            let n = len.min(self.chunk);
            out.write_all(&vec![1u8; n])?;
            Ok(n)
        }
    }
    fn parent() -> CaptureDirectory {
        CaptureDirectory::create(&std::env::temp_dir(), "aml-test").unwrap()
    }
    fn begin(parent: &CaptureDirectory) -> PathBuf {
        start_with(parent.path(), &layout()).unwrap()
    }
    fn run_pass(
        dev: &mut impl Device,
        dir: &Path,
    ) -> anyhow::Result<Pass> {
        capture_pass_inner(dev, dir, &|_| {}, Duration::from_secs(3600), &layout())
    }
    /// Тестовый вход: как capture_pass, но на Fake-устройстве и с
    /// тестовой геометрией.
    fn capture_pass_inner(
        dev: &mut impl Device,
        dir_path: &Path,
        progress: ProgressFn,
        budget: Duration,
        layout: &Layout<'_>,
    ) -> anyhow::Result<Pass> {
        let dir = CaptureDirectory::open(dir_path)?;
        let mut m: Manifest =
            serde_json::from_slice(&std::fs::read(dir_path.join("manifest.json"))?)?;
        ensure!(m.status == Status::Running, "захват уже завершён");
        let start = Instant::now();
        let stop = move || start.elapsed() >= budget;
        match drive(dev, &dir, &mut m, progress, &stop, layout) {
            Ok(()) => {
                m.status = if m.files.iter().any(|f| f.actual != f.expected) {
                    Status::Warnings
                } else {
                    Status::Complete
                };
                validate(dir.path(), &m, layout)?;
                let sums = m
                    .files
                    .iter()
                    .map(|f| format!("{}  {}\n", f.sha256, f.name))
                    .collect::<String>();
                dir.write_file("SHA256SUMS.txt", sums.as_bytes())?;
                save_manifest(&dir, &m)?;
                Ok(Pass::Done(BackupReport {
                    path: dir.path().into(),
                    status: m.status,
                }))
            }
            Err(DriveError::Window(reason)) => {
                save_manifest(&dir, &m)?;
                Ok(Pass::Interrupted(reason))
            }
            Err(DriveError::Fatal(error)) => {
                m.status = Status::Failed;
                m.error = Some(format!("{error:#}"));
                save_manifest(&dir, &m)?;
                Err(error)
            }
        }
    }

    #[test]
    fn complete_capture_in_one_pass() {
        let parent = parent();
        let dir = begin(&parent);
        let mut dev = Fake::new();
        let report = run_pass(&mut dev, &dir).unwrap();
        let Pass::Done(report) = report else { panic!("не Done") };
        assert_eq!(report.status, Status::Complete);
        assert_eq!(
            *dev.calls.borrow(),
            [
                "env",
                "size:boot",
                "read:0:false",
                "read:8:false",
                "read:0:true"
            ]
        );
        let manifest = verify_layout(&report.path, &layout()).unwrap();
        assert_eq!(manifest.files.len(), 5);
        std::fs::write(report.path.join("boot.bin"), b"corrupt!").unwrap();
        assert!(verify_layout(&report.path, &layout()).is_err());
        std::fs::remove_dir_all(parent.path()).unwrap();
    }

    #[test]
    fn interrupted_pass_keeps_prefix_and_resume_completes() {
        let parent = parent();
        let dir = begin(&parent);
        // Окно 1: чтение раздела обрывается на 3 байтах.
        let mut dev = Fake::new();
        dev.chunk = 3;
        match run_pass(&mut dev, &dir).unwrap() {
            Pass::Interrupted(reason) => {
                assert!(reason.contains("снято"), "{reason}");
            }
            Pass::Done(_) => panic!("обрыв не распознан"),
        }
        assert!(!dir.join("boot.bin").exists());
        assert_eq!(std::fs::read(dir.join("boot.bin.partial")).unwrap(), vec![1; 3]);
        let m: Manifest =
            serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(m.status, Status::Running);
        // Окно 2: Healthy-сессия докачивает с чекпоинта.
        let mut dev = Fake::new();
        match run_pass(&mut dev, &dir).unwrap() {
            Pass::Done(report) => {
                assert_eq!(report.status, Status::Complete);
                assert_eq!(
                    std::fs::read(report.path.join("boot.bin")).unwrap(),
                    vec![1; 8]
                );
                assert!(!report.path.join("boot.bin.partial").exists());
            }
            Pass::Interrupted(r) => panic!("докачка не завершилась: {r}"),
        }
        std::fs::remove_dir_all(parent.path()).unwrap();
    }

    #[test]
    fn usb_error_keeps_received_prefix_as_a_window_end() {
        let parent = parent();
        let dir = begin(&parent);
        let mut dev = Fake::new();
        dev.fail = true;
        match run_pass(&mut dev, &dir).unwrap() {
            Pass::Interrupted(reason) => assert!(reason.contains("USB"), "{reason}"),
            Pass::Done(_) => panic!("ошибка транспорта не должна давать Done"),
        }
        // env успел (он до разделов), раздел не публикуется
        assert!(dir.join("env.txt").is_file());
        assert!(dir.join("boot.bin.partial").is_file());
        let m: Manifest =
            serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(m.status, Status::Running);
        std::fs::remove_dir_all(parent.path()).unwrap();
    }

    #[test]
    fn complete_logical_partition_keeps_physical_size_without_padding() {
        let parent = parent();
        let dir = begin(&parent);
        let mut dev = Fake::new();
        dev.readable = Some(6);
        match run_pass(&mut dev, &dir).unwrap() {
            Pass::Done(report) => {
                assert_eq!(report.status, Status::Complete);
                let manifest = verify_layout(&report.path, &layout()).unwrap();
                let part = manifest
                    .files
                    .iter()
                    .find(|f| f.name == "boot.bin")
                    .unwrap();
                assert_eq!(part.expected, 6);
                assert_eq!(part.actual, 6);
                assert_eq!(part.physical_size, Some(8));
                assert_eq!(
                    std::fs::read(report.path.join("boot.bin")).unwrap(),
                    vec![1; 6]
                );
            }
            Pass::Interrupted(r) => panic!("не прошло: {r}"),
        }
        std::fs::remove_dir_all(parent.path()).unwrap();
    }

    #[test]
    fn invalid_environment_fails_hard_and_keeps_raw_snapshot() {
        for prefix in [b"".as_slice(), b"garbage", b"\xff=x"] {
            let parent = parent();
            let dir = begin(&parent);
            let mut dev = Fake::new();
            let mut raw = vec![0; amlogic::ENV_SIZE];
            raw[..prefix.len()].copy_from_slice(prefix);
            dev.environment = Some(raw.clone());
            assert!(run_pass(&mut dev, &dir).is_err());
            let m: Manifest =
                serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap())
                    .unwrap();
            assert_eq!(m.status, Status::Failed);
            assert_eq!(std::fs::read(dir.join("env-export.bin")).unwrap(), raw);
            assert!(!dir.join("env.txt").exists());
            assert!(*dev.calls.borrow() == ["env"]);
            std::fs::remove_dir_all(parent.path()).unwrap();
        }
    }

    #[test]
    fn verifier_rejects_invalid_environment_even_with_matching_checksums() {
        let parent = parent();
        let dir = begin(&parent);
        let mut dev = Fake::new();
        let report = match run_pass(&mut dev, &dir).unwrap() {
            Pass::Done(r) => r,
            Pass::Interrupted(r) => panic!("не прошло: {r}"),
        };
        let mp = report.path.join("manifest.json");
        let mut m: Manifest = serde_json::from_slice(&std::fs::read(&mp).unwrap()).unwrap();
        for f in &mut m.files {
            let data = match f.name.as_str() {
                "env-export.bin" => Some(vec![0; amlogic::ENV_SIZE]),
                "env.txt" => Some(Vec::new()),
                _ => None,
            };
            if let Some(data) = data {
                std::fs::write(report.path.join(&f.name), &data).unwrap();
                f.expected = data.len() as u64;
                f.actual = f.expected;
                f.sha256 = file_sha256(&report.path.join(&f.name)).unwrap();
            }
        }
        std::fs::write(&mp, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(verify_layout(&report.path, &layout()).is_err());
        std::fs::remove_dir_all(parent.path()).unwrap();
    }

    #[test]
    fn verifier_rejects_missing_inventory_and_unsafe_names() {
        let parent = parent();
        let dir = begin(&parent);
        let mut dev = Fake::new();
        let report = match run_pass(&mut dev, &dir).unwrap() {
            Pass::Done(r) => r,
            Pass::Interrupted(r) => panic!("не прошло: {r}"),
        };
        let path = report.path.join("manifest.json");
        let original = std::fs::read(&path).unwrap();
        let mut m: Manifest = serde_json::from_slice(&original).unwrap();
        m.files.pop();
        std::fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(verify_layout(&report.path, &layout()).is_err());
        let mut m: Manifest = serde_json::from_slice(&original).unwrap();
        m.files[0].name = "../outside".into();
        std::fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(verify_layout(&report.path, &layout()).is_err());
        std::fs::remove_dir_all(parent.path()).unwrap();
    }

    #[test]
    fn second_pass_on_a_done_capture_is_refused() {
        let parent = parent();
        let dir = begin(&parent);
        let mut dev = Fake::new();
        assert!(matches!(run_pass(&mut dev, &dir).unwrap(), Pass::Done(_)));
        let mut dev = Fake::new();
        assert!(run_pass(&mut dev, &dir).is_err());
        std::fs::remove_dir_all(parent.path()).unwrap();
    }
}
