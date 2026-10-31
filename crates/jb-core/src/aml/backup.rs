//! Чекпоинт-захват A113X (flasher.sh-модель): стоковый u-boot поднимает
//! download-окно на каждом включении (identify принимается ~450 мс),
//! но ПОСЛЕ установления сессии живёт, пока идёт работа, — таймер
//! простоя (~300–450 мс) сбрасывается identify-keepalive между кусками
//! (замер 2026-10-31: 160 МиБ одной сессией, 20 × 8 МиБ).
//!
//! Каждый [`capture_pass`] снимает сколько успеет за одну сессию и
//! сохраняет чекпоинт на диск (манифест + `.partial`-файлы — и есть
//! состояние); смерть сессии возвращает [`Pass::Interrupted`], и
//! вызывающий просит переподключить плату и продолжает с остановившегося
//! смещения. Никаких искусственных бюджетов: окно кончается тогда,
//! когда умирает сессия.
//!
//! Чтение — как у flasher.sh: `nand read <ram> <off> <n>` (shell) +
//! `upload mem` (стрим) по смещениям логического пространства, что и
//! делает возможной докачку: `upload store` возобновлению по смещению
//! не подлежит. Таблица разделов — с устройства: `imgread dtb` читает
//! DTB активного boot-образа (двойным чтением со сверкой), парсер
//! (крейт `amlogic::fdt`) выдаёт имена/размеры, сверенные с известной
//! картой платформы. На Mini нет GPT — DTB и есть таблица разделов.
//!
//! Манифест (`manifest.json`, schema 2) аутентифицирует сохранённые
//! файлы и хранит снятую с устройства разметку; формат каталога —
//! `backup/amlogic-<время>-<pid>-<n>/`, у каждого запуска свой каталог.

use crate::backup_store::{file_sha256, safe_capture_name, CaptureDirectory};
use crate::session::{Progress, ProgressFn};
use amlogic::{fdt, nand, AmlogicSession, Transport};
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Имена обычных разделов в порядке логической разметки (DTB
/// nand_partition, порядок вендора; bootloader и AML-reserved идут
/// перед ними и в DTB не входят).
pub const NORMAL_PARTITIONS: &[&str] = &[
    "tpl", "misc", "boot_a", "boot_b", "system_a", "system_b", "data",
];

/// Размер fip/bootloader на известной платформе (платформенный гейт).
pub const FIP_SIZE: u32 = 0x20_0000;
/// Начало tpl на известной платформе: bootloader (2 МиБ) + диапазон
/// AML-reserved областей (6 МиБ).
pub const PLATFORM_TPL_START: u32 = 0x80_0000;
/// Размер tpl, когда DTB задаёт его нулём («до следующего»).
const TPL_SIZE: u32 = 0x80_0000;

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
    /// Сессия умерла (окно кончилось); чекпоинт сохранён —
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

/// Раздел, снятый с устройства (device-истина на момент захвата).
#[derive(Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PartitionRecord {
    pub name: String,
    pub off: u32,
    pub physical_size: u32,
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
    /// Снятая с устройства разметка (после DTB-шага).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    layout: Vec<PartitionRecord>,
    /// Зарезервированные AML-области (адреса фиксированы платформой).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    reserved: Vec<PartitionRecord>,
    status: Status,
    files: Vec<FileRecord>,
    error: Option<String>,
}

#[derive(Debug, Clone)]
struct Layout {
    partitions: Vec<(String, u32, u32)>,
    reserved: Vec<(String, u32, u32)>,
    nand_size: u32,
}

/// Вывести карту разделов из DTB устройства: fip_size + nand_partition
/// (строгий парсер крейта amlogic), кумулятивные смещения по порядку
/// вендора; data добивает NAND. `tpl_start` — конец диапазона
/// bootloader+reserved (платформа: [`PLATFORM_TPL_START`]). Это
/// device-истина — без сравнения с известной картой (платформенный
/// гейт — [`ensure_platform`]).
fn layout_from_dtb(
    blob: &[u8],
    tpl_start: u32,
    nand_size: u32,
) -> anyhow::Result<Vec<(String, u32, u32)>> {
    let root = fdt::parse(blob).context("DTB устройства не разбирается")?;
    let compatible = root
        .prop("compatible")
        .context("в DTB нет compatible")?
        .to_ascii_lowercase();
    ensure!(
        compatible.windows(7).any(|w| w == b"amlogic")
            && (compatible.windows(3).any(|w| w == b"axg")
                || compatible.windows(4).any(|w| w == b"a113")),
        "DTB не подтверждает A113X/AXG"
    );
    let nodes = root.find_all(&|n: &fdt::Node| {
        n.prop("compatible")
            .is_some_and(|c| c.windows(12).any(|w| w == b"aml_mtd_nand"))
    });
    ensure!(nodes.len() == 1, "в DTB не ровно один aml_mtd_nand");
    let fip = fdt::be_u32(nodes[0].prop("fip_size").unwrap_or(&[]))
        .context("в DTB нет fip_size")?;
    ensure!(fip > 0 && fip <= tpl_start, "некорректный fip_size {fip:#x} в DTB");
    let parts = nodes[0]
        .child("nand_partition")
        .context("в DTB нет nand_partition")?;
    ensure!(
        parts.children.len() == NORMAL_PARTITIONS.len(),
        "в DTB {} узлов nand_partition, ожидается {}",
        parts.children.len(),
        NORMAL_PARTITIONS.len()
    );
    // bootloader и reserved-диапазон вне DTB; разделы идут с tpl_start
    let mut off = tpl_start;
    let mut out = vec![("bootloader".to_string(), 0, fip)];
    for (i, name) in NORMAL_PARTITIONS.iter().enumerate() {
        let node = &parts.children[i];
        ensure!(
            node.name == *name,
            "в DTB узел {} на месте {}",
            node.name,
            name
        );
        let raw = fdt::be_word(node.prop("size").unwrap_or(&[]))
            .context(format!("в DTB узла {name} нет размера"))?;
        ensure!(
            raw <= u32::MAX as u64,
            "размер {name} в DTB не помещается в u32"
        );
        let mut size = raw as u32;
        if name == &"tpl" {
            if size == 0 {
                // «до следующего»: на платформе это 8 МиБ (flasher VPART)
                size = TPL_SIZE;
            }
        } else if name == &"data" {
            ensure!(size == 0, "неизвестный явный размер data в DTB");
            size = nand_size
                .checked_sub(off)
                .context("разделы не помещаются в NAND")?;
        } else {
            ensure!(size > 0, "нулевой размер {name} в DTB");
        }
        out.push((name.to_string(), off, size));
        off = off
            .checked_add(size)
            .context("переполнение карты разделов")?;
    }
    ensure!(off == nand_size, "карта из DTB не покрывает NAND");
    Ok(out)
}

/// Платформенный гейт: карта с устройства обязана совпасть с известной
/// картой Capsula Mini — иначе смещения чтения ненадёжны, и лучше
/// отказаться, чем молча снять мусор.
fn ensure_platform(partitions: &[(String, u32, u32)]) -> anyhow::Result<()> {
    let known: Vec<(String, u32, u32)> = amlogic::PARTITIONS
        .iter()
        .map(|(n, o, s)| (n.to_string(), *o, *s))
        .collect();
    ensure!(
        partitions == &known[..],
        "карта разделов с устройства не совпала с известной картой \
         Capsula Mini (платформа не опознана): {partitions:?}"
    );
    Ok(())
}

impl Layout {
    /// Разметка с устройства + платформенный гейт.
    fn from_device_dtb(blob: &[u8]) -> anyhow::Result<Layout> {
        let partitions = layout_from_dtb(blob, PLATFORM_TPL_START, nand::NAND_SIZE)?;
        ensure_platform(&partitions)?;
        Ok(Layout {
            partitions,
            reserved: nand::RESERVED
                .iter()
                .map(|(n, o, s)| (n.to_string(), *o, *s))
                .collect(),
            nand_size: nand::NAND_SIZE,
        })
    }

    fn to_records(&self) -> Vec<PartitionRecord> {
        self.partitions
            .iter()
            .map(|(name, off, size)| PartitionRecord {
                name: name.clone(),
                off: *off,
                physical_size: *size,
            })
            .collect()
    }

    fn from_records(
        partitions: &[PartitionRecord],
        reserved: &[PartitionRecord],
        nand_size: u32,
    ) -> Layout {
        Layout {
            partitions: partitions
                .iter()
                .map(|r| (r.name.clone(), r.off, r.physical_size))
                .collect(),
            reserved: reserved
                .iter()
                .map(|r| (r.name.clone(), r.off, r.physical_size))
                .collect(),
            nand_size,
        }
    }
}

/// Устройство в рамках одной сессии. Все методы короткие; ошибки
/// транспорта — нормальный конец окна, их перехватывает drive.
trait Device {
    fn partition_size(&mut self, name: &str, physical: usize) -> anyhow::Result<usize>;
    fn env(&mut self) -> anyhow::Result<Vec<u8>>;
    /// DTB активного boot-образа (таблица разделов устройства).
    fn dtb(&mut self, slot: &str) -> anyhow::Result<Vec<u8>>;
    /// Разметка из DTB (платформенный гейт — у реального устройства).
    fn layout(&mut self, blob: &[u8]) -> anyhow::Result<Layout>;
    /// Прочитать диапазон NAND в `out` начиная со смещения `off`
    /// (главное пространство). `len` — в байтах ФАЙЛА: для raw=false
    /// это главные байты, для raw=true — байты вместе с OOB
    /// (`страница+OOB`-кратно); `off` всегда в главных байтах.
    /// Возвращает дописанные байты файла.
    fn read_range(
        &mut self,
        off: u32,
        len: u64,
        raw: bool,
        out: &mut dyn Write,
        progress: &dyn Fn(usize),
    ) -> anyhow::Result<usize>;
}

impl<T: Transport> Device for AmlogicSession<T> {
    fn partition_size(&mut self, name: &str, _physical: usize) -> anyhow::Result<usize> {
        Ok(self.partition_readable_size(name)?)
    }

    fn env(&mut self) -> anyhow::Result<Vec<u8>> {
        super::capture_env_raw(self)
    }

    fn dtb(&mut self, slot: &str) -> anyhow::Result<Vec<u8>> {
        self.read_dtb(slot).map_err(|e| anyhow::anyhow!("{e}"))
    }

    fn layout(&mut self, blob: &[u8]) -> anyhow::Result<Layout> {
        Layout::from_device_dtb(blob)
    }

    fn read_range(
        &mut self,
        off: u32,
        len: u64,
        raw: bool,
        out: &mut dyn Write,
        progress: &dyn Fn(usize),
    ) -> anyhow::Result<usize> {
        // длина пришла в файловых байтах; устройство читает главными
        let file_page: u64 = if raw {
            nand::raw_bytes(nand::PAGE_SIZE)? as u64
        } else {
            nand::PAGE_SIZE as u64
        };
        ensure!(len.is_multiple_of(file_page), "некратный странице кусок чтения");
        let main = if raw {
            (len / file_page * nand::PAGE_SIZE as u64) as u32
        } else {
            len as u32
        };
        let written = self
            .read_nand_range(off, main, raw, out, &|n| {
                progress(n)
            })?;
        Ok(written)
    }
}

/// Создать каталог захвата и стартовый манифест; каталог возвращается
/// вызывающему и переоткрывается каждым [`capture_pass`].
pub fn start(parent: &Path) -> anyhow::Result<PathBuf> {
    let dir = CaptureDirectory::create(parent, "amlogic")?;
    let m = Manifest {
        schema: 2,
        profile: "capsula-mini-a113x".into(),
        nand_size: nand::NAND_SIZE,
        page_size: nand::PAGE_SIZE,
        oob_size: nand::OOB_SIZE,
        device_read_passes: 1,
        layout: vec![],
        reserved: vec![],
        status: Status::Running,
        files: vec![],
        error: None,
    };
    save_manifest(&dir, &m)?;
    Ok(dir.path().into())
}

/// Один проход окна: продолжить захват из чекпоинта в `dir_path`.
/// Проход длится до полного захвата или до смерти сессии; по их
/// исчерпанию возвращается [`Pass::Interrupted`] с сохранённым
/// чекпоинтом.
pub fn capture_pass<T: Transport>(
    session: &mut AmlogicSession<T>,
    dir_path: &Path,
    progress: ProgressFn,
) -> anyhow::Result<Pass> {
    let dir = CaptureDirectory::open(dir_path)?;
    let mut m: Manifest = serde_json::from_slice(&std::fs::read(dir_path.join("manifest.json"))?)
        .context("манифест захвата не читается")?;
    ensure!(
        m.schema == 2 && m.profile == "capsula-mini-a113x",
        "неподдерживаемая схема захвата"
    );
    ensure!(
        m.status == Status::Running,
        "захват уже завершён, продолжать нечего"
    );
    let outcome = drive(session, &dir, &mut m, progress);
    match outcome {
        Ok(()) => {
            m.status = if m.files.iter().any(|f| f.actual != f.expected) {
                Status::Warnings
            } else {
                Status::Complete
            };
            validate(dir.path(), &m)?;
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

/// Слот активного boot-образа из текста окружения (boot_part); без
/// окружения — boot_a/boot_b по порядку, первый, с которого `imgread
/// dtb` отвечает.
fn dtb_slots(env_text: Option<&str>) -> Vec<&'static str> {
    let mut slots: Vec<&'static str> = Vec::new();
    if let Some(text) = env_text {
        if let Some(slot) = text
            .lines()
            .find_map(|l| l.strip_prefix("boot_part="))
            .map(str::trim)
        {
            if slot == "boot_a" {
                slots.push("boot_a");
            } else if slot == "boot_b" {
                slots.push("boot_b");
            }
        }
    }
    for s in ["boot_a", "boot_b"] {
        if !slots.contains(&s) {
            slots.push(s);
        }
    }
    slots
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

/// Один элемент захвата: докачать от чекпоинта до конца или до смерти
/// сессии.
fn capture_item(
    dev: &mut impl Device,
    dir: &CaptureDirectory,
    m: &mut Manifest,
    progress: ProgressFn,
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
            expected - cur,
            raw,
            &mut f,
            &|n| {
                progress(Progress::TransferProgress {
                    name: label.into(),
                    done: cur + n as u64,
                    total: expected,
                })
            },
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
            "{label}: снято {on_disk:#x} из {expected:#x} — сессия умерла"
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
) -> Result<(), DriveError> {
    // 1. Окружение — раз на захват, до разделов (из него берётся слот).
    let env_text = if find_record(m, "env.txt").is_none() {
        progress(Progress::Step("Amlogic: съём окружения u-boot".into()));
        let env = dev.env().map_err(|e| {
            DriveError::Window(format!("съём окружения не удался (окно?): {e:#}"))
        })?;
        if env.len() != amlogic::ENV_SIZE {
            return Err(DriveError::fatal(anyhow::anyhow!("короткий снимок окружения")));
        }
        bytes(dir, m, "env-export.bin", &env).map_err(DriveError::Fatal)?;
        let text = environment_text(&env).map_err(DriveError::Fatal)?.to_string();
        bytes(dir, m, "env.txt", text.as_bytes()).map_err(DriveError::Fatal)?;
        Some(text)
    } else {
        std::fs::read_to_string(dir.path().join("env.txt")).ok()
    };

    // 2. Разметка с устройства: DTB активного boot-образа (кэш в
    //    манифесте — чекпоинт), платформенный гейт против известной
    //    карты. На Mini нет GPT: DTB — единственная таблица разделов.
    let layout = if !m.layout.is_empty() {
        Layout::from_records(&m.layout, &m.reserved, m.nand_size)
    } else {
        progress(Progress::Step("Amlogic: чтение таблицы разделов (DTB)".into()));
        let mut blob = None;
        let mut last = None;
        for slot in dtb_slots(env_text.as_deref()) {
            match dev.dtb(slot) {
                Ok(b) => {
                    log::info!("amlogic: таблица разделов из DTB {slot}");
                    blob = Some((slot, b));
                    break;
                }
                Err(e) => last = Some((slot, e)),
            }
        }
        let (slot, blob) = blob.ok_or_else(|| {
            DriveError::Window(format!(
                "чтение DTB не удалось (окно?): {last:?}"
            ))
        })?;
        let layout = dev.layout(&blob).map_err(DriveError::fatal)?;
        bytes(dir, m, "device.dtb", &blob).map_err(DriveError::Fatal)?;
        m.layout = layout.to_records();
        m.reserved = layout
            .reserved
            .iter()
            .map(|(n, o, s)| PartitionRecord {
                name: n.clone(),
                off: *o,
                physical_size: *s,
            })
            .collect();
        save_manifest(dir, m).map_err(DriveError::Fatal)?;
        progress(Progress::Step(format!(
            "Amlogic: разметка из DTB {slot}: {} разделов",
            layout.partitions.len()
        )));
        layout
    };

    // 3. Разделы — по логической ёмкости (store size), докачка по
    //    смещениям `nand read` (бед-блоки u-boot обходит сам).
    for (name, off, size) in &layout.partitions {
        let base = format!("{name}.bin");
        let expected = match find_record(m, &base) {
            Some(r) => r.expected,
            None => {
                let readable = dev.partition_size(name, *size as usize).map_err(|e| {
                    DriveError::Window(format!("запрос логического размера {name}: {e:#}"))
                })?;
                if !(readable > 0 && readable <= *size as usize) {
                    return Err(DriveError::Window(format!(
                        "некорректный логический размер {name} ({readable:#x})"
                    )));
                }
                readable as u64
            }
        };
        if expected < *size as u64 {
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
            Item {
                base: &base,
                label: name,
                expected,
                off: *off,
                raw: false,
                physical: Some(*size as u64),
            },
        )?;
    }

    // 4. Зарезервированные области — по адресам (device-уникальны).
    for (name, off, size) in &layout.reserved {
        let base = format!("reserved-{name}.bin");
        progress(Progress::Step(format!(
            "Amlogic: зарезервированная область {name}"
        )));
        capture_item(
            dev,
            dir,
            m,
            progress,
            Item {
                base: &base,
                label: &base,
                expected: *size as u64,
                off: *off,
                raw: false,
                physical: None,
            },
        )?;
    }

    // 5. Полный сырой дамп с OOB — постранично, докачка по страницам.
    let expected_raw = nand::raw_bytes(layout.nand_size).map_err(DriveError::fatal)? as u64;
    progress(Progress::Step("Amlogic: полный сырой дамп NAND".into()));
    capture_item(
        dev,
        dir,
        m,
        progress,
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
/// суммы на диске — без обращения к USB. Разметка из манифеста
/// перепроверяется по сохранённому device.dtb.
pub fn verify(path: &Path) -> anyhow::Result<BackupReport> {
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
    validate(path, &m)?;
    Ok(BackupReport {
        path: path.into(),
        status: m.status,
    })
}

fn validate(path: &Path, m: &Manifest) -> anyhow::Result<()> {
    ensure!(
        m.schema == 2
            && m.profile == "capsula-mini-a113x"
            && m.nand_size > 0
            && m.page_size == nand::PAGE_SIZE
            && m.oob_size == nand::OOB_SIZE
            && m.device_read_passes == 1,
        "неподдерживаемая геометрия/схема захвата"
    );
    ensure!(
        matches!(m.status, Status::Complete | Status::Warnings) && m.error.is_none(),
        "захват не завершился"
    );
    ensure!(!m.layout.is_empty(), "в захвате нет разметки");
    let dtb_path = path.join("device.dtb");
    ensure!(dtb_path.is_file(), "в захвате нет device.dtb");
    let blob = std::fs::read(&dtb_path)?;
    let tpl_start = m.layout[1].off;
    let derived = layout_from_dtb(&blob, tpl_start, m.nand_size)?;
    let records: Vec<PartitionRecord> = derived
        .iter()
        .map(|(name, off, size)| PartitionRecord {
            name: name.clone(),
            off: *off,
            physical_size: *size,
        })
        .collect();
    ensure!(
        records == m.layout,
        "разметка манифеста отличается от разметки в device.dtb"
    );
    let layout = Layout::from_records(&m.layout, &m.reserved, m.nand_size);
    let mut expected = std::collections::BTreeMap::new();
    expected.insert("env-export.bin".into(), (amlogic::ENV_SIZE as u64, false));
    // Текстовый экспорт выводится локально и ограничен бинарным
    // окружением.
    expected.insert("env.txt".into(), (0, false));
    expected.insert("device.dtb".into(), (blob.len() as u64, false));
    for (name, _, size) in &layout.partitions {
        expected.insert(format!("{name}.bin"), (*size as u64, true));
    }
    for (name, _, size) in &layout.reserved {
        expected.insert(format!("reserved-{name}.bin"), (*size as u64, false));
    }
    let raw_total = (m.nand_size / m.page_size) as u64 * (m.page_size + m.oob_size) as u64;
    expected.insert("nand-full.raw.bin".into(), (raw_total, false));
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

    /// Тестовая геометрия: NAND 4096, bootloader 0..8, reserved-диапазон
    /// 8..16 (keys 8..12 внутри), tpl_start=16, разделы по 8, data —
    /// остаток. Структура узлов DTB — как у реальной платформы.
    const NAND: u32 = 4096;
    const TPL_START: u32 = 16;
    const FIP: u32 = 8;
    const REGIONS: &[(&str, u32, u32)] = &[("keys", 8, 4)];

    /// FDT-блоб с nand_partition тестовой геометрии.
    fn synthetic_dtb() -> Vec<u8> {
        struct B {
            strings: Vec<u8>,
            st: Vec<u8>,
        }
        impl B {
            fn u32(&mut self, v: u32) {
                self.st.extend_from_slice(&v.to_be_bytes());
            }
            fn stroff(&mut self, s: &str) -> u32 {
                let off = self.strings.len() as u32;
                self.strings.extend_from_slice(s.as_bytes());
                self.strings.push(0);
                off
            }
            fn prop(&mut self, name: &str, value: &[u8]) {
                let off = self.stroff(name);
                self.u32(3); // FDT_PROP
                self.u32(value.len() as u32);
                self.u32(off);
                self.st.extend_from_slice(value);
                while self.st.len() % 4 != 0 {
                    self.st.push(0);
                }
            }
            fn begin(&mut self, name: &str) {
                self.u32(1); // FDT_BEGIN_NODE
                self.st.extend_from_slice(name.as_bytes());
                self.st.push(0);
                while self.st.len() % 4 != 0 {
                    self.st.push(0);
                }
            }
            fn end(&mut self) {
                self.u32(2); // FDT_END_NODE
            }
            fn build(mut self) -> Vec<u8> {
                self.u32(9); // FDT_END
                let header = 40usize;
                let rsv = 16usize;
                let struct_off = header + rsv;
                let total = struct_off + self.st.len() + self.strings.len();
                let mut b = vec![0u8; total];
                let put = |b: &mut Vec<u8>, n: usize, v: u32| {
                    b[n..n + 4].copy_from_slice(&v.to_be_bytes())
                };
                put(&mut b, 0, 0xd00d_feed);
                put(&mut b, 4, total as u32);
                put(&mut b, 8, struct_off as u32);
                put(&mut b, 12, (struct_off + self.st.len()) as u32);
                put(&mut b, 16, header as u32);
                put(&mut b, 20, 17);
                put(&mut b, 24, 16);
                put(&mut b, 32, self.strings.len() as u32);
                put(&mut b, 36, self.st.len() as u32);
                b[struct_off..struct_off + self.st.len()].copy_from_slice(&self.st);
                b[struct_off + self.st.len()..].copy_from_slice(&self.strings);
                b
            }
        }
        let mut b = B {
            strings: vec![],
            st: vec![],
        };
        b.begin("");
        b.prop("compatible", b"amlogic,axg");
        b.begin("nand-controller@7800");
        b.prop("compatible", b"amlogic,aml_mtd_nand");
        b.prop("fip_size", &FIP.to_be_bytes());
        b.begin("nand_partition");
        for (name, size) in [
            ("tpl", TPL_START),
            ("misc", 8),
            ("boot_a", 8),
            ("boot_b", 8),
            ("system_a", 8),
            ("system_b", 8),
            ("data", 0),
        ] {
            b.begin(name);
            b.prop("size", &size.to_be_bytes());
            b.end();
        }
        b.end(); // nand_partition
        b.end(); // controller
        b.end(); // root
        b.build()
    }

    fn test_layout() -> Layout {
        Layout {
            partitions: layout_from_dtb(&synthetic_dtb(), TPL_START, NAND).unwrap(),
            reserved: REGIONS
                .iter()
                .map(|(n, o, s)| (n.to_string(), *o, *s))
                .collect(),
            nand_size: NAND,
        }
    }

    fn raw_expected() -> u64 {
        (NAND / nand::PAGE_SIZE) as u64 * (nand::PAGE_SIZE + nand::OOB_SIZE) as u64
    }

    struct Fake {
        calls: RefCell<Vec<String>>,
        fail: bool,
        environment: Option<Vec<u8>>,
        readable: Option<usize>,
        /// Сколько байт ФАЙЛА отдаёт read_range за один вызов
        /// (короткий ответ = сессия умерла посреди элемента).
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
        fn dtb(&mut self, _slot: &str) -> anyhow::Result<Vec<u8>> {
            self.calls.borrow_mut().push("dtb".into());
            Ok(synthetic_dtb())
        }
        fn layout(&mut self, blob: &[u8]) -> anyhow::Result<Layout> {
            // тестовая геометрия без платформенного гейта
            Ok(Layout {
                partitions: layout_from_dtb(blob, TPL_START, NAND)?,
                reserved: REGIONS
                    .iter()
                    .map(|(n, o, s)| (n.to_string(), *o, *s))
                    .collect(),
                nand_size: NAND,
            })
        }
        fn read_range(
            &mut self,
            off: u32,
            len: u64,
            raw: bool,
            out: &mut dyn Write,
            _: &dyn Fn(usize),
        ) -> anyhow::Result<usize> {
            self.calls.borrow_mut().push(format!("read:{off}:{raw}"));
            anyhow::ensure!(!self.fail, "USB disconnected");
            let n = (len as usize).min(self.chunk);
            out.write_all(&vec![1u8; n])?;
            Ok(n)
        }
    }
    fn parent() -> CaptureDirectory {
        CaptureDirectory::create(&std::env::temp_dir(), "aml-test").unwrap()
    }
    fn begin(parent: &CaptureDirectory) -> PathBuf {
        let dir = CaptureDirectory::create(parent.path(), "aml").unwrap();
        let m = Manifest {
            schema: 2,
            profile: "capsula-mini-a113x".into(),
            nand_size: NAND,
            page_size: nand::PAGE_SIZE,
            oob_size: nand::OOB_SIZE,
            device_read_passes: 1,
            layout: vec![],
            reserved: REGIONS
                .iter()
                .map(|(n, o, s)| PartitionRecord {
                    name: n.to_string(),
                    off: *o,
                    physical_size: *s,
                })
                .collect(),
            status: Status::Running,
            files: vec![],
            error: None,
        };
        save_manifest(&dir, &m).unwrap();
        dir.path().into()
    }
    fn run_pass(dev: &mut impl Device, dir: &Path) -> anyhow::Result<Pass> {
        capture_pass_inner(dev, dir, &|_| {})
    }
    /// Тестовый вход: как capture_pass, но на Fake-устройстве и с
    /// тестовой геометрией (платформенный гейт вне тестовой разметки).
    fn capture_pass_inner(
        dev: &mut impl Device,
        dir_path: &Path,
        progress: ProgressFn,
    ) -> anyhow::Result<Pass> {
        let dir = CaptureDirectory::open(dir_path)?;
        let mut m: Manifest =
            serde_json::from_slice(&std::fs::read(dir_path.join("manifest.json"))?)?;
        ensure!(m.status == Status::Running, "захват уже завершён");
        match drive(dev, &dir, &mut m, progress) {
            Ok(()) => {
                m.status = if m.files.iter().any(|f| f.actual != f.expected) {
                    Status::Warnings
                } else {
                    Status::Complete
                };
                validate(dir_path, &m)?;
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
                "dtb",
                "size:bootloader",
                "read:0:false",
                "size:tpl",
                "read:16:false",
                "size:misc",
                "read:32:false",
                "size:boot_a",
                "read:40:false",
                "size:boot_b",
                "read:48:false",
                "size:system_a",
                "read:56:false",
                "size:system_b",
                "read:64:false",
                "size:data",
                "read:72:false",
                "read:8:false",
                "read:0:true"
            ]
        );
        match verify(&report.path) {
            Ok(r) => assert_eq!(r.status, Status::Complete),
            Err(e) => {
                let mtxt = std::fs::read_to_string(report.path.join("manifest.json")).unwrap();
                panic!("verify failed: {e:#}
---
{mtxt}");
            }
        }
        std::fs::write(report.path.join("bootloader.bin"), b"corrupt!").unwrap();
        assert!(verify(&report.path).is_err());
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
        assert!(!dir.join("bootloader.bin").exists());
        assert_eq!(
            std::fs::read(dir.join("bootloader.bin.partial")).unwrap(),
            vec![1; 3]
        );
        let m: Manifest =
            serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(m.status, Status::Running);
        // Окно 2: здоровая сессия докачивает с чекпоинта.
        let mut dev = Fake::new();
        match run_pass(&mut dev, &dir).unwrap() {
            Pass::Done(report) => {
                assert_eq!(report.status, Status::Complete);
                assert_eq!(
                    std::fs::read(report.path.join("bootloader.bin")).unwrap(),
                    vec![1; 8]
                );
                assert!(!report.path.join("bootloader.bin.partial").exists());
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
        // env и dtb успели (они до разделов), раздел не публикуется
        assert!(dir.join("env.txt").is_file());
        assert!(dir.join("device.dtb").is_file());
        assert!(dir.join("bootloader.bin.partial").is_file());
        let m: Manifest =
            serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(m.status, Status::Running);
        assert_eq!(m.layout.len(), 8);
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
                verify(&report.path).unwrap();
                let m: Manifest = serde_json::from_slice(
                    &std::fs::read(report.path.join("manifest.json")).unwrap(),
                )
                .unwrap();
                let part = m.files.iter().find(|f| f.name == "tpl.bin").unwrap();
                assert_eq!(part.expected, 6);
                assert_eq!(part.actual, 6);
                assert_eq!(part.physical_size, Some(16));
                assert_eq!(
                    std::fs::read(report.path.join("tpl.bin")).unwrap(),
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
        assert!(verify(&report.path).is_err());
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
        assert!(verify(&report.path).is_err());
        let mut m: Manifest = serde_json::from_slice(&original).unwrap();
        m.files[0].name = "../outside".into();
        std::fs::write(&path, serde_json::to_vec(&m).unwrap()).unwrap();
        assert!(verify(&report.path).is_err());
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

    /// Разметка из DTB реальной платформы: кумулятивные смещения,
    /// tpl/data по нулю, платформенный гейт.
    #[test]
    fn mini_layout_derives_from_a_mini_dtb() {
        let sizes: [u32; 7] = [
            0,
            0x20_0000,
            0x100_0000,
            0x100_0000,
            0x400_0000,
            0x400_0000,
            0,
        ];
        let mut b = MiniBuilder::new();
        b.begin("");
        b.prop("compatible", b"amlogic,meson-axg");
        b.begin("nand-controller@7800");
        b.prop("compatible", b"amlogic,aml_mtd_nand");
        b.prop("fip_size", &FIP_SIZE.to_be_bytes());
        b.begin("nand_partition");
        for (name, size) in NORMAL_PARTITIONS.iter().zip(sizes) {
            b.begin(name);
            b.prop("size", &size.to_be_bytes());
            b.end();
        }
        b.end();
        b.end();
        b.end();
        let blob = b.build();

        let partitions = layout_from_dtb(&blob, PLATFORM_TPL_START, nand::NAND_SIZE).unwrap();
        ensure_platform(&partitions).unwrap();
        assert_eq!(partitions.len(), 8);
        assert_eq!(partitions[0], ("bootloader".into(), 0, FIP_SIZE));
        assert_eq!(partitions[1], ("tpl".into(), 0x80_0000, TPL_SIZE));
        assert_eq!(partitions[7], ("data".into(), 0xb20_0000, 0x4e0_0000));
        assert_eq!(partitions[7].1 + partitions[7].2, nand::NAND_SIZE);
        let layout = Layout::from_device_dtb(&blob).unwrap();
        assert_eq!(layout.to_records().len(), 8);

        // чужой DTB платформенный гейт отвергает
        let mut wrong = blob.clone();
        let n = wrong.len() - 1;
        wrong[n] ^= 0xff;
        assert!(Layout::from_device_dtb(&wrong).is_err());
    }

    /// Слот DTB: boot_part из окружения первый, потом fallback.
    #[test]
    fn dtb_slots_prefer_env_boot_part() {
        assert_eq!(
            dtb_slots(Some("boot_part=boot_b\nx=1")),
            ["boot_b", "boot_a"]
        );
        assert_eq!(dtb_slots(Some("x=1")), ["boot_a", "boot_b"]);
        assert_eq!(dtb_slots(Some("boot_part=capsulejb")), ["boot_a", "boot_b"]);
        assert_eq!(dtb_slots(None), ["boot_a", "boot_b"]);
        let _ = (test_layout(), raw_expected());
    }

    /// Прямой доступ к сборщику FDT для теста разметки платформы.
    struct MiniBuilder {
        strings: Vec<u8>,
        st: Vec<u8>,
    }
    impl MiniBuilder {
        fn new() -> Self {
            MiniBuilder {
                strings: vec![],
                st: vec![],
            }
        }
        fn u32(&mut self, v: u32) {
            self.st.extend_from_slice(&v.to_be_bytes());
        }
        fn stroff(&mut self, s: &str) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            off
        }
        fn prop(&mut self, name: &str, value: &[u8]) {
            let off = self.stroff(name);
            self.u32(3);
            self.u32(value.len() as u32);
            self.u32(off);
            self.st.extend_from_slice(value);
            while self.st.len() % 4 != 0 {
                self.st.push(0);
            }
        }
        fn begin(&mut self, name: &str) {
            self.u32(1);
            self.st.extend_from_slice(name.as_bytes());
            self.st.push(0);
            while self.st.len() % 4 != 0 {
                self.st.push(0);
            }
        }
        fn end(&mut self) {
            self.u32(2);
        }
        fn build(mut self) -> Vec<u8> {
            self.u32(9);
            let header = 40usize;
            let struct_off = header + 16;
            let total = struct_off + self.st.len() + self.strings.len();
            let mut b = vec![0u8; total];
            let put = |b: &mut Vec<u8>, n: usize, v: u32| {
                b[n..n + 4].copy_from_slice(&v.to_be_bytes())
            };
            put(&mut b, 0, 0xd00d_feed);
            put(&mut b, 4, total as u32);
            put(&mut b, 8, struct_off as u32);
            put(&mut b, 12, (struct_off + self.st.len()) as u32);
            put(&mut b, 16, header as u32);
            put(&mut b, 20, 17);
            put(&mut b, 24, 16);
            put(&mut b, 32, self.strings.len() as u32);
            put(&mut b, 36, self.st.len() as u32);
            b[struct_off..struct_off + self.st.len()].copy_from_slice(&self.st);
            b[struct_off + self.st.len()..].copy_from_slice(&self.strings);
            b
        }
    }
}
