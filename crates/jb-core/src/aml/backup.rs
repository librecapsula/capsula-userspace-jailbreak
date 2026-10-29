//! Однопроходный захват A113X: окружение u-boot, разделы (по
//! логической ёмкости), зарезервированные области и полный сырой дамп
//! NAND. Манифест (`manifest.json`) аутентифицирует сохранённые файлы;
//! повторяемость чтения NAND он не доказывает. Формат отличается от
//! legacy-каталога rockchip (NN_имя.img + SUCCESS.txt): каждый запуск
//! владеет свежим каталогом `backup/amlogic-<время>-<pid>-<n>`.

use crate::backup_store::{file_sha256, safe_capture_name, CaptureDirectory};
use crate::session::{Progress, ProgressFn};
use amlogic::{nand, AmlogicSession, Transport};
use anyhow::{ensure, Context};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Running,
    Failed,
    Complete,
    Warnings,
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
    chunk_size: u32,
}
fn a113x() -> Layout<'static> {
    Layout {
        partitions: amlogic::PARTITIONS,
        reserved: nand::RESERVED,
        nand_size: nand::NAND_SIZE,
        chunk_size: nand::CHUNK_SIZE,
    }
}
trait Device {
    fn partition_size(&mut self, name: &str, physical: usize) -> anyhow::Result<usize>;
    fn env(&mut self) -> anyhow::Result<Vec<u8>>;
    fn partition(
        &mut self,
        name: &str,
        size: usize,
        out: &mut dyn Write,
        progress: &dyn Fn(usize),
    ) -> anyhow::Result<usize>;
    fn nand(&mut self, offset: u32, size: u32, raw: bool) -> anyhow::Result<Vec<u8>>;
}
impl<T: Transport> Device for AmlogicSession<T> {
    fn partition_size(&mut self, name: &str, _physical: usize) -> anyhow::Result<usize> {
        Ok(self.partition_readable_size(name)?)
    }
    fn env(&mut self) -> anyhow::Result<Vec<u8>> {
        super::capture_env_raw(self)
    }
    fn partition(
        &mut self,
        name: &str,
        size: usize,
        out: &mut dyn Write,
        progress: &dyn Fn(usize),
    ) -> anyhow::Result<usize> {
        Ok(self.upload_store_to(name, size, out, progress)?)
    }
    fn nand(&mut self, offset: u32, size: u32, raw: bool) -> anyhow::Result<Vec<u8>> {
        Ok(if raw {
            self.read_raw_nand_chunk(offset, size)?
        } else {
            self.read_nand_chunk(offset, size)?
        })
    }
}

/// Захват из уже поднятой TPL-сессии; каждый образ снимается за один
/// проход по устройству.
pub fn backup<T: Transport>(
    session: &mut AmlogicSession<T>,
    parent: &Path,
    progress: ProgressFn,
) -> anyhow::Result<BackupReport> {
    capture(session, parent, progress, &a113x())
}

fn save_manifest(dir: &CaptureDirectory, m: &Manifest) -> anyhow::Result<()> {
    dir.replace_file("manifest.json", &serde_json::to_vec_pretty(m)?)?;
    Ok(())
}
fn record(
    dir: &CaptureDirectory,
    m: &mut Manifest,
    name: &str,
    expected: u64,
    actual: u64,
    physical_size: Option<u64>,
) -> anyhow::Result<()> {
    ensure!(actual <= expected, "файл {name} больше ожидаемого");
    let partial = format!("{name}.partial");
    ensure!(
        std::fs::metadata(dir.path().join(&partial))?.len() == actual,
        "размер {name} не совпал"
    );
    let hash = file_sha256(&dir.path().join(&partial))?;
    let published = if actual == expected {
        dir.publish_partial(&partial, name)?;
        name.to_string()
    } else {
        partial
    };
    m.files.push(FileRecord {
        name: published,
        expected,
        physical_size,
        actual,
        sha256: hash,
    });
    save_manifest(dir, m)
}
fn bytes(dir: &CaptureDirectory, m: &mut Manifest, name: &str, data: &[u8]) -> anyhow::Result<()> {
    // write_file публикует только после sync; record использует ту же
    // конвенцию .partial
    let partial = format!("{name}.partial");
    let mut f = dir.create_file(&partial)?;
    f.write_all(data)?;
    f.sync_all()?;
    drop(f);
    record(dir, m, name, data.len() as u64, data.len() as u64, None)
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

fn capture(
    dev: &mut impl Device,
    parent: &Path,
    progress: ProgressFn,
    layout: &Layout<'_>,
) -> anyhow::Result<BackupReport> {
    let dir = CaptureDirectory::create(parent, "amlogic")?;
    let mut m = Manifest {
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
    let result = (|| -> anyhow::Result<()> {
        progress(Progress::Step("Amlogic: съём окружения u-boot".into()));
        let env = dev.env()?;
        ensure!(env.len() == amlogic::ENV_SIZE, "короткий снимок окружения");
        bytes(&dir, &mut m, "env-export.bin", &env)?;
        let text = environment_text(&env)?;
        bytes(&dir, &mut m, "env.txt", text.as_bytes())?;
        for &(name, _, size) in layout.partitions {
            let readable = dev
                .partition_size(name, size as usize)
                .with_context(|| format!("запрос логического размера {name}"))?;
            ensure!(
                readable > 0 && readable <= size as usize,
                "некорректный логический размер {name}"
            );
            if readable < size as usize {
                progress(Progress::Step(format!(
                    "Amlogic: {name} логический размер {readable:#x}, физический {size:#x} \
                     (бед-блоки исключены)"
                )));
            }
            let filename = format!("{name}.bin");
            progress(Progress::TransferStart {
                name: name.into(),
                bytes: readable as u64,
            });
            let mut f = dir.create_file(&format!("{filename}.partial"))?;
            let received = dev.partition(name, readable, &mut f, &|done| {
                progress(Progress::TransferProgress {
                    name: name.into(),
                    done: done as u64,
                    total: readable as u64,
                })
            });
            // Принятый префикс синхронизируется даже при ошибке USB.
            let synced = f.sync_all();
            let saved = f
                .metadata()
                .map(|m| format!("{:#x}", m.len()))
                .unwrap_or_else(|_| "unknown".into());
            drop(f);
            let received = received.with_context(|| {
                format!(
                    "раздел {name}: сохранено {saved} из {readable:#x} байт в {filename}.partial"
                )
            })?;
            synced?;
            record(
                &dir,
                &mut m,
                &filename,
                readable as u64,
                received as u64,
                Some(size as u64),
            )?;
            progress(Progress::TransferDone { name: name.into() });
        }
        for &(name, off, size) in layout.reserved {
            progress(Progress::Step(format!(
                "Amlogic: зарезервированная область {name}"
            )));
            let data = dev.nand(off, size, false)?;
            ensure!(
                data.len() == size as usize,
                "короткая зарезервированная область {name}"
            );
            bytes(&dir, &mut m, &format!("reserved-{name}.bin"), &data)?;
        }
        let filename = "nand-full.raw.bin";
        let expected = nand::raw_bytes(layout.nand_size)? as u64;
        progress(Progress::TransferStart {
            name: filename.into(),
            bytes: expected,
        });
        let mut f = dir.create_file(&format!("{filename}.partial"))?;
        let mut done = 0u64;
        let raw_result = (|| -> anyhow::Result<()> {
            for off in (0..layout.nand_size).step_by(layout.chunk_size as usize) {
                let size = layout.chunk_size.min(layout.nand_size - off);
                let data = dev.nand(off, size, true)?;
                ensure!(
                    data.len() == nand::raw_bytes(size)?,
                    "короткий сырой кусок NAND на {off:#x}"
                );
                f.write_all(&data)?;
                done += data.len() as u64;
                progress(Progress::TransferProgress {
                    name: filename.into(),
                    done,
                    total: expected,
                });
            }
            Ok(())
        })();
        let synced = f.sync_all();
        drop(f);
        raw_result?;
        synced?;
        record(&dir, &mut m, filename, expected, done, None)?;
        progress(Progress::TransferDone {
            name: filename.into(),
        });
        m.status = if m.files.iter().any(|f| f.actual != f.expected) {
            Status::Warnings
        } else {
            Status::Complete
        };
        // Проверяем весь сохранённый инвентарь до публикации финального
        // статуса.
        validate(dir.path(), &m, layout)?;
        let sums = m
            .files
            .iter()
            .map(|f| format!("{}  {}\n", f.sha256, f.name))
            .collect::<String>();
        dir.write_file("SHA256SUMS.txt", sums.as_bytes())?;
        save_manifest(&dir, &m)?;
        Ok(())
    })();
    if let Err(error) = result {
        m.status = Status::Failed;
        m.error = Some(format!("{error:#}"));
        let saved = save_manifest(&dir, &m);
        return Err(error).with_context(|| {
            format!(
                "захват Amlogic не удался: {}{}",
                dir.path().display(),
                saved
                    .err()
                    .map(|e| format!("; не удалось сохранить статус ошибки: {e}"))
                    .unwrap_or_default()
            )
        });
    }
    Ok(BackupReport {
        path: dir.path().into(),
        status: m.status,
    })
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
            chunk_size: 2048,
        }
    }
    struct Fake {
        calls: RefCell<Vec<String>>,
        short: bool,
        fail: bool,
        environment: Option<Vec<u8>>,
        readable: Option<usize>,
    }
    impl Fake {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                short: false,
                fail: false,
                environment: None,
                readable: None,
            }
        }
    }
    impl Device for Fake {
        fn partition_size(&mut self, name: &str, physical: usize) -> anyhow::Result<usize> {
            self.calls.borrow_mut().push(format!("size:{name}"));
            Ok(self.readable.unwrap_or(physical))
        }
        fn env(&mut self) -> anyhow::Result<Vec<u8>> {
            self.calls.borrow_mut().push("env".into());
            Ok(self.environment.clone().unwrap_or_else(|| {
                let mut data = vec![0; amlogic::ENV_SIZE];
                data[..4].copy_from_slice(b"a=b\n");
                data
            }))
        }
        fn partition(
            &mut self,
            name: &str,
            size: usize,
            out: &mut dyn std::io::Write,
            _: &dyn Fn(usize),
        ) -> anyhow::Result<usize> {
            self.calls.borrow_mut().push(name.into());
            out.write_all(&[1; 3])?;
            anyhow::ensure!(!self.fail, "USB disconnected");
            let n = if self.short { 3 } else { size };
            if n > 3 {
                out.write_all(&vec![1; n - 3])?;
            }
            Ok(n)
        }
        fn nand(&mut self, off: u32, size: u32, raw: bool) -> anyhow::Result<Vec<u8>> {
            self.calls.borrow_mut().push(format!("nand:{off}:{raw}"));
            Ok(vec![
                2;
                if raw {
                    amlogic::nand::raw_bytes(size)?
                } else {
                    size as usize
                }
            ])
        }
    }
    fn parent() -> CaptureDirectory {
        CaptureDirectory::create(&std::env::temp_dir(), "aml-test").unwrap()
    }
    #[test]
    fn single_pass_capture_has_one_raw_file_and_no_device_rereads() {
        let parent = parent();
        let mut dev = Fake::new();
        let report = capture(&mut dev, parent.path(), &|_| {}, &layout()).unwrap();
        assert_eq!(report.status, Status::Complete);
        assert_eq!(
            *dev.calls.borrow(),
            [
                "env",
                "size:boot",
                "boot",
                "nand:8:false",
                "nand:0:true",
                "nand:2048:true"
            ]
        );
        let manifest = verify_layout(&report.path, &layout()).unwrap();
        assert_eq!(manifest.files.len(), 5);
        std::fs::write(report.path.join("boot.bin"), b"corrupt!").unwrap();
        assert!(verify_layout(&report.path, &layout()).is_err());
        std::fs::remove_dir_all(parent.path()).unwrap();
    }
    #[test]
    fn short_partition_is_preserved_but_cannot_be_complete() {
        let parent = parent();
        let mut dev = Fake::new();
        dev.short = true;
        let report = capture(&mut dev, parent.path(), &|_| {}, &layout()).unwrap();
        assert_eq!(report.status, Status::Warnings);
        assert!(report.path.join("boot.bin.partial").is_file());
        assert!(!report.path.join("boot.bin").exists());
        assert_eq!(
            verify_layout(&report.path, &layout()).unwrap().status,
            Status::Warnings
        );
        std::fs::remove_dir_all(parent.path()).unwrap();
    }
    #[test]
    fn usb_error_keeps_received_prefix_and_failed_manifest() {
        let parent = parent();
        let mut dev = Fake::new();
        dev.fail = true;
        let error = capture(&mut dev, parent.path(), &|_| {}, &layout()).unwrap_err();
        let detail = format!("{error:#}");
        assert!(detail.contains("раздел boot"));
        assert!(detail.contains("сохранено 0x3 из 0x8 байт"));
        let dir = std::fs::read_dir(parent.path())
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        let m: Manifest =
            serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(m.status, Status::Failed);
        assert_eq!(
            std::fs::read(dir.join("boot.bin.partial")).unwrap(),
            vec![1; 3]
        );
        assert!(verify_layout(&dir, &layout()).is_err());
        std::fs::remove_dir_all(parent.path()).unwrap();
    }
    #[test]
    fn complete_logical_partition_keeps_physical_size_without_padding() {
        let parent = parent();
        let mut dev = Fake::new();
        dev.readable = Some(6);
        let report = capture(&mut dev, parent.path(), &|_| {}, &layout()).unwrap();
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
        std::fs::remove_dir_all(parent.path()).unwrap();
    }
    #[test]
    fn invalid_environment_fails_before_partitions_and_keeps_raw_snapshot() {
        for prefix in [b"".as_slice(), b"garbage", b"\xff=x"] {
            let parent = parent();
            let mut dev = Fake::new();
            let mut raw = vec![0; amlogic::ENV_SIZE];
            raw[..prefix.len()].copy_from_slice(prefix);
            dev.environment = Some(raw.clone());
            assert!(capture(&mut dev, parent.path(), &|_| {}, &layout()).is_err());
            let dir = std::fs::read_dir(parent.path())
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path();
            assert_eq!(std::fs::read(dir.join("env-export.bin")).unwrap(), raw);
            assert!(!dir.join("env.txt").exists());
            let m: Manifest =
                serde_json::from_slice(&std::fs::read(dir.join("manifest.json")).unwrap()).unwrap();
            assert_eq!(m.status, Status::Failed);
            assert_eq!(*dev.calls.borrow(), ["env"]);
            std::fs::remove_dir_all(parent.path()).unwrap();
        }
    }
    #[test]
    fn verifier_rejects_invalid_environment_even_with_matching_checksums() {
        let parent = parent();
        let report = capture(&mut Fake::new(), parent.path(), &|_| {}, &layout()).unwrap();
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
        let report = capture(&mut Fake::new(), parent.path(), &|_| {}, &layout()).unwrap();
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
}
