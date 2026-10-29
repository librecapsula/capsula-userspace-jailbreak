//! userdata overlay: base image + overlay files -> a partition image
//! ready to flash. The filesystem is modified with ext4-lwext4 (an
//! lwext4 wrapper): the dump copy is mounted, the files are written,
//! the image is unmounted and re-read for verification.
//!
//! The stock firmware mounts userdata as ext2 at /data and uses
//! /data/overlay/upper as the overlayfs upper layer over the read-only
//! rootfs. Files placed at /overlay/upper/* inside the partition appear
//! at the root of the running system; a factory reset wipes /data and
//! reverts the jailbreak.
//!
//! userdata is not signed and can be rewritten freely — it is the only
//! partition the tool writes.

use crate::session::Progress;
use ext4_lwext4::{Ext4Fs, FileBlockDevice, MkfsOptions, OpenFlags};
use std::path::Path;

/// Prefix inside userdata: the overlayfs upper layer. Files placed here
/// show up at the root of the running system.
pub const UPPER_DIR: &str = "/overlay/upper";

/// Dirs the stock boot scripts expect to exist in userdata: overlayfs
/// needs an EMPTY workdir next to the upper layer (S23overlayfs.sh
/// mounts workdir=/data/overlay/work). Created on fresh images; on
/// dumps they already exist (mkdir is a no-op).
pub const LAYOUT_DIRS: &[&str] = &["/overlay", UPPER_DIR, "/overlay/work"];

/// adbd build (aarch64/glibc; built in docker/adbd, linked against
/// glibc 2.31 / OpenSSL 1.1 — runs on the stock rootfs). Listens on
/// USB and TCP:5555 at once (ADBD_TCP_PORT overrides the port).
pub const OVERLAY_ADBD: &[u8] = include_bytes!("../../../resources/overlay/usr/bin/adbd");
/// USB gadget flag for firmwares that parse it; harmless elsewhere.
pub const OVERLAY_USB_CONFIG: &[u8] =
    include_bytes!("../../../resources/overlay/etc/init.d/.usb_config");

/// One overlay file (the path is inside the userdata partition).
pub struct OverlayFile {
    pub path: String,
    pub data: Vec<u8>,
    pub mode: u32,
}

/// The overlay file set: adbd + the gadget flag + the jailbreak marker.
/// After boot they appear as /usr/bin/adbd, /etc/init.d/.usb_config and
/// /etc/jailbreak.
pub fn overlay_files(marker: String) -> Vec<OverlayFile> {
    vec![
        OverlayFile {
            path: format!("{UPPER_DIR}/usr/bin/adbd"),
            data: OVERLAY_ADBD.to_vec(),
            mode: 0o755,
        },
        OverlayFile {
            path: format!("{UPPER_DIR}/etc/init.d/.usb_config"),
            data: OVERLAY_USB_CONFIG.to_vec(),
            mode: 0o644,
        },
        OverlayFile {
            path: format!("{UPPER_DIR}/etc/jailbreak"),
            data: marker.into_bytes(),
            mode: 0o644,
        },
    ]
}

#[derive(Debug, thiserror::Error)]
pub enum UserDataError {
    /// The dump did not mount as ext2/3/4 — raw or unknown format.
    #[error("userdata не смонтировался как ext2/3/4: {0}.\n  если раздел на колонке не отформатирован — запустите с --format-userdata")]
    NotExt(String),
    #[error("не хватает места в userdata: {0}")]
    NoSpace(String),
    #[error("файл {path} не совпал после записи")]
    Verify { path: String },
    #[error(transparent)]
    Fs(#[from] ext4_lwext4::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Build the userdata image with the overlay.
///
/// - `dump` — the dumped partition (never modified; work happens on a copy);
/// - `out` — where to put the result (`work/userdata.img`);
/// - `fresh` — format a clean ext2 instead of patching the dump;
/// - `part_size` — partition size in bytes (used by `fresh`).
pub fn build_image(
    dump: &Path,
    out: &Path,
    fresh: bool,
    part_size: u64,
    files: &[OverlayFile],
    progress: &dyn Fn(Progress),
) -> Result<(), UserDataError> {
    if out.parent().is_some() {
        std::fs::create_dir_all(out.parent().unwrap())?;
    }
    if !fresh {
        if let (Ok(a), Ok(b)) = (std::fs::canonicalize(dump), std::fs::canonicalize(out)) {
            if a == b {
                return Err(UserDataError::NotExt(
                    "пути дампа и результата совпадают — дамп не модифицируется".into(),
                ));
            }
        }
    }
    let device = if fresh {
        progress(Progress::Step(format!(
            "userdata: чистый ext2 на {} байт (--format-userdata)",
            part_size
        )));
        let device = FileBlockDevice::create(out, part_size)?;
        ext4_lwext4::mkfs(device, &MkfsOptions::ext2())?;
        FileBlockDevice::open(out)?
    } else {
        progress(Progress::Step(format!(
            "userdata: копирую дамп {} → {}",
            dump.display(),
            out.display()
        )));
        std::fs::copy(dump, out)?;
        FileBlockDevice::open(out)?
    };

    let fs = Ext4Fs::mount(device, false).map_err(|e| UserDataError::NotExt(e.to_string()))?;
    for dir in LAYOUT_DIRS {
        mkdir_all(&fs, Path::new(dir))?;
    }
    for f in files {
        write_file(&fs, f).map_err(|e| no_space(e, &f.path))?;
        progress(Progress::Step(format!(
            "userdata: {} ({} байт, права {:o})",
            f.path,
            f.data.len(),
            f.mode
        )));
    }
    let _ = fs.sync();
    fs.umount()?;

    verify(out, files)?;
    progress(Progress::Step("userdata: проверка пройдена".into()));
    Ok(())
}

/// Wrap out-of-space conditions into a clear error.
fn no_space(e: UserDataError, path: &str) -> UserDataError {
    match e {
        UserDataError::Fs(ext4_lwext4::Error::NoSpace) => {
            UserDataError::NoSpace(format!("{path} не влезает в раздел"))
        }
        other => other,
    }
}

/// Write one file: create the missing directories, rewrite the content,
/// set the mode and the owner.
fn write_file(fs: &Ext4Fs, f: &OverlayFile) -> Result<(), UserDataError> {
    mkdir_all(fs, Path::new(&f.path).parent().unwrap_or(Path::new("/")))?;
    let mut file = fs.open(
        &f.path,
        OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
    )?;
    file.write_all(&f.data)?;
    file.sync()?;
    drop(file);
    fs.set_permissions(&f.path, f.mode)?;
    fs.set_owner(&f.path, 0, 0)?;
    Ok(())
}

fn mkdir_all(fs: &Ext4Fs, dir: &Path) -> Result<(), UserDataError> {
    let mut cur = String::new();
    for comp in dir.components() {
        use std::path::Component;
        let comp = match comp {
            Component::RootDir | Component::Prefix(_) => continue,
            Component::Normal(c) => c.to_string_lossy().into_owned(),
            other => return Err(UserDataError::NotExt(format!("неожидаемый путь: {other:?}"))),
        };
        cur.push('/');
        cur.push_str(&comp);
        if !fs.is_dir(&cur) {
            if let Err(e) = fs.mkdir(&cur, 0o755) {
                if !matches!(e, ext4_lwext4::Error::AlreadyExists(_)) {
                    return Err(e.into());
                }
            }
        }
    }
    Ok(())
}

/// Re-read the result read-only and compare every file.
fn verify(out: &Path, files: &[OverlayFile]) -> Result<(), UserDataError> {
    let device = FileBlockDevice::open_read_only(out)?;
    let fs = Ext4Fs::mount(device, true).map_err(|e| UserDataError::NotExt(e.to_string()))?;
    for f in files {
        let mut buf = Vec::new();
        let mut file = fs.open(&f.path, OpenFlags::READ)?;
        file.read_to_end(&mut buf)?;
        if buf != f.data {
            return Err(UserDataError::Verify {
                path: f.path.clone(),
            });
        }
        let meta = fs.metadata(&f.path)?;
        if meta.mode & 0o777 != f.mode {
            return Err(UserDataError::Verify {
                path: f.path.clone(),
            });
        }
    }
    let _ = fs.umount();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    /// lwext4 keeps global state: parallel mounts from different test
    /// threads conflict. Serialize the tests.
    static LWEXT4_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn lock_lwext4() -> MutexGuard<'static, ()> {
        LWEXT4_LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("jb-userdata-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn files() -> Vec<OverlayFile> {
        vec![
            OverlayFile {
                path: "/overlay/upper/usr/bin/adbd".into(),
                data: vec![0xa5; 126_768], // size of the bundled adbd build
                mode: 0o755,
            },
            OverlayFile {
                path: "/overlay/upper/etc/init.d/.usb_config".into(),
                data: b"usb_adb_en\n".to_vec(),
                mode: 0o644,
            },
            OverlayFile {
                path: "/overlay/upper/etc/jailbreak".into(),
                data: b"test-marker\n".to_vec(),
                mode: 0o644,
            },
        ]
    }

    #[test]
    fn fresh_image_roundtrip() {
        let _guard = lock_lwext4();
        let d = tmpdir("fresh");
        let out = d.join("userdata.img");
        build_image(
            &d.join("nonexistent-dump"),
            &out,
            true,
            4 * 1024 * 1024,
            &files(),
            &|_| {},
        )
        .expect("fresh build");
        assert!(out.metadata().unwrap().len() >= 4 * 1024 * 1024);
        // the upper layer and the empty overlayfs workdir are in place
        {
            let dev = FileBlockDevice::open_read_only(&out).unwrap();
            let fs = Ext4Fs::mount(dev, true).unwrap();
            assert!(fs.is_dir("/overlay/upper"), "no /overlay/upper");
            assert!(fs.is_dir("/overlay/work"), "no /overlay/work");
            assert!(fs.is_file("/overlay/upper/usr/bin/adbd"));
            let _ = fs.umount();
        }
        // re-running over a copy of the image must act as a replace (idempotency)
        let dump2 = d.join("dump2.img");
        std::fs::copy(&out, &dump2).unwrap();
        build_image(&dump2, &out, false, 0, &files(), &|_| {}).expect("re-patch");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn garbage_dump_rejected_with_hint() {
        let _guard = lock_lwext4();
        let d = tmpdir("garbage");
        let dump = d.join("dump.img");
        std::fs::write(&dump, vec![0xffu8; 1024 * 1024]).unwrap();
        let out = d.join("out.img");
        let err = build_image(&dump, &out, false, 0, &files(), &|_| {})
            .expect_err("a garbage dump must be rejected");
        assert!(err.to_string().contains("--format-userdata"), "{err}");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn real_adbd_binary_writes_cleanly() {
        let _guard = lock_lwext4();
        let d = tmpdir("real");
        let out = d.join("userdata.img");
        build_image(
            &d.join("dump"),
            &out,
            true,
            8 * 1024 * 1024,
            &overlay_files("unit-test".into()),
            &|_| {},
        )
        .expect("real adbd");
        assert_eq!(OVERLAY_ADBD.len(), 126_768);
        let _ = std::fs::remove_dir_all(&d);
    }
}
