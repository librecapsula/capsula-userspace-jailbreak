//! Windows implementation: devnode scanning (setupapi), package
//! installation (newdev + crypt32) and the elevated helper.

use crate::{log_line, Package, PACKAGES};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiGetDeviceInstanceIdW, SetupDiGetDeviceRegistryPropertyW,
    UpdateDriverForPlugAndPlayDevicesW, DIGCF_ALLCLASSES, DIGCF_PRESENT, SPDRP_HARDWAREID,
    SPDRP_SERVICE, SP_DEVINFO_DATA,
};
use windows_sys::Win32::Foundation::{GetLastError, MAX_PATH};
use windows_sys::Win32::Security::Cryptography::{
    CertAddEncodedCertificateToStore, CertCloseStore, CertOpenStore, CERT_STORE_ADD_USE_EXISTING,
    CERT_STORE_NO_CRYPT_RELEASE_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_SYSTEM_STORE_LOCAL_MACHINE,
    PKCS_7_ASN_ENCODING, X509_ASN_ENCODING,
};
use windows_sys::Win32::System::Console::{GetConsoleProcessList, GetConsoleWindow};
use windows_sys::Win32::UI::Shell::IsUserAnAdmin;

/// `UpdateDriverForPlugAndPlayDevices`: install even if the current
/// driver looks "better" — this is what wins the ranking war against
/// the vendor Rockusb package on freshly created devnodes.
const INSTALLFLAG_FORCE: u32 = 0x0000_0001;

/// How often the supervisor re-checks devnode bindings.
const POLL: Duration = Duration::from_millis(500);
/// The helper never outlives this (parent crash protection).
const HELPER_TTL: Duration = Duration::from_secs(30 * 60);

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    std::ffi::OsStr::new(s)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn narrow(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// A present USB devnode of the Rockchip vendor.
pub struct Node {
    pub instance_id: String,
    pub hwid: String,
    pub service: String,
}

impl Node {
    /// usbccgp is fine too: a composite parent is not ours to rebind
    /// (the post-jailbreak adb gadget may become one).
    pub fn bound_ok(&self) -> bool {
        self.service.eq_ignore_ascii_case("WinUSB") || self.service.eq_ignore_ascii_case("usbccgp")
    }
}

/// All present devnodes under `USB\VID_2207&*`.
pub fn rockchip_nodes() -> Vec<Node> {
    unsafe {
        let set = SetupDiGetClassDevsW(
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null_mut(),
            DIGCF_ALLCLASSES | DIGCF_PRESENT,
        );
        if set == -1 {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut idx: u32 = 0;
        loop {
            let mut dev: SP_DEVINFO_DATA = std::mem::zeroed();
            dev.cbSize = std::mem::size_of::<SP_DEVINFO_DATA>() as u32;
            if SetupDiEnumDeviceInfo(set, idx, &mut dev) == 0 {
                break;
            }
            idx += 1;

            let mut buf = [0u16; MAX_PATH as usize];
            let mut written = 0u32;
            if SetupDiGetDeviceInstanceIdW(
                set,
                &dev,
                buf.as_mut_ptr(),
                buf.len() as u32,
                &mut written,
            ) == 0
            {
                continue;
            }
            let instance_id = narrow(&buf[..written as usize]);
            if !instance_id.starts_with("USB\\VID_2207&") {
                continue;
            }

            let hwid = reg_string(set, &dev, SPDRP_HARDWAREID, true);
            let service = reg_string(set, &dev, SPDRP_SERVICE, false);
            out.push(Node {
                instance_id,
                hwid,
                service,
            });
        }
        SetupDiDestroyDeviceInfoList(set);
        out
    }
}

/// SPDRP_* as a string; `multi` takes the first entry of a REG_MULTI_SZ.
fn reg_string(set: isize, dev: &SP_DEVINFO_DATA, prop: u32, multi: bool) -> String {
    unsafe {
        let mut needed = 0u32;
        SetupDiGetDeviceRegistryPropertyW(
            set,
            dev,
            prop,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
        if needed == 0 {
            return String::new();
        }
        let mut buf = vec![0u8; needed as usize];
        if SetupDiGetDeviceRegistryPropertyW(
            set,
            dev,
            prop,
            std::ptr::null_mut(),
            buf.as_mut_ptr(),
            needed,
            std::ptr::null_mut(),
        ) == 0
        {
            return String::new();
        }
        let (words, _) = buf.as_chunks::<2>();
        let units: Vec<u16> = words.iter().map(|c| u16::from_ne_bytes(*c)).collect();
        let s = narrow(&units);
        if multi {
            // first line of the multi-sz is the specific hardware ID
            s.lines().next().unwrap_or("").into()
        } else {
            s
        }
    }
}

/// Write inf+cat to `dir`, keeping the original file names.
pub fn materialize(pkg: &Package, dir: &Path) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(dir.join(pkg.inf_name), pkg.inf)?;
    std::fs::write(dir.join(pkg.cat_name), pkg.cat)?;
    Ok(dir.join(pkg.inf_name))
}

/// Install the self-signed signer certificate into the LOCAL MACHINE
/// Root and TrustedPublisher stores so the catalog signature validates
/// for the driver installation. Machine stores are opened explicitly:
/// `CertOpenSystemStore` maps to the CURRENT USER stores, where a Root
/// add from an interactive process pops a modal Windows confirmation
/// dialog (and the wrong store scope for driver validation anyway).
pub fn install_cert(cer: &[u8]) -> Result<(), String> {
    unsafe {
        for name in ["Root", "TrustedPublisher"] {
            let name_w = wide(name);
            let store = CertOpenStore(
                CERT_STORE_PROV_SYSTEM_W,
                0,
                0,
                CERT_STORE_NO_CRYPT_RELEASE_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
                name_w.as_ptr().cast(),
            );
            if store.is_null() {
                return Err(format!(
                    "CertOpenStore({name}, machine) failed: {}",
                    GetLastError()
                ));
            }
            let ok = CertAddEncodedCertificateToStore(
                store,
                X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                cer.as_ptr(),
                cer.len() as u32,
                CERT_STORE_ADD_USE_EXISTING,
                std::ptr::null_mut(),
            );
            let err = GetLastError();
            CertCloseStore(store, 0);
            if ok == 0 {
                // "object already exists" is the normal second-run path
                // (CRYPT_E_EXISTS = 0x80092005); anything else is real.
                return Err(format!(
                    "CertAddEncodedCertificateToStore({name}, machine) failed: {err}"
                ));
            }
        }
    }
    Ok(())
}

/// Force-bind the hardware ID to the package at `inf_path` (present
/// devices). Also imports the package into the driver store.
pub fn force_bind(inf_path: &Path, hwid: &str) -> Result<(), String> {
    let inf_w = wide(&inf_path.to_string_lossy());
    let hwid_w = wide(hwid);
    let mut reboot: i32 = 0;
    let ok = unsafe {
        UpdateDriverForPlugAndPlayDevicesW(
            std::ptr::null_mut(),
            hwid_w.as_ptr(),
            inf_w.as_ptr(),
            INSTALLFLAG_FORCE,
            &mut reboot,
        )
    };
    if ok != 0 {
        Ok(())
    } else {
        Err(format!("driver install for {hwid} failed: {}", unsafe {
            GetLastError()
        }))
    }
}

/// Per-instance pacing state for the supervisor.
///
/// `UpdateDriverForPlugAndPlayDevices` restarts the devnode, and while
/// the node is restarting it transiently reads as misbound — without
/// pacing the supervisor would re-trigger itself on its own restart
/// forever, starving the bus with PnP churn. New instance IDs (the
/// board hops devnodes as it changes modes) are always acted on
/// immediately; repeated no-improvement rebinds of the same node get
/// rate-limited and eventually penalized.
#[derive(Default)]
struct Rebindings {
    last_attempt: std::collections::HashMap<String, Instant>,
    strikes: std::collections::HashMap<String, u32>,
    penalty_until: Option<Instant>,
}

/// Minimum spacing between rebind attempts of the same devnode.
const REBIND_COOLDOWN: Duration = Duration::from_secs(15);
/// After this many no-improvement rebinds of the same node, back off.
const REBIND_STRIKE_LIMIT: u32 = 5;
const REBIND_STRIKE_PENALTY: Duration = Duration::from_secs(60);

impl Rebindings {
    fn paced(&self, instance: &str) -> bool {
        self.last_attempt
            .get(instance)
            .is_some_and(|t| t.elapsed() < REBIND_COOLDOWN)
    }

    fn mark_attempt(&mut self, instance: &str) {
        self.last_attempt
            .insert(instance.to_string(), Instant::now());
    }
}

/// One supervisor pass: rebind misbound Rockchip devnodes that are not
/// paced. Returns human-readable actions for the log.
fn rebind_pass(dir: &Path, log: &Path, rb: &mut Rebindings) -> Vec<String> {
    let mut actions = Vec::new();
    if rb.penalty_until.is_some_and(|t| Instant::now() >= t) {
        rb.penalty_until = None;
    }
    if rb.penalty_until.is_some() {
        return actions;
    }
    let nodes = rockchip_nodes();
    // nodes that recovered on their own clear their strike record
    for n in &nodes {
        if n.bound_ok() {
            rb.strikes.remove(&n.instance_id);
        }
    }
    for pkg in PACKAGES {
        let targets: Vec<&Node> = nodes
            .iter()
            .filter(|n| n.hwid.starts_with(pkg.hwid) && !n.bound_ok())
            .collect();
        for node in &targets {
            if rb.paced(&node.instance_id) {
                continue;
            }
            rb.mark_attempt(&node.instance_id);
            let attempt = materialize(pkg, dir)
                .map_err(|e| e.to_string())
                .and_then(|inf| force_bind(&inf, pkg.hwid));
            let msg = match attempt {
                Ok(()) => format!("rebound {} -> WinUSB ({})", pkg.hwid, node.instance_id),
                Err(e) => format!("rebind {} failed: {e}", pkg.hwid),
            };
            log_line(log, &msg);
            actions.push(msg);
            let strikes = rb.strikes.entry(node.instance_id.clone()).or_insert(0);
            *strikes += 1;
            if *strikes > REBIND_STRIKE_LIMIT {
                rb.penalty_until = Some(Instant::now() + REBIND_STRIKE_PENALTY);
                let msg = format!(
                    "node {} not improving after {REBIND_STRIKE_LIMIT} rebinds — \
                     backing off for {} s (see DRIVER-SETUP.txt for manual steps)",
                    node.instance_id,
                    REBIND_STRIKE_PENALTY.as_secs()
                );
                log_line(log, &msg);
                actions.push(msg);
                rb.strikes.clear();
            }
        }
    }
    actions
}

/// The supervisor loop: one immediate pass, then keep watching while
/// the parent session lives (the done file appears on its drop).
/// The `ready` sibling of `done` appears once the initial install pass
/// has completed; `hb` is touched periodically as a liveness signal.
fn supervise(dir: &Path, done: &Path, log: &Path) {
    let ready = done.with_extension("ready");
    let hb = done.with_extension("hb");
    // Certificates first: without them the first force_bind on a fresh
    // machine would fail signature validation.
    for pkg in PACKAGES {
        if let Err(e) = install_cert(pkg.cer) {
            log_line(log, &format!("cert install failed: {e}"));
        }
    }
    let mut rb = Rebindings::default();
    rebind_pass(dir, log, &mut rb);
    let _ = std::fs::write(&ready, b"ready");
    log_line(log, "initial driver pass complete (ready)");
    let start = Instant::now();
    let mut last_hb = Instant::now();
    while !done.exists() && start.elapsed() < HELPER_TTL {
        if rockchip_nodes().iter().any(|n| !n.bound_ok()) {
            rebind_pass(dir, log, &mut rb);
        }
        if last_hb.elapsed() >= Duration::from_secs(2) {
            let _ = std::fs::write(&hb, b"hb");
            last_hb = Instant::now();
        }
        std::thread::sleep(POLL);
    }
}

/// Driver supervision session. The process itself is elevated (the
/// Windows build requires it in its UAC manifest), so the supervisor
/// is just a background thread that keeps Rockchip devnodes on WinUSB
/// for the lifetime of the run; it stops when the Session drops.
pub struct Session {
    done: PathBuf,
    log: PathBuf,
    dir: PathBuf,
    started: bool,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        let base = std::env::temp_dir().join(format!("capsula-jb-winusb-{}", std::process::id()));
        Session {
            done: base.join("done"),
            log: base.join("session.log"),
            dir: base.join("pkg"),
            started: false,
        }
    }

    /// Path of the session log (diagnostics).
    pub fn log_path(&self) -> &Path {
        &self.log
    }

    /// Start supervision (idempotent).
    pub fn ensure_supervision(&mut self) -> anyhow::Result<()> {
        if self.started {
            return Ok(());
        }
        if !self.elevated() {
            anyhow::bail!(
                "process is not elevated: the Windows build requires an \
                 administrator console (UAC manifest)"
            );
        }
        std::fs::create_dir_all(&self.dir)?;
        let dir = self.dir.clone();
        let done = self.done.clone();
        let log = self.log.clone();
        std::thread::spawn(move || supervise(&dir, &done, &log));
        log_line(&self.log, "inline supervisor started");
        self.started = true;
        Ok(())
    }

    /// True when the process runs with administrator rights.
    pub fn elevated(&self) -> bool {
        unsafe { IsUserAnAdmin() != 0 }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = std::fs::write(&self.done, b"done");
    }
}

/// Pause before exit when this console window was created for the
/// process alone — what happens when an unelevated console (or
/// Explorer) launches the tool and Windows elevates it into a NEW
/// console: without a pause the window (and all the output) would
/// vanish with the process. A shared terminal (two or more attached
/// processes) or no console at all gets no pause.
pub fn pause_if_own_console() {
    use std::io::{BufRead, Write};
    unsafe {
        if GetConsoleWindow().is_null() {
            return;
        }
        let mut procs = [0u32; 16];
        let n = GetConsoleProcessList(procs.as_mut_ptr(), 16);
        if n != 1 {
            return;
        }
    }
    let mut out = std::io::stdout();
    let _ = writeln!(out, "\npress Enter to close this window...");
    let _ = out.flush();
    let mut line = String::new();
    let _ = std::io::stdin().lock().read_line(&mut line);
}

/// An elevated relaunch may start with CWD = C:\Windows\System32 (the
/// elevation broker's default); the tool writes ota/backup/work
/// relative to the CWD, so move to the executable's directory in that
/// case. Returns the new CWD when it was changed.
pub fn fix_cwd_if_system32() -> Option<PathBuf> {
    let cwd = std::env::current_dir().ok()?;
    let cwd_s = cwd.to_string_lossy().to_lowercase();
    if !cwd_s.contains("\\windows\\system32") {
        return None;
    }
    let exe_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    std::env::set_current_dir(&exe_dir).ok()?;
    Some(exe_dir)
}
