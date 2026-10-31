//! Scenario tests for the bring_up state machine over a scripted bus
//! (Bus + MockTransport): the regular path, first generation, unknown
//! serials, a leftover usbplug, a rejected usbplug and --no-backup —
//! no hardware.

use jb_core::config::Config;
use jb_core::session::{bring_up, BringUpError, Bus, Progress};
use rockusb::loader::{opcode, LoaderSession};
use rockusb::mock::{MockTransport, Step};
use rockusb::{DeviceMode, LoaderContainer};
use std::collections::VecDeque;
use std::time::Duration;

const EP_IN: u8 = 0x81;
const EP_OUT: u8 = 0x02;
const REGULAR_SERIAL: &str = "01139EB3613ABD80";
const GIFT_SERIAL: &str = "e5fe5a07c23ce39a";

/// Device CSW reply: USBS + tag + residue=0 + status=0.
fn csw(tag: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(13);
    v.extend_from_slice(b"USBS");
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]);
    v.push(0);
    v
}

/// Expected CBW (31 bytes), fields as in rock.c.
#[allow(clippy::too_many_arguments)]
fn cbw(
    tag: u32,
    length: u32,
    flag_in: bool,
    cmdlen: u8,
    opcode: u8,
    subcode: u8,
    address: u32,
    size: u16,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(31);
    v.extend_from_slice(b"USBC");
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&length.to_le_bytes());
    v.push(if flag_in { 0x80 } else { 0x00 });
    v.push(0);
    v.push(cmdlen);
    v.push(opcode);
    v.push(subcode);
    v.extend_from_slice(&address.to_be_bytes());
    v.push(0);
    v.extend_from_slice(&size.to_be_bytes());
    v.extend_from_slice(&[0; 7]);
    v
}

/// Synthetic 471+472 container (no real firmware bytes in tests): tiny
/// DDR init + usbplug stages, RC4 off.
fn synth_loader() -> LoaderContainer {
    const HEADER_SIZE: usize = 102;
    const ENTRY_SIZE: usize = 57;
    const DATA_OFF: usize = HEADER_SIZE + 2 * ENTRY_SIZE;
    let ddra = [0x11u8; 8];
    let usbplug = [0x33u8; 16];

    let mut buf = vec![0u8; DATA_OFF + ddra.len() + usbplug.len() + 4];
    buf[0..4].copy_from_slice(b"BOOT");
    buf[4..6].copy_from_slice(&(HEADER_SIZE as u16).to_le_bytes());
    buf[21..25].copy_from_slice(b"8033");
    buf[25] = 1; // n471
    buf[31] = 1; // n472
    buf[44] = 1; // rc4_flag != 0 -> RC4 off
                 // entry 0: DDR init (0x471)
    buf[HEADER_SIZE + 1..HEADER_SIZE + 5].copy_from_slice(&1u32.to_le_bytes());
    buf[HEADER_SIZE + 45..HEADER_SIZE + 49].copy_from_slice(&(DATA_OFF as u32).to_le_bytes());
    buf[HEADER_SIZE + 49..HEADER_SIZE + 53].copy_from_slice(&(ddra.len() as u32).to_le_bytes());
    // entry 1: usbplug (0x472)
    let e1 = HEADER_SIZE + ENTRY_SIZE;
    buf[e1 + 1..e1 + 5].copy_from_slice(&2u32.to_le_bytes());
    buf[e1 + 45..e1 + 49].copy_from_slice(&((DATA_OFF + ddra.len()) as u32).to_le_bytes());
    buf[e1 + 49..e1 + 53].copy_from_slice(&(usbplug.len() as u32).to_le_bytes());
    buf[DATA_OFF..DATA_OFF + 8].copy_from_slice(&ddra);
    buf[DATA_OFF + 8..DATA_OFF + 24].copy_from_slice(&usbplug);
    let len = buf.len() - 4;
    let crc = rockusb::util::crc32_xrock(0, &buf[..len]);
    buf[len..len + 4].copy_from_slice(&crc.to_le_bytes());
    LoaderContainer::parse(buf).expect("synthetic loader")
}

/// The expected MaskROM download transfers for the synthetic loader.
fn maskrom_download_steps() -> Vec<Step> {
    let ddra = [0x11u8; 8];
    let usbplug = [0x33u8; 16];
    let with_crc = |payload: &[u8]| -> Vec<u8> {
        let mut v = payload.to_vec();
        let crc = rockusb::util::crc16_xrock(0xffff, payload);
        v.push((crc >> 8) as u8);
        v.push((crc & 0xff) as u8);
        v
    };
    vec![
        Step::ControlOut(0x0c, 0, 0x0471, with_crc(&ddra)),
        Step::ControlOut(0x0c, 0, 0x0472, with_crc(&usbplug)),
    ]
}

/// Loader-session scenario for probe (TEST_UNIT_READY) + reset(subcode).
fn probe_and_reset_steps(subcode: u8) -> Vec<Step> {
    vec![
        Step::BulkOut(cbw(
            0x5a5a0001,
            0,
            true,
            6,
            opcode::TEST_UNIT_READY,
            0,
            0,
            0,
        )),
        Step::BulkIn(csw(0x5a5a0001)),
        Step::BulkOut(cbw(
            0x5a5a0002,
            0,
            false,
            6,
            opcode::RESET_DEVICE,
            subcode,
            0,
            0,
        )),
        Step::BulkIn(csw(0x5a5a0002)),
    ]
}

/// Loader-session scenario answering the two usbplug signature probes
/// with the values from the embedded config (the real ones for this
/// loader build).
fn signature_steps(config: &Config) -> Vec<Step> {
    let sig1 = hex::decode(&config.usbplug.signature1_hex).unwrap();
    let sig2 = hex::decode(&config.usbplug.signature2_hex).unwrap();
    vec![
        Step::BulkOut(cbw(
            0x5a5a0001,
            0,
            true,
            10,
            opcode::READ_SDRAM,
            0,
            config.usbplug.signature1_addr,
            sig1.len() as u16,
        )),
        Step::BulkIn(sig1),
        Step::BulkIn(csw(0x5a5a0001)),
        Step::BulkOut(cbw(
            0x5a5a0002,
            0,
            true,
            10,
            opcode::READ_SDRAM,
            0,
            config.usbplug.signature2_addr,
            sig2.len() as u16,
        )),
        Step::BulkIn(sig2),
        Step::BulkIn(csw(0x5a5a0002)),
    ]
}

/// Loader-session scenario for the stock-loader probe
/// (attach_stock_loader: TEST_UNIT_READY only, no reset).
fn stock_probe_steps() -> Vec<Step> {
    vec![
        Step::BulkOut(cbw(
            0x5a5a0001,
            0,
            true,
            6,
            opcode::TEST_UNIT_READY,
            0,
            0,
            0,
        )),
        Step::BulkIn(csw(0x5a5a0001)),
    ]
}

/// Scripted bus: a queue of bus snapshots plus per-call transport
/// scenarios. `poll` results are consumed in order and then repeat the
/// last one; `wait_download_mode` reports the loader persona.
struct FakeBus {
    polls: VecDeque<Option<DeviceMode>>,
    serials: VecDeque<String>,
    loader_scenarios: VecDeque<Vec<Step>>,
    maskrom_scenario: Vec<Step>,
    /// wait_mode results in call order (empty = always Ok).
    wait_mode_results: VecDeque<bool>,
    serial_reads: usize,
}

impl FakeBus {
    fn new(polls: Vec<Option<DeviceMode>>, serial: &str) -> Self {
        FakeBus {
            polls: polls.into(),
            serials: VecDeque::from([serial.to_string()]),
            loader_scenarios: VecDeque::new(),
            maskrom_scenario: Vec::new(),
            wait_mode_results: VecDeque::new(),
            serial_reads: 0,
        }
    }

    fn with_loader(mut self, scenarios: Vec<Vec<Step>>) -> Self {
        self.loader_scenarios = scenarios.into();
        self
    }

    fn with_maskrom(mut self, scenario: Vec<Step>) -> Self {
        self.maskrom_scenario = scenario;
        self
    }

    fn with_wait_results(mut self, results: Vec<bool>) -> Self {
        self.wait_mode_results = results.into();
        self
    }
}

impl Bus for FakeBus {
    type T = MockTransport;

    fn poll(&mut self) -> rockusb::Result<Option<DeviceMode>> {
        Ok(match self.polls.pop_front() {
            Some(m) => m,
            None => self.polls.back().cloned().unwrap_or(None),
        })
    }

    fn loader_serial(&mut self) -> Option<String> {
        self.serial_reads += 1;
        self.serials.pop_front()
    }

    fn open_loader(&mut self) -> rockusb::Result<LoaderSession<MockTransport>> {
        let steps = self.loader_scenarios.pop_front().unwrap_or_default();
        Ok(LoaderSession::new(MockTransport::new(steps), EP_IN, EP_OUT))
    }

    fn open_maskrom(&mut self) -> rockusb::Result<MockTransport> {
        Ok(MockTransport::new(self.maskrom_scenario.clone()))
    }

    fn wait_download_mode(
        &mut self,
        _timeout: Option<Duration>,
        _hint: &str,
    ) -> rockusb::Result<DeviceMode> {
        Ok(DeviceMode::Loader)
    }

    fn wait_mode(&mut self, _mode: DeviceMode, _timeout: Duration) -> rockusb::Result<()> {
        match self.wait_mode_results.pop_front() {
            Some(false) => Err(rockusb::Error::DeviceNotFound),
            _ => Ok(()),
        }
    }
}

fn run(
    bus: &mut FakeBus,
    no_backup: bool,
) -> Result<jb_core::session::BroughtUp<MockTransport>, BringUpError> {
    let config = Config::embedded();
    let loader = synth_loader();
    let progress = |_: Progress| {};
    bring_up(
        bus,
        &config,
        &loader,
        Some(Duration::from_secs(30)),
        no_backup,
        &progress,
    )
}

/// A full regular run: 330d → serial → MaskROM → download → usbplug →
/// signatures.

#[test]
fn regular_column_goes_through_maskrom_to_usbplug() {
    let config = Config::embedded();
    // one Loader iteration (serial + probe + reset), then the MaskROM
    // appears after wait_mode; the final usbplug open happens inside
    // the MaskRom branch without another poll
    let mut bus = FakeBus::new(
        vec![Some(DeviceMode::Loader), Some(DeviceMode::MaskRom)],
        REGULAR_SERIAL,
    )
    .with_loader(vec![
        probe_and_reset_steps(0x03), // probe + reset to MaskROM
        signature_steps(&config),    // the final usbplug session
    ])
    .with_maskrom(maskrom_download_steps());

    let up = run(&mut bus, false).expect("bring-up");
    assert!(!up.firstgen);
    assert_eq!(up.serial, REGULAR_SERIAL);
    // the identity is read exactly once, at the loader persona
    assert_eq!(bus.serial_reads, 1);
}

#[test]
fn first_generation_sticks_to_the_stock_loader() {
    let mut bus = FakeBus::new(vec![Some(DeviceMode::Loader)], GIFT_SERIAL)
        .with_loader(vec![stock_probe_steps()]);

    let up = run(&mut bus, false).expect("bring-up");
    assert!(up.firstgen);
    assert_eq!(up.serial, GIFT_SERIAL);
    // no MaskROM reset ever happens on the first-generation path
    assert_eq!(bus.serial_reads, 1);
}

/// A --no-backup run keeps the stock 330d session for a REGULAR serial
/// too: no MaskROM reset, no download, no signature probes — the run
/// never reads above the stock read mask. The scripted loader scenario
/// (probe only, no reset CBW) fails the test if the regular path runs.
#[test]
fn no_backup_regular_column_sticks_to_the_stock_loader() {
    let mut bus = FakeBus::new(vec![Some(DeviceMode::Loader)], REGULAR_SERIAL)
        .with_loader(vec![stock_probe_steps()]);

    let up = run(&mut bus, true).expect("bring-up");
    // a regular column stays regular: only the transport differs
    assert!(!up.firstgen);
    assert_eq!(up.serial, REGULAR_SERIAL);
    assert_eq!(bus.serial_reads, 1);
}

#[test]
fn unreadable_serial_refuses_then_recovers_on_reentry() {
    let config = Config::embedded();
    let mut bus = FakeBus {
        // first recognition reports zeros (broken read), then a real
        // serial after the re-entry
        serials: VecDeque::from(["000000000".to_string(), REGULAR_SERIAL.to_string()]),
        polls: vec![
            Some(DeviceMode::Loader),
            None,
            Some(DeviceMode::Loader),
            Some(DeviceMode::MaskRom),
        ]
        .into(),
        loader_scenarios: vec![probe_and_reset_steps(0x03), signature_steps(&config)].into(),
        maskrom_scenario: maskrom_download_steps(),
        wait_mode_results: VecDeque::new(),
        serial_reads: 0,
    };

    let up = run(&mut bus, false).expect("bring-up after re-entry");
    assert!(!up.firstgen);
    assert_eq!(up.serial, REGULAR_SERIAL);
    assert_eq!(bus.serial_reads, 2);
}

#[test]
fn leftover_usbplug_is_refused_until_loader_reentry() {
    let config = Config::embedded();
    let mut bus = FakeBus {
        serials: VecDeque::from([REGULAR_SERIAL.to_string()]),
        polls: vec![
            Some(DeviceMode::UsbPlug),
            Some(DeviceMode::Loader),
            Some(DeviceMode::MaskRom),
        ]
        .into(),
        loader_scenarios: vec![probe_and_reset_steps(0x03), signature_steps(&config)].into(),
        maskrom_scenario: maskrom_download_steps(),
        wait_mode_results: VecDeque::new(),
        serial_reads: 0,
    };

    let up = run(&mut bus, false).expect("bring-up after re-entry");
    assert!(!up.firstgen);
    // the usbplug persona never contributed a serial
    assert_eq!(bus.serial_reads, 1);
}

#[test]
fn direct_maskrom_entry_without_serial_is_refused() {
    let config = Config::embedded();
    let mut bus = FakeBus {
        serials: VecDeque::from([REGULAR_SERIAL.to_string()]),
        polls: vec![
            Some(DeviceMode::MaskRom), // direct entry: no serial yet
            Some(DeviceMode::Loader),
            Some(DeviceMode::MaskRom),
        ]
        .into(),
        loader_scenarios: vec![probe_and_reset_steps(0x03), signature_steps(&config)].into(),
        maskrom_scenario: maskrom_download_steps(),
        wait_mode_results: VecDeque::new(),
        serial_reads: 0,
    };

    let up = run(&mut bus, false).expect("bring-up after loader re-entry");
    assert_eq!(up.serial, REGULAR_SERIAL);
    assert_eq!(bus.serial_reads, 1);
}

#[test]
fn usbplug_never_rising_is_loader_rejected() {
    let mut bus = FakeBus::new(
        vec![Some(DeviceMode::Loader), Some(DeviceMode::MaskRom)],
        REGULAR_SERIAL,
    )
    .with_loader(vec![probe_and_reset_steps(0x03)])
    .with_maskrom(maskrom_download_steps())
    // wait_mode: MaskROM after reset Ok, usbplug after download Err
    .with_wait_results(vec![true, false]);

    let err = match run(&mut bus, false) {
        Ok(_) => panic!("usbplug never rose — bring_up must be rejected"),
        Err(e) => e,
    };
    assert!(matches!(err, BringUpError::LoaderRejected), "{err}");
}

#[test]
fn wrong_dram_signatures_fail_the_bring_up() {
    let config = Config::embedded();
    // signature1 answered with garbage
    let mut bad = signature_steps(&config);
    if let Step::BulkIn(data) = &mut bad[1] {
        data[0] ^= 0xff;
    } else {
        panic!("scenario layout");
    }
    let mut bus = FakeBus::new(
        vec![Some(DeviceMode::Loader), Some(DeviceMode::MaskRom)],
        REGULAR_SERIAL,
    )
    .with_loader(vec![probe_and_reset_steps(0x03), bad])
    .with_maskrom(maskrom_download_steps());

    let err = match run(&mut bus, false) {
        Ok(_) => panic!("wrong signatures — bring_up must fail"),
        Err(e) => e,
    };
    assert!(err.to_string().contains("сигнатуры"), "{err}");
}
