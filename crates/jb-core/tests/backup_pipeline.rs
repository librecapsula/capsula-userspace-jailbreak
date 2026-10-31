//! Integration test of the full backup pipeline on MockTransport:
//! the read-limit RAM patch -> the 0xCC guard -> the GPT -> chunked
//! partition reads -> the directory layout (SHA256SUMS/SUCCESS/tsv) —
//! no hardware involved.

use jb_core::backup::{backup, CHUNK_SECTORS, GUARD_LBA};
use jb_core::config::Config;
use jb_core::gpt;
use rockusb::loader::{opcode, LoaderSession};
use rockusb::mock::{MockTransport, Step};
use std::io::Write as _;

const EP_IN: u8 = 0x81;
const EP_OUT: u8 = 0x02;
const LIMIT_ADDR: u32 = 0x0334_3EC4;
const READ_LIMIT: u32 = 0x11000; // above GUARD_LBA (0x10000); "flash" of 69632 sectors

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
    let mut v = Vec::new();
    v.extend_from_slice(b"USBC");
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&length.to_le_bytes());
    v.push(if flag_in { 0x80 } else { 0 });
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

fn csw(tag: u32) -> Vec<u8> {
    let mut v = b"USBS".to_vec();
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0, 0]);
    v
}

fn flash_info_reply(total: u32) -> Vec<u8> {
    let mut v = total.to_le_bytes().to_vec();
    v.extend_from_slice(&[0x00, 0x01, 4, 40, 25, 0x98, 0]);
    v
}

/// Minimal GPT: entries (name, first_lba, last_lba), entries at LBA2..6.
fn build_gpt_entries(entries: &[(&str, u64, u64)]) -> Vec<u8> {
    let mut data = vec![0u8; 34 * 512];
    let mut blob = vec![0u8; entries.len().max(4) * 128];
    for (i, (name, first, last)) in entries.iter().enumerate() {
        let e = &mut blob[i * 128..(i + 1) * 128];
        e[..16].copy_from_slice(&[0xaf; 16]); // type guid != 0
        e[32..40].copy_from_slice(&first.to_le_bytes());
        e[40..48].copy_from_slice(&last.to_le_bytes());
        for (j, ch) in name.encode_utf16().enumerate() {
            e[56 + j * 2..58 + j * 2].copy_from_slice(&ch.to_le_bytes());
        }
    }
    let hdr = &mut data[..512];
    hdr[..8].copy_from_slice(b"EFI PART");
    hdr[12..16].copy_from_slice(&92u32.to_le_bytes()); // header size
    hdr[72..80].copy_from_slice(&2u64.to_le_bytes()); // entry lba
    hdr[80..84].copy_from_slice(&(entries.len().max(4) as u32).to_le_bytes());
    hdr[84..88].copy_from_slice(&128u32.to_le_bytes());
    // entries CRC
    let ecrc = crc32fast::hash(&blob);
    hdr[88..92].copy_from_slice(&ecrc.to_le_bytes());
    hdr[40..48].copy_from_slice(&34u64.to_le_bytes()); // first usable
    hdr[48..56].copy_from_slice(
        &entries
            .last()
            .map(|(_, _, l)| l + 16)
            .unwrap_or(4000)
            .to_le_bytes(), // last usable
    );
    hdr[16..20].fill(0); // CRC field is zeroed for the header CRC
    let hcrc = crc32fast::hash(&hdr[..92]);
    hdr[16..20].copy_from_slice(&hcrc.to_le_bytes());
    data[512..512 + blob.len()].copy_from_slice(&blob);
    data
}

/// Minimal GPT: 2 partitions (sec 512x1, data 513x3), entries at LBA2..6.
fn build_gpt() -> Vec<u8> {
    build_gpt_entries(&[("sec", 512, 512), ("data", 513, 515)])
}

fn test_config() -> Config {
    Config::embedded()
}

#[test]
fn backup_pipeline_on_mock() {
    let gpt_raw = build_gpt();
    let mut flash = vec![0xA5u8; READ_LIMIT as usize * 512];
    // partition contents: distinct patterns
    for (i, b) in flash[512 * 512..512 * 513].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }

    let mut steps = Vec::new();
    let mut tag = 0x5a5a0000u32;
    macro_rules! t {
        () => {{
            tag += 1;
            tag
        }};
    }

    // patch_read_limit: flash_detect
    steps.push(Step::BulkOut(cbw(
        t!(),
        11,
        true,
        6,
        opcode::READ_FLASH_INFO,
        0,
        0,
        0,
    )));
    steps.push(Step::BulkIn(flash_info_reply(READ_LIMIT)));
    steps.push(Step::BulkIn(csw(tag)));
    steps.push(Step::BulkOut(cbw(
        t!(),
        5,
        true,
        6,
        opcode::READ_FLASH_ID,
        0,
        0,
        0,
    )));
    steps.push(Step::BulkIn(vec![0x2c, 0x64, 0x90, 0xa5, 0x76]));
    steps.push(Step::BulkIn(csw(tag)));
    // read_mem(limit, 4): the old value 0x10000
    steps.push(Step::BulkOut(cbw(
        t!(),
        0,
        true,
        10,
        opcode::READ_SDRAM,
        0,
        LIMIT_ADDR,
        4,
    )));
    steps.push(Step::BulkIn(0x10000u32.to_le_bytes().to_vec()));
    steps.push(Step::BulkIn(csw(tag)));
    // write_mem(limit, 4): the new value
    steps.push(Step::BulkOut(cbw(
        t!(),
        0,
        false,
        10,
        opcode::WRITE_SDRAM,
        0,
        LIMIT_ADDR,
        4,
    )));
    steps.push(Step::BulkOut(READ_LIMIT.to_le_bytes().to_vec()));
    steps.push(Step::BulkIn(csw(tag)));
    // readback
    steps.push(Step::BulkOut(cbw(
        t!(),
        0,
        true,
        10,
        opcode::READ_SDRAM,
        0,
        LIMIT_ADDR,
        4,
    )));
    steps.push(Step::BulkIn(READ_LIMIT.to_le_bytes().to_vec()));
    steps.push(Step::BulkIn(csw(tag)));

    // cc_guard: read the GUARD_LBA sector (not 0xCC)
    steps.push(Step::BulkOut(cbw(
        t!(),
        512,
        true,
        10,
        opcode::READ_LBA,
        0,
        GUARD_LBA,
        1,
    )));
    steps.push(Step::BulkIn(
        flash[GUARD_LBA as usize * 512..GUARD_LBA as usize * 512 + 512].to_vec(),
    ));
    steps.push(Step::BulkIn(csw(tag)));

    // GPT: 34 sectors from LBA1 (a single chunk)
    steps.push(Step::BulkOut(cbw(
        t!(),
        34 * 512,
        true,
        10,
        opcode::READ_LBA,
        0,
        1,
        34,
    )));
    steps.push(Step::BulkIn(gpt_raw.clone()));
    steps.push(Step::BulkIn(csw(tag)));

    // flash_detect again (for the report)
    steps.push(Step::BulkOut(cbw(
        t!(),
        11,
        true,
        6,
        opcode::READ_FLASH_INFO,
        0,
        0,
        0,
    )));
    steps.push(Step::BulkIn(flash_info_reply(READ_LIMIT)));
    steps.push(Step::BulkIn(csw(tag)));
    steps.push(Step::BulkOut(cbw(
        t!(),
        5,
        true,
        6,
        opcode::READ_FLASH_ID,
        0,
        0,
        0,
    )));
    steps.push(Step::BulkIn(vec![0x2c, 0x64, 0x90, 0xa5, 0x76]));
    steps.push(Step::BulkIn(csw(tag)));

    // sec (1 sector)
    steps.push(Step::BulkOut(cbw(
        t!(),
        512,
        true,
        10,
        opcode::READ_LBA,
        0,
        512,
        1,
    )));
    steps.push(Step::BulkIn(flash[512 * 512..512 * 513].to_vec()));
    steps.push(Step::BulkIn(csw(tag)));
    // data (3 sectors)
    steps.push(Step::BulkOut(cbw(
        t!(),
        3 * 512,
        true,
        10,
        opcode::READ_LBA,
        0,
        513,
        3,
    )));
    steps.push(Step::BulkIn(flash[513 * 512..516 * 512].to_vec()));
    steps.push(Step::BulkIn(csw(tag)));

    let transport = MockTransport::new(steps);
    let mut s = LoaderSession::new(transport, EP_IN, EP_OUT);

    let out = std::env::temp_dir().join(format!("jb-backup-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let report = backup(&mut s, &test_config(), &out, &|_| {}, false).expect("backup pipeline");
    assert_eq!(report.partitions, 2);
    assert_eq!(report.sectors_total, READ_LIMIT as u64);
    assert_eq!(report.read_limit_old, Some(0x10000));

    // the directory layout is compatible
    let sec = std::fs::read(out.join("01_sec.img")).unwrap();
    assert_eq!(sec, &flash[512 * 512..512 * 513]);
    let data_img = std::fs::read(out.join("02_data.img")).unwrap();
    assert_eq!(data_img, &flash[513 * 512..516 * 512]);
    assert!(out.join(".gpt.bin").is_file());
    let tsv = std::fs::read_to_string(out.join("partition_table.tsv")).unwrap();
    assert_eq!(tsv, "1\tsec\t512\t1\n2\tdata\t513\t3\n");
    let sums = std::fs::read_to_string(out.join("SHA256SUMS.txt")).unwrap();
    assert_eq!(sums.lines().count(), 2);
    let expected_sum = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&sec);
        hex::encode(h.finalize())
    };
    assert!(sums.starts_with(&format!("{expected_sum}  01_sec.img")));
    assert!(std::fs::read_to_string(out.join("SUCCESS.txt"))
        .unwrap()
        .starts_with("SUCCESS: "));

    // BackupStore opens and verifies the result
    let store = jb_core::backup_store::BackupStore::open(&out).unwrap();
    store.verify().expect("verify");
    assert!(store.find("sec").is_some());

    // the GPT module parses the saved dump the same way
    let parsed = gpt::Gpt::parse(&std::fs::read(out.join(".gpt.bin")).unwrap()).unwrap();
    assert_eq!(parsed.entries.len(), 2);

    let _ = std::fs::remove_dir_all(&out);
    let _ = std::io::stdout().flush();
}

#[test]
fn backup_fails_on_cc_mask() {
    // usbplug with an unpatched limit: the GUARD_LBA guard reads 0xCC.
    let mut steps = Vec::new();
    let mut tag = 0x5a5a0000u32;
    macro_rules! t {
        () => {{
            tag += 1;
            tag
        }};
    }
    steps.push(Step::BulkOut(cbw(
        t!(),
        11,
        true,
        6,
        opcode::READ_FLASH_INFO,
        0,
        0,
        0,
    )));
    steps.push(Step::BulkIn(flash_info_reply(READ_LIMIT)));
    steps.push(Step::BulkIn(csw(tag)));
    steps.push(Step::BulkOut(cbw(
        t!(),
        5,
        true,
        6,
        opcode::READ_FLASH_ID,
        0,
        0,
        0,
    )));
    steps.push(Step::BulkIn(vec![1, 2, 3, 4, 5]));
    steps.push(Step::BulkIn(csw(tag)));
    // the old limit already equals total -> no patch
    steps.push(Step::BulkOut(cbw(
        t!(),
        0,
        true,
        10,
        opcode::READ_SDRAM,
        0,
        LIMIT_ADDR,
        4,
    )));
    steps.push(Step::BulkIn(READ_LIMIT.to_le_bytes().to_vec()));
    steps.push(Step::BulkIn(csw(tag)));
    // the guard: the mask
    steps.push(Step::BulkOut(cbw(
        t!(),
        512,
        true,
        10,
        opcode::READ_LBA,
        0,
        GUARD_LBA,
        1,
    )));
    steps.push(Step::BulkIn(vec![0xcc; 512]));
    steps.push(Step::BulkIn(csw(tag)));

    let transport = MockTransport::new(steps);
    let mut s = LoaderSession::new(transport, EP_IN, EP_OUT);
    let out = std::env::temp_dir().join(format!("jb-cc-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let err = backup(&mut s, &test_config(), &out, &|_| {}, false)
        .expect_err("the mask must be caught");
    assert!(err.to_string().contains("0xCC"), "{err}");
    let _ = std::fs::remove_dir_all(&out);
}

/// The partition write is chunked with progress events per chunk (the
/// progress bar must move during a long userdata flash).
#[test]
fn write_partition_is_chunked_with_progress() {
    use jb_core::flash::write_partition_padded;
    use jb_core::gpt::{Gpt, GptEntry};
    use jb_core::session::Progress;

    let total = CHUNK_SECTORS as u64 + 3;
    let gpt = Gpt {
        entries: vec![GptEntry {
            idx: 1,
            name: "user".into(),
            first_lba: 512,
            last_lba: 512 + total - 1,
            sectors: total,
        }],
        first_usable_lba: 34,
        last_usable_lba: 1_000_000,
        entries_end_lba: 6,
    };

    // an image smaller than the partition -> zero-padded to psize
    let dir = std::env::temp_dir().join(format!("jb-flash-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let img = dir.join("user.img");
    std::fs::write(&img, b"payload!!").unwrap();
    let mut data = vec![0u8; total as usize * 512];
    data[..9].copy_from_slice(b"payload!!");

    let mut steps = Vec::new();
    let mut tag = 0x5a5a0000u32;
    // chunk 1: CHUNK_SECTORS sectors from LBA 512
    tag += 1;
    steps.push(Step::BulkOut(cbw(
        tag,
        CHUNK_SECTORS * 512,
        false,
        10,
        opcode::WRITE_LBA,
        0,
        512,
        CHUNK_SECTORS as u16,
    )));
    steps.push(Step::BulkOut(data[..CHUNK_SECTORS as usize * 512].to_vec()));
    steps.push(Step::BulkIn(csw(tag)));
    // chunk 2: the remaining 3 sectors
    tag += 1;
    steps.push(Step::BulkOut(cbw(
        tag,
        3 * 512,
        false,
        10,
        opcode::WRITE_LBA,
        0,
        512 + CHUNK_SECTORS,
        3,
    )));
    steps.push(Step::BulkOut(data[CHUNK_SECTORS as usize * 512..].to_vec()));
    steps.push(Step::BulkIn(csw(tag)));

    let transport = MockTransport::new(steps);
    let mut s = LoaderSession::new(transport, EP_IN, EP_OUT);

    let events = std::cell::RefCell::new(Vec::new());
    let progress = |ev: Progress| events.borrow_mut().push(ev);
    write_partition_padded(&mut s, &gpt, "user", &img, &progress).expect("write");

    let evs = events.into_inner();
    assert!(matches!(
        evs.first(),
        Some(Progress::PartitionStart { sectors, .. }) if *sectors == total
    ));
    let mut prog = evs.iter().filter_map(|e| match e {
        Progress::PartitionProgress { done, .. } => Some(*done),
        _ => None,
    });
    assert_eq!(prog.next(), Some(CHUNK_SECTORS as u64));
    assert_eq!(prog.next(), Some(total));
    assert!(matches!(evs.last(), Some(Progress::PartitionDone { .. })));

    let _ = std::fs::remove_dir_all(&dir);
}

/// Stock loader (first generation): no RAM patch, no guard — the dump
/// runs anyway. Partitions from GUARD_LBA up come back as 0xCC (fully
/// above the mask) or lose their tail (straddling, boot_b-like); the
/// store stays verifiable, the run must warn about it.
#[test]
fn backup_on_stock_loader_keeps_masked_partitions() {
    use jb_core::session::Progress;

    const GUARD: u64 = GUARD_LBA as u64;
    let entries = [
        ("low", 512, 514),             // fully below the mask
        ("straddle", GUARD - 2, GUARD + 1), // crosses GUARD like boot_b
        ("high", GUARD + 16, GUARD + 17),   // fully above the mask
    ];
    let gpt_raw = build_gpt_entries(&entries);

    // real flash content below the mask, 0xCC above it
    let real = |lba: u64| -> Vec<u8> { (0..512).map(|i| (lba as usize * 7 + i) as u8).collect() };
    let cc = vec![0xccu8; 512];
    let low_reply = [real(512), real(513), real(514)].concat();
    let straddle_reply = [real(GUARD - 2), real(GUARD - 1), cc.clone(), cc.clone()].concat();
    let high_reply = [cc.clone(), cc.clone()].concat();

    let mut steps = Vec::new();
    let mut tag = 0x5a5a0000u32;
    macro_rules! t {
        () => {{
            tag += 1;
            tag
        }};
    }

    // GPT: 34 sectors from LBA1
    steps.push(Step::BulkOut(cbw(
        t!(),
        34 * 512,
        true,
        10,
        opcode::READ_LBA,
        0,
        1,
        34,
    )));
    steps.push(Step::BulkIn(gpt_raw.clone()));
    steps.push(Step::BulkIn(csw(tag)));

    // flash_detect (for the report)
    steps.push(Step::BulkOut(cbw(
        t!(),
        11,
        true,
        6,
        opcode::READ_FLASH_INFO,
        0,
        0,
        0,
    )));
    steps.push(Step::BulkIn(flash_info_reply(READ_LIMIT)));
    steps.push(Step::BulkIn(csw(tag)));
    steps.push(Step::BulkOut(cbw(
        t!(),
        5,
        true,
        6,
        opcode::READ_FLASH_ID,
        0,
        0,
        0,
    )));
    steps.push(Step::BulkIn(vec![0x2c, 0x64, 0x90, 0xa5, 0x76]));
    steps.push(Step::BulkIn(csw(tag)));

    // low (3 sectors)
    steps.push(Step::BulkOut(cbw(
        t!(),
        3 * 512,
        true,
        10,
        opcode::READ_LBA,
        0,
        512,
        3,
    )));
    steps.push(Step::BulkIn(low_reply.clone()));
    steps.push(Step::BulkIn(csw(tag)));
    // straddle (4 sectors: 2 real + 0xCC tail — the unmeasured crossing
    // READ_LBA assumption)
    steps.push(Step::BulkOut(cbw(
        t!(),
        4 * 512,
        true,
        10,
        opcode::READ_LBA,
        0,
        (GUARD - 2) as u32,
        4,
    )));
    steps.push(Step::BulkIn(straddle_reply.clone()));
    steps.push(Step::BulkIn(csw(tag)));
    // high (2 sectors of 0xCC)
    steps.push(Step::BulkOut(cbw(
        t!(),
        2 * 512,
        true,
        10,
        opcode::READ_LBA,
        0,
        (GUARD + 16) as u32,
        2,
    )));
    steps.push(Step::BulkIn(high_reply.clone()));
    steps.push(Step::BulkIn(csw(tag)));

    let transport = MockTransport::new(steps);
    let mut s = LoaderSession::new(transport, EP_IN, EP_OUT);

    let events = std::cell::RefCell::new(Vec::new());
    let progress = |ev: Progress| events.borrow_mut().push(ev);
    let out = std::env::temp_dir().join(format!("jb-stock-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&out);
    let report = backup(&mut s, &test_config(), &out, &progress, true).expect("stock backup");
    assert_eq!(report.partitions, 3);
    assert_eq!(report.read_limit_old, None);

    // every partition is dumped full-size with what the device returned
    assert_eq!(std::fs::read(out.join("01_low.img")).unwrap(), low_reply);
    assert_eq!(std::fs::read(out.join("02_straddle.img")).unwrap(), straddle_reply);
    assert_eq!(std::fs::read(out.join("03_high.img")).unwrap(), high_reply);
    assert_eq!(
        std::fs::read_to_string(out.join("SHA256SUMS.txt"))
            .unwrap()
            .lines()
            .count(),
        3
    );
    assert!(std::fs::read_to_string(out.join("SUCCESS.txt"))
        .unwrap()
        .starts_with("SUCCESS: "));
    jb_core::backup_store::BackupStore::open(&out)
        .unwrap()
        .verify()
        .expect("verify");

    // straddle and high are flagged, low is not; the run ends with the
    // NOT-intact warning naming both
    let evs = events.into_inner();
    let step_msgs: Vec<&str> = evs
        .iter()
        .filter_map(|e| match e {
            Progress::Step(m) => Some(m.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(
        step_msgs
            .iter()
            .filter(|m| m.contains("выше маски чтения"))
            .count(),
        2
    );
    assert!(step_msgs
        .iter()
        .any(|m| m.contains("НЕцелостный") && m.contains("straddle") && m.contains("high")));

    let _ = std::fs::remove_dir_all(&out);
}
