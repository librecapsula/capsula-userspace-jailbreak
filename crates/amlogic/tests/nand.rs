use amlogic::{nand, req, AmlogicSession, Error, RAM_SCRATCH};
use amlogic::{MockTransport, Step};

fn command(text: &str) -> Vec<u8> {
    let mut payload = vec![0; 64];
    payload[..text.len()].copy_from_slice(text.as_bytes());
    payload
}

fn cmd(text: &str) -> Vec<Step> {
    vec![
        Step::ControlOut(req::BULKCMD, 0, 2, command(text)),
        Step::BulkIn(b"success\0".to_vec()),
    ]
}

/// The keepalive identify of every read stage.
fn id() -> Vec<Step> {
    vec![Step::ControlIn(req::IDENTIFY_HOST, 0, 0, vec![0, 7, 0, 16])]
}

fn uploaded(size: usize, byte: u8) -> Vec<Step> {
    let mut steps = cmd(&format!("upload mem {RAM_SCRATCH:#x} normal {size:#x}"));
    let mut remaining = size;
    while remaining > 0 {
        let n = remaining.min(65536);
        let mut head = vec![0; 16];
        head[4..8].copy_from_slice(&(n as u32).to_le_bytes());
        steps.push(Step::ControlIn(
            req::READ_MEDIA,
            4096,
            n.div_ceil(4096) as u16,
            head,
        ));
        steps.push(Step::BulkIn(vec![byte; n]));
        remaining -= n;
    }
    steps
}

fn session(steps: Vec<Step>) -> AmlogicSession<MockTransport> {
    AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02)
}

fn read(
    s: &mut AmlogicSession<MockTransport>,
    off: u32,
    len: u32,
    raw: bool,
) -> amlogic::Result<Vec<u8>> {
    let mut out = Vec::new();
    let n = s.read_nand_range(off, len, raw, &mut out, &|_| {})?;
    assert_eq!(n, out.len());
    Ok(out)
}

#[test]
fn raw_geometry_includes_oob() {
    assert_eq!(nand::raw_bytes(0x800000).unwrap(), 0x840000);
    assert_eq!(nand::raw_bytes(0x10000000).unwrap(), 0x10800000);
    assert!(nand::raw_bytes(1).is_err());
}

#[test]
fn raw_read_uses_pages_not_bytes() {
    let mut steps = id();
    steps.extend(cmd("echo; mw.b 0x1080000 0xa5 0x1080"));
    steps.extend(cmd("echo; nand read.raw 0x1080000 0x800 0x2"));
    steps.extend(uploaded(4224, 0x37));
    let mut s = session(steps);
    assert_eq!(read(&mut s, 0x800, 0x1000, true).unwrap(), vec![0x37; 4224]);
    assert_eq!(s.transport().pos, s.transport().steps.len());
}

#[test]
fn logical_read_uploads_region_once() {
    let mut steps = id();
    steps.extend(cmd("echo; mw.b 0x1080000 0xa5 0x80000"));
    steps.extend(cmd("echo; nand read 0x1080000 0x280000 0x80000"));
    steps.extend(uploaded(0x80000, 0x41));
    let mut s = session(steps);
    assert_eq!(read(&mut s, 0x280000, 0x80000, false).unwrap(), vec![0x41; 0x80000]);
    assert_eq!(s.transport().pos, s.transport().steps.len());
}

#[test]
fn nand_ranges_and_raw_alignment_are_checked_before_usb() {
    for (offset, len, raw) in [
        (0, 0, false),
        (0xfffff000, 0x2000, false),
        (0x10000000, 2048, false),
        (1, 2048, true),
        (0, 2049, true),
    ] {
        let mut s = session(vec![]);
        let result = read(&mut s, offset, len, raw);
        assert!(matches!(result, Err(Error::InvalidArgument(_))), "{offset} {len} {raw}");
        assert_eq!(s.transport().pos, 0);
    }
}

#[test]
fn generic_ram_reads_still_cap_at_the_vendor_chunk() {
    let mut s = session(vec![]);
    assert!(s.upload_read(RAM_SCRATCH, 0x840000).is_err());
    assert_eq!(s.transport().pos, 0);
    let mut s = session(uploaded(0x800000, 0x43));
    let data = s.upload_read(RAM_SCRATCH, 0x800000).unwrap();
    assert_eq!(data.len(), 0x800000);
    assert_eq!(s.transport().pos, s.transport().steps.len());
}

#[test]
fn unchanged_sentinel_is_not_a_nand_capture() {
    let mut steps = id();
    steps.extend(cmd("echo; mw.b 0x1080000 0xa5 0x840"));
    steps.extend(cmd("echo; nand read.raw 0x1080000 0x0 0x1"));
    steps.extend(uploaded(2112, 0xa5));
    let mut s = session(steps);
    let mut out = Vec::new();
    assert!(s
        .read_nand_range(0, 2048, true, &mut out, &|_| {})
        .is_err());
    assert!(out.is_empty());
    assert_eq!(s.transport().pos, s.transport().steps.len());
}

/// A `failed:` status (bad block) with real data in the buffer keeps
/// every received byte — nothing is trimmed on a partial prefix.
#[test]
fn bad_block_status_keeps_changed_stage() {
    let mut steps = id();
    steps.extend(cmd("echo; mw.b 0x1080000 0xa5 0x840"));
    steps.push(Step::ControlOut(
        req::BULKCMD,
        0,
        2,
        command("echo; nand read.raw 0x1080000 0x0 0x1"),
    ));
    steps.push(Step::BulkIn(b"failed:\0".to_vec()));
    steps.extend(uploaded(2112, 0x37));
    let mut s = session(steps);
    let data = read(&mut s, 0, 2048, true).unwrap();
    assert_eq!(data, vec![0x37; 2112]);
    assert_eq!(s.transport().pos, s.transport().steps.len());
}

/// A multi-stage read keeps the keepalive per stage and writes stages
/// to the sink as they complete.
#[test]
fn long_read_splits_into_stages_with_keepalive() {
    let len = nand::READ_STAGE_MAIN as u32 + 0x10_0000;
    let mut steps = Vec::new();
    // stage 1: full READ_STAGE_MAIN
    steps.extend(id());
    steps.extend(cmd(&format!("echo; mw.b {RAM_SCRATCH:#x} 0xa5 {:#x}", nand::READ_STAGE_MAIN)));
    steps.extend(cmd(&format!(
        "echo; nand read {RAM_SCRATCH:#x} 0x0 {:#x}",
        nand::READ_STAGE_MAIN
    )));
    steps.extend(uploaded(nand::READ_STAGE_MAIN, 0x11));
    // stage 2: tail of 1 MiB
    steps.extend(id());
    steps.extend(cmd(&format!("echo; mw.b {RAM_SCRATCH:#x} 0xa5 0x100000")));
    steps.extend(cmd(&format!(
        "echo; nand read {RAM_SCRATCH:#x} {:#x} 0x100000",
        nand::READ_STAGE_MAIN
    )));
    steps.extend(uploaded(0x10_0000, 0x22));
    let mut s = session(steps);
    let mut out = Vec::new();
    let progress = std::cell::RefCell::new(Vec::new());
    let n = s
        .read_nand_range(0, len, false, &mut out, &|p| {
            progress.borrow_mut().push(p)
        })
        .unwrap();
    assert_eq!(n as u64, len as u64);
    assert_eq!(out[..nand::READ_STAGE_MAIN].to_vec(), vec![0x11; nand::READ_STAGE_MAIN]);
    assert_eq!(&out[nand::READ_STAGE_MAIN..], &vec![0x22; 0x10_0000][..]);
    // per-stage progress
    assert_eq!(
        progress.borrow().clone(),
        vec![nand::READ_STAGE_MAIN, len as usize]
    );
    assert_eq!(s.transport().pos, s.transport().steps.len());
}

/// A transport error mid-stream still writes the received prefix of the
/// stage into the sink before propagating (checkpoint contract).
#[test]
fn transport_death_keeps_received_prefix() {
    let mut steps = id();
    steps.extend(cmd(&format!("echo; mw.b {RAM_SCRATCH:#x} 0xa5 {:#x}", nand::READ_STAGE_MAIN)));
    steps.extend(cmd(&format!(
        "echo; nand read {RAM_SCRATCH:#x} 0x0 {:#x}",
        nand::READ_STAGE_MAIN
    )));
    // arm succeeds, then the stream dies after one burst
    steps.extend(cmd(&format!(
        "upload mem {RAM_SCRATCH:#x} normal {:#x}",
        nand::READ_STAGE_MAIN
    )));
    let mut head = vec![0u8; 16];
    head[4..8].copy_from_slice(&65536u32.to_le_bytes());
    steps.push(Step::ControlIn(req::READ_MEDIA, 4096, 16, head));
    steps.push(Step::BulkIn(vec![0x55u8; 65536]));
    steps.push(Step::BulkError("killed".into()));
    let mut s = session(steps);
    let mut out = Vec::new();
    let err = s
        .read_nand_range(0, nand::READ_STAGE_MAIN as u32, false, &mut out, &|_| {})
        .unwrap_err();
    assert!(err.to_string().contains("killed"));
    assert_eq!(out, vec![0x55u8; 65536]);
}
