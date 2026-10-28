use amlogic::{nand, req, AmlogicSession, Error, RAM_SCRATCH};
use usbcore::{MockTransport, Step};

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

#[test]
fn raw_geometry_includes_oob() {
    assert_eq!(nand::raw_bytes(0x800000).unwrap(), 0x840000);
    assert_eq!(nand::raw_bytes(0x10000000).unwrap(), 0x10800000);
    assert!(nand::raw_bytes(1).is_err());
}

#[test]
fn raw_read_uses_pages_not_bytes() {
    let mut steps = cmd("echo; mw.b 0x1080000 0xa5 0x1080");
    steps.extend(cmd("echo; nand read.raw 0x1080000 0x800 0x2"));
    steps.extend(uploaded(4224, 0x37));
    let mut s = session(steps);
    assert_eq!(s.read_raw_nand_chunk(2048, 4096).unwrap(), vec![0x37; 4224]);
    assert_eq!(s.transport().pos, s.transport().steps.len());
}

#[test]
fn logical_read_uploads_region_once() {
    let mut steps = cmd("echo; mw.b 0x1080000 0xa5 0x80000");
    steps.extend(cmd("echo; nand read 0x1080000 0x280000 0x80000"));
    steps.extend(uploaded(0x80000, 0x41));
    let mut s = session(steps);
    let data = s.read_nand_chunk(0x280000, 0x80000).unwrap();
    assert_eq!(data, vec![0x41; 0x80000]);
    assert_eq!(s.transport().pos, s.transport().steps.len());
}

#[test]
fn nand_ranges_and_raw_alignment_are_checked_before_usb() {
    for (offset, size, raw) in [
        (0, 0, false),
        (0, 0x800001, false),
        (0xfffff000, 0x2000, false),
        (0x10000000, 2048, false),
        (1, 2048, true),
        (0, 2049, true),
    ] {
        let mut s = session(vec![]);
        let result = if raw {
            s.read_raw_nand_chunk(offset, size)
        } else {
            s.read_nand_chunk(offset, size)
        };
        assert!(matches!(result, Err(Error::InvalidArgument(_))));
        assert_eq!(s.transport().pos, 0);
    }
}

#[test]
fn raw_buffer_supports_eight_mib_plus_oob_without_expanding_generic_ram_reads() {
    let mut s = session(uploaded(0x840000, 0x43));
    let data = s.read_nand_buffer(0x840000).unwrap();
    assert_eq!(data.len(), 0x840000);
    assert!(data.iter().all(|&b| b == 0x43));
    assert!(s.read_nand_buffer(0x840001).is_err());
    assert!(s.upload_read(RAM_SCRATCH, 0x840000).is_err());
}

#[test]
fn unchanged_sentinel_is_not_a_nand_capture() {
    let mut steps = cmd("echo; mw.b 0x1080000 0xa5 0x840");
    steps.extend(cmd("echo; nand read.raw 0x1080000 0x0 0x1"));
    steps.extend(uploaded(2112, 0xa5));
    let mut s = session(steps);
    assert!(s.read_raw_nand_chunk(0, 2048).is_err());
    assert_eq!(s.transport().pos, s.transport().steps.len());
}
