//! Read-path regressions: the USB boundary is mocked, the protocol and
//! writer (including its partial/error behavior) are real.

use amlogic::{req, AmlogicSession, Error};
use std::cell::RefCell;
use std::io::{self, Write};
use usbcore::{MockTransport, Step};

fn command(text: &str) -> Vec<u8> {
    let mut bytes = vec![0; 64];
    bytes[..text.len()].copy_from_slice(text.as_bytes());
    bytes
}

fn head(bytes: u32) -> Vec<u8> {
    let mut data = vec![0; 16];
    data[0..4].copy_from_slice(&0xefe8u32.to_le_bytes());
    data[4..8].copy_from_slice(&bytes.to_le_bytes());
    data
}

fn armed(text: &str) -> Vec<Step> {
    vec![
        Step::ControlOut(req::BULKCMD, 0, 2, command(text)),
        Step::BulkIn(b"success\0".to_vec()),
    ]
}

fn session(steps: Vec<Step>) -> AmlogicSession<MockTransport> {
    AmlogicSession::new(MockTransport::new(steps), 0x81, 0x02)
}

#[test]
fn upload_writer_preserves_split_packets_and_tail() {
    let mut steps = armed("upload store bootloader normal 0x10201");
    steps.extend([
        Step::ControlIn(req::READ_MEDIA, 4096, 16, head(65536)),
        Step::BulkIn(vec![0x11; 17]),
        Step::BulkIn(vec![0x22; 65519]),
        Step::ControlIn(req::READ_MEDIA, 4096, 1, head(513)),
        Step::BulkIn(vec![0x33; 513]),
    ]);
    let mut s = session(steps);
    let progress = RefCell::new(Vec::new());
    let mut out = Vec::new();
    let n = s
        .upload_store_to("bootloader", 66049, &mut out, &|n| {
            progress.borrow_mut().push(n);
        })
        .unwrap();
    assert_eq!(n, 66049);
    assert_eq!(&out[..17], &[0x11; 17]);
    assert!(out[17..65536].iter().all(|&b| b == 0x22));
    assert_eq!(&out[65536..], &[0x33; 513]);
    assert_eq!(*progress.borrow(), [17, 65536, 66049]);
}

#[test]
fn upload_writer_preserves_prefix_on_disconnect() {
    let mut steps = armed("upload store bootloader normal 0x4");
    steps.extend([
        Step::ControlIn(req::READ_MEDIA, 4096, 1, head(4)),
        Step::BulkIn(b"ab".to_vec()),
        Step::BulkError("link disconnected".into()),
    ]);
    let mut s = session(steps);
    let mut out = Vec::new();
    let err = s
        .upload_store_to("bootloader", 4, &mut out, &|_| {})
        .unwrap_err();
    assert!(matches!(err, Error::Usb(ref text) if text.contains("link disconnected")));
    assert_eq!(out, b"ab");
}

struct FullDisk(Vec<u8>);

impl Write for FullDisk {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        if self.0.len() == 2 {
            return Err(io::Error::from(io::ErrorKind::StorageFull));
        }
        let n = data.len().min(2 - self.0.len());
        self.0.extend_from_slice(&data[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn upload_writer_failure_stops_before_next_burst() {
    let mut steps = armed("upload store bootloader normal 0x8");
    steps.extend([
        Step::ControlIn(req::READ_MEDIA, 4096, 1, head(4)),
        Step::BulkIn(b"abcd".to_vec()),
        Step::ControlIn(req::READ_MEDIA, 4096, 1, head(4)),
        Step::BulkIn(b"efgh".to_vec()),
    ]);
    let mut s = session(steps);
    let mut out = FullDisk(Vec::new());
    let err = s
        .upload_store_to("bootloader", 8, &mut out, &|_| {})
        .unwrap_err();
    assert!(matches!(err, Error::Io(ref e) if e.kind() == io::ErrorKind::StorageFull));
    assert_eq!(out.0, b"ab");
    assert_eq!(s.transport().pos, 4);
}

#[test]
fn upload_rejects_burst_larger_than_remaining_before_bulk() {
    let mut steps = armed("upload store bootloader normal 0x201");
    steps.extend([
        Step::ControlIn(req::READ_MEDIA, 4096, 1, head(1024)),
        Step::BulkIn(vec![7; 1024]),
    ]);
    let mut s = session(steps);
    let mut out = Vec::new();
    assert!(s
        .upload_store_to("bootloader", 513, &mut out, &|_| {})
        .is_err());
    assert!(out.is_empty());
    assert_eq!(s.transport().pos, 3);
}

#[test]
fn upload_rejects_short_head_before_bulk() {
    let mut steps = armed("upload store bootloader normal 0x4");
    steps.push(Step::ControlIn(req::READ_MEDIA, 4096, 1, vec![0; 15]));
    let mut s = session(steps);
    assert!(s
        .upload_store_to("bootloader", 4, &mut Vec::new(), &|_| {})
        .is_err());
    assert_eq!(s.transport().pos, 3);
}

#[test]
fn upload_zero_payload_packet_is_error_with_prefix_retained() {
    let mut steps = armed("upload store bootloader normal 0x4");
    steps.extend([
        Step::ControlIn(req::READ_MEDIA, 4096, 1, head(4)),
        Step::BulkIn(b"ab".to_vec()),
        Step::BulkIn(vec![]),
    ]);
    let mut s = session(steps);
    let mut out = Vec::new();
    assert!(s
        .upload_store_to("bootloader", 4, &mut out, &|_| {})
        .is_err());
    assert_eq!(out, b"ab");
}

#[test]
fn upload_zero_head_is_a_short_stream_not_a_transport_error() {
    let mut steps = armed("upload store bootloader normal 0x4");
    steps.push(Step::ControlIn(req::READ_MEDIA, 4096, 1, head(0)));
    let mut s = session(steps);
    let mut out = Vec::new();
    assert_eq!(
        s.upload_store_to("bootloader", 4, &mut out, &|_| {})
            .unwrap(),
        0
    );
    assert!(out.is_empty());
}

#[test]
fn dram_read_rejects_a_short_stream() {
    let mut steps = armed("upload mem 0x2000000 normal 0x4");
    steps.push(Step::ControlIn(req::READ_MEDIA, 4096, 1, head(0)));
    let mut s = session(steps);
    assert!(s.read_dram(amlogic::ENV_ADDR, 4, &|_| {}).is_err());
}

#[test]
fn bulk_command_rejects_embedded_nul_before_usb() {
    let mut s = session(vec![Step::ControlOut(
        req::BULKCMD,
        0,
        2,
        command("echo\0ignored"),
    )]);
    assert!(s.send_bulk_cmd("echo\0ignored").is_err());
    assert_eq!(s.transport().pos, 0);
}

#[test]
fn tpl_command_rejects_embedded_nul_before_usb() {
    let mut s = session(vec![
        Step::ControlOut(req::TPL_CMD, 0, 1, b"echo\0ignored\0".to_vec()),
        Step::ControlIn(req::TPL_STAT, 0, 0, b"success\0".to_vec()),
    ]);
    assert!(s.tpl_cmd("echo\0ignored").is_err());
    assert_eq!(s.transport().pos, 0);
}

#[test]
fn identify_rejects_zero_version() {
    let mut s = session(vec![Step::ControlIn(req::IDENTIFY_HOST, 0, 0, vec![0; 8])]);
    assert!(s.identify().is_err());
}

#[test]
fn identify_accepts_four_byte_tpl_reply() {
    let mut s = session(vec![Step::ControlIn(
        req::IDENTIFY_HOST,
        0,
        0,
        vec![0, 7, 0, 16],
    )]);
    assert_eq!(s.identify().unwrap().stage(), amlogic::Stage::Tpl);
}

#[test]
fn upload_rejects_unknown_partition_and_oversized_range_before_usb() {
    for (name, size, text) in [
        (
            "bootloader;echo",
            4,
            "upload store bootloader;echo normal 0x4",
        ),
        (
            "bootloader",
            0x200001,
            "upload store bootloader normal 0x200001",
        ),
    ] {
        let mut s = session(armed(text));
        assert!(s
            .upload_store_to(name, size, &mut Vec::new(), &|_| {})
            .is_err());
        assert_eq!(s.transport().pos, 0);
    }
}

#[test]
fn staged_nand_read_rejects_burst_larger_than_stage() {
    let mut steps = armed("echo; mw.b 0x1080000 0xa5 0x200");
    steps.extend(armed("echo; nand read 0x1080000 0x0 0x200"));
    steps.extend(armed("upload mem 0x1080000 normal 0x200"));
    steps.extend([
        Step::ControlIn(req::READ_MEDIA, 4096, 1, head(1024)),
        Step::BulkIn(vec![7; 1024]),
    ]);
    let mut s = session(steps);
    assert!(s.read_nand_range(0, 512, &|_| {}).is_err());
    assert_eq!(s.transport().pos, 7);
}

#[test]
fn bootrom_identification_does_not_send_burning_prime() {
    let mut s = session(vec![Step::ControlIn(
        req::IDENTIFY_HOST,
        0,
        0,
        vec![0, 7, 0, 0],
    )]);
    assert_eq!(s.identify_and_prime().unwrap().stage(), amlogic::Stage::Ipl);
    assert_eq!(s.transport().pos, 1);
}

#[test]
fn tpl_identification_primes_after_identify() {
    let mut steps = vec![Step::ControlIn(req::IDENTIFY_HOST, 0, 0, vec![0, 7, 0, 16])];
    steps.extend(armed("echo"));
    let mut s = session(steps);
    assert_eq!(s.identify_and_prime().unwrap().stage(), amlogic::Stage::Tpl);
    assert_eq!(s.transport().pos, 3);
}

#[test]
fn malformed_prime_status_is_not_retried_as_a_pipe_failure() {
    let mut steps = vec![
        Step::ControlOut(req::BULKCMD, 0, 2, command("echo")),
        Step::BulkIn(vec![]),
    ];
    steps.extend(armed("echo"));
    let mut s = session(steps);
    assert!(s.prime().is_err());
    assert_eq!(s.transport().pos, 2);
}

#[test]
fn upload_preserves_bytes_from_an_errored_completion_and_stops() {
    for prefix in [b"ab".as_slice(), b"abcd".as_slice()] {
        let mut steps = armed("upload store bootloader normal 0x4");
        steps.extend([
            Step::ControlIn(req::READ_MEDIA, 4096, 1, head(4)),
            Step::BulkPartialError(prefix.to_vec(), "device disconnected".into()),
            Step::BulkIn(b"cd".to_vec()),
        ]);
        let mut s = session(steps);
        let mut out = Vec::new();
        let err = s
            .upload_store_to("bootloader", 4, &mut out, &|_| {})
            .unwrap_err();
        assert!(matches!(err, Error::Usb(ref text) if text.contains("disconnected")));
        assert_eq!(out, prefix);
        assert_eq!(s.transport().pos, 4);
    }
}
