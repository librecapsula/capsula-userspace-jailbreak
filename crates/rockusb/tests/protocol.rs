//! Protocol scenario tests on MockTransport: bit-exact CBW/CSW
//! sequences after rock.c of xrock, MaskROM upload with CRC/RC4 and the
//! edge cases.

use rockusb::loader::{opcode, LoaderSession, RESET_SUBCODE_MASKROM};
use rockusb::maskrom::MaskRomSession;
use rockusb::mock::{MockTransport, Step};
use rockusb::util::{crc16_xrock, Rc4};

const EP_IN: u8 = 0x81;
const EP_OUT: u8 = 0x02;

/// Device CSW reply: USBS + tag + residue=0 + status=0.
fn csw(tag: u32) -> Vec<u8> {
    let mut v = Vec::with_capacity(13);
    v.extend_from_slice(b"USBS");
    v.extend_from_slice(&tag.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]);
    v.push(0);
    v
}

/// Expected CBW (31 bytes) with the fields as in rock.c.
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
    v.push(0); // lun
    v.push(cmdlen);
    v.push(opcode);
    v.push(subcode);
    v.extend_from_slice(&address.to_be_bytes());
    v.push(0); // reserved6
    v.extend_from_slice(&size.to_be_bytes());
    v.extend_from_slice(&[0; 7]); // reserved9..12: the CB is exactly 16 bytes, CBW = 31
    v
}

// --- loader (usbplug) ----------------------------------------------------

#[test]
fn loader_ready_roundtrip() {
    // CBW tags start at 0x5a5a0001
    let t = MockTransport::new(vec![
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
    ]);
    let mut s = LoaderSession::new(t, EP_IN, EP_OUT);
    s.ready().expect("ready");
}

#[test]
fn loader_flash_detect_parses_info() {
    // 447455 sectors (Capsule-14), block 0x100, page 4, ecc 40...
    let mut info = Vec::new();
    info.extend_from_slice(&447455u32.to_le_bytes());
    info.extend_from_slice(&0x0100u16.to_le_bytes());
    info.extend_from_slice(&[4, 40, 25, 0x98, 0]);
    let t = MockTransport::new(vec![
        Step::BulkOut(cbw(
            0x5a5a0001,
            11,
            true,
            6,
            opcode::READ_FLASH_INFO,
            0,
            0,
            0,
        )),
        Step::BulkIn(info),
        Step::BulkIn(csw(0x5a5a0001)),
        Step::BulkOut(cbw(0x5a5a0002, 5, true, 6, opcode::READ_FLASH_ID, 0, 0, 0)),
        Step::BulkIn(vec![0x2c, 0x64, 0x90, 0xa5, 0x76]),
        Step::BulkIn(csw(0x5a5a0002)),
    ]);
    let mut s = LoaderSession::new(t, EP_IN, EP_OUT);
    let f = s.flash_detect().expect("flash_detect");
    assert_eq!(f.sector_total, 447455);
    assert_eq!(f.id, [0x2c, 0x64, 0x90, 0xa5, 0x76]);
}

#[test]
fn loader_read_lba_two_sectors() {
    let data = vec![0xA5u8; 1024];
    let t = MockTransport::new(vec![
        Step::BulkOut(cbw(
            0x5a5a0001,
            1024,
            true,
            10,
            opcode::READ_LBA,
            0,
            0x10000,
            2,
        )),
        Step::BulkIn(data.clone()),
        Step::BulkIn(csw(0x5a5a0001)),
    ]);
    let mut s = LoaderSession::new(t, EP_IN, EP_OUT);
    let mut buf = vec![0u8; 1024];
    s.read_lba(0x10000, &mut buf).expect("read_lba");
    assert_eq!(buf, data);
}

#[test]
fn loader_write_mem_limit_patch() {
    // usbplug read-limit patch (backup.sh): 4 bytes at 0x3343ec4.
    // length=0 (rock.c); the data follows the CBW.
    let val = 447455u32.to_le_bytes().to_vec();
    let t = MockTransport::new(vec![
        Step::BulkOut(cbw(
            0x5a5a0001,
            0,
            false,
            10,
            opcode::WRITE_SDRAM,
            0,
            0x03343ec4,
            4,
        )),
        Step::BulkOut(val),
        Step::BulkIn(csw(0x5a5a0001)),
    ]);
    let mut s = LoaderSession::new(t, EP_IN, EP_OUT);
    s.write_mem(0x03343ec4, &447455u32.to_le_bytes())
        .expect("write_mem");
}

#[test]
fn loader_read_mem_length_zero() {
    // READ_SDRAM with length=0, size=8 (rock_read_raw parity).
    let t = MockTransport::new(vec![
        Step::BulkOut(cbw(
            0x5a5a0001,
            0,
            true,
            10,
            opcode::READ_SDRAM,
            0,
            0x03012290,
            8,
        )),
        Step::BulkIn(vec![0x29, 0xc5, 0x4e, 0xb9, 0x1f, 0x01, 0x09, 0x6b]),
        Step::BulkIn(csw(0x5a5a0001)),
    ]);
    let mut s = LoaderSession::new(t, EP_IN, EP_OUT);
    let mut buf = [0u8; 8];
    s.read_mem(0x03012290, &mut buf).expect("read_mem");
    assert_eq!(buf[..6], [0x29, 0xc5, 0x4e, 0xb9, 0x1f, 0x01]);
}

#[test]
fn loader_reset_maskrom() {
    let t = MockTransport::new(vec![
        Step::BulkOut(cbw(
            0x5a5a0001,
            0,
            false,
            6,
            opcode::RESET_DEVICE,
            RESET_SUBCODE_MASKROM,
            0,
            0,
        )),
        Step::BulkIn(csw(0x5a5a0001)),
    ]);
    let mut s = LoaderSession::new(t, EP_IN, EP_OUT);
    s.reset(RESET_SUBCODE_MASKROM).expect("reset");
}

#[test]
fn loader_bad_csw_rejected() {
    let mut bad = csw(0x5a5a0001);
    bad[12] = 1; // status = error
    let t = MockTransport::new(vec![
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
        Step::BulkIn(bad),
    ]);
    let mut s = LoaderSession::new(t, EP_IN, EP_OUT);
    let err = s.ready().expect_err("must fail");
    assert!(matches!(err, rockusb::Error::CommandFailed(1)), "{err}");
}

#[test]
fn loader_lba_rejects_unaligned_size() {
    // the library API reports an error instead of panicking; no transfer
    // is attempted, so the scenario is empty
    let mut s = LoaderSession::new(MockTransport::new(vec![]), EP_IN, EP_OUT);
    let err = s.read_lba(0, &mut [0u8; 100]).expect_err("must refuse");
    assert!(matches!(err, rockusb::Error::Loader(_)), "{err}");

    let mut s = LoaderSession::new(MockTransport::new(vec![]), EP_IN, EP_OUT);
    let err = s.write_lba(0, &[0u8; 100]).expect_err("must refuse");
    assert!(matches!(err, rockusb::Error::Loader(_)), "{err}");
}

// --- maskrom (DownloadBoot) ----------------------------------------------

#[test]
fn maskrom_upload_appends_crc16_be() {
    let payload = b"capsula".to_vec();
    let mut expect = payload.clone();
    let crc = crc16_xrock(0xffff, &payload);
    expect.push((crc >> 8) as u8);
    expect.push((crc & 0xff) as u8);

    let t = MockTransport::new(vec![Step::ControlOut(0x0c, 0, 0x0472, expect)]);
    let mut s = MaskRomSession::new(t);
    s.upload_memory(0x0472, &payload, false).expect("upload");
}

#[test]
fn maskrom_upload_rc4_encrypts_before_crc() {
    let payload = b"0123456789abcdef".to_vec();
    let mut expect = Rc4::encrypt_copy(&Rc4::ROCKCHIP_KEY, &payload);
    let crc = crc16_xrock(0xffff, &expect);
    expect.push((crc >> 8) as u8);
    expect.push((crc & 0xff) as u8);

    let t = MockTransport::new(vec![Step::ControlOut(0x0c, 0, 0x0471, expect)]);
    let mut s = MaskRomSession::new(t);
    s.upload_memory(0x0471, &payload, true).expect("upload");
}

#[test]
fn maskrom_upload_chunking_and_edge_4095() {
    // 100 bytes: one 102-byte chunk (data+CRC)
    let payload = vec![0x33u8; 100];
    let mut one = payload.clone();
    let crc = crc16_xrock(0xffff, &payload);
    one.push((crc >> 8) as u8);
    one.push((crc & 0xff) as u8);

    let t = MockTransport::new(vec![Step::ControlOut(0x0c, 0, 0x0472, one)]);
    MaskRomSession::new(t)
        .upload_memory(0x0472, &payload, false)
        .expect("upload 100");

    // 4095 bytes: +1 zero byte (the 4095 edge), +CRC -> 4098 = 4096 + 2
    let payload = vec![0x77u8; 4095];
    let mut padded = payload.clone();
    padded.push(0);
    let crc = crc16_xrock(0xffff, &padded);
    let mut full = padded;
    full.push((crc >> 8) as u8);
    full.push((crc & 0xff) as u8);
    let (first, second) = full.split_at(4096);

    let t = MockTransport::new(vec![
        Step::ControlOut(0x0c, 0, 0x0472, first.to_vec()),
        Step::ControlOut(0x0c, 0, 0x0472, second.to_vec()),
    ]);
    MaskRomSession::new(t)
        .upload_memory(0x0472, &payload, false)
        .expect("upload 4095");
}
