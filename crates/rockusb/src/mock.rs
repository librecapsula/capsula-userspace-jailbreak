//! Mock transport for scenario tests of the protocols, no hardware.

use crate::error::{Error, Result};
use crate::transport::Transport;

/// One expected scenario step: which control request or bulk transfer
/// should happen and what to answer.
#[derive(Debug, Clone)]
pub enum Step {
    /// Expect control_out(request, value, index) with this data (checked).
    ControlOut(u8, u16, u16, Vec<u8>),
    /// Expect a bulk write to any endpoint with this content.
    BulkOut(Vec<u8>),
    /// Answer a bulk read with these bytes (exhaustion is an error).
    BulkIn(Vec<u8>),
}

#[derive(Default)]
pub struct MockTransport {
    pub steps: Vec<Step>,
    pub pos: usize,
}

impl MockTransport {
    pub fn new(steps: Vec<Step>) -> Self {
        MockTransport { steps, pos: 0 }
    }

    fn next(&mut self, what: &str) -> Result<Step> {
        if self.pos >= self.steps.len() {
            return Err(Error::Usb(format!("mock: scenario exhausted ({what})")));
        }
        let s = self.steps[self.pos].clone();
        self.pos += 1;
        Ok(s)
    }
}

impl Transport for MockTransport {
    fn control_out(&mut self, request: u8, value: u16, index: u16, data: &[u8]) -> Result<()> {
        match self.next("control_out")? {
            Step::ControlOut(r, v, i, expect) => {
                if r != request || v != value || i != index || expect != data {
                    return Err(Error::Usb(format!(
                        "mock: control_out mismatch\n  expected: {}",
                        hex::encode(&expect),
                    )));
                }
                Ok(())
            }
            other => Err(Error::Usb(format!(
                "mock: expected {other:?}, got control_out"
            ))),
        }
    }

    fn bulk_write(&mut self, _endpoint: u8, data: &[u8]) -> Result<()> {
        match self.next("bulk_write")? {
            Step::BulkOut(expect) => {
                if expect != data {
                    return Err(Error::Usb(format!(
                        "mock: bulk_write mismatch\n  expected: {}",
                        hex::encode(expect),
                    )));
                }
                Ok(())
            }
            other => Err(Error::Usb(format!(
                "mock: expected {other:?}, got bulk_write"
            ))),
        }
    }

    fn bulk_read(&mut self, _endpoint: u8, buf: &mut [u8]) -> Result<()> {
        let mut filled = 0;
        while filled < buf.len() {
            match self.next("bulk_read")? {
                Step::BulkIn(data) => {
                    if filled + data.len() > buf.len() {
                        return Err(Error::Usb("mock: bulk_read would overflow".into()));
                    }
                    buf[filled..filled + data.len()].copy_from_slice(&data);
                    filled += data.len();
                }
                other => return Err(Error::Usb(format!("mock: expected data, got {other:?}"))),
            }
        }
        Ok(())
    }
}
