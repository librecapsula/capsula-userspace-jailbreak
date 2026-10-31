//! Minimal flattened-device-tree reader (FDT spec v17) — enough to
//! pull the vendor NAND partition table out of the boot-image DTB
//! (`imgread dtb`), mirroring the strict structural validation of the
//! reference Go tool: unknown boards must be refused, not guessed.

use crate::error::{Error, Result};

/// One parsed node: name, properties in file order, children in file order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    pub name: String,
    pub props: Vec<(String, Vec<u8>)>,
    pub children: Vec<Node>,
}

impl Node {
    /// First property value with this name.
    pub fn prop(&self, name: &str) -> Option<&[u8]> {
        self.props
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }

    /// Direct child by name.
    pub fn child(&self, name: &str) -> Option<&Node> {
        self.children.iter().find(|c| c.name == name)
    }

    /// All descendants (self not included) matching `pred`, in file order.
    pub fn find_all<'a>(&'a self, pred: &dyn Fn(&Node) -> bool) -> Vec<&'a Node> {
        let mut out = Vec::new();
        for c in &self.children {
            if pred(c) {
                out.push(c);
            }
            out.extend(c.find_all(pred));
        }
        out
    }
}

/// Device-side numbers are big-endian u32/u64 (FDT spec).
pub fn be_u32(b: &[u8]) -> Option<u32> {
    b.get(..4).map(|s| u32::from_be_bytes(s.try_into().unwrap()))
}

/// 4-byte values read as u32, 8-byte as u64 (the DTB encodes both).
pub fn be_word(b: &[u8]) -> Option<u64> {
    match b.len() {
        4 => be_u32(b).map(u64::from),
        8 => b.try_into().ok().map(u64::from_be_bytes),
        _ => None,
    }
}

const FDT_BEGIN_NODE: u32 = 1;
const FDT_END_NODE: u32 = 2;
const FDT_PROP: u32 = 3;
const FDT_NOP: u32 = 4;
const FDT_END: u32 = 9;
const FDT_MAGIC: u32 = 0xd00d_feed;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn u32(&mut self) -> Result<u32> {
        let b = self
            .data
            .get(self.pos..self.pos + 4)
            .ok_or_else(|| Error::InvalidResponse("DTB обрезан в structure block".into()))?;
        self.pos += 4;
        Ok(u32::from_be_bytes(b.try_into().unwrap()))
    }

    fn cstr(&mut self) -> Result<&'a [u8]> {
        let rest = self
            .data
            .get(self.pos..)
            .ok_or_else(|| Error::InvalidResponse("DTB обрезан в строке".into()))?;
        let end = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| Error::InvalidResponse("DTB: строка без NUL".into()))?;
        let s = &rest[..end];
        self.pos = (self.pos + end + 1 + 3) & !3;
        Ok(s)
    }
}

/// Parse and structurally validate a whole FDT blob. Structural rules
/// (spec §2.3 + the reference tool's strictness): valid header and
/// block bounds, well-formed token stream ending with FDT_END, unique
/// node and property names, node names without '/'.
pub fn parse(data: &[u8]) -> Result<Node> {
    if data.len() < 40 {
        return Err(Error::InvalidResponse("DTB короче заголовка".into()));
    }
    let word = |n: usize| u32::from_be_bytes(data[n..n + 4].try_into().unwrap());
    let totalsize = word(4) as usize;
    if word(0) != FDT_MAGIC {
        return Err(Error::InvalidResponse("DTB: неверный magic".into()));
    }
    if totalsize != data.len() {
        return Err(Error::InvalidResponse(format!(
            "DTB: totalsize {totalsize} != {} байт блоба",
            data.len()
        )));
    }
    let off_struct = word(8) as usize;
    let off_strings = word(12) as usize;
    if word(24) < 16 {
        return Err(Error::InvalidResponse("DTB: last_comp_version < 16".into()));
    }
    if word(20) < 17 || off_struct < 40 || off_struct >= data.len() {
        return Err(Error::InvalidResponse("DTB: неверный заголовок".into()));
    }
    let size_struct = word(36) as usize;
    if size_struct == 0 || off_struct + size_struct > data.len() {
        return Err(Error::InvalidResponse("DTB: structure block вне блоба".into()));
    }
    if off_strings >= data.len() || word(32) as usize > data.len() - off_strings {
        return Err(Error::InvalidResponse("DTB: strings block вне блоба".into()));
    }
    let strings = &data[off_strings..off_strings + word(32) as usize];

    // memory reservation map: (u64, u64) pairs, terminated by (0, 0)
    let mut rsv = word(16) as usize;
    loop {
        let Some(pair) = data.get(rsv..rsv + 16) else {
            return Err(Error::InvalidResponse("DTB: rsvmap вне блоба".into()));
        };
        rsv += 16;
        if pair.iter().all(|&b| b == 0) {
            break;
        }
        if rsv > off_struct {
            return Err(Error::InvalidResponse("DTB: rsvmap не завершён".into()));
        }
    }

    let mut r = Reader {
        data: &data[off_struct..off_struct + size_struct],
        pos: 0,
    };
    let mut stack: Vec<Node> = Vec::new();
    let mut root: Option<Node> = None;
    loop {
        match r.u32()? {
            FDT_NOP => {}
            FDT_BEGIN_NODE => {
                let n = r.cstr()?;
                if n.contains(&b'/') {
                    return Err(Error::InvalidResponse("DTB: '/' в имени узла".into()));
                }
                stack.push(Node {
                    name: String::from_utf8_lossy(n).into_owned(),
                    props: Vec::new(),
                    children: Vec::new(),
                });
            }
            FDT_PROP => {
                let len = r.u32()? as usize;
                let nameoff = r.u32()? as usize;
                let Some(value) = r.data.get(r.pos..r.pos + len) else {
                    return Err(Error::InvalidResponse("DTB: значение свойства обрезано".into()));
                };
                r.pos += len;
                r.pos = (r.pos + 3) & !3;
                let Some(nul) = strings.get(nameoff..).and_then(|s| s.iter().position(|&b| b == 0))
                else {
                    return Err(Error::InvalidResponse("DTB: имя свойства вне strings".into()));
                };
                let pname = String::from_utf8_lossy(&strings[nameoff..nameoff + nul]).into_owned();
                let node = stack
                    .last_mut()
                    .ok_or_else(|| Error::InvalidResponse("DTB: свойство вне узла".into()))?;
                if node.props.iter().any(|(n, _)| *n == pname) {
                    return Err(Error::InvalidResponse(format!("DTB: повторное свойство {pname}")));
                }
                node.props.push((pname, value.to_vec()));
            }
            FDT_END_NODE => {
                let node = stack
                    .pop()
                    .ok_or_else(|| Error::InvalidResponse("DTB: лишний FDT_END_NODE".into()))?;
                match stack.last_mut() {
                    Some(parent) => {
                        if parent.children.iter().any(|c| c.name == node.name) {
                            return Err(Error::InvalidResponse(format!(
                                "DTB: повторный узел {}",
                                node.name
                            )));
                        }
                        parent.children.push(node);
                    }
                    None => {
                        if root.is_some() {
                            return Err(Error::InvalidResponse("DTB: второй корень".into()));
                        }
                        root = Some(node);
                    }
                }
            }
            FDT_END => {
                if !stack.is_empty() {
                    return Err(Error::InvalidResponse("DTB: незакрытые узлы".into()));
                }
                return root.ok_or_else(|| Error::InvalidResponse("DTB: нет корневого узла".into()));
            }
            t => return Err(Error::InvalidResponse(format!("DTB: неизвестный токен {t:#x}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Byte-exact FDT blob builder for tests.
    struct Builder {
        strings: Vec<u8>,
        st: Vec<u8>,
        depth: usize,
    }

    impl Builder {
        fn new() -> Self {
            Builder {
                strings: Vec::new(),
                st: Vec::new(),
                depth: 0,
            }
        }
        fn stroff(&mut self, s: &str) -> u32 {
            let off = self.strings.len() as u32;
            self.strings.extend_from_slice(s.as_bytes());
            self.strings.push(0);
            off
        }
        fn u32(&mut self, v: u32) {
            self.st.extend_from_slice(&v.to_be_bytes());
        }
        fn prop(&mut self, name: &str, value: &[u8]) {
            let off = self.stroff(name);
            self.u32(FDT_PROP);
            self.u32(value.len() as u32);
            self.u32(off);
            self.st.extend_from_slice(value);
            while self.st.len() % 4 != 0 {
                self.st.push(0);
            }
        }
        fn begin(&mut self, name: &str) {
            self.u32(FDT_BEGIN_NODE);
            self.st.extend_from_slice(name.as_bytes());
            self.st.push(0);
            while self.st.len() % 4 != 0 {
                self.st.push(0);
            }
            self.depth += 1;
        }
        fn end(&mut self) {
            self.u32(FDT_END_NODE);
            self.depth -= 1;
        }
        fn build(mut self) -> Vec<u8> {
            self.u32(FDT_END);
            let header = 40usize;
            let rsvmap = 16usize; // empty (0, 0) terminator
            let struct_off = header + rsvmap;
            let total = struct_off + self.st.len() + self.strings.len();
            let mut b = vec![0u8; total];
            let put = |b: &mut [u8], n: usize, v: u32| b[n..n + 4].copy_from_slice(&v.to_be_bytes());
            put(&mut b, 0, FDT_MAGIC);
            put(&mut b, 4, total as u32);
            put(&mut b, 8, struct_off as u32);
            put(&mut b, 12, (struct_off + self.st.len()) as u32);
            put(&mut b, 16, header as u32);
            put(&mut b, 20, 17);
            put(&mut b, 24, 16);
            put(&mut b, 32, self.strings.len() as u32);
            put(&mut b, 36, self.st.len() as u32);
            b[struct_off..struct_off + self.st.len()].copy_from_slice(&self.st);
            b[struct_off + self.st.len()..].copy_from_slice(&self.strings);
            b
        }
    }

    /// / { compatible; nand-controller@7800 { fip_size; nand_partition {
    /// tpl { size }; data { size } } } }
    fn sample_blob() -> Vec<u8> {
        let mut b = Builder::new();
        b.begin("");
        b.prop("compatible", b"amlogic,axg");
        b.begin("nand-controller@7800");
        b.prop("fip_size", &0x20_0000u32.to_be_bytes());
        b.begin("nand_partition");
        b.begin("tpl");
        b.prop("size", &0u32.to_be_bytes());
        b.end();
        b.begin("data");
        b.prop("size", &0x4e0_0000u32.to_be_bytes());
        b.end();
        b.end(); // nand_partition
        b.end(); // nand-controller
        b.end(); // root
        b.build()
    }

    #[test]
    fn parses_and_finds_partition_sizes() {
        let root = parse(&sample_blob()).unwrap();
        assert_eq!(root.prop("compatible"), Some(&b"amlogic,axg".to_vec()[..]));
        assert_eq!(root.name, "");
        let ctrl = root.child("nand-controller@7800").unwrap();
        assert_eq!(be_u32(ctrl.prop("fip_size").unwrap()), Some(0x20_0000));
        let parts = ctrl.child("nand_partition").unwrap();
        assert_eq!(be_u32(parts.child("tpl").unwrap().prop("size").unwrap()), Some(0));
        assert_eq!(
            be_u32(parts.child("data").unwrap().prop("size").unwrap()),
            Some(0x4e0_0000)
        );
        assert_eq!(be_word(&[0x00, 0x01, 0x00, 0x00]), Some(0x1_0000));
        assert_eq!(be_word(&[0, 0, 0, 1, 0, 0, 0, 0]), Some(0x1_0000_0000));
        assert_eq!(be_word(&[1, 2, 3]), None);
    }

    #[test]
    fn rejects_malformed_blobs() {
        let blob = sample_blob();
        assert!(parse(&blob[..blob.len() - 1]).is_err(), "обрезанный блоб");
        let mut bad = blob.clone();
        bad[0] = 0;
        assert!(parse(&bad).is_err(), "битый magic");
        let mut bad = blob.clone();
        bad[4..8].copy_from_slice(&(blob.len() as u32 + 4).to_be_bytes());
        assert!(parse(&bad).is_err(), "totalsize врёт");
        let mut bad = blob.clone();
        bad[20..24].copy_from_slice(&16u32.to_be_bytes());
        assert!(parse(&bad).is_err(), "version < 17");
        let mut bad = blob.clone();
        bad[36..40].copy_from_slice(&0u32.to_be_bytes());
        assert!(parse(&bad).is_err(), "нулевой structure block");
    }

    #[test]
    fn rejects_duplicate_property_and_node() {
        let mut b = Builder::new();
        b.begin("");
        b.prop("compatible", b"x");
        b.prop("compatible", b"y");
        b.end();
        let blob = b.build();
        assert!(parse(&blob).is_err(), "повторное свойство");

        let mut b = Builder::new();
        b.begin("");
        b.begin("a");
        b.end();
        b.begin("a");
        b.end();
        b.end();
        let blob = b.build();
        assert!(parse(&blob).is_err(), "повторный узел");
    }

    #[test]
    fn rejects_unbalanced_tokens_and_bad_names() {
        let mut b = Builder::new();
        b.begin("");
        b.prop("compatible", b"x");
        // нет end() для корня
        let blob = b.build();
        assert!(parse(&blob).is_err(), "незакрытый корень");

        let mut b = Builder::new();
        b.begin("");
        b.begin("sub/node");
        b.end();
        b.end();
        let blob = b.build();
        assert!(parse(&blob).is_err(), "'/' в имени узла");
    }
}

