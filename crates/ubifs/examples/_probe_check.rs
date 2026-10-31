fn main() {
    for name in ["g1-none", "g3-none", "g2-none"] {
        let comp = std::fs::read(format!("tests/data/{name}.ubifs.zlib")).unwrap();
        let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&comp).unwrap();
        let leb = u32::from_le_bytes(raw[36..40].try_into().unwrap()) as usize;
        let lebs: Vec<Option<Vec<u8>>> = raw.chunks(leb).map(|c| Some(c.to_vec())).collect();
        let report = ubifs::check::check(&lebs);
        println!(
            "{name}: ok={} problems={}",
            report.is_ok(),
            report.problems.len()
        );
        for p in &report.problems {
            println!("  {:?}: {}", p.kind, p.detail);
        }
    }
}
