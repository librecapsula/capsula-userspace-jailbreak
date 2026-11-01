//! Compile the lwext4 xattr stubs (see src/lwext4_xattr_stubs.c):
//! ext4-lwext4 without the gpl-xattr feature leaves the xattr entry
//! points undefined, which breaks linking on strict linkers.

fn main() {
    let mut build = cc::Build::new();
    build
        .file("src/lwext4_xattr_stubs.c")
        .warnings(false)
        .compile("lwext4_xattr_stubs");
    println!("cargo:rerun-if-changed=src/lwext4_xattr_stubs.c");
}
