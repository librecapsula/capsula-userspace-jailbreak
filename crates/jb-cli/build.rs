fn main() {
    println!("cargo:rerun-if-changed=capsula-jb.manifest");
    println!("cargo:rerun-if-changed=capsula-jb.rc");
    #[cfg(target_env = "msvc")]
    let _ = embed_resource::compile("capsula-jb.rc", embed_resource::NONE);
}
