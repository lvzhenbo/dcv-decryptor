use std::{
    env, fs,
    ops::Deref,
    path::{Path, PathBuf},
};

fn out_dir() -> PathBuf {
    Path::new(&env::var("OUT_DIR").expect("env")).to_path_buf()
}

fn cleanup() {
    let _ = fs::remove_dir_all(out_dir());
}

fn compile() {
    let proto_dir = Path::new(&env::var("CARGO_MANIFEST_DIR").expect("env")).join("proto");

    let files = &[proto_dir.join("license_protocol.proto")];

    let slices = files.iter().map(Deref::deref).collect::<Vec<_>>();

    let out_dir = out_dir();
    fs::create_dir(&out_dir).expect("create_dir");

    protobuf_codegen::Codegen::new()
        .pure()
        .out_dir(&out_dir)
        .inputs(&slices)
        .include(&proto_dir)
        .run()
        .expect("Codegen failed.");
}

fn main() {
    cleanup();
    compile();
}
