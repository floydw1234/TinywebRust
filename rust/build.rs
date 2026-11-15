//! Compiles the TinyWeb protobuf schemas from `../proto`
//! into Rust types via prost.
//!
//! The generated code lands in `$OUT_DIR/tinyweb.rs` (one file per
//! protobuf package) and is included by `src/proto.rs`.

use std::path::PathBuf;

fn main() {
    let proto_dir: PathBuf = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../proto")
        .canonicalize()
        .expect("failed to resolve ../proto relative to rust/");

    // The wire schemas that make up the TinyWeb protocol.
    let protos = [
        "envelope.proto",
        "content.proto",
        "api.proto",
        "message.proto",
        "client_request.proto",
    ];
    let proto_files: Vec<PathBuf> = protos.iter().map(|f| proto_dir.join(f)).collect();

    for proto in &proto_files {
        println!("cargo:rerun-if-changed={}", proto.display());
    }
    println!("cargo:rerun-if-changed=build.rs");

    prost_build::Config::new()
        .compile_protos(&proto_files, &[proto_dir])
        .expect("failed to compile TinyWeb .proto schemas with prost-build");
}
