//! Compiles `proto/nebula.proto` into `$OUT_DIR`.
//!
//! Requires `protoc` on PATH (`apt install protobuf-compiler`).

fn main() {
    println!("cargo:rerun-if-changed=../../proto/nebula.proto");

    tonic_prost_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../../proto/nebula.proto"], &["../../proto"])
        .expect("compiling proto/nebula.proto");
}
