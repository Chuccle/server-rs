fn main() {
    let schemas_dir = std::path::Path::new("./schemas");

    let out_dir = std::env::var("OUT_DIR").unwrap();

    // Make sure flatc is installed
    let flatc_status = std::process::Command::new("flatc")
        .arg("--version")
        .status()
        .expect("Failed to execute flatc. Make sure it's installed and in your PATH");

    assert!(flatc_status.success(), "flatc command failed");

    // Compile the FlatBuffer schema
    let schema_path = schemas_dir.join("metadata_flatbuffer.fbs");
    let status = std::process::Command::new("flatc")
        .args(["--rust", "-o", &out_dir, schema_path.to_str().unwrap()])
        .status()
        .expect("Failed to execute flatc command");

    assert!(status.success(), "flatc compilation failed");

    // Rerun only when the schema changes. The previous path pointed at
    // `src/schemas/`, which does not exist - and cargo treats a missing
    // rerun-if-changed path as always stale, so this ran on every build.
    // The contract module (`schemas/generated/blorg_contract.rs`) needs no
    // entry here: it is pulled in by `include!`, which rustc tracks itself.
    println!("cargo:rerun-if-changed={}", schema_path.display());
}
