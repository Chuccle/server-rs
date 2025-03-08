fn main() {
    let schemas_dir = std::path::Path::new("./schemas");

    let out_dir = std::env::var("OUT_DIR").unwrap();

    // Make sure flatc is installed
    let flatc_status = std::process::Command::new("flatc")
        .arg("--version")
        .status()
        .expect("Failed to execute flatc. Make sure it's installed and in your PATH");

    if !flatc_status.success() {
        panic!("flatc command failed");
    }

    // Compile the FlatBuffer schema
    let schema_path = schemas_dir.join("metadata_flatbuffer.fbs");
    let status = std::process::Command::new("flatc")
        .args(["--rust", "-o", &out_dir, schema_path.to_str().unwrap()])
        .status()
        .expect("Failed to execute flatc command");

    if !status.success() {
        panic!("flatc compilation failed");
    }

    // Make cargo watch for changes in schema files
    println!("cargo:rerun-if-changed=src/schemas/metadata_flatbuffer.fbs");
}
