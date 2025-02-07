extern crate capnpc;

fn main() {
    let generated_dir = "src/generated";
    capnpc::CompilerCommand::new()
        .output_path(generated_dir)
        .src_prefix("schemas")
        .file("schemas/metadata.capnp")
        .run()
        .expect("capnp compiles");

    for entry in std::fs::read_dir(generated_dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            let content = std::fs::read_to_string(&path).unwrap();
            std::fs::write(&path, format!("#![allow(clippy::all)]\n{}", content)).unwrap();
        }
    }
}
