//! Thin entry point.
//!
//! Everything lives in the library target so that `benches/` and `tests/` can
//! reach the hot paths directly - a binary-only crate is not reachable from
//! either.

#[tokio::main]
async fn main() -> std::io::Result<()> {
    server_rs::run().await
}
