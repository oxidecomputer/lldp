fn main() -> anyhow::Result<()> {
    // Emit detailed build information, for use in the `/build-info` endpoint.
    vergen::EmitBuilder::builder()
        .all_cargo()
        .all_rustc()
        .all_git()
        .emit()
}
