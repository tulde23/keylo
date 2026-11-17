include!("../../build-version.rs");

fn main() {
    stamp_version();
    tauri_build::build()
}
