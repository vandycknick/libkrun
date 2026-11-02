#[path = "../live_build.rs"]
mod live_build;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    live_build::emit()
}
