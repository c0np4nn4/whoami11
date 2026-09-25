#[path = "bench/paper.rs"]
mod paper;

fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    paper::main()
}
