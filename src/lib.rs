mod cli;
mod container;
mod envelope;
pub mod game_profile;
mod hashing;
mod markers;
pub mod model;
mod oodle;
mod rules;
pub mod scanner;
mod threat_intel;

/// Runs the command-line scanner with arguments from the current process.
///
/// The returned value follows the documented CLI exit-code contract.
pub fn run_cli() -> i32 {
    match cli::run(std::env::args_os().skip(1).collect()) {
        Ok(exit_code) => exit_code,
        Err(error) => {
            eprintln!("INCOMPLETE: {error:#}");
            4
        }
    }
}
