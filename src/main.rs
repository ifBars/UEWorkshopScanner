fn main() {
    let exit_code = ue_workshop_scanner::run_cli();
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
}
