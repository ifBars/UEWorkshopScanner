use std::process::{Command, Output};

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ue-workshop-scanner"))
        .args(arguments)
        .output()
        .expect("scanner process should start")
}

#[test]
fn help_describes_inputs_and_exit_codes() {
    let output = run(&["--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("<file.utoc|directory>"));
    assert!(stdout.contains("0 allow"));
    assert!(stdout.contains("4 incomplete/error"));
}

#[test]
fn version_uses_the_package_version() {
    let output = run(&["--version"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert_eq!(
        stdout.trim(),
        format!("ue-workshop-scanner {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn missing_input_fails_closed() {
    let output = run(&["definitely-missing-workshop-item"]);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(4));
    assert!(stderr.contains("input does not exist"));
}
