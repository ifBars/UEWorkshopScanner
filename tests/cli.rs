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

#[test]
fn lists_the_meccha_game_profile() {
    let output = run(&["--list-games"]);
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.contains("meccha-chameleon"));
    assert!(stdout.contains("4704690"));
}

#[test]
fn writes_a_versioned_profile_aware_report_to_a_file() {
    let fixture = std::env::temp_dir().join(format!("uews-cli-fixture-{}", std::process::id()));
    let report = fixture.join("report.json");
    std::fs::create_dir_all(&fixture).unwrap();
    std::fs::write(fixture.join("readme.txt"), "benign fixture").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_ue-workshop-scanner"))
        .arg(&fixture)
        .args(["--game", "meccha-chameleon", "--output"])
        .arg(&report)
        .output()
        .expect("scanner process should start");

    assert_eq!(output.status.code(), Some(4));
    assert!(output.stdout.is_empty());
    let value: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&report).unwrap()).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["game_profile"]["id"], "meccha-chameleon");
    assert_eq!(value["game_profile"]["steam_app_id"], 4_704_690);

    std::fs::remove_dir_all(fixture).unwrap();
}
