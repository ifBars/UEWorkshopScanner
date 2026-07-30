use ue_workshop_scanner::{
    game_profile::game_profile,
    scanner::{REPORT_SCHEMA_VERSION, Scanner, ScannerOptions},
};

#[test]
fn external_integrations_can_scan_with_a_built_in_profile() {
    let fixture = std::env::temp_dir().join(format!("uews-api-fixture-{}", std::process::id()));
    std::fs::create_dir_all(&fixture).unwrap();
    std::fs::write(fixture.join("readme.txt"), "benign fixture").unwrap();

    let mut options = ScannerOptions::default();
    options.game_profile = game_profile("meccha-chameleon").unwrap();
    let report = Scanner::new(options).unwrap().scan(&fixture).unwrap();

    assert_eq!(report.schema_version, REPORT_SCHEMA_VERSION);
    assert_eq!(
        report
            .game_profile
            .as_ref()
            .map(|profile| profile.id.as_str()),
        Some("meccha-chameleon")
    );
    assert_eq!(report.verdict, "incomplete");

    std::fs::remove_dir_all(fixture).unwrap();
}
