use std::{
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use ue_workshop_scanner::{
    game_profile::game_profile,
    model::Report,
    scanner::{Scanner, ScannerOptions},
};

const MECCHA_PROFILE_ID: &str = "meccha-chameleon";

#[derive(Debug, Error)]
pub enum ScanError {
    #[error("the selected Workshop item does not exist: {0}")]
    InputNotFound(PathBuf),
    #[error("the scanner task stopped unexpectedly: {0}")]
    Task(tokio::task::JoinError),
    #[error("the scanner could not inspect this map: {0}")]
    Scanner(String),
    #[error("could not create the report folder: {0}")]
    ReportDirectory(std::io::Error),
    #[error("the scanner report could not be encoded: {0}")]
    EncodeReport(serde_json::Error),
    #[error("the scanner report could not be saved: {0}")]
    WriteReport(std::io::Error),
}

#[derive(Clone, Debug)]
pub struct ScanOutcome {
    pub report: Report,
    pub report_path: PathBuf,
}

pub async fn scan_workshop_item(input: PathBuf) -> Result<ScanOutcome, ScanError> {
    if !input.exists() {
        return Err(ScanError::InputNotFound(input));
    }

    let report = tokio::task::spawn_blocking(move || scan_with_core(input))
        .await
        .map_err(ScanError::Task)?
        .map_err(ScanError::Scanner)?;

    let report_path = next_report_path();
    if let Some(parent) = report_path.parent() {
        std::fs::create_dir_all(parent).map_err(ScanError::ReportDirectory)?;
    }
    let report_bytes = serde_json::to_vec_pretty(&report).map_err(ScanError::EncodeReport)?;
    std::fs::write(&report_path, report_bytes).map_err(ScanError::WriteReport)?;

    Ok(ScanOutcome {
        report,
        report_path,
    })
}

fn scan_with_core(input: PathBuf) -> Result<Report, String> {
    let profile = game_profile(MECCHA_PROFILE_ID)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| format!("the built-in {MECCHA_PROFILE_ID} profile is missing"))?;
    let mut options = ScannerOptions::default();
    options.game_profile = Some(profile);
    options.require_oodle_decoder = true;
    let scanner = Scanner::new(options).map_err(|error| error.to_string())?;

    scanner.scan(input).map_err(|error| error.to_string())
}

pub fn reveal_report(path: &Path) -> Result<(), std::io::Error> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer.exe")
            .arg(format!("/select,{}", path.display()))
            .spawn()?;
    }
    Ok(())
}

fn next_report_path() -> PathBuf {
    let root = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("UEWorkshopScanner")
        .join("reports");
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    root.join(format!("scan-{timestamp}-{}.json", std::process::id()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_paths_are_local_json_files() {
        let path = next_report_path();
        assert_eq!(
            path.extension().and_then(|value| value.to_str()),
            Some("json")
        );
        assert!(path.to_string_lossy().contains("UEWorkshopScanner"));
        assert!(path.to_string_lossy().contains("reports"));
    }

    #[test]
    fn desktop_scan_fails_before_chunks_when_oodle_is_missing() {
        let input = std::env::temp_dir().join(format!("uews-gui-core-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&input);
        std::fs::create_dir_all(&input).unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let error = runtime
            .block_on(scan_workshop_item(input.clone()))
            .unwrap_err()
            .to_string();

        std::fs::remove_dir_all(input).unwrap();
        assert!(error.contains("Oodle is required for this scan"));
        assert!(!error.contains("retoc could not read chunk"));
    }
}
