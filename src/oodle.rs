use crate::hashing::sha256_file;
use anyhow::{Context, Result, bail};
use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};

const BUNDLED_OODLE_FILE: &str = "oo2core_9_win64.dll";
const EPIC_OODLE_2_9_10_REDIST_SHA256: &[&str] = &[
    "6f5d41a7892ea6b2db420f2458dad2f84a63901c9a93ce9497337b16c195f457",
    "111a505e64a3bf1b89c05aab2dd16306bc2267a5ea3f0c9722a3b6152091ce1c",
];
const BINARY_EULA_VERSION: &str = "1";
const BINARY_EULA: &str = include_str!("../BINARY-EULA.txt");
const PROJECT_LICENSE: &str = include_str!("../LICENSE");
const THIRD_PARTY_NOTICES: &str = include_str!("../THIRD_PARTY_NOTICES.txt");

pub(crate) fn configure(
    explicit_path: Option<&Path>,
    expected_digest: Option<&str>,
    accept_eula: bool,
) -> Result<()> {
    match (explicit_path, expected_digest) {
        (Some(path), Some(digest)) => {
            let actual = verify_decoder(path, Some(digest))?;
            configure_decoder(path, &actual)?;
            Ok(())
        }
        (None, None) => {
            let bundled = std::env::current_exe()
                .context("could not resolve the scanner executable path")?
                .with_file_name(BUNDLED_OODLE_FILE);
            if bundled.exists() {
                let actual = verify_decoder(&bundled, None)?;
                if !EPIC_OODLE_2_9_10_REDIST_SHA256.contains(&actual.as_str()) {
                    bail!(
                        "bundled {BUNDLED_OODLE_FILE} is not an approved Oodle 2.9.10 redist build; got SHA-256 {actual}"
                    );
                }
                configure_decoder(&bundled, &actual)?;
                ensure_bundled_eula_accepted(accept_eula)?;
            }
            Ok(())
        }
        _ => bail!("--oodle-path and --oodle-sha256 must be supplied together"),
    }
}

pub(crate) fn accept_bundled_eula() -> Result<()> {
    let bundled = std::env::current_exe()
        .context("could not resolve the scanner executable path")?
        .with_file_name(BUNDLED_OODLE_FILE);
    if !bundled.is_file() {
        bail!("no bundled {BUNDLED_OODLE_FILE} was found beside the scanner executable");
    }
    configure(None, None, true)
}

fn verify_decoder(path: &Path, expected_digest: Option<&str>) -> Result<String> {
    if !path.is_file() {
        bail!(
            "configured Oodle decoder does not exist: {}",
            path.display()
        );
    }
    let actual = sha256_file(path)?;
    if expected_digest.is_some_and(|expected| !actual.eq_ignore_ascii_case(expected)) {
        bail!(
            "configured Oodle digest mismatch; expected {}, got {actual}",
            expected_digest.unwrap_or_default()
        );
    }
    Ok(actual)
}

fn configure_decoder(path: &Path, actual_digest: &str) -> Result<()> {
    let canonical_path = path
        .canonicalize()
        .with_context(|| format!("could not resolve decoder path {}", path.display()))?;
    oodle_loader::configure(&canonical_path, actual_digest)
        .context("could not configure the process-wide Oodle decoder")
}

pub(crate) fn print_licenses() {
    println!("=== UEWorkshopScanner source license ===\n{PROJECT_LICENSE}");
    println!("\n=== Compiled binary EULA ===\n{BINARY_EULA}");
    println!("\n=== Third-party notices ===\n{THIRD_PARTY_NOTICES}");
}

fn ensure_bundled_eula_accepted(accept_flag: bool) -> Result<()> {
    let acceptance_path = eula_acceptance_path()?;
    if eula_acceptance_is_current(&acceptance_path) {
        return Ok(());
    }
    if accept_flag {
        persist_eula_acceptance(&acceptance_path)?;
        return Ok(());
    }
    if io::stdin().is_terminal() && io::stdout().is_terminal() {
        eprintln!(
            "This distribution includes Epic Games Licensed Technology.\n\
             Review the complete terms with --licenses.\n\
             Accept UEWorkshopScanner Binary EULA version {BINARY_EULA_VERSION}? [y/N]"
        );
        eprint!("> ");
        io::stderr()
            .flush()
            .context("could not display EULA prompt")?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .context("could not read EULA response")?;
        if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            persist_eula_acceptance(&acceptance_path)?;
            return Ok(());
        }
        bail!("the bundled Oodle EULA was not accepted");
    }
    bail!(
        "the bundled Oodle EULA has not been accepted; review it with --licenses, then rerun with --accept-eula"
    )
}

fn eula_acceptance_path() -> Result<PathBuf> {
    let base = std::env::var_os("UEWS_CONFIG_HOME")
        .or_else(|| std::env::var_os("LOCALAPPDATA"))
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .context("could not locate a user configuration directory")?;
    Ok(base
        .join("UEWorkshopScanner")
        .join(format!("binary-eula-v{BINARY_EULA_VERSION}.accepted")))
}

fn eula_acceptance_is_current(path: &Path) -> bool {
    std::fs::read_to_string(path)
        .is_ok_and(|value| value.trim() == format!("accepted={BINARY_EULA_VERSION}"))
}

fn persist_eula_acceptance(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .context("EULA acceptance path has no parent")?;
    std::fs::create_dir_all(parent)?;
    std::fs::write(path, format!("accepted={BINARY_EULA_VERSION}\n"))?;
    eprintln!(
        "Accepted UEWorkshopScanner Binary EULA version {BINARY_EULA_VERSION}; recorded at {}",
        path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_only_the_current_eula_acceptance_record() {
        let path = std::env::temp_dir().join(format!("uews-eula-test-{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        assert!(!eula_acceptance_is_current(&path));
        std::fs::write(&path, "accepted=0\n").unwrap();
        assert!(!eula_acceptance_is_current(&path));
        std::fs::write(&path, format!("accepted={BINARY_EULA_VERSION}\n")).unwrap();
        assert!(eula_acceptance_is_current(&path));
        std::fs::remove_file(path).unwrap();
    }
}
