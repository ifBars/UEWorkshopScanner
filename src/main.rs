mod container;
mod envelope;
mod hashing;
mod markers;
mod model;
mod rules;
mod threat_intel;

use anyhow::{Context, Result, bail};
use envelope::inspect_input;
use hashing::sha256_file;
use model::{AnalysisCompleteness, Report};
use std::{
    ffi::OsString,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};
use threat_intel::{classify_disposition, classify_families, verdict_for};

const RETOC_REVISION: &str = "d034ade1ae8117d4786eaf6b0418d4cf48474d7f";
const BUNDLED_OODLE_FILE: &str = "oo2core_9_win64.dll";
const EPIC_OODLE_2_9_10_REDIST_SHA256: &[&str] = &[
    "6f5d41a7892ea6b2db420f2458dad2f84a63901c9a93ce9497337b16c195f457",
    "111a505e64a3bf1b89c05aab2dd16306bc2267a5ea3f0c9722a3b6152091ce1c",
];
const BINARY_EULA_VERSION: &str = "1";
const BINARY_EULA: &str = include_str!("../BINARY-EULA.txt");
const PROJECT_LICENSE: &str = include_str!("../LICENSE");
const THIRD_PARTY_NOTICES: &str = include_str!("../THIRD_PARTY_NOTICES.txt");

#[derive(Debug)]
struct Options {
    input: PathBuf,
    oodle_path: Option<PathBuf>,
    oodle_sha256: Option<String>,
    max_item_bytes: u64,
    accept_eula: bool,
}

fn main() {
    match run() {
        Ok(0) => {}
        Ok(exit_code) => std::process::exit(exit_code),
        Err(error) => {
            eprintln!("INCOMPLETE: {error:#}");
            std::process::exit(4);
        }
    }
}

fn run() -> Result<i32> {
    let args = std::env::args_os().skip(1).collect::<Vec<_>>();
    if args.is_empty()
        || args
            .iter()
            .any(|argument| argument == "--help" || argument == "-h")
    {
        print_help();
        return Ok(0);
    }
    if args
        .iter()
        .any(|argument| argument == "--version" || argument == "-V")
    {
        println!("ue-workshop-scanner {}", env!("CARGO_PKG_VERSION"));
        return Ok(0);
    }
    if args.iter().any(|argument| argument == "--licenses") {
        print_licenses();
        return Ok(0);
    }

    let options = parse_options(args)?;
    if configure_oodle(&options)? {
        ensure_bundled_eula_accepted(options.accept_eula)?;
    }

    let mut target = inspect_input(&options.input, options.max_item_bytes)?;
    let (mut container_artifacts, container_counts, mut container_reasons) =
        container::scan_utocs(&target.utocs, options.max_item_bytes);
    target.counts.chunks_seen += container_counts.chunks_seen;
    target.counts.chunks_scanned += container_counts.chunks_scanned;
    target.counts.chunks_skipped_for_size += container_counts.chunks_skipped_for_size;
    target.reasons.append(&mut container_reasons);
    target.loose_artifacts.append(&mut container_artifacts);
    target.loose_artifacts.sort_by(|left, right| {
        left.location
            .cmp(&right.location)
            .then_with(|| left.kind.cmp(right.kind))
    });

    let mut findings = target
        .loose_artifacts
        .iter()
        .flat_map(rules::evaluate_artifact)
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        left.location
            .cmp(&right.location)
            .then_with(|| left.rule_id.cmp(right.rule_id))
    });
    let complete = target.reasons.is_empty();
    let completeness = AnalysisCompleteness {
        status: if complete { "Complete" } else { "Incomplete" },
        is_complete: complete,
        review_recommended: !complete,
        reasons: target.reasons,
    };
    let families = classify_families(&findings);
    let disposition = classify_disposition(&findings, &families, &completeness);
    let verdict = verdict_for(&disposition, &completeness);
    let notes = vec![
        "IoStore content was read in-process through retoc; UnrealPak and Unreal Engine were not started.".to_owned(),
        "Loose files were inspected as bytes only; scripts and executables were never loaded or executed.".to_owned(),
        "The patched Oodle adapter performs no network requests and requires an explicit path plus SHA-256 digest.".to_owned(),
    ];

    let report = Report {
        scanner: "ue-workshop-scanner",
        version: env!("CARGO_PKG_VERSION"),
        retoc_revision: RETOC_REVISION,
        input: options.input.display().to_string(),
        input_kind: target.kind,
        input_sha256: target.input_hash,
        verdict,
        complete,
        analysis_completeness: completeness,
        disposition,
        threat_families: families,
        chunks_seen: target.counts.chunks_seen,
        chunks_scanned: target.counts.chunks_scanned,
        chunks_skipped_for_size: target.counts.chunks_skipped_for_size,
        files_seen: target.counts.files_seen,
        files_scanned: target.counts.files_scanned,
        files_skipped: target.counts.files_skipped,
        artifacts: target.loose_artifacts,
        findings,
        notes,
    };
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(match verdict {
        "allow" => 0,
        "review" => 2,
        "block" => 3,
        _ => 4,
    })
}

fn parse_options(args: Vec<OsString>) -> Result<Options> {
    let mut args = args.into_iter();
    let input = args.next().map(PathBuf::from).context(
        "usage: ue-workshop-scanner <file.utoc|directory> [--oodle-path <dll> --oodle-sha256 <hex>] [--max-item-mb <n>] [--accept-eula]",
    )?;
    let mut oodle_path = None;
    let mut oodle_sha256 = None;
    let mut max_item_bytes = 32 * 1024 * 1024;
    let mut accept_eula = false;
    while let Some(argument) = args.next() {
        match argument.to_string_lossy().as_ref() {
            "--oodle-path" => {
                oodle_path = Some(PathBuf::from(
                    args.next().context("--oodle-path needs a value")?,
                ));
            }
            "--oodle-sha256" => {
                oodle_sha256 = Some(
                    args.next()
                        .context("--oodle-sha256 needs a value")?
                        .to_string_lossy()
                        .into_owned(),
                );
            }
            "--max-item-mb" | "--max-chunk-mb" => {
                let value = args
                    .next()
                    .context("--max-item-mb needs a value")?
                    .to_string_lossy()
                    .parse::<u64>()
                    .context("--max-item-mb must be an integer")?;
                if !(1..=2048).contains(&value) {
                    bail!("--max-item-mb must be between 1 and 2048");
                }
                max_item_bytes = value * 1024 * 1024;
            }
            "--accept-eula" => accept_eula = true,
            "--licenses" => unreachable!("handled before option parsing"),
            unknown => bail!("unknown argument: {unknown}"),
        }
    }
    Ok(Options {
        input,
        oodle_path,
        oodle_sha256,
        max_item_bytes,
        accept_eula,
    })
}

fn configure_oodle(options: &Options) -> Result<bool> {
    match (&options.oodle_path, &options.oodle_sha256) {
        (Some(path), Some(digest)) => {
            if !path.is_file() {
                bail!(
                    "configured Oodle decoder does not exist: {}",
                    path.display()
                );
            }
            let actual = sha256_file(path)?;
            if !actual.eq_ignore_ascii_case(digest) {
                bail!("configured Oodle digest mismatch; expected {digest}, got {actual}");
            }
            // SAFETY: This occurs before retoc or any worker thread is created.
            unsafe {
                std::env::set_var("UEWS_OODLE_PATH", path);
                std::env::set_var("UEWS_OODLE_SHA256", actual);
            }
            Ok(false)
        }
        (None, None) => {
            let bundled = std::env::current_exe()
                .context("could not resolve the scanner executable path")?
                .with_file_name(BUNDLED_OODLE_FILE);
            if !bundled.exists() {
                return Ok(false);
            }
            let actual = sha256_file(&bundled)?;
            if !EPIC_OODLE_2_9_10_REDIST_SHA256.contains(&actual.as_str()) {
                bail!(
                    "bundled {BUNDLED_OODLE_FILE} is not an approved Oodle 2.9.10 redist build; got SHA-256 {actual}"
                );
            }
            // SAFETY: This occurs before retoc or any worker thread is created.
            unsafe {
                std::env::set_var("UEWS_OODLE_PATH", bundled);
                std::env::set_var("UEWS_OODLE_SHA256", actual);
            }
            Ok(true)
        }
        _ => bail!("--oodle-path and --oodle-sha256 must be supplied together"),
    }
}

fn print_licenses() {
    println!("=== UEWorkshopScanner source license ===\n{PROJECT_LICENSE}");
    println!("\n=== Compiled binary EULA ===\n{BINARY_EULA}");
    println!("\n=== Third-party notices ===\n{THIRD_PARTY_NOTICES}");
}

fn print_help() {
    println!(
        "UEWorkshopScanner {}\n\
         Static malware scanner for Unreal Engine Workshop content.\n\n\
         Usage:\n  \
           ue-workshop-scanner <file.utoc|directory> [options]\n  \
           ue-workshop-scanner --licenses\n\n\
         Options:\n  \
           --max-item-mb <n>        Per-file/chunk scan cap (1-2048, default 32)\n  \
           --max-chunk-mb <n>       Backward-compatible alias for --max-item-mb\n  \
           --oodle-path <dll>       Explicit Oodle decoder path\n  \
           --oodle-sha256 <hex>     Required digest for an explicit decoder\n  \
           --accept-eula            Accept the bundled binary EULA non-interactively\n  \
           --licenses               Print source license, binary EULA, and notices\n  \
           -h, --help               Print help\n  \
           -V, --version            Print version\n\n\
         Exit codes:\n  \
           0 allow     2 review     3 block     4 incomplete/error",
        env!("CARGO_PKG_VERSION")
    );
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
