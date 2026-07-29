use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use retoc::{Config, iostore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

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
    max_chunk_bytes: u64,
    accept_eula: bool,
}

#[derive(Serialize)]
struct Report {
    scanner: &'static str,
    retoc_revision: &'static str,
    input: String,
    input_sha256: String,
    verdict: &'static str,
    complete: bool,
    chunks_seen: usize,
    chunks_scanned: usize,
    chunks_skipped_for_size: usize,
    artifacts: Vec<Artifact>,
    findings: Vec<Finding>,
    notes: Vec<String>,
}

#[derive(Serialize)]
struct Artifact {
    location: String,
    size: u64,
    markers: BTreeSet<&'static str>,
}

struct ChunkScan {
    artifact: Option<Artifact>,
    scanned: bool,
    skipped_for_size: bool,
}

#[derive(Serialize)]
struct Finding {
    rule_id: &'static str,
    title: &'static str,
    severity: &'static str,
    blocking: bool,
    location: String,
    evidence: Vec<&'static str>,
}

struct MarkerDefinition {
    name: &'static str,
    patterns: &'static [&'static str],
}

const MARKERS: &[MarkerDefinition] = &[
    MarkerDefinition {
        name: "auto-execution",
        patterns: &["ReceiveBeginPlay", "Event BeginPlay", "K2_ReceiveBeginPlay"],
    },
    MarkerDefinition {
        name: "launch-url",
        patterns: &["LaunchURL", "execLaunchURL", "Launch URL"],
    },
    MarkerDefinition {
        name: "local-file-scheme",
        patterns: &["file://", "file:\\\\", "steam://"],
    },
    MarkerDefinition {
        name: "user-directory",
        patterns: &[
            "GetPlatformUserDir",
            "GetUserDirectory",
            "Get User Directory",
        ],
    },
    MarkerDefinition {
        name: "file-write",
        patterns: &["ToFile", "Save Json to File", "SaveJsonToFile", "WriteFile"],
    },
    MarkerDefinition {
        name: "json-conversion",
        patterns: &["FromString", "JsonObject", "Json Blueprint Utilities"],
    },
    MarkerDefinition {
        name: "script-extension",
        patterns: &[".bat", ".cmd", ".ps1", ".vbs", ".hta"],
    },
    MarkerDefinition {
        name: "process-shell",
        patterns: &["powershell", "pwsh", "cmd.exe", "cmd /c", "ShellExecute"],
    },
    MarkerDefinition {
        name: "downloader",
        patterns: &[
            "Invoke-WebRequest",
            "iwr ",
            "DownloadString",
            "DownloadFile",
            "GetByteArrayAsync",
            "-OutFile",
        ],
    },
    MarkerDefinition {
        name: "hidden-execution",
        patterns: &[
            "-w hidden",
            "-WindowStyle Hidden",
            "-ep bypass",
            "ExecutionPolicy Bypass",
            "start /min",
        ],
    },
    MarkerDefinition {
        name: "polyglot-batch",
        patterns: &["if not defined", "%~f0", "&exit", "set _Z="],
    },
    MarkerDefinition {
        name: "external-url",
        patterns: &["http://", "https://"],
    },
    MarkerDefinition {
        name: "temp-directory",
        patterns: &["$env:TEMP", "%TEMP%", "GetTempPath"],
    },
    MarkerDefinition {
        name: "historical-rce-name",
        patterns: &["BP_RCE_Test"],
    },
];

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
    validate_input(&options.input)?;
    if configure_oodle(&options)? {
        ensure_bundled_eula_accepted(options.accept_eula)?;
    }

    let input_hash = sha256_file(&options.input)?;
    let store = iostore::open(&options.input, Arc::new(Config::default()))
        .with_context(|| format!("retoc could not open {}", options.input.display()))?;

    let chunks = store.chunks().collect::<Vec<_>>();
    let chunks_seen = chunks.len();
    let scans = chunks
        .par_iter()
        .map(|chunk| -> Result<ChunkScan> {
            if chunk.size() == 0 {
                return Ok(ChunkScan {
                    artifact: None,
                    scanned: false,
                    skipped_for_size: false,
                });
            }
            if chunk.size() > options.max_chunk_bytes {
                return Ok(ChunkScan {
                    artifact: None,
                    scanned: false,
                    skipped_for_size: true,
                });
            }

            let location = chunk
                .path()
                .unwrap_or_else(|| format!("chunk:{:?}", chunk.id()));
            let bytes = chunk
                .read()
                .with_context(|| format!("retoc could not read {location}"))?;
            let markers = scan_markers(&bytes);
            Ok(ChunkScan {
                artifact: (!markers.is_empty()).then_some(Artifact {
                    location,
                    size: chunk.size(),
                    markers,
                }),
                scanned: true,
                skipped_for_size: false,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let mut artifacts = Vec::new();
    let mut chunks_scanned = 0;
    let mut chunks_skipped_for_size = 0;
    for scan in scans {
        chunks_scanned += usize::from(scan.scanned);
        chunks_skipped_for_size += usize::from(scan.skipped_for_size);
        artifacts.extend(scan.artifact);
    }

    let findings = artifacts.iter().flat_map(evaluate).collect::<Vec<_>>();
    let complete = chunks_skipped_for_size == 0;
    let verdict = if findings.iter().any(|finding| finding.blocking) {
        "block"
    } else if !complete {
        "incomplete"
    } else if findings.is_empty() {
        "allow"
    } else {
        "review"
    };

    let mut notes = vec![
        "IoStore content was read in-process through retoc; UnrealPak and Unreal Engine were not started.".to_owned(),
        "The patched Oodle adapter performs no network requests and requires an explicit path plus SHA-256 digest.".to_owned(),
    ];
    if chunks_skipped_for_size > 0 {
        notes.push(format!(
            "{chunks_skipped_for_size} chunks exceeded the configured size cap; allow is prohibited."
        ));
    }

    let report = Report {
        scanner: "ue-workshop-scanner",
        retoc_revision: RETOC_REVISION,
        input: options.input.display().to_string(),
        input_sha256: input_hash,
        verdict,
        complete,
        chunks_seen,
        chunks_scanned,
        chunks_skipped_for_size,
        artifacts,
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
        "usage: ue-workshop-scanner <file.utoc> [--oodle-path <dll> --oodle-sha256 <hex>] [--max-chunk-mb <n>] [--accept-eula]\n       ue-workshop-scanner --licenses",
    )?;
    let mut oodle_path = None;
    let mut oodle_sha256 = None;
    let mut max_chunk_bytes = 32 * 1024 * 1024;
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
            "--max-chunk-mb" => {
                let value = args
                    .next()
                    .context("--max-chunk-mb needs a value")?
                    .to_string_lossy()
                    .parse::<u64>()
                    .context("--max-chunk-mb must be an integer")?;
                if !(1..=2048).contains(&value) {
                    bail!("--max-chunk-mb must be between 1 and 2048");
                }
                max_chunk_bytes = value * 1024 * 1024;
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
        max_chunk_bytes,
        accept_eula,
    })
}

fn validate_input(input: &Path) -> Result<()> {
    if !input.is_file() {
        bail!("input does not exist: {}", input.display());
    }
    if !input
        .extension()
        .is_some_and(|value| value.eq_ignore_ascii_case("utoc"))
    {
        bail!("UEWorkshopScanner currently accepts a .utoc IoStore entry point");
    }
    let ucas = input.with_extension("ucas");
    if !ucas.is_file() {
        bail!("companion .ucas file is missing: {}", ucas.display());
    }
    Ok(())
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
            if bundled.exists() {
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
            } else {
                Ok(false)
            }
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
           ue-workshop-scanner <file.utoc> [options]\n  \
           ue-workshop-scanner --licenses\n\n\
         Options:\n  \
           --max-chunk-mb <n>       Per-chunk scan cap (1-2048, default 32)\n  \
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
        .or_else(|| {
            std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))
        })
        .context(
            "could not locate a user configuration directory; set UEWS_CONFIG_HOME or use an explicit Oodle path",
        )?;
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
        .context("EULA acceptance path has no parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("could not create {}", parent.display()))?;
    std::fs::write(path, format!("accepted={BINARY_EULA_VERSION}\n"))
        .with_context(|| format!("could not record EULA acceptance at {}", path.display()))?;
    eprintln!(
        "Accepted UEWorkshopScanner Binary EULA version {BINARY_EULA_VERSION}; recorded at {}",
        path.display()
    );
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String> {
    let bytes =
        std::fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn scan_markers(bytes: &[u8]) -> BTreeSet<&'static str> {
    let ascii = String::from_utf8_lossy(bytes).to_lowercase();
    let utf16_le_even = utf16_text(bytes, 0, true);
    let utf16_le_odd = utf16_text(bytes, 1, true);
    let utf16_be_even = utf16_text(bytes, 0, false);
    let utf16_be_odd = utf16_text(bytes, 1, false);
    let texts = [
        &*ascii,
        &utf16_le_even,
        &utf16_le_odd,
        &utf16_be_even,
        &utf16_be_odd,
    ];

    MARKERS
        .iter()
        .filter(|definition| {
            definition.patterns.iter().any(|pattern| {
                let pattern = pattern.to_lowercase();
                texts.iter().any(|text| text.contains(&pattern))
            })
        })
        .map(|definition| definition.name)
        .collect()
}

fn utf16_text(bytes: &[u8], offset: usize, little_endian: bool) -> String {
    let units = bytes
        .get(offset..)
        .unwrap_or_default()
        .chunks_exact(2)
        .map(|pair| {
            if little_endian {
                u16::from_le_bytes([pair[0], pair[1]])
            } else {
                u16::from_be_bytes([pair[0], pair[1]])
            }
        })
        .collect::<Vec<_>>();
    String::from_utf16_lossy(&units).to_lowercase()
}

fn evaluate(artifact: &Artifact) -> Vec<Finding> {
    let has = |name| artifact.markers.contains(name);
    let mut findings = Vec::new();
    let mut add = |rule_id, title, severity, blocking, evidence| {
        findings.push(Finding {
            rule_id,
            title,
            severity,
            blocking,
            location: artifact.location.clone(),
            evidence,
        });
    };

    if has("historical-rce-name") {
        add(
            "UWS101",
            "Historical RCE test name retained in cooked asset metadata",
            "high",
            false,
            vec!["historical-rce-name"],
        );
    }
    if has("auto-execution") && has("launch-url") {
        let dangerous = has("local-file-scheme") || has("script-extension") || has("process-shell");
        add(
            "UWS102",
            "Automatic Blueprint execution reaches LaunchURL",
            if dangerous { "critical" } else { "high" },
            dangerous,
            vec!["auto-execution", "launch-url"],
        );
    }
    if has("auto-execution") && has("user-directory") && has("file-write") {
        add(
            "UWS103",
            "Automatic Blueprint logic writes outside the game content area",
            if has("script-extension") {
                "critical"
            } else {
                "high"
            },
            true,
            vec!["auto-execution", "user-directory", "file-write"],
        );
    }
    if has("process-shell") && has("downloader") && has("script-extension") {
        add(
            "UWS104",
            "Shell downloader and script execution markers",
            "critical",
            true,
            vec!["process-shell", "downloader", "script-extension"],
        );
    }
    if has("json-conversion") && has("file-write") && has("polyglot-batch") && has("process-shell")
    {
        add(
            "UWS105",
            "JSON/batch polyglot construction",
            "critical",
            true,
            vec![
                "json-conversion",
                "file-write",
                "polyglot-batch",
                "process-shell",
            ],
        );
    }
    if has("process-shell") && has("hidden-execution") {
        add(
            "UWS106",
            "Hidden command-shell execution",
            if has("downloader") {
                "critical"
            } else {
                "high"
            },
            has("downloader"),
            vec!["process-shell", "hidden-execution"],
        );
    }
    if has("auto-execution")
        && has("external-url")
        && (has("launch-url") || has("file-write") || has("downloader"))
    {
        add(
            "UWS107",
            "External endpoint used from automatic Blueprint behavior",
            "high",
            false,
            vec!["auto-execution", "external-url"],
        );
    }
    if has("auto-execution")
        && has("user-directory")
        && has("file-write")
        && has("process-shell")
        && has("downloader")
    {
        add(
            "UWS108",
            "Meccha Chameleon Blueprint dropper behavior chain",
            "critical",
            true,
            vec![
                "auto-execution",
                "user-directory",
                "file-write",
                "process-shell",
                "downloader",
            ],
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_ascii_and_unaligned_utf16_markers() {
        let mut bytes = b"ReceiveBeginPlay GetPlatformUserDir ".to_vec();
        bytes.push(0xff);
        for unit in "ToFile powershell Invoke-WebRequest".encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }

        let markers = scan_markers(&bytes);
        assert!(markers.contains("auto-execution"));
        assert!(markers.contains("user-directory"));
        assert!(markers.contains("file-write"));
        assert!(markers.contains("process-shell"));
        assert!(markers.contains("downloader"));
    }

    #[test]
    fn complete_dropper_chain_blocks() {
        let artifact = Artifact {
            location: "BP_InertFixture.uasset".to_owned(),
            size: 1,
            markers: [
                "auto-execution",
                "user-directory",
                "file-write",
                "process-shell",
                "downloader",
            ]
            .into_iter()
            .collect(),
        };

        let findings = evaluate(&artifact);
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "UWS108" && finding.blocking)
        );
    }

    #[test]
    fn ordinary_begin_play_is_not_a_finding() {
        let artifact = Artifact {
            location: "BP_Door.uasset".to_owned(),
            size: 1,
            markers: ["auto-execution"].into_iter().collect(),
        };

        assert!(evaluate(&artifact).is_empty());
    }

    #[test]
    fn recognizes_only_the_current_eula_acceptance_record() {
        let path = std::env::temp_dir().join(format!(
            "uews-eula-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_file(&path);

        assert!(!eula_acceptance_is_current(&path));
        std::fs::write(&path, "accepted=0\n").unwrap();
        assert!(!eula_acceptance_is_current(&path));
        std::fs::write(&path, format!("accepted={BINARY_EULA_VERSION}\n")).unwrap();
        assert!(eula_acceptance_is_current(&path));

        std::fs::remove_file(path).unwrap();
    }
}
