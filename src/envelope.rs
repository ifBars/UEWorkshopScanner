use crate::{
    hashing::sha256_file,
    markers::scan_markers,
    model::{Artifact, CompletenessReason, ScanCounts},
};
use anyhow::{Context, Result, bail};
use std::{
    fs,
    path::{Path, PathBuf},
};

const DANGEROUS_EXTENSIONS: &[&str] = &[
    "exe", "dll", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "scr", "msi", "lnk", "wsf",
];
const CONTAINER_EXTENSIONS: &[&str] = &["utoc", "ucas", "pak"];

pub struct InputTarget {
    pub kind: &'static str,
    pub input_hash: Option<String>,
    pub utocs: Vec<PathBuf>,
    pub loose_artifacts: Vec<Artifact>,
    pub counts: ScanCounts,
    pub reasons: Vec<CompletenessReason>,
}

pub fn inspect_input(input: &Path, max_file_bytes: u64) -> Result<InputTarget> {
    if input.is_file() {
        if !has_extension(input, "utoc") {
            bail!("file input must be a .utoc IoStore entry point");
        }
        let mut reasons = Vec::new();
        validate_companion(input, &mut reasons);
        return Ok(InputTarget {
            kind: "utoc",
            input_hash: Some(sha256_file(input)?),
            utocs: vec![input.to_owned()],
            loose_artifacts: Vec::new(),
            counts: ScanCounts::default(),
            reasons,
        });
    }
    if !input.is_dir() {
        bail!("input does not exist: {}", input.display());
    }

    let mut files = Vec::new();
    let mut reasons = Vec::new();
    walk(input, input, &mut files, &mut reasons)?;
    files.sort();

    let mut utocs = Vec::new();
    let mut loose_artifacts = Vec::new();
    let mut counts = ScanCounts::default();
    for file in files {
        counts.files_seen += 1;
        if has_extension(&file, "utoc") {
            validate_companion(&file, &mut reasons);
            utocs.push(file);
            continue;
        }
        if CONTAINER_EXTENSIONS
            .iter()
            .any(|ext| has_extension(&file, ext))
        {
            continue;
        }

        let metadata = match fs::metadata(&file) {
            Ok(metadata) => metadata,
            Err(error) => {
                counts.files_skipped += 1;
                reasons.push(reason(
                    "file-metadata-failed",
                    "envelope-read",
                    format!("Could not inspect file metadata: {error}"),
                    Some(relative(input, &file)),
                ));
                continue;
            }
        };
        if metadata.len() > max_file_bytes {
            counts.files_skipped += 1;
            reasons.push(reason(
                "file-skipped-for-size",
                "envelope-read",
                format!("File exceeds the configured {} byte limit", max_file_bytes),
                Some(relative(input, &file)),
            ));
            continue;
        }
        let bytes = match fs::read(&file) {
            Ok(bytes) => bytes,
            Err(error) => {
                counts.files_skipped += 1;
                reasons.push(reason(
                    "file-read-failed",
                    "envelope-read",
                    format!("Could not read file: {error}"),
                    Some(relative(input, &file)),
                ));
                continue;
            }
        };
        counts.files_scanned += 1;
        let mut markers = scan_markers(&bytes);
        let dangerous =
            extension(&file).is_some_and(|ext| DANGEROUS_EXTENSIONS.contains(&ext.as_str()));
        if dangerous {
            markers.insert("dangerous-extension");
        }
        if bytes.starts_with(b"MZ")
            && !extension(&file).is_some_and(|ext| matches!(ext.as_str(), "exe" | "dll" | "scr"))
        {
            markers.insert("disguised-executable");
        }
        if !markers.is_empty() {
            loose_artifacts.push(Artifact {
                location: relative(input, &file),
                kind: "loose-file",
                size: metadata.len(),
                sha256: Some(sha256_file(&file)?),
                markers,
            });
        }
    }
    if utocs.is_empty() {
        reasons.push(reason(
            "no-iostore-entrypoint",
            "container-discovery",
            "No .utoc IoStore entry point was found".to_owned(),
            None,
        ));
    }
    Ok(InputTarget {
        kind: "directory",
        input_hash: None,
        utocs,
        loose_artifacts,
        counts,
        reasons,
    })
}

fn walk(
    root: &Path,
    directory: &Path,
    files: &mut Vec<PathBuf>,
    reasons: &mut Vec<CompletenessReason>,
) -> Result<()> {
    for entry in fs::read_dir(directory)
        .with_context(|| format!("could not enumerate {}", directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            reasons.push(reason(
                "symlink-skipped",
                "envelope-discovery",
                "Symbolic links are not followed".to_owned(),
                Some(relative(root, &path)),
            ));
        } else if file_type.is_dir() {
            walk(root, &path, files, reasons)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn validate_companion(utoc: &Path, reasons: &mut Vec<CompletenessReason>) {
    let ucas = utoc.with_extension("ucas");
    if !ucas.is_file() {
        reasons.push(reason(
            "missing-ucas-companion",
            "container-discovery",
            "The .utoc entry point has no companion .ucas file".to_owned(),
            Some(utoc.display().to_string()),
        ));
    }
}

fn reason(
    reason_id: &'static str,
    phase: &'static str,
    summary: String,
    location: Option<String>,
) -> CompletenessReason {
    CompletenessReason {
        reason_id,
        phase,
        summary,
        location,
    }
}

fn extension(path: &Path) -> Option<String> {
    path.extension()
        .map(|value| value.to_string_lossy().to_ascii_lowercase())
}

fn has_extension(path: &Path, expected: &str) -> bool {
    extension(path).is_some_and(|value| value == expected)
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "uews-envelope-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn detects_loose_scripts_without_executing_them() {
        let root = temp_dir();
        fs::write(
            root.join("payload.ps1"),
            "powershell Invoke-WebRequest https://127.0.0.1/a",
        )
        .unwrap();
        let target = inspect_input(&root, 1024).unwrap();
        assert!(
            target.loose_artifacts[0]
                .markers
                .contains("dangerous-extension")
        );
        assert!(target.loose_artifacts[0].markers.contains("raw-ip-url"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn detects_disguised_portable_executables() {
        let root = temp_dir();
        fs::write(root.join("map.png"), b"MZ inert fixture").unwrap();
        let target = inspect_input(&root, 1024).unwrap();
        assert!(
            target.loose_artifacts[0]
                .markers
                .contains("disguised-executable")
        );
        fs::remove_dir_all(root).unwrap();
    }
}
