use crate::{
    container,
    envelope::inspect_input,
    game_profile::{GameProfile, GameProfileSummary},
    model::{AnalysisCompleteness, Report},
    oodle, rules,
    threat_intel::{classify_disposition, classify_families, verdict_for},
};
use anyhow::Result;
use std::path::{Path, PathBuf};

const RETOC_REVISION: &str = "d034ade1ae8117d4786eaf6b0418d4cf48474d7f";
pub const REPORT_SCHEMA_VERSION: u32 = 2;
/// Default per-file and decoded IoStore chunk limit.
///
/// Unreal texture and map assets can legitimately exceed 32 MiB. The scanner
/// still applies a finite limit so malformed or unusually large content cannot
/// request an unbounded allocation.
pub const DEFAULT_MAX_ITEM_BYTES: u64 = 512 * 1024 * 1024;

/// An explicitly authorized Oodle decoder for compressed IoStore content.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct OodleDecoder {
    pub path: PathBuf,
    pub sha256: String,
}

impl OodleDecoder {
    pub fn new(path: impl Into<PathBuf>, sha256: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            sha256: sha256.into(),
        }
    }
}

/// Options shared by embedded and command-line scanner integrations.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ScannerOptions {
    pub max_item_bytes: u64,
    pub game_profile: Option<GameProfile>,
    pub oodle_decoder: Option<OodleDecoder>,
    pub accept_bundled_eula: bool,
    /// Require an approved Oodle decoder to be ready before scanning.
    ///
    /// Player-facing integrations should enable this for games whose IoStore
    /// content is Oodle-compressed. Failing early prevents the process-wide
    /// decoder from caching an unconfigured initialization attempt.
    pub require_oodle_decoder: bool,
}

impl Default for ScannerOptions {
    fn default() -> Self {
        Self {
            max_item_bytes: DEFAULT_MAX_ITEM_BYTES,
            game_profile: None,
            oodle_decoder: None,
            accept_bundled_eula: false,
            require_oodle_decoder: false,
        }
    }
}

/// Reusable scanner facade for launchers, mod managers, and tests.
///
/// Oodle is process-wide: multiple scanners may reuse the same decoder
/// configuration, but cannot switch decoder DLLs after initialization.
pub struct Scanner {
    options: ScannerOptions,
}

impl Scanner {
    pub fn new(options: ScannerOptions) -> Result<Self> {
        let decoder = options.oodle_decoder.as_ref();
        oodle::configure(
            decoder.map(|value| value.path.as_path()),
            decoder.map(|value| value.sha256.as_str()),
            options.accept_bundled_eula,
            options.require_oodle_decoder,
        )?;
        Ok(Self { options })
    }

    pub fn scan(&self, input: impl AsRef<Path>) -> Result<Report> {
        scan(
            input.as_ref(),
            self.options.max_item_bytes,
            self.options.game_profile.as_ref(),
        )
    }
}

pub(crate) fn scan(
    input: &Path,
    max_item_bytes: u64,
    game_profile: Option<&GameProfile>,
) -> Result<Report> {
    let mut target = inspect_input(input, max_item_bytes)?;
    let (mut container_artifacts, container_counts, mut container_reasons) =
        container::scan_utocs(&target.utocs, max_item_bytes);
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

    Ok(Report {
        schema_version: REPORT_SCHEMA_VERSION,
        scanner: "ue-workshop-scanner",
        version: env!("CARGO_PKG_VERSION"),
        retoc_revision: RETOC_REVISION,
        input: input.display().to_string(),
        input_kind: target.kind,
        input_sha256: target.input_hash,
        game_profile: game_profile.map(GameProfileSummary::from),
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
        notes: vec![
            "IoStore content was read in-process through retoc; UnrealPak and Unreal Engine were not started.".to_owned(),
            "Loose files were inspected as bytes only; scripts and executables were never loaded or executed.".to_owned(),
            "The patched Oodle adapter performs no network requests and accepts only a verified, process-wide decoder configuration.".to_owned(),
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limit_allows_normal_large_unreal_assets() {
        assert_eq!(
            ScannerOptions::default().max_item_bytes,
            DEFAULT_MAX_ITEM_BYTES
        );
        assert_eq!(DEFAULT_MAX_ITEM_BYTES, 512 * 1024 * 1024);
    }
}
