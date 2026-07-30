use crate::{
    container,
    envelope::inspect_input,
    model::{AnalysisCompleteness, Report},
    rules,
    threat_intel::{classify_disposition, classify_families, verdict_for},
};
use anyhow::Result;
use std::path::Path;

const RETOC_REVISION: &str = "d034ade1ae8117d4786eaf6b0418d4cf48474d7f";

pub(crate) fn scan(input: &Path, max_item_bytes: u64) -> Result<Report> {
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
        scanner: "ue-workshop-scanner",
        version: env!("CARGO_PKG_VERSION"),
        retoc_revision: RETOC_REVISION,
        input: input.display().to_string(),
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
        notes: vec![
            "IoStore content was read in-process through retoc; UnrealPak and Unreal Engine were not started.".to_owned(),
            "Loose files were inspected as bytes only; scripts and executables were never loaded or executed.".to_owned(),
            "The patched Oodle adapter performs no network requests and requires an explicit path plus SHA-256 digest.".to_owned(),
        ],
    })
}
