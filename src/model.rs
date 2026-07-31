use crate::game_profile::GameProfileSummary;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub schema_version: u32,
    pub scanner: &'static str,
    pub version: &'static str,
    pub retoc_revision: &'static str,
    pub input: String,
    pub input_kind: &'static str,
    pub input_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub game_profile: Option<GameProfileSummary>,
    pub verdict: &'static str,
    pub complete: bool,
    pub analysis_completeness: AnalysisCompleteness,
    pub disposition: ThreatDisposition,
    pub threat_families: Vec<ThreatFamilyMatch>,
    pub chunks_seen: usize,
    pub chunks_scanned: usize,
    pub chunks_skipped_for_size: usize,
    pub files_seen: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub artifacts: Vec<Artifact>,
    pub findings: Vec<Finding>,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Artifact {
    pub location: String,
    pub kind: &'static str,
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub markers: BTreeSet<&'static str>,
    pub evidence: Vec<MarkerEvidence>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct MarkerEvidence {
    pub marker: &'static str,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub byte_offset: Option<u64>,
    pub encoding: &'static str,
}

impl MarkerEvidence {
    pub fn observed(
        marker: &'static str,
        value: String,
        byte_offset: usize,
        encoding: &'static str,
    ) -> Self {
        Self {
            marker,
            value,
            byte_offset: Some(byte_offset as u64),
            encoding,
        }
    }

    pub fn metadata(marker: &'static str, value: impl Into<String>) -> Self {
        Self {
            marker,
            value: value.into(),
            byte_offset: None,
            encoding: "metadata",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub severity: &'static str,
    pub blocking: bool,
    pub location: String,
    pub evidence: Vec<MarkerEvidence>,
}

impl Finding {
    pub fn new(
        rule_id: &'static str,
        title: &'static str,
        category: &'static str,
        severity: &'static str,
        blocking: bool,
        location: String,
        evidence: Vec<MarkerEvidence>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(rule_id.as_bytes());
        hasher.update([0]);
        hasher.update(location.as_bytes());
        let digest = hex::encode(hasher.finalize());
        Self {
            id: format!("{}-{}", rule_id.to_ascii_lowercase(), &digest[..16]),
            rule_id,
            title,
            category,
            severity,
            blocking,
            location,
            evidence,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AnalysisCompleteness {
    pub status: &'static str,
    pub is_complete: bool,
    pub review_recommended: bool,
    pub reasons: Vec<CompletenessReason>,
}

#[derive(Clone, Debug, Serialize)]
pub struct CompletenessReason {
    pub reason_id: &'static str,
    pub phase: &'static str,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ThreatDisposition {
    pub classification: &'static str,
    pub headline: &'static str,
    pub summary: String,
    pub blocking_recommended: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_threat_family_id: Option<&'static str>,
    pub related_finding_ids: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ThreatFamilyMatch {
    pub family_id: &'static str,
    pub variant_id: &'static str,
    pub display_name: &'static str,
    pub summary: &'static str,
    pub match_kind: &'static str,
    pub confidence: f64,
    pub exact_hash_match: bool,
    pub matched_rules: Vec<&'static str>,
    pub evidence: Vec<ThreatFamilyEvidence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ThreatFamilyEvidence {
    pub kind: &'static str,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

#[derive(Default)]
pub struct ScanCounts {
    pub chunks_seen: usize,
    pub chunks_scanned: usize,
    pub chunks_skipped_for_size: usize,
    pub files_seen: usize,
    pub files_scanned: usize,
    pub files_skipped: usize,
}
