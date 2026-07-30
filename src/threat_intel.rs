use crate::model::{
    AnalysisCompleteness, Finding, ThreatDisposition, ThreatFamilyEvidence, ThreatFamilyMatch,
};
use std::collections::{BTreeSet, HashMap};

pub fn classify_families(findings: &[Finding]) -> Vec<ThreatFamilyMatch> {
    let by_location = findings.iter().fold(
        HashMap::<&str, BTreeSet<&str>>::new(),
        |mut grouped, finding| {
            grouped
                .entry(&finding.location)
                .or_default()
                .insert(finding.rule_id);
            grouped
        },
    );

    let mut matches = Vec::new();
    for (location, rules) in by_location {
        let variant = if rules.contains("UWS108") {
            Some((
                "blueprint-user-write-shell-download",
                0.99,
                vec!["UWS103", "UWS104", "UWS108"],
            ))
        } else if rules.contains("UWS105") && rules.contains("UWS104") {
            Some((
                "json-batch-polyglot-dropper",
                0.97,
                vec!["UWS104", "UWS105"],
            ))
        } else if rules.contains("UWS102")
            && findings
                .iter()
                .any(|finding| finding.location == location && finding.blocking)
        {
            Some(("launch-url-local-script", 0.94, vec!["UWS102"]))
        } else if rules.contains("UWS109") || rules.contains("UWS113") {
            let matched = ["UWS109", "UWS113"]
                .into_iter()
                .filter(|rule| rules.contains(rule))
                .collect();
            Some(("encoded-powershell-dropper", 0.95, matched))
        } else if rules.contains("UWS110") || rules.contains("UWS112") {
            let matched = ["UWS110", "UWS112"]
                .into_iter()
                .filter(|rule| rules.contains(rule))
                .collect();
            Some(("lolbin-script-host-dropper", 0.93, matched))
        } else {
            None
        };

        if let Some((variant_id, confidence, matched_rules)) = variant {
            matches.push(ThreatFamilyMatch {
                family_id: "meccha-workshop-dropper",
                variant_id,
                display_name: "Meccha Chameleon Workshop Dropper",
                summary: "Cooked Workshop content stages or launches an external Windows payload.",
                match_kind: "BehaviorVariant",
                confidence,
                exact_hash_match: false,
                evidence: matched_rules
                    .iter()
                    .map(|rule_id| ThreatFamilyEvidence {
                        kind: "rule",
                        value: format!("{rule_id} matched at {location}"),
                        rule_id: Some(*rule_id),
                        location: Some(location.to_owned()),
                    })
                    .collect(),
                matched_rules,
            });
        }
    }

    matches.sort_by(|left, right| {
        right
            .confidence
            .total_cmp(&left.confidence)
            .then_with(|| left.variant_id.cmp(right.variant_id))
    });
    matches.dedup_by(|left, right| {
        left.family_id == right.family_id && left.variant_id == right.variant_id
    });
    matches
}

pub fn classify_disposition(
    findings: &[Finding],
    families: &[ThreatFamilyMatch],
    completeness: &AnalysisCompleteness,
) -> ThreatDisposition {
    if let Some(family) = families.first() {
        let matched_rules = family
            .matched_rules
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        return ThreatDisposition {
            classification: "KnownThreat",
            headline: "Likely malware detected",
            summary: format!(
                "The content matches the analyzed behavior family \"{}\".",
                family.display_name
            ),
            blocking_recommended: true,
            primary_threat_family_id: Some(family.family_id),
            related_finding_ids: findings
                .iter()
                .filter(|finding| matched_rules.contains(finding.rule_id))
                .map(|finding| finding.id.clone())
                .collect(),
        };
    }

    let blocking = findings
        .iter()
        .filter(|finding| finding.blocking)
        .collect::<Vec<_>>();
    if !blocking.is_empty() {
        return ThreatDisposition {
            classification: "Suspicious",
            headline: "Suspicious behavior detected",
            summary:
                "High-confidence correlated behavior was detected, but no named threat family matched."
                    .to_owned(),
            blocking_recommended: true,
            primary_threat_family_id: None,
            related_finding_ids: blocking
                .iter()
                .map(|finding| finding.id.clone())
                .collect(),
        };
    }

    if !completeness.is_complete {
        return ThreatDisposition {
            classification: "ManualReviewRequired",
            headline: "Manual review required",
            summary: "Analysis did not complete enough to support a clean verdict.".to_owned(),
            blocking_recommended: true,
            primary_threat_family_id: None,
            related_finding_ids: Vec::new(),
        };
    }

    if !findings.is_empty() {
        return ThreatDisposition {
            classification: "Suspicious",
            headline: "Suspicious behavior detected",
            summary: "Dual-use behavior requires review before the content is trusted.".to_owned(),
            blocking_recommended: false,
            primary_threat_family_id: None,
            related_finding_ids: findings.iter().map(|finding| finding.id.clone()).collect(),
        };
    }

    ThreatDisposition {
        classification: "Clean",
        headline: "No known threats detected",
        summary: "No known threat family or correlated suspicious behavior matched.".to_owned(),
        blocking_recommended: false,
        primary_threat_family_id: None,
        related_finding_ids: Vec::new(),
    }
}

pub fn verdict_for(
    disposition: &ThreatDisposition,
    completeness: &AnalysisCompleteness,
) -> &'static str {
    match disposition.classification {
        "KnownThreat" => "block",
        "Suspicious" if disposition.blocking_recommended => "block",
        "Suspicious" => "review",
        "ManualReviewRequired" => "incomplete",
        "Clean" if completeness.is_complete => "allow",
        _ => "incomplete",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CompletenessReason, Finding};

    fn complete() -> AnalysisCompleteness {
        AnalysisCompleteness {
            status: "Complete",
            is_complete: true,
            review_recommended: false,
            reasons: Vec::new(),
        }
    }

    #[test]
    fn dropper_rule_becomes_named_family_and_known_threat() {
        let finding = Finding::new(
            "UWS108",
            "dropper",
            "threat-family",
            "critical",
            true,
            "BP_Dropper.uasset".to_owned(),
            vec!["downloader"],
        );
        let families = classify_families(std::slice::from_ref(&finding));
        let disposition =
            classify_disposition(std::slice::from_ref(&finding), &families, &complete());

        assert_eq!(families[0].family_id, "meccha-workshop-dropper");
        assert_eq!(disposition.classification, "KnownThreat");
        assert_eq!(verdict_for(&disposition, &complete()), "block");
    }

    #[test]
    fn incomplete_clean_scan_requires_review() {
        let incomplete = AnalysisCompleteness {
            status: "Incomplete",
            is_complete: false,
            review_recommended: true,
            reasons: vec![CompletenessReason {
                reason_id: "chunk-skipped",
                phase: "container-read",
                summary: "chunk skipped".to_owned(),
                location: None,
            }],
        };
        let disposition = classify_disposition(&[], &[], &incomplete);
        assert_eq!(disposition.classification, "ManualReviewRequired");
        assert_eq!(verdict_for(&disposition, &incomplete), "incomplete");
    }
}
