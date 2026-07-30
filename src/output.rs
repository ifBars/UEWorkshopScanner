use crate::model::{Finding, Report};
use anyhow::{Result, bail};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write,
};

/// Supported command-line report formats.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum OutputFormat {
    #[default]
    Json,
    Summary,
}

impl OutputFormat {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "summary" | "simple" | "text" => Ok(Self::Summary),
            _ => bail!("unknown output format: {value}; expected json or summary"),
        }
    }
}

/// Formats a compact, human-readable decision without discarding verdict or
/// completeness information.
pub fn format_summary(report: &Report) -> String {
    let mut output = String::new();
    let block = if report.disposition.blocking_recommended {
        "yes"
    } else {
        "no"
    };
    let complete = if report.complete { "yes" } else { "no" };

    writeln!(output, "block: {block}").expect("writing to a String cannot fail");
    writeln!(output, "verdict: {}", report.verdict).expect("writing to a String cannot fail");
    writeln!(output, "complete: {complete}").expect("writing to a String cannot fail");
    writeln!(output, "message: {}", report.disposition.headline)
        .expect("writing to a String cannot fail");
    if let Some(family) = report.disposition.primary_threat_family_id {
        writeln!(output, "threat family: {family}").expect("writing to a String cannot fail");
    }

    write_rules(&mut output, &report.findings);
    if !report.analysis_completeness.reasons.is_empty() {
        writeln!(output, "analysis issues:").expect("writing to a String cannot fail");
        for reason in &report.analysis_completeness.reasons {
            write!(output, "- {}: {}", reason.reason_id, reason.summary)
                .expect("writing to a String cannot fail");
            if let Some(location) = &reason.location {
                write!(output, " ({location})").expect("writing to a String cannot fail");
            }
            output.push('\n');
        }
    }
    output
}

fn write_rules(output: &mut String, findings: &[Finding]) {
    let mut rules = BTreeMap::<&str, (&str, &str, BTreeSet<&str>)>::new();
    for finding in findings {
        let entry = rules.entry(finding.rule_id).or_insert((
            finding.title,
            finding.severity,
            BTreeSet::new(),
        ));
        entry.2.insert(&finding.location);
    }

    if rules.is_empty() {
        output.push_str("rules triggered: none\n");
        return;
    }

    writeln!(output, "rules triggered: {}", rules.len()).expect("writing to a String cannot fail");
    for (rule_id, (title, severity, locations)) in rules {
        writeln!(output, "- {rule_id} [{severity}] {title}")
            .expect("writing to a String cannot fail");
        for location in locations {
            writeln!(output, "  location: {location}").expect("writing to a String cannot fail");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AnalysisCompleteness, ThreatDisposition};

    fn report(verdict: &'static str, blocking: bool, complete: bool) -> Report {
        Report {
            schema_version: 1,
            scanner: "ue-workshop-scanner",
            version: "test",
            retoc_revision: "test",
            input: "fixture".to_owned(),
            input_kind: "directory",
            input_sha256: None,
            game_profile: None,
            verdict,
            complete,
            analysis_completeness: AnalysisCompleteness {
                status: if complete { "Complete" } else { "Incomplete" },
                is_complete: complete,
                review_recommended: !complete,
                reasons: Vec::new(),
            },
            disposition: ThreatDisposition {
                classification: if blocking { "Suspicious" } else { "Clean" },
                headline: if blocking {
                    "Blocking recommended"
                } else {
                    "No known threats detected"
                },
                summary: "test".to_owned(),
                blocking_recommended: blocking,
                primary_threat_family_id: None,
                related_finding_ids: Vec::new(),
            },
            threat_families: Vec::new(),
            chunks_seen: 0,
            chunks_scanned: 0,
            chunks_skipped_for_size: 0,
            files_seen: 0,
            files_scanned: 0,
            files_skipped: 0,
            artifacts: Vec::new(),
            findings: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn accepts_friendly_summary_aliases() {
        assert_eq!(
            OutputFormat::parse("summary").unwrap(),
            OutputFormat::Summary
        );
        assert_eq!(
            OutputFormat::parse("simple").unwrap(),
            OutputFormat::Summary
        );
        assert_eq!(OutputFormat::parse("text").unwrap(), OutputFormat::Summary);
        assert_eq!(OutputFormat::parse("json").unwrap(), OutputFormat::Json);
    }

    #[test]
    fn groups_duplicate_rule_matches_and_lists_each_location() {
        let findings = vec![
            Finding::new(
                "UWS108",
                "Dropper chain",
                "execution",
                "critical",
                true,
                "first.uasset".to_owned(),
                vec!["inert marker"],
            ),
            Finding::new(
                "UWS108",
                "Dropper chain",
                "execution",
                "critical",
                true,
                "second.uasset".to_owned(),
                vec!["inert marker"],
            ),
        ];
        let mut output = String::new();

        write_rules(&mut output, &findings);

        assert!(output.contains("rules triggered: 1"));
        assert!(output.contains("- UWS108 [critical] Dropper chain"));
        assert!(output.contains("location: first.uasset"));
        assert!(output.contains("location: second.uasset"));
    }

    #[test]
    fn renders_the_final_blocking_recommendation() {
        let allow = format_summary(&report("allow", false, true));
        let incomplete = format_summary(&report("incomplete", true, false));

        assert!(allow.starts_with("block: no\nverdict: allow\ncomplete: yes\n"));
        assert!(allow.contains("rules triggered: none"));
        assert!(incomplete.starts_with("block: yes\nverdict: incomplete\ncomplete: no\n"));
    }
}
