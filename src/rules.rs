use crate::model::{Artifact, Finding};

pub fn evaluate_artifact(artifact: &Artifact) -> Vec<Finding> {
    let has = |name| artifact.markers.contains(name);
    let execution_context =
        has("auto-execution") || has("file-write") || has("dangerous-extension");
    let mut findings = Vec::new();
    let mut add = |rule_id, title, category, severity, blocking, evidence: Vec<&'static str>| {
        findings.push(Finding::new(
            rule_id,
            title,
            category,
            severity,
            blocking,
            artifact.location.clone(),
            evidence,
        ));
    };

    if has("historical-rce-name") {
        add(
            "UWS101",
            "Historical RCE test name retained in cooked asset metadata",
            "indicator",
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
            "execution",
            if dangerous { "critical" } else { "high" },
            dangerous,
            vec!["auto-execution", "launch-url"],
        );
    }
    if has("auto-execution") && has("user-directory") && has("file-write") {
        add(
            "UWS103",
            "Automatic Blueprint logic writes outside the game content area",
            "staging",
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
            "download-execute",
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
            "obfuscation",
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
            "execution",
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
            "network",
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
            "threat-family",
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
    if has("process-shell") && has("encoded-command") && execution_context {
        add(
            "UWS109",
            "Encoded command reaches a shell execution path",
            "obfuscation",
            "critical",
            true,
            vec!["process-shell", "encoded-command"],
        );
    }
    if has("lolbin") && has("external-url") && execution_context {
        add(
            "UWS110",
            "Windows living-off-the-land binary reaches an external endpoint",
            "download-execute",
            "critical",
            true,
            vec!["lolbin", "external-url"],
        );
    }
    if has("base64-decode") && has("process-shell") && execution_context {
        add(
            "UWS111",
            "Base64 decoding is correlated with shell execution",
            "obfuscation",
            "critical",
            true,
            vec!["base64-decode", "process-shell"],
        );
    }
    if has("script-host") && has("script-extension") && execution_context {
        add(
            "UWS112",
            "Windows Script Host execution chain",
            "execution",
            "critical",
            true,
            vec!["script-host", "script-extension"],
        );
    }
    if has("process-shell")
        && has("downloader")
        && has("policy-bypass")
        && (execution_context || has("hidden-execution"))
    {
        add(
            "UWS113",
            "PowerShell policy bypass in a download-and-execute chain",
            "download-execute",
            "critical",
            true,
            vec!["process-shell", "downloader", "policy-bypass"],
        );
    }
    if has("raw-ip-url") && has("downloader") && (has("process-shell") || has("lolbin")) {
        add(
            "UWS114",
            "Downloader uses a raw IP payload endpoint",
            "network",
            "critical",
            execution_context,
            vec!["raw-ip-url", "downloader"],
        );
    }
    if artifact.kind == "loose-file" && has("dangerous-extension") {
        add(
            "UWS200",
            "Executable or script file is present directly in Workshop content",
            "file",
            "critical",
            true,
            vec!["dangerous-extension"],
        );
    }
    if artifact.kind == "loose-file" && has("disguised-executable") {
        add(
            "UWS201",
            "Portable executable content is disguised with a non-executable extension",
            "file",
            "critical",
            true,
            vec!["disguised-executable"],
        );
    }
    if artifact.kind == "loose-file"
        && has("process-shell")
        && has("downloader")
        && has("external-url")
        && !has("dangerous-extension")
    {
        add(
            "UWS202",
            "Loose file contains a shell download-and-execute chain",
            "download-execute",
            "high",
            false,
            vec!["process-shell", "downloader", "external-url"],
        );
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn artifact(markers: &[&'static str]) -> Artifact {
        Artifact {
            location: "BP_Fixture.uasset".to_owned(),
            kind: "iostore-chunk",
            size: 1,
            sha256: None,
            markers: markers.iter().copied().collect::<BTreeSet<_>>(),
        }
    }

    #[test]
    fn complete_dropper_chain_blocks() {
        let findings = evaluate_artifact(&artifact(&[
            "auto-execution",
            "user-directory",
            "file-write",
            "process-shell",
            "downloader",
        ]));
        assert!(
            findings
                .iter()
                .any(|finding| finding.rule_id == "UWS108" && finding.blocking)
        );
    }

    #[test]
    fn encoded_shell_requires_execution_context() {
        let text_only = evaluate_artifact(&artifact(&["process-shell", "encoded-command"]));
        assert!(!text_only.iter().any(|finding| finding.rule_id == "UWS109"));

        let active = evaluate_artifact(&artifact(&[
            "auto-execution",
            "process-shell",
            "encoded-command",
        ]));
        assert!(
            active
                .iter()
                .any(|finding| finding.rule_id == "UWS109" && finding.blocking)
        );
    }

    #[test]
    fn ordinary_begin_play_is_not_a_finding() {
        assert!(evaluate_artifact(&artifact(&["auto-execution"])).is_empty());
    }

    #[test]
    fn documentation_is_not_a_blocking_chain() {
        let findings =
            evaluate_artifact(&artifact(&["process-shell", "downloader", "external-url"]));
        assert!(findings.iter().all(|finding| !finding.blocking));
    }
}
