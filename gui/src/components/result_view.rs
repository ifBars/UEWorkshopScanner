use crate::{
    scanner::reveal_report,
    state::ScanState,
    view_model::{PlayerVerdict, player_verdict},
};
use dioxus::prelude::*;

#[component]
pub fn ResultView(scan_state: Signal<ScanState>) -> Element {
    match &*scan_state.read() {
        ScanState::Ready => rsx! {
            div { class: "ready-note",
                svg {
                    width: "18",
                    height: "18",
                    view_box: "0 0 24 24",
                    fill: "none",
                    stroke: "currentColor",
                    stroke_width: "1.8",
                    circle { cx: "12", cy: "12", r: "9" }
                    path { d: "M12 11v5" }
                    path { d: "M12 8h.01" }
                }
                p {
                    strong { "Your map stays private. " }
                    "The scanner checks it on this computer and does not upload or run its contents."
                }
            }
        },
        ScanState::Running => rsx! {
            section { class: "result-card scanning",
                div { class: "large-spinner" }
                h2 { "Checking the map" }
                p { "This can take a little while for larger Workshop maps." }
                small { "Don't load the map until the scan finishes." }
            }
        },
        ScanState::Error(error) => rsx! {
            section { class: "result-card error",
                ResultIcon { verdict: PlayerVerdict::Incomplete }
                p { class: "result-label", "SCAN INCOMPLETE" }
                h2 { "We couldn't check this map" }
                p { class: "result-message",
                    "Don't load it yet. Try again, or ask for help if the problem continues."
                }
                details { class: "technical-details",
                    summary { "Show error details" }
                    pre { "{error}" }
                }
            }
        },
        ScanState::Complete(outcome) => {
            let verdict = player_verdict(&outcome.report);
            let report_path = outcome.report_path.clone();
            let reasons = outcome
                .report
                .threat_families
                .iter()
                .map(|family| family.display_name.to_owned())
                .chain(
                    outcome
                        .report
                        .findings
                        .iter()
                        .map(|finding| finding.title.to_owned()),
                )
                .collect::<Vec<_>>();

            rsx! {
                section { class: "result-card {verdict.css_class()}",
                    ResultIcon { verdict }
                    p { class: "result-label",
                        match verdict {
                            PlayerVerdict::Allow => "SCAN FINISHED",
                            PlayerVerdict::Review => "NEEDS REVIEW",
                            PlayerVerdict::Block => "THREAT DETECTED",
                            PlayerVerdict::Incomplete => "SCAN INCOMPLETE",
                        }
                    }
                    h2 { "{verdict.label()}" }
                    p { class: "result-message", "{verdict.action()}" }

                    if !reasons.is_empty() {
                        div { class: "reason-box",
                            h3 { "Why this result?" }
                            ul {
                                for reason in reasons.iter().take(5) {
                                    li { "{reason}" }
                                }
                            }
                        }
                    }

                    if verdict == PlayerVerdict::Incomplete
                        && !outcome.report.analysis_completeness.reasons.is_empty()
                    {
                        div { class: "reason-box",
                            h3 { "What went wrong?" }
                            ul {
                                for reason in &outcome.report.analysis_completeness.reasons {
                                    li { "{reason.summary}" }
                                }
                            }
                        }
                    }

                    button {
                        class: "button secondary report-button",
                        onclick: move |_| {
                            if let Err(error) = reveal_report(&report_path) {
                                tracing::warn!(%error, "could not reveal report");
                            }
                        },
                        "Open saved report"
                    }

                    details { class: "technical-details",
                        summary { "Technical details" }
                        div { class: "technical-grid",
                            span { "Scanner verdict" }
                            code { "{outcome.report.verdict}" }
                            span { "Scan complete" }
                            code { "{outcome.report.complete}" }
                            span { "Findings" }
                            code { "{outcome.report.findings.len()}" }
                            span { "Report format" }
                            code { "v{outcome.report.schema_version}" }
                        }
                        if !outcome.report.findings.is_empty() {
                            div { class: "technical-list",
                                for finding in &outcome.report.findings {
                                    p {
                                        strong { "{finding.rule_id}" }
                                        " — {finding.severity} — {finding.location}"
                                    }
                                }
                            }
                        }
                        code { class: "report-path", "{outcome.report_path.display()}" }
                    }
                }
            }
        }
    }
}

#[component]
fn ResultIcon(verdict: PlayerVerdict) -> Element {
    let path = match verdict {
        PlayerVerdict::Allow => "M8 12l2.5 2.5L16.5 8",
        PlayerVerdict::Review => "M12 8v5m0 3h.01",
        PlayerVerdict::Block | PlayerVerdict::Incomplete => "M8 8l8 8m0-8-8 8",
    };

    rsx! {
        div { class: "result-icon",
            svg {
                width: "32",
                height: "32",
                view_box: "0 0 24 24",
                fill: "none",
                stroke: "currentColor",
                stroke_width: "1.8",
                path { d: "M12 3l7 3v5c0 4.7-2.8 8.2-7 10-4.2-1.8-7-5.3-7-10V6l7-3z" }
                path { d: "{path}" }
            }
        }
    }
}
