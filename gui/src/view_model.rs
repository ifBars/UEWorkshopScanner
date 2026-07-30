use ue_workshop_scanner::model::Report;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlayerVerdict {
    Allow,
    Review,
    Block,
    Incomplete,
}

impl PlayerVerdict {
    pub fn label(self) -> &'static str {
        match self {
            Self::Allow => "No known threat detected",
            Self::Review => "Review this map",
            Self::Block => "Do not load this map",
            Self::Incomplete => "Scan could not finish",
        }
    }

    pub fn action(self) -> &'static str {
        match self {
            Self::Allow => {
                "No current rule matched. This reduces risk, but it does not prove the map is safe."
            }
            Self::Review => "Do not load the map until its findings have been reviewed.",
            Self::Block => "Keep the map blocked and unsubscribe from it.",
            Self::Incomplete => {
                "Treat the map as blocked because the scanner could not inspect everything."
            }
        }
    }

    pub fn css_class(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Review => "review",
            Self::Block => "block",
            Self::Incomplete => "incomplete",
        }
    }
}

pub fn player_verdict(report: &Report) -> PlayerVerdict {
    classify_player_verdict(report.verdict, report.complete)
}

fn classify_player_verdict(verdict: &str, complete: bool) -> PlayerVerdict {
    match (verdict, complete) {
        ("allow", true) => PlayerVerdict::Allow,
        ("review", true) => PlayerVerdict::Review,
        ("block", _) => PlayerVerdict::Block,
        _ => PlayerVerdict::Incomplete,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requires_a_complete_allow_report() {
        assert_eq!(classify_player_verdict("allow", true), PlayerVerdict::Allow);
        assert_eq!(
            classify_player_verdict("allow", false),
            PlayerVerdict::Incomplete
        );
    }

    #[test]
    fn maps_review_and_block_without_severity_guessing() {
        assert_eq!(
            classify_player_verdict("review", true),
            PlayerVerdict::Review
        );
        assert_eq!(classify_player_verdict("block", true), PlayerVerdict::Block);
    }
}
