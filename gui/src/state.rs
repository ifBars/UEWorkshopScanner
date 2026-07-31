use crate::scanner::ScanOutcome;

#[derive(Clone)]
pub enum SetupState {
    Ready,
    EulaRequired,
    Accepting,
    Error(String),
}

impl SetupState {
    pub fn initial() -> Self {
        match ue_workshop_scanner::licensing::bundled_eula_is_accepted() {
            Ok(true) => Self::Ready,
            Ok(false) => Self::EulaRequired,
            Err(error) => Self::Error(error.to_string()),
        }
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[derive(Clone, Default)]
pub enum ScanState {
    #[default]
    Ready,
    Running,
    Complete(Box<ScanOutcome>),
    Error(String),
}

impl ScanState {
    pub fn shows_picker(&self) -> bool {
        matches!(self, Self::Ready)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picker_is_only_visible_before_a_scan() {
        assert!(ScanState::Ready.shows_picker());
        assert!(!ScanState::Running.shows_picker());
        assert!(!ScanState::Error("test".to_owned()).shows_picker());
    }
}
