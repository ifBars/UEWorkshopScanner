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
