//! Binary-distribution licensing helpers for player-facing integrations.

use anyhow::Result;

/// The complete terms governing builds that bundle Epic Games Licensed
/// Technology.
pub fn binary_eula_text() -> &'static str {
    crate::oodle::binary_eula_text()
}

/// Returns whether the current user has accepted the current bundled-binary
/// EULA version.
pub fn bundled_eula_is_accepted() -> Result<bool> {
    crate::oodle::bundled_eula_is_accepted()
}

/// Records explicit acceptance of the bundled-binary EULA and verifies the
/// approved Oodle decoder beside the current executable.
pub fn accept_bundled_eula() -> Result<()> {
    crate::oodle::accept_bundled_eula()
}
