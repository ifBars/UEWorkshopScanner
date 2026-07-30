use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const MECCHA_CHAMELEON: &str = include_str!("../game-profiles/meccha-chameleon.json");

/// Declarative information needed to discover and integrate with a supported game.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GameProfile {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub steam_app_id: u32,
    pub unreal_engine: String,
    pub container_extensions: Vec<String>,
    pub integration: String,
}

/// Stable game identity included in each profile-aware scan report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct GameProfileSummary {
    pub id: String,
    pub name: String,
    pub steam_app_id: u32,
}

impl From<&GameProfile> for GameProfileSummary {
    fn from(profile: &GameProfile) -> Self {
        Self {
            id: profile.id.clone(),
            name: profile.name.clone(),
            steam_app_id: profile.steam_app_id,
        }
    }
}

/// Returns every game profile embedded in this build.
pub fn built_in_game_profiles() -> Result<Vec<GameProfile>> {
    Ok(vec![serde_json::from_str(MECCHA_CHAMELEON).context(
        "embedded Meccha Chameleon game profile is invalid",
    )?])
}

/// Finds an embedded game profile by its stable identifier.
pub fn game_profile(id: &str) -> Result<Option<GameProfile>> {
    Ok(built_in_game_profiles()?
        .into_iter()
        .find(|profile| profile.id == id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meccha_profile_has_the_expected_steam_identity() {
        let profile = game_profile("meccha-chameleon").unwrap().unwrap();

        assert_eq!(profile.steam_app_id, 4_704_690);
        assert_eq!(profile.unreal_engine, "5.6");
        assert!(profile.container_extensions.contains(&"utoc".to_owned()));
    }
}
