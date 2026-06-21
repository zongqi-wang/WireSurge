use serde::Serialize;
use wiresurge_core::{Result, serialize_json};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginCapability {
    pub name: String,
    pub granted_by_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PluginManifestDraft {
    pub id: String,
    pub name: String,
    pub version: String,
    pub capabilities: Vec<PluginCapability>,
}

impl PluginManifestDraft {
    pub fn example() -> Self {
        Self {
            id: "example.generator".to_string(),
            name: "Example Generator".to_string(),
            version: "0.1.0".to_string(),
            capabilities: vec![
                PluginCapability {
                    name: "deterministic-random".to_string(),
                    granted_by_default: true,
                },
                PluginCapability {
                    name: "filesystem".to_string(),
                    granted_by_default: false,
                },
                PluginCapability {
                    name: "network".to_string(),
                    granted_by_default: false,
                },
                PluginCapability {
                    name: "keychain".to_string(),
                    granted_by_default: false,
                },
            ],
        }
    }

    pub fn to_json(&self) -> Result<String> {
        serialize_json(self)
    }
}
