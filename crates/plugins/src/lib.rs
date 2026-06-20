use wiresurge_core::{json_array, json_object, json_string};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginCapability {
    pub name: String,
    pub granted_by_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
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

    pub fn to_json(&self) -> String {
        let capabilities = self
            .capabilities
            .iter()
            .map(|capability| {
                json_object(&[
                    ("name", json_string(&capability.name)),
                    (
                        "granted_by_default",
                        capability.granted_by_default.to_string(),
                    ),
                ])
            })
            .collect::<Vec<_>>();
        json_object(&[
            ("id", json_string(&self.id)),
            ("name", json_string(&self.name)),
            ("version", json_string(&self.version)),
            ("capabilities", json_array(&capabilities)),
        ])
    }
}
