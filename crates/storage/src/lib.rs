use std::fs;
use std::path::{Path, PathBuf};

use wiresurge_core::{RequestSpec, Result, WireSurgeError, serialize_json};
use wiresurge_metrics::{ReportSummary, RunnerStats};

#[derive(Debug, Clone)]
pub struct WorkspaceStore {
    root: PathBuf,
}

impl WorkspaceStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn metadata_dir(&self) -> PathBuf {
        self.root.join(".wiresurge")
    }

    pub fn init(&self) -> Result<()> {
        fs::create_dir_all(self.requests_dir())?;
        fs::create_dir_all(self.reports_dir())?;
        fs::create_dir_all(self.runners_dir())?;
        fs::create_dir_all(self.metadata_dir().join("environments"))?;
        let workspace = self.metadata_dir().join("workspace.yaml");
        if !workspace.exists() {
            fs::write(workspace, "name: \"WireSurge Workspace\"\nversion: 1\n")?;
        }
        Ok(())
    }

    pub fn exists(&self) -> bool {
        self.metadata_dir().join("workspace.yaml").exists()
    }

    pub fn workspace_json(&self) -> Result<String> {
        if !self.exists() {
            return Err(WireSurgeError::new(
                "workspace_not_found",
                "no .wiresurge workspace found",
            )
            .with_hint("Run `wiresurge workspace init` first."));
        }
        serialize_json(&serde_json::json!({
            "root": self.root.display().to_string(),
            "metadata_dir": self.metadata_dir().display().to_string(),
            "exists": true,
        }))
    }

    pub fn create_request(&self, request: &RequestSpec) -> Result<()> {
        self.ensure_workspace()?;
        fs::write(self.request_path(&request.id), request.to_yaml()?)?;
        Ok(())
    }

    pub fn update_request(&self, id: &str, request: &RequestSpec) -> Result<()> {
        self.ensure_workspace()?;
        let path = self.request_path(id);
        if !path.exists() {
            return Err(WireSurgeError::new(
                "request_not_found",
                format!("request '{id}' was not found"),
            )
            .at("id"));
        }
        let mut updated = request.clone();
        updated.id = id.to_string();
        fs::write(path, updated.to_yaml()?)?;
        Ok(())
    }

    pub fn delete_request(&self, id: &str) -> Result<()> {
        self.ensure_workspace()?;
        let path = self.request_path(id);
        if !path.exists() {
            return Err(WireSurgeError::new(
                "request_not_found",
                format!("request '{id}' was not found"),
            )
            .at("id"));
        }
        fs::remove_file(path)?;
        Ok(())
    }

    pub fn load_request(&self, id: &str) -> Result<RequestSpec> {
        self.ensure_workspace()?;
        let path = self.request_path(id);
        let input = fs::read_to_string(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                WireSurgeError::new("request_not_found", format!("request '{id}' was not found"))
                    .at("id")
            } else {
                error.into()
            }
        })?;
        RequestSpec::from_yaml(&input)
    }

    pub fn list_requests(&self) -> Result<Vec<RequestSpec>> {
        self.ensure_workspace()?;
        let mut requests = Vec::new();
        if !self.requests_dir().exists() {
            return Ok(requests);
        }
        for entry in fs::read_dir(self.requests_dir())? {
            let entry = entry?;
            if entry
                .path()
                .extension()
                .and_then(|extension| extension.to_str())
                == Some("yaml")
            {
                let input = fs::read_to_string(entry.path())?;
                requests.push(RequestSpec::from_yaml(&input)?);
            }
        }
        requests.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(requests)
    }

    pub fn write_runner_snapshot(&self, stats: &RunnerStats) -> Result<()> {
        self.ensure_workspace()?;
        fs::create_dir_all(self.runners_dir())?;
        fs::write(
            self.runners_dir().join(format!("{}.json", stats.id)),
            stats.to_json()?,
        )?;
        Ok(())
    }

    pub fn runner_entries_json(&self) -> Result<String> {
        self.ensure_workspace()?;
        let mut entries = Vec::new();
        if self.runners_dir().exists() {
            for entry in fs::read_dir(self.runners_dir())? {
                let entry = entry?;
                if entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    == Some("json")
                {
                    entries.push(parse_stored_json(&fs::read_to_string(entry.path())?)?);
                }
            }
        }
        entries.sort_by_key(serde_json::Value::to_string);
        serialize_json(&entries)
    }

    pub fn write_report(
        &self,
        report_dir: &Path,
        summary: &ReportSummary,
        details_json: &str,
    ) -> Result<()> {
        self.ensure_workspace()?;
        fs::create_dir_all(report_dir)?;
        let summary_json = summary.to_json()?;
        fs::write(report_dir.join("summary.json"), &summary_json)?;
        fs::write(report_dir.join("details.json"), details_json)?;
        fs::write(
            report_dir.join("index.html"),
            report_html(summary, &summary_json, details_json),
        )?;
        fs::create_dir_all(self.reports_dir())?;
        let canonical_dir = report_dir
            .canonicalize()
            .unwrap_or_else(|_| report_dir.to_path_buf());
        fs::write(
            self.reports_dir().join(format!("{}.json", summary.id)),
            &summary_json,
        )?;
        fs::write(
            self.reports_dir().join(format!("{}.path", summary.id)),
            canonical_dir.display().to_string(),
        )?;
        Ok(())
    }

    pub fn report_entries_json(&self) -> Result<String> {
        self.ensure_workspace()?;
        let mut entries = Vec::new();
        if self.reports_dir().exists() {
            for entry in fs::read_dir(self.reports_dir())? {
                let entry = entry?;
                if entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    == Some("json")
                {
                    entries.push(parse_stored_json(&fs::read_to_string(entry.path())?)?);
                }
            }
        }
        entries.sort_by_key(serde_json::Value::to_string);
        serialize_json(&entries)
    }

    pub fn load_report_summary(&self, id: &str) -> Result<String> {
        self.ensure_workspace()?;
        let path = self.reports_dir().join(format!("{id}.json"));
        fs::read_to_string(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                WireSurgeError::new("report_not_found", format!("report '{id}' was not found"))
                    .at("id")
            } else {
                error.into()
            }
        })
    }

    fn ensure_workspace(&self) -> Result<()> {
        if self.exists() {
            Ok(())
        } else {
            Err(
                WireSurgeError::new("workspace_not_found", "no .wiresurge workspace found")
                    .with_hint("Run `wiresurge workspace init` first."),
            )
        }
    }

    fn request_path(&self, id: &str) -> PathBuf {
        self.requests_dir().join(format!("{id}.yaml"))
    }

    fn requests_dir(&self) -> PathBuf {
        self.metadata_dir().join("requests")
    }

    fn reports_dir(&self) -> PathBuf {
        self.metadata_dir().join("reports")
    }

    fn runners_dir(&self) -> PathBuf {
        self.metadata_dir().join("runners")
    }
}

fn report_html(summary: &ReportSummary, summary_json: &str, details_json: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>WireSurge Report {id}</title>
  <style type="text/css">
    body {{ font-family: system-ui, sans-serif; margin: 40px; line-height: 1.5; color: #17202a; }}
    pre {{ background: #eef2f6; padding: 16px; overflow: auto; border-radius: 8px; }}
  </style>
</head>
<body>
  <h1>WireSurge Report {id}</h1>
  <p>Status: <strong>{status}</strong></p>
  <p>Duration: {duration:.3} ms</p>
  <h2>Summary</h2>
  <pre>{summary}</pre>
  <h2>Details</h2>
  <pre>{details}</pre>
</body>
</html>"#,
        id = summary.id,
        status = summary.status,
        duration = summary.duration_ms,
        summary = html_escape(summary_json),
        details = html_escape(details_json),
    )
}

fn parse_stored_json(input: &str) -> Result<serde_json::Value> {
    serde_json::from_str(input).map_err(|error| {
        WireSurgeError::new("invalid_stored_json", error.to_string()).at(format!(
            "line {}, column {}",
            error.line(),
            error.column()
        ))
    })
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    #[test]
    fn creates_and_lists_requests() {
        let root = std::env::temp_dir().join(format!(
            "wiresurge-storage-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = WorkspaceStore::new(&root);
        store.init().unwrap();
        let request =
            RequestSpec::from_json(r#"{"id":"req-a","name":"A","url":"http://localhost"}"#)
                .unwrap();
        store.create_request(&request).unwrap();
        let requests = store.list_requests().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].id, "req-a");
        let _ = fs::remove_dir_all(root);
    }
}
