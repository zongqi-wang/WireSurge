//! P0-A regressions (P0A-08): write safety — create-new semantics and no
//! symlink-following, per ADR 0005; intentionally fails on the current
//! implementation.

use std::path::{Path, PathBuf};

use wiresurge_core::RequestSpec;
use wiresurge_storage::WorkspaceStore;

struct TempDir(PathBuf);

impl TempDir {
    /// The dir does not need to exist yet: `store.init()` creates it.
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "wiresurge-p0a-storage-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        TempDir(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn spec(id: &str) -> RequestSpec {
    RequestSpec::from_json(&format!(
        r#"{{"id":"{id}","name":"{id}","method":"GET","url":"http://example.com/"}}"#
    ))
    .unwrap()
}

#[test]
fn create_request_rejects_an_existing_id() {
    let dir = TempDir::new();
    let store = WorkspaceStore::new(dir.path());
    store.init().unwrap();

    store.create_request(&spec("a")).expect("first create");
    let second = store.create_request(&spec("a"));
    assert!(
        second.is_err(),
        "creating a request with an existing id must fail, got {second:?}"
    );
}

#[cfg(unix)]
#[test]
fn create_request_does_not_follow_symlinks() {
    let dir = TempDir::new();
    let store = WorkspaceStore::new(dir.path());
    store.init().unwrap();

    let outside = dir.path().join("outside.yaml");
    std::fs::write(&outside, b"ORIGINAL").unwrap();
    let requests = dir.path().join(".wiresurge").join("requests");
    std::os::unix::fs::symlink(&outside, requests.join("a.yaml")).unwrap();

    let result = store.create_request(&spec("a"));
    assert!(
        result.is_err(),
        "writing through a symlink must be rejected, got {result:?}"
    );
    assert_eq!(
        std::fs::read_to_string(&outside).unwrap(),
        "ORIGINAL",
        "the symlink target must not be modified"
    );
}
