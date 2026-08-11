//! P0-A regressions (P0A-02, P0A-03, P0A-05): CLI honesty — each test
//! encodes the ADR 0002/0003 contract and intentionally fails on the
//! current implementation where noted.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn wiresurge() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wiresurge"))
}

fn run_in(dir: &Path, args: &[&str]) -> Output {
    wiresurge()
        .current_dir(dir)
        .args(args)
        .output()
        .expect("spawn wiresurge")
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "wiresurge-p0a-cli-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
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

/// ADR 0002: a huge but finite `--duration-s` is rejected at admission
/// (7-day cap) with the structured JSON error envelope — never a panic.
#[test]
fn huge_finite_duration_is_rejected_with_structured_error() {
    let out = run_in(
        Path::new("."),
        &[
            "load",
            "127.0.0.1:53",
            "--duration-s",
            "1e20",
            "--output",
            "json",
        ],
    );
    assert_eq!(
        out.status.code(),
        Some(2),
        "oversized duration must exit 2 (rejected); got {:?}\nstdout: {}\nstderr: {}",
        out.status,
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout must be a single JSON value");
    assert!(
        value["error"]["code"].is_string(),
        "structured error envelope on stdout; got: {stdout}"
    );
}

/// ADR 0003 + 0004: a run with zero goodput exits non-zero and the load JSON
/// reports the goodput rate.
///
/// Currently: exits 0.
#[test]
fn load_against_unreachable_target_exits_nonzero_with_goodput_metric() {
    let out = run_in(
        Path::new("."),
        &[
            "load",
            "127.0.0.1:9",
            "--count",
            "1",
            "--timeout-ms",
            "200",
            "--output",
            "json",
        ],
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_ne!(
        out.status.code(),
        Some(0),
        "a run with zero goodput must not exit 0\nstdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(
        stdout.contains("goodput_qps"),
        "load JSON must report the goodput rate (ADR 0004); got: {stdout}"
    );
}

/// PIN (ADR 0002): `--count 0` is a documented empty run — immediate
/// success, zero traffic — not an error.
#[test]
fn count_zero_is_an_immediate_successful_empty_run() {
    let out = run_in(
        Path::new("."),
        &["load", "127.0.0.1:53", "--count", "0", "--output", "json"],
    );
    assert_eq!(
        out.status.code(),
        Some(0),
        "count 0 must be an immediate successful empty run\nstderr: {}",
        String::from_utf8_lossy(&out.stderr),
    );
}

/// ADR 0003: every runner record must reach a terminal state after a
/// transport failure.
///
/// Currently: stays "active".
#[test]
fn runner_record_terminates_after_connect_failure() {
    let tmp = TempDir::new();

    let init = run_in(tmp.path(), &["workspace", "init"]);
    assert!(
        init.status.success(),
        "workspace init failed: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    let create = run_in(
        tmp.path(),
        &[
            "request",
            "create",
            "--json",
            r#"{"id":"r1","name":"R1","method":"GET","url":"http://127.0.0.1:1/"}"#,
        ],
    );
    assert!(
        create.status.success(),
        "request create failed: {}",
        String::from_utf8_lossy(&create.stderr)
    );

    let run = run_in(tmp.path(), &["run", "r1"]);
    assert!(
        !run.status.success(),
        "run against an unreachable target must fail; stdout: {}",
        String::from_utf8_lossy(&run.stdout)
    );

    let runners_dir = tmp.path().join(".wiresurge").join("runners");
    let mut seen = 0;
    for entry in std::fs::read_dir(&runners_dir).expect("runners dir must exist") {
        let entry = entry.expect("read runner entry");
        let value: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(entry.path()).unwrap())
                .expect("runner record is JSON");
        seen += 1;
        assert!(
            value["status"] != "active",
            "runner record left active after failure: {}",
            entry.path().display()
        );
    }
    assert!(
        seen >= 1,
        "expected at least one runner record in {}",
        runners_dir.display()
    );
}
