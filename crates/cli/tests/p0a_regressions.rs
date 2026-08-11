//! PIN (ADR 0002): `--count 0` is a documented empty run — immediate
//! success, zero traffic — not an error.

use std::path::Path;
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

/// ADR 0002: a huge but finite `--duration-s` is rejected at admission
/// (7-day cap) with the structured JSON error envelope — never a panic.
///
/// Currently: panics, exit 101.
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
