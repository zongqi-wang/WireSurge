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
