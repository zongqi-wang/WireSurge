//! Stream-level checks against the real `wiresurge` binary: what actually lands
//! on fd-1 (stdout) and fd-2 (stderr), which the in-process `dispatch` helper
//! cannot observe (banner and live progress write straight to the process fd-2).

use std::process::Command;

fn wiresurge() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wiresurge"))
}

#[test]
fn json_mode_stdout_is_one_json_value_and_stderr_is_empty() {
    let output = wiresurge()
        .args([
            "--output",
            "json",
            "load",
            "127.0.0.1",
            "--protocol",
            "udp",
            "--count",
            "0",
        ])
        .output()
        .expect("run wiresurge");

    assert!(output.status.success(), "exit: {:?}", output.status);
    assert!(
        output.stderr.is_empty(),
        "json mode leaked stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is a single JSON value");
    assert!(value.get("workers").is_some(), "json carries workers");
}

#[test]
fn human_mode_banner_on_stderr_summary_on_stdout() {
    let output = wiresurge()
        .args(["load", "127.0.0.1", "--protocol", "udp", "--count", "0"])
        .output()
        .expect("run wiresurge");

    assert!(output.status.success(), "exit: {:?}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("wiresurge load ->"),
        "banner on stderr: {stderr}"
    );
    assert!(
        !stdout.contains("wiresurge load ->"),
        "banner must not leak into stdout: {stdout}"
    );
    assert!(stdout.contains("duration"), "summary on stdout: {stdout}");
}
