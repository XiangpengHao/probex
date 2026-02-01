//! Integration tests for snitch
//!
//! Note: These tests require root privileges and eBPF support.
//! Run with: sudo -E cargo test --package snitch --test integration_test

use std::{
    process::{Command, Stdio},
    time::Duration,
};

/// Test that the snitch binary exists and shows help
#[test]
fn test_help_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_snitch"))
        .arg("--help")
        .output()
        .expect("failed to execute snitch");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("eBPF process tracing tool"));
    assert!(stdout.contains("--output"));
    assert!(stdout.contains("COMMAND"));
}

/// Test that snitch requires a command argument
#[test]
fn test_requires_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_snitch"))
        .output()
        .expect("failed to execute snitch");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("required") || stderr.contains("COMMAND"),
        "stderr: {}",
        stderr
    );
}

/// Test version flag
#[test]
fn test_version_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_snitch"))
        .arg("--version")
        .output()
        .expect("failed to execute snitch");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("snitch"));
}

/// Integration test that runs snitch with a simple command
/// Requires root privileges to run
#[test]
#[ignore = "requires root privileges and eBPF support"]
fn test_trace_sleep() {
    use std::io::Read;

    let mut child = Command::new(env!("CARGO_BIN_EXE_snitch"))
        .args(["--", "sleep", "0.1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn snitch");

    // Wait for the process to complete with timeout
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "snitch exited with error");
                break;
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    child.kill().expect("failed to kill snitch");
                    panic!("snitch timed out");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("error waiting for snitch: {}", e),
        }
    }

    // Read stdout and verify we got some JSON events
    let mut stdout = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut stdout)
        .expect("failed to read stdout");

    // Should have at least one event (process_exit at minimum)
    assert!(!stdout.is_empty(), "expected some output events");

    // Verify output is valid JSON lines
    for line in stdout.lines() {
        if line.is_empty() {
            continue;
        }
        let parsed: serde_json::Value =
            serde_json::from_str(line).expect(&format!("invalid JSON: {}", line));
        assert!(parsed.get("type").is_some(), "event missing 'type' field");
        assert!(parsed.get("ts_ns").is_some(), "event missing 'ts_ns' field");
        assert!(parsed.get("pid").is_some(), "event missing 'pid' field");
    }
}

/// Test output to file
#[test]
#[ignore = "requires root privileges and eBPF support"]
fn test_output_to_file() {
    use std::fs;

    let temp_file = "/tmp/snitch_test_output.jsonl";

    // Clean up any existing file
    let _ = fs::remove_file(temp_file);

    let status = Command::new(env!("CARGO_BIN_EXE_snitch"))
        .args(["-o", temp_file, "--", "true"])
        .status()
        .expect("failed to run snitch");

    assert!(status.success(), "snitch exited with error");

    // Verify file was created and contains valid JSON
    let content = fs::read_to_string(temp_file).expect("failed to read output file");
    assert!(!content.is_empty(), "output file is empty");

    // Clean up
    let _ = fs::remove_file(temp_file);
}
