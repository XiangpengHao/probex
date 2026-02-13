//! Integration tests for probex
//!
//! Note: These tests require root privileges and eBPF support.
//! Run with: sudo -E cargo test --package probex --test integration_test

use std::{
    process::{Command, Stdio},
    time::Duration,
};

/// Test that the probex binary exists and shows help
#[test]
fn test_help_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_probex"))
        .arg("--help")
        .output()
        .expect("failed to execute probex");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("eBPF process tracing tool"));
    assert!(stdout.contains("--output"));
    assert!(stdout.contains("COMMAND"));
}

/// Test that probex requires a command argument
#[test]
fn test_requires_command() {
    let output = Command::new(env!("CARGO_BIN_EXE_probex"))
        .output()
        .expect("failed to execute probex");

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
    let output = Command::new(env!("CARGO_BIN_EXE_probex"))
        .arg("--version")
        .output()
        .expect("failed to execute probex");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("probex"));
}

/// Integration test that runs probex with a simple command
/// Requires root privileges to run
#[test]
#[ignore = "requires root privileges and eBPF support"]
fn test_trace_sleep() {
    use std::fs::File;

    use arrow::array::Array;
    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let temp_file = "/tmp/probex_test_sleep.parquet";

    // Clean up any existing file
    let _ = std::fs::remove_file(temp_file);

    let mut child = Command::new(env!("CARGO_BIN_EXE_probex"))
        .args(["-o", temp_file, "--", "sleep", "0.1"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn probex");

    // Wait for the process to complete with timeout
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                assert!(status.success(), "probex exited with error");
                break;
            }
            Ok(None) => {
                if start.elapsed() > timeout {
                    child.kill().expect("failed to kill probex");
                    panic!("probex timed out");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => panic!("error waiting for probex: {}", e),
        }
    }

    // Read and verify Parquet output
    let file = File::open(temp_file).expect("failed to open parquet file");
    let builder =
        ParquetRecordBatchReaderBuilder::try_new(file).expect("failed to create parquet reader");

    let reader = builder.build().expect("failed to build reader");

    let mut total_rows = 0;
    let mut has_process_exit = false;

    for batch_result in reader {
        let batch = batch_result.expect("failed to read batch");
        total_rows += batch.num_rows();

        // Check event_type column for process_exit
        let event_type_col = batch
            .column_by_name("event_type")
            .expect("missing event_type column");
        let event_types = event_type_col
            .as_any()
            .downcast_ref::<arrow::array::StringArray>()
            .expect("event_type should be StringArray");

        for i in 0..event_types.len() {
            if event_types.value(i) == "process_exit" {
                has_process_exit = true;
            }
        }
    }

    // Should have at least one event (process_exit at minimum)
    assert!(total_rows > 0, "expected some output events");
    assert!(has_process_exit, "expected at least one process_exit event");

    // Clean up
    let _ = std::fs::remove_file(temp_file);
}

/// Test output to file (default behavior)
#[test]
#[ignore = "requires root privileges and eBPF support"]
fn test_output_to_file() {
    use std::fs::{self, File};

    use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;

    let temp_file = "/tmp/probex_test_output.parquet";

    // Clean up any existing file
    let _ = fs::remove_file(temp_file);

    let status = Command::new(env!("CARGO_BIN_EXE_probex"))
        .args(["-o", temp_file, "--", "true"])
        .status()
        .expect("failed to run probex");

    assert!(status.success(), "probex exited with error");

    // Verify file was created and contains valid Parquet data
    let file = File::open(temp_file).expect("failed to open parquet file");
    let builder =
        ParquetRecordBatchReaderBuilder::try_new(file).expect("failed to create parquet reader");

    // Verify schema has expected columns
    let schema = builder.schema();
    assert!(
        schema.column_with_name("event_type").is_some(),
        "missing event_type column"
    );
    assert!(
        schema.column_with_name("ts_ns").is_some(),
        "missing ts_ns column"
    );
    assert!(
        schema.column_with_name("pid").is_some(),
        "missing pid column"
    );
    assert!(
        schema.column_with_name("cpu").is_some(),
        "missing cpu column"
    );

    // Read all batches to verify file is valid
    let reader = builder.build().expect("failed to build reader");
    let mut total_rows = 0;
    for batch_result in reader {
        let batch = batch_result.expect("failed to read batch");
        total_rows += batch.num_rows();
    }

    assert!(total_rows > 0, "output file has no events");

    // Clean up
    let _ = fs::remove_file(temp_file);
}

/// Test that default output file is trace.parquet
#[test]
#[ignore = "requires root privileges and eBPF support"]
fn test_default_output_file() {
    use std::fs;

    let default_file = "trace.parquet";

    // Clean up any existing file
    let _ = fs::remove_file(default_file);

    let status = Command::new(env!("CARGO_BIN_EXE_probex"))
        .args(["--", "true"])
        .status()
        .expect("failed to run probex");

    assert!(status.success(), "probex exited with error");

    // Verify default file was created
    assert!(
        fs::metadata(default_file).is_ok(),
        "default output file trace.parquet was not created"
    );

    // Clean up
    let _ = fs::remove_file(default_file);
}
