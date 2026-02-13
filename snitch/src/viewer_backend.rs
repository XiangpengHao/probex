//! Viewer backend functionality used by `snitch`.
//!
//! Uses DataFusion to query parquet trace files.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Histogram bucket for density visualization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistogramBucket {
    pub bucket_start_ns: u64,
    pub bucket_end_ns: u64,
    pub count: usize,
    pub counts_by_type: HashMap<String, usize>,
}

/// Response for histogram data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistogramResponse {
    pub buckets: Vec<HistogramBucket>,
    pub total_in_range: usize,
}

/// Event counts by type for filter badges.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct EventTypeCounts {
    pub counts: HashMap<String, usize>,
}

/// Latency summary statistics in nanoseconds.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct LatencySummary {
    pub count: usize,
    pub avg_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub max_ns: u64,
}

/// Read/write syscall latency summaries.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SyscallLatencyStats {
    pub read: LatencySummary,
    pub write: LatencySummary,
    pub mmap_alloc_bytes: u64,
    pub munmap_free_bytes: u64,
}

/// Summary statistics about the trace.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TraceSummary {
    pub total_events: usize,
    pub event_types: Vec<String>,
    pub unique_pids: Vec<u32>,
    pub min_ts_ns: u64,
    pub max_ts_ns: u64,
    pub cpu_sample_frequency_hz: Option<u64>,
}

/// Process lifetime information for timeline visualization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessLifetime {
    pub pid: u32,
    pub process_name: Option<String>,
    pub parent_pid: Option<u32>,
    pub start_ns: u64,
    pub end_ns: Option<u64>,
    pub exit_code: Option<i32>,
    pub was_forked: bool,
    pub did_exit: bool,
}

/// Response containing process lifetimes.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessLifetimesResponse {
    pub processes: Vec<ProcessLifetime>,
}

/// Sparse event marker for timeline visualization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventMarker {
    pub ts_ns: u64,
    pub event_type: String,
}

/// Events grouped by PID for timeline visualization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessEventsResponse {
    pub events_by_pid: HashMap<u32, Vec<EventMarker>>,
    pub cpu_sample_counts_by_pid: HashMap<u32, Vec<u16>>,
    pub cpu_sample_bucket_count: usize,
}

/// Aggregated flamegraph response for one event type in a range.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct EventFlamegraphResponse {
    pub event_type: String,
    pub total_samples: usize,
    pub svg: Option<String>,
}

mod backend {
    use super::*;
    use datafusion::arrow::array::{
        Array, Float32Array, Float64Array, Int32Array, Int64Array, ListArray, StringArray,
        StringViewArray, StructArray, UInt32Array, UInt64Array,
    };
    use datafusion::prelude::*;
    use inferno::flamegraph;
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use std::collections::HashSet;
    use std::fs::File;
    use std::io::{Error as IoError, ErrorKind};
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, OnceLock};
    use wholesym::{LookupAddress, SymbolManager, SymbolManagerConfig};

    static SESSION_CTX: OnceLock<Arc<SessionContext>> = OnceLock::new();
    static TRACE_FILE_METADATA: OnceLock<TraceFileMetadata> = OnceLock::new();

    const PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY: &str = "snitch.sample_freq_hz";

    #[derive(Clone, Copy, Debug, Default)]
    struct TraceFileMetadata {
        cpu_sample_frequency_hz: Option<u64>,
    }

    fn get_ctx() -> Result<&'static Arc<SessionContext>, Box<dyn std::error::Error + Send + Sync>> {
        SESSION_CTX
            .get()
            .ok_or_else(|| "DataFusion session not initialized".into())
    }

    pub async fn initialize(
        parquet_file: PathBuf,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if SESSION_CTX.get().is_some() {
            return Ok(());
        }
        if !parquet_file.exists() {
            return Err(IoError::new(
                ErrorKind::NotFound,
                format!("Parquet file not found: {}", parquet_file.display()),
            )
            .into());
        }

        let metadata = read_trace_file_metadata(&parquet_file);
        let _ = TRACE_FILE_METADATA.set(metadata);

        let ctx = SessionContext::new();

        let path_str = parquet_file.to_string_lossy();
        ctx.register_parquet("events", path_str.as_ref(), ParquetReadOptions::default())
            .await?;
        let has_inline_proc_maps = ctx
            .table("events")
            .await
            .map(|df| {
                df.schema()
                    .has_column_with_unqualified_name("proc_maps_snapshot")
            })
            .unwrap_or(false);

        if !has_inline_proc_maps {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "Trace {} is missing required proc_maps_snapshot column. Regenerate with current snitch.",
                    parquet_file.display()
                ),
            )
            .into());
        }

        // Verify we can read the table
        let df = ctx.sql("SELECT COUNT(*) as cnt FROM events").await?;
        let batches = df.collect().await?;
        let count = if let Some(batch) = batches.first() {
            if batch.num_rows() > 0 {
                batch
                    .column(0)
                    .as_any()
                    .downcast_ref::<Int64Array>()
                    .map(|arr| arr.value(0))
                    .unwrap_or(0)
            } else {
                0
            }
        } else {
            0
        };

        SESSION_CTX.set(Arc::new(ctx)).map_err(|_| {
            IoError::new(
                ErrorKind::AlreadyExists,
                "DataFusion session already initialized",
            )
        })?;

        log::info!("Loaded {count} events from {:?}", parquet_file);
        Ok(())
    }

    fn read_trace_file_metadata(parquet_file: &Path) -> TraceFileMetadata {
        let Ok(file) = File::open(parquet_file) else {
            return TraceFileMetadata::default();
        };
        let Ok(reader) = SerializedFileReader::new(file) else {
            return TraceFileMetadata::default();
        };

        let cpu_sample_frequency_hz = reader
            .metadata()
            .file_metadata()
            .key_value_metadata()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry.key == PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY)
            })
            .and_then(|entry| entry.value.as_ref())
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|hz| *hz > 0);

        TraceFileMetadata {
            cpu_sample_frequency_hz,
        }
    }

    fn extract_string(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> String {
        batch
            .column_by_name(col)
            .and_then(|c| c.as_any().downcast_ref::<StringViewArray>())
            .map(|arr| {
                if arr.is_null(row) {
                    String::new()
                } else {
                    arr.value(row).to_string()
                }
            })
            .unwrap_or_default()
    }

    fn extract_option_string(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> Option<String> {
        batch
            .column_by_name(col)
            .and_then(|c| c.as_any().downcast_ref::<StringViewArray>())
            .and_then(|arr| {
                if arr.is_null(row) {
                    None
                } else {
                    let value = arr.value(row);
                    if value.is_empty() {
                        None
                    } else {
                        Some(value.to_string())
                    }
                }
            })
    }

    fn extract_u64(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> u64 {
        batch
            .column_by_name(col)
            .and_then(|c| c.as_any().downcast_ref::<UInt64Array>())
            .map(|arr| if arr.is_null(row) { 0 } else { arr.value(row) })
            .unwrap_or(0)
    }

    fn extract_u32(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> u32 {
        batch
            .column_by_name(col)
            .and_then(|c| c.as_any().downcast_ref::<UInt32Array>())
            .map(|arr| if arr.is_null(row) { 0 } else { arr.value(row) })
            .unwrap_or(0)
    }

    fn extract_option_u64(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> Option<u64> {
        batch
            .column_by_name(col)
            .and_then(|c| c.as_any().downcast_ref::<UInt64Array>())
            .and_then(|arr| {
                if arr.is_null(row) {
                    None
                } else {
                    Some(arr.value(row))
                }
            })
    }

    fn extract_option_u32(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> Option<u32> {
        batch
            .column_by_name(col)
            .and_then(|c| c.as_any().downcast_ref::<UInt32Array>())
            .and_then(|arr| {
                if arr.is_null(row) {
                    None
                } else {
                    Some(arr.value(row))
                }
            })
    }

    fn extract_option_i32(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> Option<i32> {
        batch
            .column_by_name(col)
            .and_then(|c| c.as_any().downcast_ref::<Int32Array>())
            .and_then(|arr| {
                if arr.is_null(row) {
                    None
                } else {
                    Some(arr.value(row))
                }
            })
    }

    pub async fn query_histogram(
        start_ns: u64,
        end_ns: u64,
        num_buckets: usize,
    ) -> Result<HistogramResponse, Box<dyn std::error::Error + Send + Sync>> {
        let ctx = get_ctx()?;

        let range = end_ns.saturating_sub(start_ns);
        let bucket_count = num_buckets.max(1);
        let bucket_size = range.div_ceil(bucket_count as u64).max(1);

        // Query to get counts grouped by bucket and event type
        let sql = format!(
            "SELECT
                CAST(FLOOR((ts_ns - {}) / {}) AS BIGINT) as bucket_idx,
                event_type,
                COUNT(*) as cnt
            FROM events
            WHERE ts_ns >= {} AND ts_ns <= {}
            GROUP BY bucket_idx, event_type
            ORDER BY bucket_idx",
            start_ns, bucket_size, start_ns, end_ns
        );

        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        // Always return a fixed bucket count so downstream timeline math remains stable.
        let mut buckets = (0..bucket_count)
            .map(|bucket_idx| {
                let bucket_start = start_ns + (bucket_idx as u64 * bucket_size);
                let bucket_end = bucket_start.saturating_add(bucket_size).min(end_ns);
                HistogramBucket {
                    bucket_start_ns: bucket_start,
                    bucket_end_ns: bucket_end,
                    count: 0,
                    counts_by_type: std::collections::HashMap::new(),
                }
            })
            .collect::<Vec<_>>();

        let mut total_in_range = 0usize;

        for batch in &batches {
            for row in 0..batch.num_rows() {
                let bucket_idx = batch
                    .column_by_name("bucket_idx")
                    .and_then(|column| {
                        column
                            .as_any()
                            .downcast_ref::<Int64Array>()
                            .map(|arr| arr.value(row))
                            .or_else(|| {
                                column
                                    .as_any()
                                    .downcast_ref::<Int32Array>()
                                    .map(|arr| arr.value(row) as i64)
                            })
                            .or_else(|| {
                                column
                                    .as_any()
                                    .downcast_ref::<UInt64Array>()
                                    .map(|arr| arr.value(row) as i64)
                            })
                            .or_else(|| {
                                column
                                    .as_any()
                                    .downcast_ref::<UInt32Array>()
                                    .map(|arr| arr.value(row) as i64)
                            })
                            .or_else(|| {
                                column
                                    .as_any()
                                    .downcast_ref::<Float64Array>()
                                    .map(|arr| arr.value(row).floor() as i64)
                            })
                            .or_else(|| {
                                column
                                    .as_any()
                                    .downcast_ref::<Float32Array>()
                                    .map(|arr| arr.value(row).floor() as i64)
                            })
                    })
                    .unwrap_or(0);

                let event_type = extract_string(batch, "event_type", row);
                let cnt = batch
                    .column_by_name("cnt")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .map(|arr| arr.value(row) as usize)
                    .unwrap_or(0);

                total_in_range += cnt;

                let clamped_idx = (bucket_idx.max(0) as usize).min(bucket_count.saturating_sub(1));
                let bucket = buckets
                    .get_mut(clamped_idx)
                    .expect("histogram bucket index should be in range");

                bucket.count += cnt;
                *bucket.counts_by_type.entry(event_type).or_insert(0) += cnt;
            }
        }

        Ok(HistogramResponse {
            buckets,
            total_in_range,
        })
    }

    pub async fn query_event_type_counts(
        start_ns: Option<u64>,
        end_ns: Option<u64>,
    ) -> Result<EventTypeCounts, Box<dyn std::error::Error + Send + Sync>> {
        let ctx = get_ctx()?;

        let where_clause = match (start_ns, end_ns) {
            (Some(s), Some(e)) => format!("WHERE ts_ns >= {} AND ts_ns <= {}", s, e),
            (Some(s), None) => format!("WHERE ts_ns >= {}", s),
            (None, Some(e)) => format!("WHERE ts_ns <= {}", e),
            (None, None) => String::new(),
        };

        let sql = format!(
            "SELECT event_type, COUNT(*) as cnt FROM events {} GROUP BY event_type",
            where_clause
        );

        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        let mut counts = std::collections::HashMap::new();

        for batch in &batches {
            for row in 0..batch.num_rows() {
                let event_type = extract_string(batch, "event_type", row);
                let cnt = batch
                    .column_by_name("cnt")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .map(|arr| arr.value(row) as usize)
                    .unwrap_or(0);
                counts.insert(event_type, cnt);
            }
        }

        Ok(EventTypeCounts { counts })
    }

    pub async fn query_pid_event_type_counts(
        pid: u32,
        start_ns: Option<u64>,
        end_ns: Option<u64>,
    ) -> Result<EventTypeCounts, Box<dyn std::error::Error + Send + Sync>> {
        let ctx = get_ctx()?;

        let mut conditions = vec![format!("pid = {}", pid)];
        if let Some(start) = start_ns {
            conditions.push(format!("ts_ns >= {}", start));
        }
        if let Some(end) = end_ns {
            conditions.push(format!("ts_ns <= {}", end));
        }

        let where_clause = format!("WHERE {}", conditions.join(" AND "));
        let sql = format!(
            "SELECT event_type, COUNT(*) as cnt FROM events {} GROUP BY event_type",
            where_clause
        );

        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        let mut counts = std::collections::HashMap::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                let event_type = extract_string(batch, "event_type", row);
                let cnt = batch
                    .column_by_name("cnt")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .map(|arr| arr.value(row) as usize)
                    .unwrap_or(0);
                counts.insert(event_type, cnt);
            }
        }

        Ok(EventTypeCounts { counts })
    }

    pub async fn query_syscall_latency_stats(
        start_ns: u64,
        end_ns: u64,
        pid: Option<u32>,
    ) -> Result<SyscallLatencyStats, Box<dyn std::error::Error + Send + Sync>> {
        let ctx = get_ctx()?;

        let mut conditions = vec![
            format!("ts_ns >= {}", start_ns),
            format!("ts_ns <= {}", end_ns),
        ];
        if let Some(pid) = pid {
            conditions.push(format!("pid = {}", pid));
        }

        let sql = format!(
            "SELECT pid, ts_ns, event_type, count
             FROM events
             WHERE {}
               AND event_type IN (
                 'syscall_read_enter', 'syscall_read_exit',
                 'syscall_write_enter', 'syscall_write_exit',
                 'syscall_io_uring_enter_enter', 'syscall_io_uring_enter_exit',
                 'syscall_mmap_enter', 'syscall_munmap_enter'
               )
             ORDER BY pid, ts_ns",
            conditions.join(" AND ")
        );

        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        let mut pending_read: std::collections::HashMap<u32, std::collections::VecDeque<u64>> =
            std::collections::HashMap::new();
        let mut pending_write: std::collections::HashMap<u32, std::collections::VecDeque<u64>> =
            std::collections::HashMap::new();
        let mut pending_io_uring: std::collections::HashMap<u32, std::collections::VecDeque<u64>> =
            std::collections::HashMap::new();
        let mut read_latencies: Vec<u64> = Vec::new();
        let mut write_latencies: Vec<u64> = Vec::new();
        let mut io_uring_enter_latencies: Vec<u64> = Vec::new();
        let mut mmap_alloc_bytes: u64 = 0;
        let mut munmap_free_bytes: u64 = 0;

        for batch in &batches {
            for row in 0..batch.num_rows() {
                let pid = extract_u32(batch, "pid", row);
                let ts = extract_u64(batch, "ts_ns", row);
                let event_type = extract_string(batch, "event_type", row);
                let count = extract_option_u64(batch, "count", row).unwrap_or(0);

                match event_type.as_str() {
                    "syscall_read_enter" => pending_read.entry(pid).or_default().push_back(ts),
                    "syscall_read_exit" => {
                        if let Some(queue) = pending_read.get_mut(&pid)
                            && let Some(start_ts) = queue.pop_front()
                            && ts >= start_ts
                        {
                            read_latencies.push(ts - start_ts);
                        }
                    }
                    "syscall_write_enter" => pending_write.entry(pid).or_default().push_back(ts),
                    "syscall_write_exit" => {
                        if let Some(queue) = pending_write.get_mut(&pid)
                            && let Some(start_ts) = queue.pop_front()
                            && ts >= start_ts
                        {
                            write_latencies.push(ts - start_ts);
                        }
                    }
                    "syscall_io_uring_enter_enter" => {
                        pending_io_uring.entry(pid).or_default().push_back(ts)
                    }
                    "syscall_io_uring_enter_exit" => {
                        if let Some(queue) = pending_io_uring.get_mut(&pid)
                            && let Some(start_ts) = queue.pop_front()
                            && ts >= start_ts
                        {
                            io_uring_enter_latencies.push(ts - start_ts);
                        }
                    }
                    "syscall_mmap_enter" => {
                        mmap_alloc_bytes = mmap_alloc_bytes.saturating_add(count);
                    }
                    "syscall_munmap_enter" => {
                        munmap_free_bytes = munmap_free_bytes.saturating_add(count);
                    }
                    _ => {}
                }
            }
        }

        // io_uring_enter can represent read or write style I/O submissions.
        // Without SQE opcode tracing, attribute these latencies to both aggregates.
        if !io_uring_enter_latencies.is_empty() {
            read_latencies.extend(io_uring_enter_latencies.iter().copied());
            write_latencies.extend(io_uring_enter_latencies.iter().copied());
        }

        Ok(SyscallLatencyStats {
            read: summarize_latencies(&read_latencies),
            write: summarize_latencies(&write_latencies),
            mmap_alloc_bytes,
            munmap_free_bytes,
        })
    }

    fn summarize_latencies(latencies: &[u64]) -> LatencySummary {
        if latencies.is_empty() {
            return LatencySummary::default();
        }

        let mut sorted = latencies.to_vec();
        sorted.sort_unstable();
        let count = sorted.len();
        let sum: u128 = sorted.iter().map(|v| *v as u128).sum();
        let avg_ns = (sum / count as u128) as u64;
        let p50_idx = ((count - 1) * 50) / 100;
        let p95_idx = ((count - 1) * 95) / 100;
        let max_ns = *sorted.last().unwrap_or(&0);

        LatencySummary {
            count,
            avg_ns,
            p50_ns: sorted[p50_idx],
            p95_ns: sorted[p95_idx],
            max_ns,
        }
    }

    pub async fn query_summary() -> Result<TraceSummary, Box<dyn std::error::Error + Send + Sync>> {
        let ctx = get_ctx()?;

        // Get total count
        let count_df = ctx.sql("SELECT COUNT(*) as cnt FROM events").await?;
        let count_batches = count_df.collect().await?;
        let total_events = count_batches
            .first()
            .and_then(|b| b.column(0).as_any().downcast_ref::<Int64Array>())
            .map(|arr| arr.value(0) as usize)
            .unwrap_or(0);

        // Get distinct event types
        let types_df = ctx
            .sql("SELECT DISTINCT event_type FROM events ORDER BY event_type")
            .await?;
        let types_batches = types_df.collect().await?;
        let event_types: Vec<String> = types_batches
            .iter()
            .flat_map(|b| (0..b.num_rows()).map(move |i| extract_string(b, "event_type", i)))
            .filter(|s| !s.is_empty())
            .collect();

        // Get distinct PIDs
        let pids_df = ctx
            .sql("SELECT DISTINCT pid FROM events ORDER BY pid")
            .await?;
        let pids_batches = pids_df.collect().await?;
        let unique_pids: Vec<u32> = pids_batches
            .iter()
            .flat_map(|b| (0..b.num_rows()).map(move |i| extract_u32(b, "pid", i)))
            .collect();

        // Get time range
        let time_df = ctx
            .sql("SELECT MIN(ts_ns) as min_ts, MAX(ts_ns) as max_ts FROM events")
            .await?;
        let time_batches = time_df.collect().await?;
        let (min_ts_ns, max_ts_ns) = time_batches
            .first()
            .map(|b| {
                let min = b
                    .column_by_name("min_ts")
                    .and_then(|c| c.as_any().downcast_ref::<UInt64Array>())
                    .map(|arr| arr.value(0))
                    .unwrap_or(0);
                let max = b
                    .column_by_name("max_ts")
                    .and_then(|c| c.as_any().downcast_ref::<UInt64Array>())
                    .map(|arr| arr.value(0))
                    .unwrap_or(0);
                (min, max)
            })
            .unwrap_or((0, 0));

        Ok(TraceSummary {
            total_events,
            event_types,
            unique_pids,
            min_ts_ns,
            max_ts_ns,
            cpu_sample_frequency_hz: TRACE_FILE_METADATA
                .get()
                .and_then(|metadata| metadata.cpu_sample_frequency_hz),
        })
    }

    pub async fn query_process_lifetimes()
    -> Result<ProcessLifetimesResponse, Box<dyn std::error::Error + Send + Sync>> {
        let ctx = get_ctx()?;

        // Get all fork events (child creation)
        let fork_sql = "SELECT child_pid, parent_pid, ts_ns FROM events WHERE event_type = 'process_fork' ORDER BY ts_ns";
        let fork_df = ctx.sql(fork_sql).await?;
        let fork_batches = fork_df.collect().await?;

        // Get all exit events
        let exit_sql = "SELECT pid, exit_code, ts_ns FROM events WHERE event_type = 'process_exit' ORDER BY ts_ns";
        let exit_df = ctx.sql(exit_sql).await?;
        let exit_batches = exit_df.collect().await?;

        // Get first and last seen times for all PIDs
        let times_sql = "SELECT pid, MIN(ts_ns) as first_seen, MAX(ts_ns) as last_seen FROM events GROUP BY pid";
        let times_df = ctx.sql(times_sql).await?;
        let times_batches = times_df.collect().await?;

        // Best-effort process names for each PID (available in newer traces).
        // This query may fail on older parquet files that do not have process_name.
        let name_batches = match ctx
            .sql(
                "SELECT pid, process_name, ts_ns FROM events
                 WHERE process_name IS NOT NULL AND process_name <> ''
                 ORDER BY ts_ns",
            )
            .await
        {
            Ok(df) => df.collect().await.unwrap_or_default(),
            Err(_) => Vec::new(),
        };

        // Build maps
        let mut fork_info: std::collections::HashMap<u32, (u32, u64)> =
            std::collections::HashMap::new(); // child -> (parent, ts)
        let mut exit_info: std::collections::HashMap<u32, (i32, u64)> =
            std::collections::HashMap::new(); // pid -> (exit_code, ts)
        let mut pid_times: std::collections::HashMap<u32, (u64, u64)> =
            std::collections::HashMap::new(); // pid -> (first, last)
        let mut pid_names: std::collections::HashMap<u32, String> =
            std::collections::HashMap::new(); // pid -> name

        // Parse fork events
        for batch in &fork_batches {
            for row in 0..batch.num_rows() {
                let child_pid = extract_option_u32(batch, "child_pid", row);
                let parent_pid = extract_option_u32(batch, "parent_pid", row);
                let ts = extract_u64(batch, "ts_ns", row);
                if let (Some(child), Some(parent)) = (child_pid, parent_pid) {
                    fork_info.entry(child).or_insert((parent, ts));
                }
            }
        }

        // Parse exit events
        for batch in &exit_batches {
            for row in 0..batch.num_rows() {
                let pid = extract_u32(batch, "pid", row);
                let exit_code = extract_option_i32(batch, "exit_code", row).unwrap_or(0);
                let ts = extract_u64(batch, "ts_ns", row);
                exit_info.entry(pid).or_insert((exit_code, ts));
            }
        }

        // Parse first/last times
        for batch in &times_batches {
            for row in 0..batch.num_rows() {
                let pid = extract_u32(batch, "pid", row);
                let first = extract_u64(batch, "first_seen", row);
                let last = extract_u64(batch, "last_seen", row);
                pid_times.insert(pid, (first, last));
            }
        }

        // Parse process names (keep first-seen non-empty name for each PID)
        for batch in &name_batches {
            for row in 0..batch.num_rows() {
                let pid = extract_u32(batch, "pid", row);
                if let Some(name) = extract_option_string(batch, "process_name", row) {
                    pid_names.entry(pid).or_insert(name);
                }
            }
        }

        // Build process lifetimes
        let mut processes: Vec<ProcessLifetime> = Vec::new();
        for (pid, (first_seen, last_seen)) in &pid_times {
            let (parent_pid, start_ns, was_forked) =
                if let Some((parent, fork_ts)) = fork_info.get(pid) {
                    (Some(*parent), *fork_ts, true)
                } else {
                    (None, *first_seen, false)
                };

            let (end_ns, exit_code, did_exit) = if let Some((code, exit_ts)) = exit_info.get(pid) {
                (Some(*exit_ts), Some(*code), true)
            } else {
                (Some(*last_seen), None, false)
            };

            processes.push(ProcessLifetime {
                pid: *pid,
                process_name: pid_names.get(pid).cloned(),
                parent_pid,
                start_ns,
                end_ns,
                exit_code,
                was_forked,
                did_exit,
            });
        }

        // Sort by start time
        processes.sort_by_key(|p| p.start_ns);

        Ok(ProcessLifetimesResponse { processes })
    }

    pub async fn query_process_events(
        start_ns: u64,
        end_ns: u64,
        max_events_per_pid: usize,
    ) -> Result<ProcessEventsResponse, Box<dyn std::error::Error + Send + Sync>> {
        const CPU_SAMPLE_BUCKETS: usize = 600;

        if max_events_per_pid == 0 {
            return Ok(ProcessEventsResponse {
                events_by_pid: std::collections::HashMap::new(),
                cpu_sample_counts_by_pid: std::collections::HashMap::new(),
                cpu_sample_bucket_count: CPU_SAMPLE_BUCKETS,
            });
        }

        let ctx = get_ctx()?;

        // Query events in the time range, grouped by PID
        // We sample if there are too many events per PID
        let sql = format!(
            "SELECT pid, ts_ns, event_type FROM events WHERE ts_ns >= {} AND ts_ns <= {} ORDER BY pid, ts_ns",
            start_ns, end_ns
        );

        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        let mut events_by_pid: std::collections::HashMap<u32, Vec<EventMarker>> =
            std::collections::HashMap::new();
        let mut events_seen_by_pid: std::collections::HashMap<u32, usize> =
            std::collections::HashMap::new();
        let mut cpu_sample_counts_by_pid: std::collections::HashMap<u32, Vec<u16>> =
            std::collections::HashMap::new();

        let range_ns = end_ns.saturating_sub(start_ns).max(1);
        let bucket_size_ns = range_ns.div_ceil(CPU_SAMPLE_BUCKETS as u64).max(1);

        for batch in &batches {
            for row in 0..batch.num_rows() {
                let pid = extract_u32(batch, "pid", row);
                let ts_ns = extract_u64(batch, "ts_ns", row);
                let event_type = extract_string(batch, "event_type", row);

                if event_type == "cpu_sample" {
                    let mut bucket_idx = ts_ns.saturating_sub(start_ns) / bucket_size_ns;
                    if bucket_idx >= CPU_SAMPLE_BUCKETS as u64 {
                        bucket_idx = (CPU_SAMPLE_BUCKETS - 1) as u64;
                    }
                    let counts = cpu_sample_counts_by_pid
                        .entry(pid)
                        .or_insert_with(|| vec![0u16; CPU_SAMPLE_BUCKETS]);
                    let bucket = &mut counts[bucket_idx as usize];
                    *bucket = bucket.saturating_add(1);
                }

                let events = events_by_pid.entry(pid).or_default();
                let seen = events_seen_by_pid.entry(pid).or_default();
                *seen += 1;

                // Sample events if we have too many for this PID
                if events.len() < max_events_per_pid {
                    events.push(EventMarker { ts_ns, event_type });
                } else {
                    // Reservoir sampling: replace with decreasing probability
                    let idx = rand_index(*seen);
                    if idx < max_events_per_pid {
                        events[idx] = EventMarker { ts_ns, event_type };
                    }
                }
            }
        }

        // Sort events by timestamp for each PID
        for events in events_by_pid.values_mut() {
            events.sort_by_key(|e| e.ts_ns);
        }

        Ok(ProcessEventsResponse {
            events_by_pid,
            cpu_sample_counts_by_pid,
            cpu_sample_bucket_count: CPU_SAMPLE_BUCKETS,
        })
    }

    #[derive(Clone, Debug)]
    struct ProcMapSegment {
        start_addr: u64,
        end_addr: u64,
        file_offset: u64,
        path: String,
    }

    #[derive(Clone, Debug)]
    struct SampledStackRow {
        stack_kind: Option<String>,
        stack_frames: Option<String>,
        stack_trace: Option<String>,
        proc_maps_snapshot: Option<Vec<ProcMapSegment>>,
    }

    fn extract_option_proc_maps_snapshot(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        row: usize,
    ) -> Option<Vec<ProcMapSegment>> {
        let column = batch.column_by_name("proc_maps_snapshot")?;
        let list_array = column.as_any().downcast_ref::<ListArray>()?;
        if list_array.is_null(row) {
            return None;
        }

        let list_values = list_array.value(row);
        let struct_array = list_values.as_any().downcast_ref::<StructArray>()?;
        let start_array = struct_array
            .column_by_name("start_addr")?
            .as_any()
            .downcast_ref::<UInt64Array>()?;
        let end_array = struct_array
            .column_by_name("end_addr")?
            .as_any()
            .downcast_ref::<UInt64Array>()?;
        let offset_array = struct_array
            .column_by_name("file_offset")?
            .as_any()
            .downcast_ref::<UInt64Array>()?;
        let path_column = struct_array.column_by_name("path")?;

        let mut segments = Vec::with_capacity(struct_array.len());
        for idx in 0..struct_array.len() {
            if start_array.is_null(idx) || end_array.is_null(idx) || offset_array.is_null(idx) {
                continue;
            }

            let path = if let Some(path_array) =
                path_column.as_any().downcast_ref::<StringViewArray>()
            {
                if path_array.is_null(idx) {
                    continue;
                }
                path_array.value(idx).to_string()
            } else if let Some(path_array) = path_column.as_any().downcast_ref::<StringArray>() {
                if path_array.is_null(idx) {
                    continue;
                }
                path_array.value(idx).to_string()
            } else {
                continue;
            };

            segments.push(ProcMapSegment {
                start_addr: start_array.value(idx),
                end_addr: end_array.value(idx),
                file_offset: offset_array.value(idx),
                path,
            });
        }

        Some(segments)
    }

    struct OfflineUserSymbolizer {
        symbol_manager: SymbolManager,
        symbol_cache: std::collections::HashMap<(String, u64), Option<Vec<String>>>,
        symbol_map_cache: std::collections::HashMap<String, Option<wholesym::SymbolMap>>,
    }

    impl OfflineUserSymbolizer {
        fn new() -> Self {
            Self {
                symbol_manager: SymbolManager::with_config(SymbolManagerConfig::default()),
                symbol_cache: std::collections::HashMap::new(),
                symbol_map_cache: std::collections::HashMap::new(),
            }
        }

        fn runtime_file_offset(runtime_ip: u64, map_start: u64, map_file_offset: u64) -> u64 {
            runtime_ip
                .saturating_sub(map_start)
                .saturating_add(map_file_offset)
        }

        async fn ensure_symbol_map_loaded(&mut self, path: &str) {
            if self.symbol_map_cache.contains_key(path) {
                return;
            }
            let symbol_map = self
                .symbol_manager
                .load_symbol_map_for_binary_at_path(Path::new(path), None)
                .await
                .ok();
            self.symbol_map_cache.insert(path.to_string(), symbol_map);
        }

        async fn symbolize_addrs_batch(&mut self, path: &str, addrs: &[u64]) {
            if addrs.is_empty() {
                return;
            }

            let path_key = path.to_string();
            let mut unresolved = Vec::new();
            let mut seen = HashSet::new();
            for addr in addrs {
                if !seen.insert(*addr) {
                    continue;
                }
                let cache_key = (path_key.clone(), *addr);
                if self.symbol_cache.contains_key(&cache_key) {
                    continue;
                }
                unresolved.push(*addr);
            }

            if unresolved.is_empty() {
                return;
            }

            self.ensure_symbol_map_loaded(path).await;

            let Some(symbol_map) = self
                .symbol_map_cache
                .get(&path_key)
                .and_then(|m| m.as_ref())
            else {
                for addr in unresolved {
                    self.symbol_cache.insert((path_key.clone(), addr), None);
                }
                return;
            };

            for addr in unresolved {
                let symbol = symbol_map
                    .lookup(LookupAddress::FileOffset(addr))
                    .await
                    .and_then(symbol_labels_from_address_info);
                self.symbol_cache.insert((path_key.clone(), addr), symbol);
            }
        }

        fn lookup_symbol_labels(&self, path: &str, addr: u64) -> Option<Vec<String>> {
            self.symbol_cache
                .get(&(path.to_string(), addr))
                .cloned()
                .flatten()
        }
    }

    fn symbol_labels_from_address_info(address_info: wholesym::AddressInfo) -> Option<Vec<String>> {
        if let Some(frames) = &address_info.frames {
            let mut labels: Vec<String> = frames
                .iter()
                .filter_map(|frame| {
                    frame
                        .function
                        .as_ref()
                        .filter(|function| !function.is_empty())
                        .cloned()
                })
                .collect();
            if !labels.is_empty() {
                // wholesym returns inline frames from innermost to outermost.
                // Folded stacks should be root to leaf.
                labels.reverse();
                return Some(labels);
            }
        }

        if address_info.symbol.name.is_empty() || address_info.symbol.name == "??" {
            None
        } else {
            Some(vec![address_info.symbol.name])
        }
    }

    fn parse_stack_frames(stack_frames: &str) -> Vec<u64> {
        stack_frames
            .split(';')
            .filter_map(|token| {
                let trimmed = token.trim();
                let hex = trimmed
                    .strip_prefix("0x")
                    .or_else(|| trimmed.strip_prefix("0X"))
                    .unwrap_or(trimmed);
                u64::from_str_radix(hex, 16).ok()
            })
            .collect()
    }

    fn find_segment_for_ip(segments: &[ProcMapSegment], ip: u64) -> Option<&ProcMapSegment> {
        segments
            .iter()
            .find(|segment| ip >= segment.start_addr && ip < segment.end_addr)
    }

    async fn symbolize_user_frames(
        frames: &[u64],
        inline_snapshot: Option<&[ProcMapSegment]>,
        symbolizer: &mut OfflineUserSymbolizer,
    ) -> Vec<String> {
        let mut labels = Vec::with_capacity(frames.len() + 1);
        labels.push("[user]".to_string());

        let Some(segments) = inline_snapshot else {
            labels.extend(frames.iter().map(|ip| format!("0x{ip:x}")));
            return labels;
        };

        if segments.is_empty() {
            labels.extend(frames.iter().map(|ip| format!("0x{ip:x}")));
            return labels;
        }

        let mapped_segments: Vec<Option<&ProcMapSegment>> = frames
            .iter()
            .map(|ip| find_segment_for_ip(segments, *ip))
            .collect();

        let mut frame_symbol_keys: Vec<Option<(String, u64)>> = Vec::with_capacity(frames.len());
        let mut unresolved_by_path: std::collections::HashMap<String, Vec<u64>> =
            std::collections::HashMap::new();

        for (ip, maybe_segment) in frames.iter().zip(mapped_segments.iter()) {
            if let Some(segment) = maybe_segment {
                let file_offset = OfflineUserSymbolizer::runtime_file_offset(
                    *ip,
                    segment.start_addr,
                    segment.file_offset,
                );
                frame_symbol_keys.push(Some((segment.path.clone(), file_offset)));
                unresolved_by_path
                    .entry(segment.path.clone())
                    .or_default()
                    .push(file_offset);
            } else {
                frame_symbol_keys.push(None);
            }
        }

        for (path, addrs) in unresolved_by_path {
            symbolizer.symbolize_addrs_batch(&path, &addrs).await;
        }

        for (ip, maybe_key) in frames.iter().zip(frame_symbol_keys.into_iter()) {
            if let Some((path, addr)) = maybe_key
                && let Some(symbols) = symbolizer.lookup_symbol_labels(&path, addr)
            {
                labels.extend(symbols);
            } else {
                labels.push(format!("0x{ip:x}"));
            }
        }
        labels
    }

    fn parse_kernel_labels_from_stack_trace(stack_trace: &str) -> Vec<String> {
        let mut labels = Vec::new();
        let mut in_kernel_section = false;
        for frame in stack_trace.split(';').filter(|frame| !frame.is_empty()) {
            if frame == "[kernel]" {
                in_kernel_section = true;
                labels.push(frame.to_string());
                continue;
            }
            if in_kernel_section {
                labels.push(frame.to_string());
            }
        }
        labels
    }

    fn sanitize_flame_frame_label(label: &str) -> String {
        let cleaned = label
            .replace(';', ":")
            .replace(['\n', '\r'], " ")
            .trim()
            .to_string();
        if cleaned.is_empty() {
            "[unknown]".to_string()
        } else {
            cleaned
        }
    }

    fn render_flamegraph_svg(
        event_type: &str,
        folded_counts: &std::collections::HashMap<String, usize>,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut entries: Vec<(&String, &usize)> = folded_counts.iter().collect();
        entries.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));

        let mut folded_lines: Vec<String> = Vec::with_capacity(entries.len());
        for (stack, count) in entries {
            if stack.is_empty() || *count == 0 {
                continue;
            }
            folded_lines.push(format!("{stack} {count}"));
        }

        if folded_lines.is_empty() {
            return Ok(String::new());
        }

        let mut opts = flamegraph::Options::default();
        opts.title = format!("snitch · {event_type}");
        opts.count_name = "samples".to_string();

        let input = folded_lines.iter().map(String::as_str);
        let mut svg = Vec::<u8>::new();
        flamegraph::from_lines(&mut opts, input, &mut svg)?;
        Ok(String::from_utf8(svg)?)
    }

    pub async fn query_event_flamegraph(
        start_ns: u64,
        end_ns: u64,
        pid: Option<u32>,
        event_type: String,
        max_stacks: usize,
    ) -> Result<EventFlamegraphResponse, Box<dyn std::error::Error + Send + Sync>> {
        let ctx = get_ctx()?;
        if event_type.is_empty() || max_stacks == 0 {
            return Ok(EventFlamegraphResponse::default());
        }

        let mut conditions = vec![
            format!("ts_ns >= {}", start_ns),
            format!("ts_ns <= {}", end_ns),
            format!("event_type = '{}'", event_type.replace('\'', "''")),
            "(\
              (stack_frames IS NOT NULL AND stack_frames <> '')\
              OR\
              (stack_trace IS NOT NULL AND stack_trace <> '')\
             )"
            .to_string(),
        ];
        if let Some(pid) = pid {
            conditions.push(format!("pid = {}", pid));
        }

        let sql = format!(
            "SELECT stack_kind, stack_frames, stack_trace, proc_maps_snapshot
             FROM events
             WHERE {}",
            conditions.join(" AND ")
        );
        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        let mut sampled_rows: Vec<SampledStackRow> = Vec::new();
        let mut rows_seen = 0usize;
        let mut rng_state = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut hasher = DefaultHasher::new();
            start_ns.hash(&mut hasher);
            end_ns.hash(&mut hasher);
            pid.hash(&mut hasher);
            event_type.hash(&mut hasher);
            hasher.finish() | 1
        };

        for batch in &batches {
            for row in 0..batch.num_rows() {
                let stack_kind = extract_option_string(batch, "stack_kind", row);
                let stack_frames = extract_option_string(batch, "stack_frames", row);
                let stack_trace = extract_option_string(batch, "stack_trace", row);
                let proc_maps_snapshot = extract_option_proc_maps_snapshot(batch, row);
                let sampled_row = SampledStackRow {
                    stack_kind,
                    stack_frames,
                    stack_trace,
                    proc_maps_snapshot,
                };

                rows_seen += 1;
                if sampled_rows.len() < max_stacks {
                    sampled_rows.push(sampled_row);
                    continue;
                }

                rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let idx = (rng_state as usize) % rows_seen;
                if idx < max_stacks {
                    sampled_rows[idx] = sampled_row;
                }
            }
        }

        let mut user_symbolizer = OfflineUserSymbolizer::new();

        let mut folded_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut total_samples = 0usize;

        for row in sampled_rows {
            let labels: Vec<String> = match (row.stack_kind.as_deref(), row.stack_frames.as_deref())
            {
                (Some("user"), Some(frames_hex)) if !frames_hex.is_empty() => {
                    let frames = parse_stack_frames(frames_hex);
                    symbolize_user_frames(
                        &frames,
                        row.proc_maps_snapshot.as_deref(),
                        &mut user_symbolizer,
                    )
                    .await
                }
                (Some("both"), Some(frames_hex)) if !frames_hex.is_empty() => {
                    let frames = parse_stack_frames(frames_hex);
                    let mut labels = symbolize_user_frames(
                        &frames,
                        row.proc_maps_snapshot.as_deref(),
                        &mut user_symbolizer,
                    )
                    .await;
                    if let Some(stack_trace) = row.stack_trace.as_deref() {
                        labels.extend(parse_kernel_labels_from_stack_trace(stack_trace));
                    }
                    labels
                }
                _ => row
                    .stack_trace
                    .unwrap_or_default()
                    .split(';')
                    .filter(|frame| !frame.is_empty())
                    .map(str::to_string)
                    .collect(),
            };

            if labels.is_empty() {
                continue;
            }

            total_samples += 1;
            let folded = labels
                .into_iter()
                .map(|label| sanitize_flame_frame_label(&label))
                .collect::<Vec<_>>()
                .join(";");
            *folded_counts.entry(folded).or_insert(0) += 1;
        }

        let svg = if folded_counts.is_empty() {
            None
        } else {
            Some(render_flamegraph_svg(&event_type, &folded_counts)?)
        };

        Ok(EventFlamegraphResponse {
            event_type,
            total_samples,
            svg,
        })
    }

    // Simple pseudo-random index for reservoir sampling
    fn rand_index(n: usize) -> usize {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        use std::time::{SystemTime, UNIX_EPOCH};

        let mut hasher = DefaultHasher::new();
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        seed.hash(&mut hasher);
        n.hash(&mut hasher);
        (hasher.finish() as usize) % n
    }
}

pub async fn initialize(
    parquet_file: std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    backend::initialize(parquet_file).await
}

pub async fn query_summary() -> Result<TraceSummary, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_summary().await
}

pub async fn query_histogram(
    start_ns: u64,
    end_ns: u64,
    num_buckets: usize,
) -> Result<HistogramResponse, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_histogram(start_ns, end_ns, num_buckets).await
}

pub async fn query_event_type_counts(
    start_ns: Option<u64>,
    end_ns: Option<u64>,
) -> Result<EventTypeCounts, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_event_type_counts(start_ns, end_ns).await
}

pub async fn query_pid_event_type_counts(
    pid: u32,
    start_ns: Option<u64>,
    end_ns: Option<u64>,
) -> Result<EventTypeCounts, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_pid_event_type_counts(pid, start_ns, end_ns).await
}

pub async fn query_syscall_latency_stats(
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
) -> Result<SyscallLatencyStats, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_syscall_latency_stats(start_ns, end_ns, pid).await
}

pub async fn query_process_lifetimes()
-> Result<ProcessLifetimesResponse, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_process_lifetimes().await
}

pub async fn query_process_events(
    start_ns: u64,
    end_ns: u64,
    max_events_per_pid: usize,
) -> Result<ProcessEventsResponse, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_process_events(start_ns, end_ns, max_events_per_pid).await
}

pub async fn query_event_flamegraph(
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
    event_type: String,
    max_stacks: usize,
) -> Result<EventFlamegraphResponse, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_event_flamegraph(start_ns, end_ns, pid, event_type, max_stacks).await
}
