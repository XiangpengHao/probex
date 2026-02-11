//! Server-side functionality for snitch-viewer.
//!
//! Uses DataFusion to query parquet trace files and exposes server functions
//! for the Dioxus frontend.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Trace event structure matching the parquet schema from snitch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TraceEvent {
    pub event_type: String,
    pub ts_ns: u64,
    pub pid: u32,
    pub process_name: Option<String>,
    pub cpu: u8,
    // SchedSwitch fields
    pub prev_pid: Option<u32>,
    pub next_pid: Option<u32>,
    pub prev_state: Option<i64>,
    // ProcessFork fields
    pub parent_pid: Option<u32>,
    pub child_pid: Option<u32>,
    // ProcessExit fields
    pub exit_code: Option<i32>,
    // PageFault fields
    pub address: Option<u64>,
    pub error_code: Option<u64>,
    // Syscall fields
    pub fd: Option<i64>,
    pub count: Option<u64>,
    pub ret: Option<i64>,
}

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

/// Filters for querying events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilters {
    pub event_type: Option<String>,
    pub event_types: Vec<String>,
    pub pid: Option<u32>,
    pub start_ns: Option<u64>,
    pub end_ns: Option<u64>,
    pub limit: usize,
    pub offset: usize,
}

/// Summary statistics about the trace.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TraceSummary {
    pub total_events: usize,
    pub event_types: Vec<String>,
    pub unique_pids: Vec<u32>,
    pub min_ts_ns: u64,
    pub max_ts_ns: u64,
}

/// Response containing events and metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsResponse {
    pub events: Vec<TraceEvent>,
    pub total_count: usize,
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
}

#[cfg(feature = "server")]
mod backend {
    use super::*;
    use datafusion::arrow::array::{
        Array, Int32Array, Int64Array, StringViewArray, UInt8Array, UInt32Array, UInt64Array,
    };
    use datafusion::prelude::*;
    use std::io::{Error as IoError, ErrorKind};
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    static SESSION_CTX: OnceLock<Arc<SessionContext>> = OnceLock::new();

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

        let ctx = SessionContext::new();

        let path_str = parquet_file.to_string_lossy();
        ctx.register_parquet("events", path_str.as_ref(), ParquetReadOptions::default())
            .await?;

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

    fn extract_u8(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> u8 {
        batch
            .column_by_name(col)
            .and_then(|c| c.as_any().downcast_ref::<UInt8Array>())
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

    fn extract_option_i64(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> Option<i64> {
        batch
            .column_by_name(col)
            .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
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

    fn build_where_clause(filters: &EventFilters) -> String {
        let mut conditions = Vec::new();

        // Single event type filter (legacy)
        if let Some(ref event_type) = filters.event_type {
            if !event_type.is_empty() {
                conditions.push(format!("event_type = '{}'", event_type.replace('\'', "''")));
            }
        }

        // Multiple event types filter
        if !filters.event_types.is_empty() {
            let types: Vec<String> = filters
                .event_types
                .iter()
                .map(|t| format!("'{}'", t.replace('\'', "''")))
                .collect();
            conditions.push(format!("event_type IN ({})", types.join(", ")));
        }

        // PID filter
        if let Some(pid) = filters.pid {
            conditions.push(format!("pid = {}", pid));
        }

        // Time range filter
        if let Some(start) = filters.start_ns {
            conditions.push(format!("ts_ns >= {}", start));
        }
        if let Some(end) = filters.end_ns {
            conditions.push(format!("ts_ns <= {}", end));
        }

        if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        }
    }

    pub async fn query_events(
        filters: EventFilters,
    ) -> Result<EventsResponse, Box<dyn std::error::Error + Send + Sync>> {
        let ctx = get_ctx()?;

        let where_clause = build_where_clause(&filters);

        // Get total count
        let count_sql = format!("SELECT COUNT(*) as cnt FROM events {}", where_clause);
        let count_df = ctx.sql(&count_sql).await?;
        let count_batches = count_df.collect().await?;
        let total_count = count_batches
            .first()
            .and_then(|b| b.column(0).as_any().downcast_ref::<Int64Array>())
            .map(|arr| arr.value(0) as usize)
            .unwrap_or(0);

        // Query events with pagination
        let limit = if filters.limit == 0 {
            100
        } else {
            filters.limit
        };
        let sql = format!(
            "SELECT * FROM events {} ORDER BY ts_ns ASC LIMIT {} OFFSET {}",
            where_clause, limit, filters.offset
        );

        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        let mut events = Vec::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                let event = TraceEvent {
                    event_type: extract_string(batch, "event_type", row),
                    ts_ns: extract_u64(batch, "ts_ns", row),
                    pid: extract_u32(batch, "pid", row),
                    process_name: extract_option_string(batch, "process_name", row),
                    cpu: extract_u8(batch, "cpu", row),
                    prev_pid: extract_option_u32(batch, "prev_pid", row),
                    next_pid: extract_option_u32(batch, "next_pid", row),
                    prev_state: extract_option_i64(batch, "prev_state", row),
                    parent_pid: extract_option_u32(batch, "parent_pid", row),
                    child_pid: extract_option_u32(batch, "child_pid", row),
                    exit_code: extract_option_i32(batch, "exit_code", row),
                    address: extract_option_u64(batch, "address", row),
                    error_code: extract_option_u64(batch, "error_code", row),
                    fd: extract_option_i64(batch, "fd", row),
                    count: extract_option_u64(batch, "count", row),
                    ret: extract_option_i64(batch, "ret", row),
                };
                events.push(event);
            }
        }

        Ok(EventsResponse {
            events,
            total_count,
        })
    }

    pub async fn query_histogram(
        start_ns: u64,
        end_ns: u64,
        num_buckets: usize,
    ) -> Result<HistogramResponse, Box<dyn std::error::Error + Send + Sync>> {
        let ctx = get_ctx()?;

        let range = end_ns.saturating_sub(start_ns);
        let bucket_size = if num_buckets > 0 && range > 0 {
            range / num_buckets as u64
        } else {
            1
        };

        // Query to get counts grouped by bucket and event type
        let sql = format!(
            "SELECT
                FLOOR((ts_ns - {}) / {}) as bucket_idx,
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

        // Build buckets
        let mut bucket_map: std::collections::HashMap<i64, HistogramBucket> =
            std::collections::HashMap::new();

        let mut total_in_range = 0usize;

        for batch in &batches {
            for row in 0..batch.num_rows() {
                let bucket_idx = batch
                    .column_by_name("bucket_idx")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .map(|arr| arr.value(row))
                    .unwrap_or(0);

                let event_type = extract_string(batch, "event_type", row);
                let cnt = batch
                    .column_by_name("cnt")
                    .and_then(|c| c.as_any().downcast_ref::<Int64Array>())
                    .map(|arr| arr.value(row) as usize)
                    .unwrap_or(0);

                total_in_range += cnt;

                let bucket = bucket_map.entry(bucket_idx).or_insert_with(|| {
                    let bucket_start = start_ns + (bucket_idx as u64 * bucket_size);
                    let bucket_end = bucket_start + bucket_size;
                    HistogramBucket {
                        bucket_start_ns: bucket_start,
                        bucket_end_ns: bucket_end.min(end_ns),
                        count: 0,
                        counts_by_type: std::collections::HashMap::new(),
                    }
                });

                bucket.count += cnt;
                *bucket.counts_by_type.entry(event_type).or_insert(0) += cnt;
            }
        }

        let mut buckets: Vec<HistogramBucket> = bucket_map.into_values().collect();
        buckets.sort_by_key(|b| b.bucket_start_ns);

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
        let mut read_latencies: Vec<u64> = Vec::new();
        let mut write_latencies: Vec<u64> = Vec::new();
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
                        if let Some(queue) = pending_read.get_mut(&pid) {
                            if let Some(start_ts) = queue.pop_front() {
                                if ts >= start_ts {
                                    read_latencies.push(ts - start_ts);
                                }
                            }
                        }
                    }
                    "syscall_write_enter" => pending_write.entry(pid).or_default().push_back(ts),
                    "syscall_write_exit" => {
                        if let Some(queue) = pending_write.get_mut(&pid) {
                            if let Some(start_ts) = queue.pop_front() {
                                if ts >= start_ts {
                                    write_latencies.push(ts - start_ts);
                                }
                            }
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

        for batch in &batches {
            for row in 0..batch.num_rows() {
                let pid = extract_u32(batch, "pid", row);
                let ts_ns = extract_u64(batch, "ts_ns", row);
                let event_type = extract_string(batch, "event_type", row);

                let events = events_by_pid.entry(pid).or_insert_with(Vec::new);

                // Sample events if we have too many for this PID
                if events.len() < max_events_per_pid {
                    events.push(EventMarker { ts_ns, event_type });
                } else {
                    // Reservoir sampling: replace with decreasing probability
                    let idx = rand_index(events.len() + 1);
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

        Ok(ProcessEventsResponse { events_by_pid })
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

#[cfg(feature = "server")]
pub async fn initialize(
    parquet_file: std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    backend::initialize(parquet_file).await
}

#[server]
pub async fn get_events(filters: EventFilters) -> Result<EventsResponse, ServerFnError> {
    backend::query_events(filters)
        .await
        .map_err(|e| ServerFnError::new(format!("Query failed: {}", e)))
}

#[server]
pub async fn get_summary() -> Result<TraceSummary, ServerFnError> {
    backend::query_summary()
        .await
        .map_err(|e| ServerFnError::new(format!("Summary query failed: {}", e)))
}

#[server]
pub async fn get_histogram(
    start_ns: u64,
    end_ns: u64,
    num_buckets: usize,
) -> Result<HistogramResponse, ServerFnError> {
    backend::query_histogram(start_ns, end_ns, num_buckets)
        .await
        .map_err(|e| ServerFnError::new(format!("Histogram query failed: {}", e)))
}

#[server]
pub async fn get_event_type_counts(
    start_ns: Option<u64>,
    end_ns: Option<u64>,
) -> Result<EventTypeCounts, ServerFnError> {
    backend::query_event_type_counts(start_ns, end_ns)
        .await
        .map_err(|e| ServerFnError::new(format!("Event type counts query failed: {}", e)))
}

#[server]
pub async fn get_pid_event_type_counts(
    pid: u32,
    start_ns: Option<u64>,
    end_ns: Option<u64>,
) -> Result<EventTypeCounts, ServerFnError> {
    backend::query_pid_event_type_counts(pid, start_ns, end_ns)
        .await
        .map_err(|e| ServerFnError::new(format!("PID event counts query failed: {}", e)))
}

#[server]
pub async fn get_syscall_latency_stats(
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
) -> Result<SyscallLatencyStats, ServerFnError> {
    backend::query_syscall_latency_stats(start_ns, end_ns, pid)
        .await
        .map_err(|e| ServerFnError::new(format!("Syscall latency stats query failed: {}", e)))
}

#[server]
pub async fn get_process_lifetimes() -> Result<ProcessLifetimesResponse, ServerFnError> {
    backend::query_process_lifetimes()
        .await
        .map_err(|e| ServerFnError::new(format!("Process lifetimes query failed: {}", e)))
}

#[server]
pub async fn get_process_events(
    start_ns: u64,
    end_ns: u64,
    max_events_per_pid: usize,
) -> Result<ProcessEventsResponse, ServerFnError> {
    backend::query_process_events(start_ns, end_ns, max_events_per_pid)
        .await
        .map_err(|e| ServerFnError::new(format!("Process events query failed: {}", e)))
}
