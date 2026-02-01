//! Server-side functionality for snitch-viewer.
//!
//! Uses DataFusion to query parquet trace files and exposes server functions
//! for the Dioxus frontend.

use dioxus::prelude::*;
use serde::{Deserialize, Serialize};

/// Trace event structure matching the parquet schema from snitch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TraceEvent {
    pub event_type: String,
    pub ts_ns: u64,
    pub pid: u32,
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

/// Filters for querying events.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EventFilters {
    pub event_type: Option<String>,
    pub pid: Option<u32>,
    pub limit: usize,
    pub offset: usize,
}

/// Summary statistics about the trace.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

#[cfg(feature = "server")]
mod backend {
    use super::*;
    use datafusion::arrow::array::{
        Array, Int32Array, Int64Array, StringArray, UInt32Array, UInt64Array, UInt8Array,
    };
    use datafusion::prelude::*;
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    static PARQUET_FILE: OnceLock<PathBuf> = OnceLock::new();
    static SESSION_CTX: OnceLock<Arc<SessionContext>> = OnceLock::new();

    pub fn set_parquet_file(path: PathBuf) {
        PARQUET_FILE.set(path).ok();
    }

    fn get_ctx() -> Result<&'static Arc<SessionContext>, Box<dyn std::error::Error + Send + Sync>> {
        SESSION_CTX
            .get()
            .ok_or_else(|| "DataFusion session not initialized".into())
    }

    pub async fn init_datafusion() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let parquet_file = PARQUET_FILE.get().ok_or("Parquet file not set")?;
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

        SESSION_CTX.set(Arc::new(ctx)).ok();
        log::info!("Loaded {} events from {:?}", count, parquet_file);
        Ok(())
    }

    fn extract_string(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> String {
        batch
            .column_by_name(col)
            .and_then(|c| c.as_any().downcast_ref::<StringArray>())
            .map(|arr| {
                if arr.is_null(row) {
                    String::new()
                } else {
                    arr.value(row).to_string()
                }
            })
            .unwrap_or_default()
    }

    fn extract_u64(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> u64 {
        batch
            .column_by_name(col)
            .and_then(|c| c.as_any().downcast_ref::<UInt64Array>())
            .map(|arr| {
                if arr.is_null(row) {
                    0
                } else {
                    arr.value(row)
                }
            })
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
            .map(|arr| {
                if arr.is_null(row) {
                    0
                } else {
                    arr.value(row)
                }
            })
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
            .map(|arr| {
                if arr.is_null(row) {
                    0
                } else {
                    arr.value(row)
                }
            })
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

    pub async fn query_events(
        filters: EventFilters,
    ) -> Result<EventsResponse, Box<dyn std::error::Error + Send + Sync>> {
        let ctx = get_ctx()?;

        // Build WHERE clause
        let mut conditions = Vec::new();
        if let Some(ref event_type) = filters.event_type {
            if !event_type.is_empty() {
                conditions.push(format!("event_type = '{}'", event_type.replace('\'', "''")));
            }
        }
        if let Some(pid) = filters.pid {
            conditions.push(format!("pid = {}", pid));
        }

        let where_clause = if conditions.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", conditions.join(" AND "))
        };

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
        let limit = if filters.limit == 0 { 100 } else { filters.limit };
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
            .flat_map(|b| {
                (0..b.num_rows()).map(move |i| extract_string(b, "event_type", i))
            })
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
}

#[cfg(feature = "server")]
pub use backend::init_datafusion;
#[cfg(feature = "server")]
pub use backend::set_parquet_file;

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
