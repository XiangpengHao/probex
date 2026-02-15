//! Viewer backend functionality used by `probex`.
//!
//! Uses DataFusion to query parquet trace files.

pub use probex_common::viewer_api::{
    EventFlamegraphResponse, EventMarker, EventTypeCounts, HistogramBucket, HistogramResponse,
    IoStatistics, IoTypeStats, LatencyBucket, LatencySummary, ProcessEventsResponse,
    ProcessLifetime, ProcessLifetimesResponse, SizeBucket, SyscallLatencyStats, TraceSummary,
};
use std::error::Error;

mod backend {
    use super::*;
    use datafusion::arrow::array::{
        Array, Int32Array, Int64Array, ListArray, StringArray, StringViewArray, UInt32Array,
        UInt64Array,
    };
    use datafusion::arrow::datatypes::DataType;
    use datafusion::prelude::*;
    use inferno::flamegraph;
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use std::fs::File;
    use std::io::{Error as IoError, ErrorKind};
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock};

    static SESSION_CTX: OnceLock<Arc<SessionContext>> = OnceLock::new();
    static TRACE_FILE_METADATA: OnceLock<TraceFileMetadata> = OnceLock::new();

    const PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY: &str = "probex.sample_freq_hz";
    const PARQUET_METADATA_STACK_TRACE_FORMAT_KEY: &str = "probex.stack_trace_format";
    const STACK_TRACE_FORMAT_SYMBOLIZED_V1: &str = "symbolized_v1";
    type BackendResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

    #[derive(Clone, Debug)]
    struct TraceFileMetadata {
        cpu_sample_frequency_hz: u64,
    }

    fn get_ctx() -> BackendResult<&'static Arc<SessionContext>> {
        SESSION_CTX
            .get()
            .ok_or_else(|| "DataFusion session not initialized".into())
    }

    pub async fn initialize(parquet_file: PathBuf) -> BackendResult<()> {
        if SESSION_CTX.get().is_some() {
            return Err(IoError::new(
                ErrorKind::AlreadyExists,
                "DataFusion session is already initialized",
            )
            .into());
        }
        if !parquet_file.exists() {
            return Err(IoError::new(
                ErrorKind::NotFound,
                format!("Parquet file not found: {}", parquet_file.display()),
            )
            .into());
        }

        let metadata = read_trace_file_metadata(&parquet_file)?;
        let _ = TRACE_FILE_METADATA.set(metadata);

        let ctx = SessionContext::new();

        let path_str = parquet_file.to_string_lossy();
        ctx.register_parquet("events", path_str.as_ref(), ParquetReadOptions::default())
            .await?;
        let events_table = ctx.table("events").await?;
        let has_stack_trace = events_table
            .schema()
            .has_column_with_unqualified_name("stack_trace");
        let has_legacy_stack_frames = events_table
            .schema()
            .has_column_with_unqualified_name("stack_frames");
        let has_legacy_proc_maps = events_table
            .schema()
            .has_column_with_unqualified_name("proc_maps_snapshot");

        if !has_stack_trace {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "Trace {} is missing required stack_trace column. Regenerate with current probex.",
                    parquet_file.display()
                ),
            )
            .into());
        }
        if has_legacy_stack_frames || has_legacy_proc_maps {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "Trace {} uses legacy stack columns. Regenerate with current probex.",
                    parquet_file.display()
                ),
            )
            .into());
        }
        let stack_trace_field = events_table
            .schema()
            .field_with_unqualified_name("stack_trace")
            .map_err(|error| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("failed to resolve stack_trace field: {error}"),
                )
            })?;
        let expected_stack_trace_type = DataType::List(Arc::new(
            datafusion::arrow::datatypes::Field::new("item", DataType::Utf8View, true),
        ));
        if stack_trace_field.data_type() != &expected_stack_trace_type {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "column 'stack_trace' must have type List<Utf8View>, got {:?}",
                    stack_trace_field.data_type()
                ),
            )
            .into());
        }

        // Verify we can read the table
        let df = ctx.sql("SELECT COUNT(*) as cnt FROM events").await?;
        let batches = df.collect().await?;
        let count_batch = batches.first().ok_or_else(|| {
            IoError::new(ErrorKind::InvalidData, "COUNT(*) query returned no rows")
        })?;
        let count = extract_i64(count_batch, "cnt", 0)?;

        SESSION_CTX.set(Arc::new(ctx)).map_err(|_| {
            IoError::new(
                ErrorKind::AlreadyExists,
                "DataFusion session already initialized",
            )
        })?;

        log::info!("Loaded {count} events from {:?}", parquet_file);
        Ok(())
    }

    fn read_trace_file_metadata(
        parquet_file: &std::path::Path,
    ) -> BackendResult<TraceFileMetadata> {
        let file = File::open(parquet_file)?;
        let reader = SerializedFileReader::new(file)?;

        let key_value_entries = reader.metadata().file_metadata().key_value_metadata();
        let metadata_value = |key: &str| -> Option<&str> {
            key_value_entries
                .and_then(|entries| entries.iter().find(|entry| entry.key == key))
                .and_then(|entry| entry.value.as_deref())
        };

        let cpu_sample_frequency_hz = metadata_value(PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY)
            .ok_or_else(|| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!(
                        "required parquet metadata key '{}' missing",
                        PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY
                    ),
                )
            })?
            .parse::<u64>()
            .map_err(|error| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!(
                        "invalid '{}' metadata value: {}",
                        PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY, error
                    ),
                )
            })?;
        if cpu_sample_frequency_hz == 0 {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "metadata '{}' must be > 0",
                    PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY
                ),
            )
            .into());
        }
        let stack_trace_format = metadata_value(PARQUET_METADATA_STACK_TRACE_FORMAT_KEY)
            .ok_or_else(|| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!(
                        "required parquet metadata key '{}' missing",
                        PARQUET_METADATA_STACK_TRACE_FORMAT_KEY
                    ),
                )
            })?;
        if stack_trace_format != STACK_TRACE_FORMAT_SYMBOLIZED_V1 {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "metadata '{}' must be '{}', got '{}'",
                    PARQUET_METADATA_STACK_TRACE_FORMAT_KEY,
                    STACK_TRACE_FORMAT_SYMBOLIZED_V1,
                    stack_trace_format
                ),
            )
            .into());
        }

        Ok(TraceFileMetadata {
            cpu_sample_frequency_hz,
        })
    }

    fn extract_string(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> BackendResult<String> {
        let column = batch.column_by_name(col).ok_or_else(|| {
            IoError::new(ErrorKind::InvalidData, format!("missing column '{col}'"))
        })?;
        if let Some(arr) = column.as_any().downcast_ref::<StringViewArray>() {
            if arr.is_null(row) {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    format!("column '{col}' has NULL at row {row}"),
                )
                .into());
            }
            return Ok(arr.value(row).to_string());
        }
        if let Some(arr) = column.as_any().downcast_ref::<StringArray>() {
            if arr.is_null(row) {
                return Err(IoError::new(
                    ErrorKind::InvalidData,
                    format!("column '{col}' has NULL at row {row}"),
                )
                .into());
            }
            return Ok(arr.value(row).to_string());
        }
        Err(IoError::new(
            ErrorKind::InvalidData,
            format!("column '{col}' has unexpected string type"),
        )
        .into())
    }

    fn extract_option_string(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> BackendResult<Option<String>> {
        let column = batch.column_by_name(col).ok_or_else(|| {
            IoError::new(ErrorKind::InvalidData, format!("missing column '{col}'"))
        })?;
        if let Some(arr) = column.as_any().downcast_ref::<StringViewArray>() {
            return Ok(if arr.is_null(row) {
                None
            } else {
                let value = arr.value(row);
                (!value.is_empty()).then(|| value.to_string())
            });
        }
        if let Some(arr) = column.as_any().downcast_ref::<StringArray>() {
            return Ok(if arr.is_null(row) {
                None
            } else {
                let value = arr.value(row);
                (!value.is_empty()).then(|| value.to_string())
            });
        }
        Err(IoError::new(
            ErrorKind::InvalidData,
            format!("column '{col}' has unexpected string type"),
        )
        .into())
    }

    fn extract_option_stack_trace_labels(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        row: usize,
    ) -> BackendResult<Option<Vec<String>>> {
        let column = batch
            .column_by_name("stack_trace")
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "missing column 'stack_trace'"))?;
        let list_array = column.as_any().downcast_ref::<ListArray>().ok_or_else(|| {
            IoError::new(
                ErrorKind::InvalidData,
                "column 'stack_trace' has unexpected type, expected List",
            )
        })?;
        if list_array.is_null(row) {
            return Ok(None);
        }

        let values = list_array.value(row);
        if let Some(arr) = values.as_any().downcast_ref::<StringViewArray>() {
            let mut labels = Vec::with_capacity(arr.len());
            for idx in 0..arr.len() {
                if arr.is_null(idx) {
                    return Err(IoError::new(
                        ErrorKind::InvalidData,
                        "stack_trace label contains NULL",
                    )
                    .into());
                }
                let label = arr.value(idx);
                if !label.is_empty() {
                    labels.push(label.to_string());
                }
            }
            return Ok(Some(labels));
        }
        if let Some(arr) = values.as_any().downcast_ref::<StringArray>() {
            let mut labels = Vec::with_capacity(arr.len());
            for idx in 0..arr.len() {
                if arr.is_null(idx) {
                    return Err(IoError::new(
                        ErrorKind::InvalidData,
                        "stack_trace label contains NULL",
                    )
                    .into());
                }
                let label = arr.value(idx);
                if !label.is_empty() {
                    labels.push(label.to_string());
                }
            }
            return Ok(Some(labels));
        }

        Err(IoError::new(
            ErrorKind::InvalidData,
            "stack_trace list items must be Utf8View/Utf8",
        )
        .into())
    }

    fn extract_u64(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> BackendResult<u64> {
        let arr = batch
            .column_by_name(col)
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, format!("missing column '{col}'")))?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("column '{col}' has unexpected type, expected UInt64"),
                )
            })?;
        if arr.is_null(row) {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!("column '{col}' has NULL at row {row}"),
            )
            .into());
        }
        Ok(arr.value(row))
    }

    fn extract_u32(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> BackendResult<u32> {
        let arr = batch
            .column_by_name(col)
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, format!("missing column '{col}'")))?
            .as_any()
            .downcast_ref::<UInt32Array>()
            .ok_or_else(|| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("column '{col}' has unexpected type, expected UInt32"),
                )
            })?;
        if arr.is_null(row) {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!("column '{col}' has NULL at row {row}"),
            )
            .into());
        }
        Ok(arr.value(row))
    }

    fn extract_option_u64(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> BackendResult<Option<u64>> {
        let arr = batch
            .column_by_name(col)
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, format!("missing column '{col}'")))?
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("column '{col}' has unexpected type, expected UInt64"),
                )
            })?;
        Ok(if arr.is_null(row) {
            None
        } else {
            Some(arr.value(row))
        })
    }

    fn extract_option_u32(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> BackendResult<Option<u32>> {
        let arr = batch
            .column_by_name(col)
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, format!("missing column '{col}'")))?
            .as_any()
            .downcast_ref::<UInt32Array>()
            .ok_or_else(|| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("column '{col}' has unexpected type, expected UInt32"),
                )
            })?;
        Ok(if arr.is_null(row) {
            None
        } else {
            Some(arr.value(row))
        })
    }

    fn extract_option_i32(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> BackendResult<Option<i32>> {
        let arr = batch
            .column_by_name(col)
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, format!("missing column '{col}'")))?
            .as_any()
            .downcast_ref::<Int32Array>()
            .ok_or_else(|| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("column '{col}' has unexpected type, expected Int32"),
                )
            })?;
        Ok(if arr.is_null(row) {
            None
        } else {
            Some(arr.value(row))
        })
    }

    fn extract_i64(
        batch: &datafusion::arrow::record_batch::RecordBatch,
        col: &str,
        row: usize,
    ) -> BackendResult<i64> {
        let arr = batch
            .column_by_name(col)
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, format!("missing column '{col}'")))?
            .as_any()
            .downcast_ref::<Int64Array>()
            .ok_or_else(|| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("column '{col}' has unexpected type, expected Int64"),
                )
            })?;
        if arr.is_null(row) {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!("column '{col}' has NULL at row {row}"),
            )
            .into());
        }
        Ok(arr.value(row))
    }

    pub async fn query_histogram(
        start_ns: u64,
        end_ns: u64,
        num_buckets: usize,
    ) -> BackendResult<HistogramResponse> {
        if end_ns < start_ns {
            return Err(IoError::new(ErrorKind::InvalidInput, "end_ns must be >= start_ns").into());
        }
        if num_buckets == 0 {
            return Err(IoError::new(ErrorKind::InvalidInput, "num_buckets must be > 0").into());
        }
        let ctx = get_ctx()?;

        let range = end_ns.saturating_sub(start_ns);
        let bucket_count = num_buckets;
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
                let bucket_idx = extract_i64(batch, "bucket_idx", row)?;
                let event_type = extract_string(batch, "event_type", row)?;
                let cnt = extract_i64(batch, "cnt", row)? as usize;

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
    ) -> BackendResult<EventTypeCounts> {
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
                let event_type = extract_string(batch, "event_type", row)?;
                let cnt = extract_i64(batch, "cnt", row)? as usize;
                counts.insert(event_type, cnt);
            }
        }

        Ok(EventTypeCounts { counts })
    }

    pub async fn query_pid_event_type_counts(
        pid: u32,
        start_ns: Option<u64>,
        end_ns: Option<u64>,
    ) -> BackendResult<EventTypeCounts> {
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
                let event_type = extract_string(batch, "event_type", row)?;
                let cnt = extract_i64(batch, "cnt", row)? as usize;
                counts.insert(event_type, cnt);
            }
        }

        Ok(EventTypeCounts { counts })
    }

    pub async fn query_syscall_latency_stats(
        start_ns: u64,
        end_ns: u64,
        pid: Option<u32>,
    ) -> BackendResult<SyscallLatencyStats> {
        if end_ns < start_ns {
            return Err(IoError::new(ErrorKind::InvalidInput, "end_ns must be >= start_ns").into());
        }
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
                let pid = extract_u32(batch, "pid", row)?;
                let ts = extract_u64(batch, "ts_ns", row)?;
                let event_type = extract_string(batch, "event_type", row)?;
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
                        let count = extract_option_u64(batch, "count", row)?.ok_or_else(|| {
                            IoError::new(
                                ErrorKind::InvalidData,
                                "syscall_mmap_enter row missing required count",
                            )
                        })?;
                        mmap_alloc_bytes = mmap_alloc_bytes.saturating_add(count);
                    }
                    "syscall_munmap_enter" => {
                        let count = extract_option_u64(batch, "count", row)?.ok_or_else(|| {
                            IoError::new(
                                ErrorKind::InvalidData,
                                "syscall_munmap_enter row missing required count",
                            )
                        })?;
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
        let max_ns = *sorted
            .last()
            .expect("sorted must be non-empty when latencies is non-empty");

        LatencySummary {
            count,
            avg_ns,
            p50_ns: sorted[p50_idx],
            p95_ns: sorted[p95_idx],
            max_ns,
        }
    }

    pub async fn query_summary() -> BackendResult<TraceSummary> {
        let ctx = get_ctx()?;

        // Get total count
        let count_df = ctx.sql("SELECT COUNT(*) as cnt FROM events").await?;
        let count_batches = count_df.collect().await?;
        let count_batch = count_batches.first().ok_or_else(|| {
            IoError::new(ErrorKind::InvalidData, "COUNT(*) query returned no rows")
        })?;
        let total_events = extract_i64(count_batch, "cnt", 0)? as usize;

        // Get distinct event types
        let types_df = ctx
            .sql("SELECT DISTINCT event_type FROM events ORDER BY event_type")
            .await?;
        let types_batches = types_df.collect().await?;
        let mut event_types: Vec<String> = Vec::new();
        for batch in &types_batches {
            for i in 0..batch.num_rows() {
                event_types.push(extract_string(batch, "event_type", i)?);
            }
        }

        // Get distinct PIDs
        let pids_df = ctx
            .sql("SELECT DISTINCT pid FROM events ORDER BY pid")
            .await?;
        let pids_batches = pids_df.collect().await?;
        let mut unique_pids: Vec<u32> = Vec::new();
        for batch in &pids_batches {
            for i in 0..batch.num_rows() {
                unique_pids.push(extract_u32(batch, "pid", i)?);
            }
        }

        // Get time range
        let time_df = ctx
            .sql("SELECT MIN(ts_ns) as min_ts, MAX(ts_ns) as max_ts FROM events")
            .await?;
        let time_batches = time_df.collect().await?;
        let (min_ts_ns, max_ts_ns) = if total_events == 0 {
            (0, 0)
        } else if let Some(batch) = time_batches.first() {
            (
                extract_u64(batch, "min_ts", 0)?,
                extract_u64(batch, "max_ts", 0)?,
            )
        } else {
            return Err(IoError::new(ErrorKind::InvalidData, "missing min/max result row").into());
        };

        Ok(TraceSummary {
            total_events,
            event_types,
            unique_pids,
            min_ts_ns,
            max_ts_ns,
            cpu_sample_frequency_hz: TRACE_FILE_METADATA
                .get()
                .ok_or_else(|| {
                    IoError::new(ErrorKind::InvalidData, "trace metadata not initialized")
                })?
                .cpu_sample_frequency_hz,
        })
    }

    pub async fn query_process_lifetimes() -> BackendResult<ProcessLifetimesResponse> {
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

        let name_sql = "SELECT pid, process_name, ts_ns FROM events
            WHERE process_name IS NOT NULL AND process_name <> ''
            ORDER BY ts_ns";
        let name_df = ctx.sql(name_sql).await?;
        let name_batches = name_df.collect().await?;

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
                let child_pid = extract_option_u32(batch, "child_pid", row)?;
                let parent_pid = extract_option_u32(batch, "parent_pid", row)?;
                let ts = extract_u64(batch, "ts_ns", row)?;
                if let (Some(child), Some(parent)) = (child_pid, parent_pid) {
                    fork_info.entry(child).or_insert((parent, ts));
                }
            }
        }

        // Parse exit events
        for batch in &exit_batches {
            for row in 0..batch.num_rows() {
                let pid = extract_u32(batch, "pid", row)?;
                let exit_code = extract_option_i32(batch, "exit_code", row)?.ok_or_else(|| {
                    IoError::new(
                        ErrorKind::InvalidData,
                        "process_exit row missing required exit_code",
                    )
                })?;
                let ts = extract_u64(batch, "ts_ns", row)?;
                exit_info.entry(pid).or_insert((exit_code, ts));
            }
        }

        // Parse first/last times
        for batch in &times_batches {
            for row in 0..batch.num_rows() {
                let pid = extract_u32(batch, "pid", row)?;
                let first = extract_u64(batch, "first_seen", row)?;
                let last = extract_u64(batch, "last_seen", row)?;
                pid_times.insert(pid, (first, last));
            }
        }

        // Parse process names (keep first-seen non-empty name for each PID)
        for batch in &name_batches {
            for row in 0..batch.num_rows() {
                let pid = extract_u32(batch, "pid", row)?;
                if let Some(name) = extract_option_string(batch, "process_name", row)? {
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
    ) -> BackendResult<ProcessEventsResponse> {
        const CPU_SAMPLE_BUCKETS_MAX: usize = 600;
        const CPU_SAMPLE_TARGET_SAMPLES_PER_BUCKET: f64 = 3.0;

        if end_ns < start_ns {
            return Err(IoError::new(ErrorKind::InvalidInput, "end_ns must be >= start_ns").into());
        }
        if max_events_per_pid == 0 {
            return Err(
                IoError::new(ErrorKind::InvalidInput, "max_events_per_pid must be > 0").into(),
            );
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

        let sample_frequency_hz = TRACE_FILE_METADATA
            .get()
            .ok_or_else(|| IoError::new(ErrorKind::InvalidData, "trace metadata not initialized"))?
            .cpu_sample_frequency_hz;
        let range_ns = end_ns.saturating_sub(start_ns).max(1);
        let expected_samples_total =
            (sample_frequency_hz as f64) * (range_ns as f64 / 1_000_000_000.0);
        let max_buckets_by_density =
            ((expected_samples_total / CPU_SAMPLE_TARGET_SAMPLES_PER_BUCKET).floor() as usize)
                .max(1);
        let cpu_sample_bucket_count = max_buckets_by_density.min(CPU_SAMPLE_BUCKETS_MAX);
        let bucket_size_ns = range_ns.div_ceil(cpu_sample_bucket_count as u64).max(1);

        let mut rng_state = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};

            let mut hasher = DefaultHasher::new();
            start_ns.hash(&mut hasher);
            end_ns.hash(&mut hasher);
            max_events_per_pid.hash(&mut hasher);
            hasher.finish() | 1
        };

        for batch in &batches {
            for row in 0..batch.num_rows() {
                let pid = extract_u32(batch, "pid", row)?;
                let ts_ns = extract_u64(batch, "ts_ns", row)?;
                let event_type = extract_string(batch, "event_type", row)?;

                if event_type == "cpu_sample" {
                    let mut bucket_idx = ts_ns.saturating_sub(start_ns) / bucket_size_ns;
                    if bucket_idx >= cpu_sample_bucket_count as u64 {
                        bucket_idx = (cpu_sample_bucket_count - 1) as u64;
                    }
                    let counts = cpu_sample_counts_by_pid
                        .entry(pid)
                        .or_insert_with(|| vec![0u16; cpu_sample_bucket_count]);
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
                    rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let idx = (rng_state as usize) % *seen;
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
            cpu_sample_bucket_count,
        })
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
        opts.title = format!("probex · {event_type}");
        opts.count_name = "samples".to_string();
        opts.colors = flamegraph::Palette::Basic(flamegraph::color::BasicPalette::Aqua);
        opts.bgcolors = Some(flamegraph::color::BackgroundColor::Blue);
        opts.hash = true;
        opts.deterministic = true;

        let input = folded_lines.iter().map(String::as_str);
        let mut svg = Vec::<u8>::new();
        flamegraph::from_lines(&mut opts, input, &mut svg)?;
        Ok(String::from_utf8(svg)?)
    }

    pub async fn query_io_statistics(
        start_ns: u64,
        end_ns: u64,
        pid: Option<u32>,
    ) -> BackendResult<IoStatistics> {
        if end_ns < start_ns {
            return Err(IoError::new(ErrorKind::InvalidInput, "end_ns must be >= start_ns").into());
        }
        let ctx = get_ctx()?;

        let pid_filter = pid
            .map(|p| format!("AND pid = {}", p))
            .unwrap_or_default();

        let sql = format!(
            "SELECT io_type, latency_ns, request_bytes, actual_bytes
             FROM events
             WHERE event_type = 'io_complete'
               AND ts_ns >= {start_ns}
               AND ts_ns <= {end_ns}
               {pid_filter}"
        );

        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        // Collect (latency, actual_bytes) per io_type, plus all sizes for the combined histogram
        let mut ops_data: std::collections::HashMap<String, Vec<(u64, u64)>> =
            std::collections::HashMap::new();
        let mut all_sizes: Vec<u64> = Vec::new();
        let mut total_ops: u64 = 0;
        let mut total_bytes: u64 = 0;

        for batch in &batches {
            for row in 0..batch.num_rows() {
                let io_type = extract_option_string(batch, "io_type", row)?
                    .unwrap_or_else(|| "unknown".to_string());
                let latency = extract_option_u64(batch, "latency_ns", row)?.unwrap_or(0);
                let actual = extract_option_u64(batch, "actual_bytes", row)?.unwrap_or(0);

                ops_data
                    .entry(io_type)
                    .or_default()
                    .push((latency, actual));
                all_sizes.push(actual);
                total_ops += 1;
                total_bytes = total_bytes.saturating_add(actual);
            }
        }

        let mut by_operation: Vec<IoTypeStats> = ops_data
            .into_iter()
            .map(|(op, data)| compute_io_type_stats(op, data))
            .collect();
        by_operation.sort_by(|a, b| b.total_ops.cmp(&a.total_ops));

        Ok(IoStatistics {
            by_operation,
            size_histogram: compute_size_histogram(&all_sizes),
            total_ops,
            total_bytes,
            time_range_ns: (start_ns, end_ns),
        })
    }

    fn compute_io_type_stats(operation: String, mut data: Vec<(u64, u64)>) -> IoTypeStats {
        data.sort_by_key(|(lat, _)| *lat);

        let total_ops = data.len() as u64;
        let total_bytes: u64 = data.iter().map(|(_, b)| *b).sum();
        let total_latency: u128 = data.iter().map(|(l, _)| *l as u128).sum();

        let avg_latency_ns = if total_ops > 0 {
            (total_latency / total_ops as u128) as u64
        } else {
            0
        };
        let p50_ns = percentile_latency(&data, 50);
        let p95_ns = percentile_latency(&data, 95);
        let p99_ns = percentile_latency(&data, 99);
        let max_ns = data.last().map(|(l, _)| *l).unwrap_or(0);

        let latency_histogram = latency_bucket_ranges()
            .into_iter()
            .map(|(min, max, label)| {
                let count = data
                    .iter()
                    .filter(|(l, _)| *l >= min && *l < max)
                    .count() as u64;
                LatencyBucket {
                    min_ns: min,
                    max_ns: max,
                    count,
                    label: label.to_string(),
                }
            })
            .collect();

        IoTypeStats {
            operation,
            total_ops,
            total_bytes,
            avg_latency_ns,
            p50_ns,
            p95_ns,
            p99_ns,
            max_ns,
            latency_histogram,
        }
    }

    fn percentile_latency(sorted_data: &[(u64, u64)], pct: usize) -> u64 {
        if sorted_data.is_empty() {
            return 0;
        }
        let idx = (sorted_data.len() * pct / 100).min(sorted_data.len() - 1);
        sorted_data[idx].0
    }

    fn latency_bucket_ranges() -> Vec<(u64, u64, &'static str)> {
        vec![
            (0, 1_000, "<1us"),
            (1_000, 10_000, "1-10us"),
            (10_000, 100_000, "10-100us"),
            (100_000, 1_000_000, "100us-1ms"),
            (1_000_000, 10_000_000, "1-10ms"),
            (10_000_000, 100_000_000, "10-100ms"),
            (100_000_000, 1_000_000_000, "100ms-1s"),
            (1_000_000_000, u64::MAX, ">1s"),
        ]
    }

    fn compute_size_histogram(sizes: &[u64]) -> Vec<SizeBucket> {
        let ranges: Vec<(u64, u64, &str)> = vec![
            (0, 64, "<64B"),
            (64, 512, "64-512B"),
            (512, 4_096, "512B-4KB"),
            (4_096, 65_536, "4-64KB"),
            (65_536, 1_048_576, "64KB-1MB"),
            (1_048_576, 16_777_216, "1-16MB"),
            (16_777_216, u64::MAX, ">16MB"),
        ];
        ranges
            .into_iter()
            .map(|(min, max, label)| {
                let count = sizes.iter().filter(|&&s| s >= min && s < max).count() as u64;
                SizeBucket {
                    min_bytes: min,
                    max_bytes: max,
                    count,
                    label: label.to_string(),
                }
            })
            .collect()
    }

    pub async fn query_event_flamegraph(
        start_ns: u64,
        end_ns: u64,
        pid: Option<u32>,
        event_type: String,
        max_stacks: usize,
    ) -> BackendResult<EventFlamegraphResponse> {
        let ctx = get_ctx()?;
        if end_ns < start_ns {
            return Err(IoError::new(ErrorKind::InvalidInput, "end_ns must be >= start_ns").into());
        }
        if event_type.is_empty() {
            return Err(
                IoError::new(ErrorKind::InvalidInput, "event_type must not be empty").into(),
            );
        }
        if max_stacks == 0 {
            return Err(IoError::new(ErrorKind::InvalidInput, "max_stacks must be > 0").into());
        }

        let mut conditions = vec![
            format!("ts_ns >= {}", start_ns),
            format!("ts_ns <= {}", end_ns),
            format!("event_type = '{}'", event_type.replace('\'', "''")),
            "(stack_trace IS NOT NULL)".to_string(),
        ];
        if let Some(pid) = pid {
            conditions.push(format!("pid = {}", pid));
        }

        let sql = format!(
            "SELECT stack_trace
             FROM events
             WHERE {}",
            conditions.join(" AND ")
        );
        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        let mut sampled_stack_traces: Vec<Vec<String>> = Vec::new();
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
                let Some(stack_trace_labels) = extract_option_stack_trace_labels(batch, row)?
                else {
                    continue;
                };
                if stack_trace_labels.is_empty() {
                    continue;
                }

                rows_seen += 1;
                if sampled_stack_traces.len() < max_stacks {
                    sampled_stack_traces.push(stack_trace_labels);
                    continue;
                }

                rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
                let idx = (rng_state as usize) % rows_seen;
                if idx < max_stacks {
                    sampled_stack_traces[idx] = stack_trace_labels;
                }
            }
        }

        let mut folded_counts: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        let mut total_samples = 0usize;

        for labels in sampled_stack_traces {
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

pub async fn query_io_statistics(
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
) -> Result<IoStatistics, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_io_statistics(start_ns, end_ns, pid).await
}
