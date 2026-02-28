//! Viewer backend functionality used by `probex`.
//!
//! Uses DataFusion to query parquet trace files.

pub use probex_common::viewer_api::{
    CumulativeMemoryPoint, CustomEventDebugField, CustomEventDebugRow, CustomEventField,
    CustomEventPayload, CustomEventsDebugResponse, CustomPayloadSchema, CustomPayloadTypeKind,
    EventDetail, EventFlamegraphResponse, EventListResponse, EventMarker, EventTypeCounts,
    HistogramBucket, HistogramResponse, IoStatistics, IoTypeStats, LatencySummary,
    MemoryStatistics, ProbeSchema, ProbeSchemaKind, ProbeSchemaSource, ProbeSchemasPageResponse,
    ProbeSchemasResponse, ProcessEventsResponse, ProcessLifetime, ProcessLifetimesResponse,
    SyscallLatencyStats, TraceSummary,
};
use std::error::Error;

mod backend {
    use super::*;
    use crate::{viewer_privileged_daemon_client, viewer_probe_catalog};
    use datafusion::arrow::array::{
        Array, Int32Array, Int64Array, ListArray, StringArray, StringViewArray, UInt32Array,
        UInt64Array,
    };
    use datafusion::arrow::datatypes::DataType;
    use datafusion::prelude::*;
    use inferno::flamegraph;
    use parquet::file::reader::{FileReader, SerializedFileReader};
    use serde::Deserialize;
    use std::fs::File;
    use std::io::{Error as IoError, ErrorKind};
    use std::path::PathBuf;
    use std::sync::{Arc, OnceLock, RwLock};

    static LOADED_TRACE: OnceLock<RwLock<Option<LoadedTrace>>> = OnceLock::new();

    const PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY: &str = "probex.sample_freq_hz";
    const PARQUET_METADATA_STACK_TRACE_FORMAT_KEY: &str = "probex.stack_trace_format";
    const PARQUET_METADATA_CUSTOM_PAYLOAD_SCHEMAS_KEY: &str = "probex.custom_payload_schemas_v1";
    const STACK_TRACE_FORMAT_SYMBOLIZED_V1: &str = "symbolized_v1";
    type BackendResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

    fn looks_like_permission_error(error_text: &str) -> bool {
        let lower = error_text.to_ascii_lowercase();
        lower.contains("permission denied")
            || lower.contains("operation not permitted")
            || lower.contains("eperm")
            || lower.contains("eacces")
    }

    fn wants_function_kinds(query: &viewer_probe_catalog::ProbeSchemasQuery) -> bool {
        query.kinds.as_ref().is_none_or(|kinds| {
            kinds
                .iter()
                .any(|kind| matches!(kind, ProbeSchemaKind::Fentry | ProbeSchemaKind::Fexit))
        })
    }

    fn to_privileged_query(
        query: viewer_probe_catalog::ProbeSchemasQuery,
    ) -> probex_common::viewer_api::PrivilegedProbeSchemasQuery {
        probex_common::viewer_api::PrivilegedProbeSchemasQuery {
            search: query.search,
            category: query.category,
            provider: query.provider,
            kinds: query.kinds,
            source: query.source,
            offset: query.offset,
            limit: query.limit,
            include_fields: query.include_fields,
        }
    }

    #[derive(Debug, Deserialize)]
    struct JsonPayloadValue {
        field_id: u16,
        name: String,
        type_kind: String,
        value_u64: u64,
        value_i64: Option<i64>,
    }

    #[derive(Clone, Debug)]
    struct TraceFileMetadata {
        cpu_sample_frequency_hz: u64,
        _custom_payload_schemas: Vec<CustomPayloadSchema>,
    }

    #[derive(Clone)]
    struct LoadedTrace {
        ctx: Arc<SessionContext>,
        metadata: TraceFileMetadata,
    }

    fn loaded_trace_lock() -> &'static RwLock<Option<LoadedTrace>> {
        LOADED_TRACE.get_or_init(|| RwLock::new(None))
    }

    fn get_loaded_trace() -> BackendResult<LoadedTrace> {
        loaded_trace_lock()
            .read()
            .map_err(|_| IoError::other("failed to lock loaded trace state"))?
            .clone()
            .ok_or_else(|| "DataFusion session not initialized".into())
    }

    fn get_ctx() -> BackendResult<Arc<SessionContext>> {
        Ok(get_loaded_trace()?.ctx)
    }

    fn get_trace_metadata() -> BackendResult<TraceFileMetadata> {
        Ok(get_loaded_trace()?.metadata)
    }

    pub async fn initialize(parquet_file: PathBuf) -> BackendResult<()> {
        load_trace_file(parquet_file).await?;
        Ok(())
    }

    pub async fn load_trace_file(parquet_file: PathBuf) -> BackendResult<()> {
        if !parquet_file.exists() {
            return Err(IoError::new(
                ErrorKind::NotFound,
                format!("Parquet file not found: {}", parquet_file.display()),
            )
            .into());
        }

        let metadata = read_trace_file_metadata(&parquet_file)?;

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
        let has_custom_schema_id = events_table
            .schema()
            .has_column_with_unqualified_name("custom_schema_id");
        let has_custom_payload_json = events_table
            .schema()
            .has_column_with_unqualified_name("custom_payload_json");

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
        if !has_custom_schema_id || !has_custom_payload_json {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "Trace {} is missing required custom payload columns. Regenerate with current probex.",
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
        let custom_schema_id_field = events_table
            .schema()
            .field_with_unqualified_name("custom_schema_id")
            .map_err(|error| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("failed to resolve custom_schema_id field: {error}"),
                )
            })?;
        if custom_schema_id_field.data_type() != &DataType::UInt32 {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "column 'custom_schema_id' must have type UInt32, got {:?}",
                    custom_schema_id_field.data_type()
                ),
            )
            .into());
        }
        let custom_payload_json_field = events_table
            .schema()
            .field_with_unqualified_name("custom_payload_json")
            .map_err(|error| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("failed to resolve custom_payload_json field: {error}"),
                )
            })?;
        let custom_payload_ty = custom_payload_json_field.data_type();
        if custom_payload_ty != &DataType::Utf8 && custom_payload_ty != &DataType::Utf8View {
            return Err(IoError::new(
                ErrorKind::InvalidData,
                format!(
                    "column 'custom_payload_json' must have type Utf8 or Utf8View, got {:?}",
                    custom_payload_ty
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

        let mut loaded = loaded_trace_lock()
            .write()
            .map_err(|_| IoError::other("failed to lock loaded trace state"))?;
        *loaded = Some(LoadedTrace {
            ctx: Arc::new(ctx),
            metadata,
        });

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
        let custom_payload_schemas_json =
            metadata_value(PARQUET_METADATA_CUSTOM_PAYLOAD_SCHEMAS_KEY).ok_or_else(|| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!(
                        "required parquet metadata key '{}' missing",
                        PARQUET_METADATA_CUSTOM_PAYLOAD_SCHEMAS_KEY
                    ),
                )
            })?;
        let custom_payload_schemas: Vec<CustomPayloadSchema> =
            serde_json::from_str(custom_payload_schemas_json).map_err(|error| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!(
                        "invalid '{}' metadata value: {}",
                        PARQUET_METADATA_CUSTOM_PAYLOAD_SCHEMAS_KEY, error
                    ),
                )
            })?;

        Ok(TraceFileMetadata {
            cpu_sample_frequency_hz,
            _custom_payload_schemas: custom_payload_schemas,
        })
    }

    pub async fn query_probe_schemas_page(
        query: viewer_probe_catalog::ProbeSchemasQuery,
    ) -> BackendResult<ProbeSchemasPageResponse> {
        match viewer_probe_catalog::query_probe_schemas_page(query.clone()).await {
            Ok(page) => {
                if wants_function_kinds(&query) {
                    match viewer_probe_catalog::has_function_probes_loaded() {
                        Ok(true) => {}
                        Ok(false) => {
                            return viewer_privileged_daemon_client::query_probe_schemas_page_via_daemon(
                                to_privileged_query(query),
                            )
                            .await
                            .map_err(|fallback_error| {
                                IoError::new(
                                    ErrorKind::PermissionDenied,
                                    format!(
                                        "local catalog has no fentry/fexit probes; privileged daemon fallback failed: {fallback_error:#}"
                                    ),
                                )
                            })
                            .map_err(Into::into);
                        }
                        Err(error) => {
                            let error_text = error.to_string();
                            if looks_like_permission_error(&error_text) {
                                return viewer_privileged_daemon_client::query_probe_schemas_page_via_daemon(
                                    to_privileged_query(query),
                                )
                                .await
                                .map_err(|fallback_error| {
                                    IoError::new(
                                        ErrorKind::PermissionDenied,
                                        format!(
                                            "probe schemas page local function probe check failed: {error_text}; privileged daemon fallback failed: {fallback_error:#}"
                                        ),
                                    )
                                })
                                .map_err(Into::into);
                            }
                            return Err(error);
                        }
                    }
                }
                Ok(page)
            }
            Err(error) => {
                let error_text = error.to_string();
                if !looks_like_permission_error(&error_text) {
                    return Err(error);
                }
                let page = viewer_privileged_daemon_client::query_probe_schemas_page_via_daemon(
                    to_privileged_query(query),
                )
                .await
                .map_err(|fallback_error| {
                    IoError::new(
                        ErrorKind::PermissionDenied,
                        format!(
                            "probe schemas page query failed: {error_text}; privileged daemon fallback failed: {fallback_error:#}"
                        ),
                    )
                })?;
                Ok(page)
            }
        }
    }

    pub async fn query_probe_schema_detail(display_name: String) -> BackendResult<ProbeSchema> {
        match viewer_probe_catalog::query_probe_schema_detail(display_name.clone()).await {
            Ok(schema) => Ok(schema),
            Err(error) => {
                let error_text = error.to_string();
                let is_function_probe =
                    display_name.starts_with("fentry:") || display_name.starts_with("fexit:");
                if !looks_like_permission_error(&error_text)
                    && !(is_function_probe && error_text.to_ascii_lowercase().contains("not found"))
                {
                    return Err(error);
                }
                let schema = viewer_privileged_daemon_client::query_probe_schema_detail_via_daemon(
                    display_name,
                )
                .await
                .map_err(|fallback_error| {
                    IoError::new(
                        ErrorKind::PermissionDenied,
                        format!(
                            "probe schema detail query failed: {error_text}; privileged daemon fallback failed: {fallback_error:#}"
                        ),
                    )
                })?;
                Ok(schema)
            }
        }
    }

    pub async fn query_probe_schemas() -> BackendResult<ProbeSchemasResponse> {
        viewer_probe_catalog::query_probe_schemas().await
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

    fn parse_custom_payload_json(
        payload_raw: &str,
        ctx_label: &str,
    ) -> BackendResult<Vec<CustomEventField>> {
        let payload_values: Vec<JsonPayloadValue> =
            serde_json::from_str(payload_raw).map_err(|error| {
                IoError::new(
                    ErrorKind::InvalidData,
                    format!("invalid custom_payload_json at {ctx_label}: {error}"),
                )
            })?;

        payload_values
            .into_iter()
            .map(|value| {
                let type_kind = match value.type_kind.as_str() {
                    "u64" => CustomPayloadTypeKind::U64,
                    "i64" => CustomPayloadTypeKind::I64,
                    other => {
                        return Err(IoError::new(
                            ErrorKind::InvalidData,
                            format!("unsupported custom payload type kind '{other}'"),
                        )
                        .into());
                    }
                };
                let display_value = match type_kind {
                    CustomPayloadTypeKind::U64 => value.value_u64.to_string(),
                    CustomPayloadTypeKind::I64 => value
                        .value_i64
                        .unwrap_or(value.value_u64 as i64)
                        .to_string(),
                };
                Ok(CustomEventField {
                    field_id: value.field_id,
                    name: value.name,
                    type_kind,
                    value_u64: value.value_u64,
                    value_i64: value.value_i64,
                    display_value,
                })
            })
            .collect()
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
            "SELECT pid, ts_ns, event_type, count, submit_ts_ns, io_uring_res
             FROM events
             WHERE {}
               AND event_type IN (
                 'syscall_read_enter', 'syscall_read_exit',
                 'syscall_write_enter', 'syscall_write_exit',
                 'io_uring_complete',
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
        let mut io_uring_latencies: Vec<u64> = Vec::new();
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
                    "io_uring_complete" => {
                        let submit_ts =
                            extract_option_u64(batch, "submit_ts_ns", row)?.unwrap_or(0);
                        if submit_ts > 0 && ts >= submit_ts {
                            io_uring_latencies.push(ts - submit_ts);
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

        Ok(SyscallLatencyStats {
            read: summarize_latencies(&read_latencies),
            write: summarize_latencies(&write_latencies),
            io_uring: summarize_latencies(&io_uring_latencies),
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
        let metadata = get_trace_metadata()?;

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
            cpu_sample_frequency_hz: metadata.cpu_sample_frequency_hz,
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

            let (end_ns, exit) = if let Some((code, exit_ts)) = exit_info.get(pid) {
                (*exit_ts, Some(*code))
            } else {
                (*last_seen, None)
            };

            processes.push(ProcessLifetime {
                pid: *pid,
                process_name: pid_names.get(pid).cloned(),
                parent_pid,
                start_ns,
                end_ns,
                exit,
                was_forked,
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
        const CPU_SAMPLE_BUCKETS_MAX: usize = 2000;
        const CPU_SAMPLE_TARGET_SAMPLES_PER_BUCKET: f64 = 1.0;

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

        let sample_frequency_hz = get_trace_metadata()?.cpu_sample_frequency_hz;
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
        // Use Mem palette (green/blue/grey tones) as a substitute for greyish
        opts.colors = flamegraph::Palette::Multi(flamegraph::color::MultiPalette::Rust);
        opts.bgcolors = None;
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

        let mut conditions = vec![format!("ts_ns >= {start_ns}"), format!("ts_ns <= {end_ns}")];
        if let Some(pid) = pid {
            conditions.push(format!("pid = {pid}"));
        }

        let sql = format!(
            "SELECT pid, ts_ns, event_type, count, ret, submit_ts_ns, io_uring_res, stack_trace
             FROM events
             WHERE {}
               AND event_type IN (
                 'syscall_read_enter', 'syscall_read_exit',
                 'syscall_write_enter', 'syscall_write_exit',
                 'syscall_fsync_enter', 'syscall_fsync_exit',
                 'syscall_fdatasync_enter', 'syscall_fdatasync_exit',
                 'io_uring_complete'
               )
             ORDER BY pid, ts_ns",
            conditions.join(" AND ")
        );

        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        // Per-pid queues for enter events: (ts_ns, request_bytes, stack_trace)
        type PendingRead = std::collections::HashMap<
            u32,
            std::collections::VecDeque<(u64, u64, Option<Vec<String>>)>,
        >;
        type PendingWrite = std::collections::HashMap<
            u32,
            std::collections::VecDeque<(u64, u64, Option<Vec<String>>)>,
        >;
        type PendingFsync =
            std::collections::HashMap<u32, std::collections::VecDeque<(u64, Option<Vec<String>>)>>;
        type PendingFdatasync =
            std::collections::HashMap<u32, std::collections::VecDeque<(u64, Option<Vec<String>>)>>;
        type OpsData<'a> =
            std::collections::HashMap<&'a str, Vec<(u64, u64, u32, u64, Option<Vec<String>>)>>;

        let mut pending_read: PendingRead = std::collections::HashMap::new();
        let mut pending_write: PendingWrite = std::collections::HashMap::new();
        let mut pending_fsync: PendingFsync = std::collections::HashMap::new();
        let mut pending_fdatasync: PendingFdatasync = std::collections::HashMap::new();

        // Collected (latency_ns, actual_bytes, pid, end_ts, stack_trace) per operation
        let mut ops_data: OpsData = std::collections::HashMap::new();

        for batch in &batches {
            for row in 0..batch.num_rows() {
                let pid = extract_u32(batch, "pid", row)?;
                let ts = extract_u64(batch, "ts_ns", row)?;
                let event_type = extract_string(batch, "event_type", row)?;

                match event_type.as_str() {
                    "syscall_read_enter" => {
                        let count = extract_option_u64(batch, "count", row)?.unwrap_or(0);
                        let stack = extract_option_stack_trace_labels(batch, row)?;
                        pending_read
                            .entry(pid)
                            .or_default()
                            .push_back((ts, count, stack));
                    }
                    "syscall_read_exit" => {
                        if let Some(queue) = pending_read.get_mut(&pid)
                            && let Some((enter_ts, request_bytes, stack)) = queue.pop_front()
                            && ts >= enter_ts
                        {
                            let ret = extract_i64(batch, "ret", row)?;
                            let actual_bytes = ret.max(0) as u64;
                            ops_data.entry("read").or_default().push((
                                ts - enter_ts,
                                actual_bytes,
                                pid,
                                ts,
                                stack,
                            ));
                            let _ = request_bytes;
                        }
                    }
                    "syscall_write_enter" => {
                        let count = extract_option_u64(batch, "count", row)?.unwrap_or(0);
                        let stack = extract_option_stack_trace_labels(batch, row)?;
                        pending_write
                            .entry(pid)
                            .or_default()
                            .push_back((ts, count, stack));
                    }
                    "syscall_write_exit" => {
                        if let Some(queue) = pending_write.get_mut(&pid)
                            && let Some((enter_ts, request_bytes, stack)) = queue.pop_front()
                            && ts >= enter_ts
                        {
                            let ret = extract_i64(batch, "ret", row)?;
                            let actual_bytes = ret.max(0) as u64;
                            ops_data.entry("write").or_default().push((
                                ts - enter_ts,
                                actual_bytes,
                                pid,
                                ts,
                                stack,
                            ));
                            let _ = request_bytes;
                        }
                    }
                    "syscall_fsync_enter" => {
                        let stack = extract_option_stack_trace_labels(batch, row)?;
                        pending_fsync.entry(pid).or_default().push_back((ts, stack));
                    }
                    "syscall_fsync_exit" => {
                        if let Some(queue) = pending_fsync.get_mut(&pid)
                            && let Some((enter_ts, stack)) = queue.pop_front()
                            && ts >= enter_ts
                        {
                            ops_data.entry("fsync").or_default().push((
                                ts - enter_ts,
                                0,
                                pid,
                                ts,
                                stack,
                            ));
                        }
                    }
                    "syscall_fdatasync_enter" => {
                        let stack = extract_option_stack_trace_labels(batch, row)?;
                        pending_fdatasync
                            .entry(pid)
                            .or_default()
                            .push_back((ts, stack));
                    }
                    "syscall_fdatasync_exit" => {
                        if let Some(queue) = pending_fdatasync.get_mut(&pid)
                            && let Some((enter_ts, stack)) = queue.pop_front()
                            && ts >= enter_ts
                        {
                            ops_data.entry("fdatasync").or_default().push((
                                ts - enter_ts,
                                0,
                                pid,
                                ts,
                                stack,
                            ));
                        }
                    }
                    "io_uring_complete" => {
                        let submit_ts =
                            extract_option_u64(batch, "submit_ts_ns", row)?.unwrap_or(0);
                        let res = extract_option_i32(batch, "io_uring_res", row)?.unwrap_or(0);
                        if submit_ts > 0 && ts >= submit_ts {
                            let actual_bytes = res.max(0) as u64;
                            // io_uring_complete usually has the stack of the completion, not submission.
                            // Ideally we'd want the submission stack, but we don't have it here easily.
                            // We'll use the completion stack as a proxy or just None if not useful.
                            // The user might be interested in who processed the completion.
                            let stack = extract_option_stack_trace_labels(batch, row)?;
                            ops_data.entry("io_uring").or_default().push((
                                ts - submit_ts,
                                actual_bytes,
                                pid,
                                ts,
                                stack,
                            ));
                        }
                    }
                    _ => {}
                }
            }
        }

        let mut total_ops: u64 = 0;
        let mut total_bytes: u64 = 0;
        for data in ops_data.values() {
            for &(_, actual, _, _, _) in data {
                total_ops += 1;
                total_bytes = total_bytes.saturating_add(actual);
            }
        }

        let mut by_operation: Vec<IoTypeStats> = ops_data
            .into_iter()
            .map(|(op, data)| compute_io_type_stats(op.to_string(), data))
            .collect();
        by_operation.sort_by_key(|b| std::cmp::Reverse(b.total_ops));

        Ok(IoStatistics {
            by_operation,
            total_ops,
            total_bytes,
            time_range_ns: (start_ns, end_ns),
        })
    }

    type BackendIoOpData = Vec<(u64, u64, u32, u64, Option<Vec<String>>)>;

    fn compute_io_type_stats(operation: String, mut data: BackendIoOpData) -> IoTypeStats {
        data.sort_by_key(|(lat, _, _, _, _)| *lat);

        let total_ops = data.len() as u64;
        let total_bytes: u64 = data.iter().map(|(_, b, _, _, _)| *b).sum();
        let total_latency: u128 = data.iter().map(|(l, _, _, _, _)| *l as u128).sum();

        let avg_latency_ns = if total_ops > 0 {
            (total_latency / total_ops as u128) as u64
        } else {
            0
        };

        let get_sample = |pct: usize| -> Option<EventDetail> {
            if data.is_empty() {
                return None;
            }
            let idx = if pct == 100 {
                data.len() - 1
            } else {
                ((data.len() * pct) / 100).min(data.len() - 1)
            };
            let (lat, _, pid, ts, ref stack) = data[idx];
            Some(EventDetail {
                ts_ns: ts,
                latency_ns: Some(lat),
                event_type: operation.clone(),
                pid,
                stack_trace: stack.clone(),
                custom_payload: None,
            })
        };

        let p50_event = get_sample(50);
        let p95_event = get_sample(95);
        let p99_event = get_sample(99);
        let max_event = get_sample(100);

        let latencies_ns: Vec<u64> = data.iter().map(|(l, _, _, _, _)| *l).collect();

        let mut sizes_bytes: Vec<u64> = data.iter().map(|(_, b, _, _, _)| *b).collect();
        sizes_bytes.sort_unstable();

        IoTypeStats {
            operation,
            total_ops,
            total_bytes,
            avg_latency_ns,
            p50_event,
            p95_event,
            p99_event,
            max_event,
            latencies_ns,
            sizes_bytes,
        }
    }

    pub async fn query_memory_statistics(
        start_ns: u64,
        end_ns: u64,
        pid: Option<u32>,
    ) -> BackendResult<MemoryStatistics> {
        if end_ns < start_ns {
            return Err(IoError::new(ErrorKind::InvalidInput, "end_ns must be >= start_ns").into());
        }
        let ctx = get_ctx()?;

        let mut conditions = vec![format!("ts_ns >= {start_ns}"), format!("ts_ns <= {end_ns}")];
        if let Some(pid) = pid {
            conditions.push(format!("pid = {pid}"));
        }

        let sql = format!(
            "SELECT pid, ts_ns, event_type, count, ret, stack_trace
             FROM events
             WHERE {}
               AND event_type IN (
                 'syscall_mmap_enter', 'syscall_mmap_exit',
                 'syscall_munmap_enter', 'syscall_munmap_exit',
                 'syscall_brk_enter', 'syscall_brk_exit'
               )
             ORDER BY pid, ts_ns",
            conditions.join(" AND ")
        );

        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        type PendingMmap = std::collections::HashMap<
            u32,
            std::collections::VecDeque<(u64, u64, Option<Vec<String>>)>,
        >;
        type PendingMunmap = std::collections::HashMap<
            u32,
            std::collections::VecDeque<(u64, u64, Option<Vec<String>>)>,
        >;
        type PendingBrk =
            std::collections::HashMap<u32, std::collections::VecDeque<(u64, Option<Vec<String>>)>>;

        type MemOpsData = Vec<(u64, u64, u32, u64, Option<Vec<String>>)>;
        type OpsData<'a> =
            std::collections::HashMap<&'a str, Vec<(u64, u64, u32, u64, Option<Vec<String>>)>>;

        // Per-pid pending queues: mmap/munmap store (ts_ns, count, stack), brk stores (ts_ns, stack)
        let mut pending_mmap: PendingMmap = std::collections::HashMap::new();
        let mut pending_munmap: PendingMunmap = std::collections::HashMap::new();
        let mut pending_brk: PendingBrk = std::collections::HashMap::new();

        // Per-pid last known brk address for delta computation
        let mut last_brk: std::collections::HashMap<u32, i64> = std::collections::HashMap::new();

        // Collected (latency_ns, bytes, pid, end_ts, stack) per operation
        let mut mmap_data: MemOpsData = Vec::new();
        let mut munmap_data: MemOpsData = Vec::new();
        let mut brk_data: MemOpsData = Vec::new();

        // Cumulative memory events: (ts_ns, signed_delta_bytes)
        let mut cumulative_events: Vec<(u64, i64)> = Vec::new();

        // Track brk alloc vs free separately for summary
        let mut brk_grow_ops: u64 = 0;
        let mut brk_grow_bytes: u64 = 0;
        let mut brk_shrink_ops: u64 = 0;
        let mut brk_shrink_bytes: u64 = 0;

        for batch in &batches {
            for row in 0..batch.num_rows() {
                let pid = extract_u32(batch, "pid", row)?;
                let ts = extract_u64(batch, "ts_ns", row)?;
                let event_type = extract_string(batch, "event_type", row)?;

                match event_type.as_str() {
                    "syscall_mmap_enter" => {
                        let count = extract_option_u64(batch, "count", row)?.unwrap_or(0);
                        let stack = extract_option_stack_trace_labels(batch, row)?;
                        pending_mmap
                            .entry(pid)
                            .or_default()
                            .push_back((ts, count, stack));
                    }
                    "syscall_mmap_exit" => {
                        if let Some(queue) = pending_mmap.get_mut(&pid)
                            && let Some((enter_ts, requested_bytes, stack)) = queue.pop_front()
                            && ts >= enter_ts
                        {
                            let ret = extract_i64(batch, "ret", row)?;
                            // ret >= 0 means success (valid mapped address)
                            if ret >= 0 {
                                let latency = ts - enter_ts;
                                mmap_data.push((latency, requested_bytes, pid, ts, stack));
                                cumulative_events.push((ts, requested_bytes as i64));
                            }
                        }
                    }
                    "syscall_munmap_enter" => {
                        let count = extract_option_u64(batch, "count", row)?.unwrap_or(0);
                        let stack = extract_option_stack_trace_labels(batch, row)?;
                        pending_munmap
                            .entry(pid)
                            .or_default()
                            .push_back((ts, count, stack));
                    }
                    "syscall_munmap_exit" => {
                        if let Some(queue) = pending_munmap.get_mut(&pid)
                            && let Some((enter_ts, freed_bytes, stack)) = queue.pop_front()
                            && ts >= enter_ts
                        {
                            let ret = extract_i64(batch, "ret", row)?;
                            // ret == 0 means success
                            if ret == 0 {
                                let latency = ts - enter_ts;
                                munmap_data.push((latency, freed_bytes, pid, ts, stack));
                                cumulative_events.push((ts, -(freed_bytes as i64)));
                            }
                        }
                    }
                    "syscall_brk_enter" => {
                        let stack = extract_option_stack_trace_labels(batch, row)?;
                        pending_brk.entry(pid).or_default().push_back((ts, stack));
                    }
                    "syscall_brk_exit" => {
                        if let Some(queue) = pending_brk.get_mut(&pid)
                            && let Some((enter_ts, stack)) = queue.pop_front()
                            && ts >= enter_ts
                        {
                            let ret = extract_i64(batch, "ret", row)?;
                            if ret > 0 {
                                if let Some(&prev_brk) = last_brk.get(&pid) {
                                    let delta = ret - prev_brk;
                                    if delta != 0 {
                                        let latency = ts - enter_ts;
                                        let abs_delta = delta.unsigned_abs();
                                        brk_data.push((latency, abs_delta, pid, ts, stack));
                                        cumulative_events.push((ts, delta));
                                        if delta > 0 {
                                            brk_grow_ops += 1;
                                            brk_grow_bytes += abs_delta;
                                        } else {
                                            brk_shrink_ops += 1;
                                            brk_shrink_bytes += abs_delta;
                                        }
                                    }
                                }
                                last_brk.insert(pid, ret);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Build per-operation stats using same helper as IO
        let mut ops_data: OpsData = std::collections::HashMap::new();
        if !mmap_data.is_empty() {
            ops_data.insert("mmap", mmap_data);
        }
        if !munmap_data.is_empty() {
            ops_data.insert("munmap", munmap_data);
        }
        if !brk_data.is_empty() {
            ops_data.insert("brk", brk_data);
        }

        let mut by_operation: Vec<IoTypeStats> = ops_data
            .into_iter()
            .map(|(op, data)| compute_io_type_stats(op.to_string(), data))
            .collect();
        by_operation.sort_by_key(|b| std::cmp::Reverse(b.total_ops));

        // Compute alloc/free totals
        let mmap_stats = by_operation.iter().find(|s| s.operation == "mmap");
        let munmap_stats = by_operation.iter().find(|s| s.operation == "munmap");

        let total_alloc_ops = mmap_stats.map_or(0, |s| s.total_ops) + brk_grow_ops;
        let total_alloc_bytes = mmap_stats.map_or(0, |s| s.total_bytes) + brk_grow_bytes;
        let total_free_ops = munmap_stats.map_or(0, |s| s.total_ops) + brk_shrink_ops;
        let total_free_bytes = munmap_stats.map_or(0, |s| s.total_bytes) + brk_shrink_bytes;

        // Build cumulative memory usage timeline
        cumulative_events.sort_by_key(|(ts, _)| *ts);
        let mut cumulative_usage: Vec<CumulativeMemoryPoint> =
            Vec::with_capacity(cumulative_events.len());
        let mut running_sum: i64 = 0;
        for (ts, delta) in &cumulative_events {
            running_sum += delta;
            cumulative_usage.push(CumulativeMemoryPoint {
                ts_ns: *ts,
                cumulative_bytes: running_sum,
            });
        }

        Ok(MemoryStatistics {
            by_operation,
            total_alloc_ops,
            total_alloc_bytes,
            total_free_ops,
            total_free_bytes,
            cumulative_usage,
            time_range_ns: (start_ns, end_ns),
        })
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

    pub async fn query_custom_events_debug() -> BackendResult<CustomEventsDebugResponse> {
        const CUSTOM_EVENTS_DEBUG_LIMIT: usize = 500;

        let ctx = get_ctx()?;
        let sql = format!(
            "SELECT ts_ns, event_type, pid, tgid, process_name, custom_schema_id, custom_payload_json \
             FROM events \
             WHERE custom_schema_id IS NOT NULL \
             ORDER BY ts_ns ASC \
             LIMIT {CUSTOM_EVENTS_DEBUG_LIMIT}"
        );
        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        let mut events = Vec::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                let ts_ns = extract_u64(batch, "ts_ns", row)?;
                let event_type = extract_string(batch, "event_type", row)?;
                let pid = extract_u32(batch, "pid", row)?;
                let tgid = extract_u32(batch, "tgid", row)?;
                let process_name = extract_option_string(batch, "process_name", row)?;
                let schema_id =
                    extract_option_u32(batch, "custom_schema_id", row)?.ok_or_else(|| {
                        IoError::new(
                            ErrorKind::InvalidData,
                            "custom event row is missing custom_schema_id",
                        )
                    })?;
                let payload_raw = extract_option_string(batch, "custom_payload_json", row)?
                    .unwrap_or_else(|| "[]".to_string());
                let fields = parse_custom_payload_json(
                    &payload_raw,
                    format!("ts_ns={ts_ns}, pid={pid}").as_str(),
                )?
                .into_iter()
                .map(|field| CustomEventDebugField {
                    field_id: field.field_id,
                    name: field.name,
                    type_kind: field.type_kind,
                    value_u64: field.value_u64,
                    value_i64: field.value_i64,
                    display_value: field.display_value,
                })
                .collect::<Vec<_>>();

                events.push(CustomEventDebugRow {
                    ts_ns,
                    event_type,
                    pid,
                    tgid,
                    process_name,
                    schema_id,
                    fields,
                });
            }
        }

        Ok(CustomEventsDebugResponse {
            shown: events.len(),
            events,
            limit: CUSTOM_EVENTS_DEBUG_LIMIT,
        })
    }

    pub async fn query_event_list(
        start_ns: u64,
        end_ns: u64,
        pid: u32,
        limit: usize,
        offset: usize,
        event_types: &[String],
    ) -> BackendResult<EventListResponse> {
        let ctx = get_ctx()?;

        let type_filter = if event_types.is_empty() {
            String::new()
        } else {
            let quoted: Vec<String> = event_types.iter().map(|t| format!("'{t}'")).collect();
            format!(" AND event_type IN ({})", quoted.join(","))
        };

        let count_sql = format!(
            "SELECT COUNT(*) as cnt FROM events WHERE pid = {pid} AND ts_ns >= {start_ns} AND ts_ns <= {end_ns}{type_filter}"
        );
        let count_df = ctx.sql(&count_sql).await?;
        let count_batches = count_df.collect().await?;
        let total_in_range = extract_i64(
            count_batches.first().ok_or_else(|| {
                IoError::new(ErrorKind::InvalidData, "count query returned no rows")
            })?,
            "cnt",
            0,
        )? as usize;

        let sql = format!(
            "SELECT ts_ns, event_type, pid, stack_trace, custom_schema_id, custom_payload_json FROM events \
             WHERE pid = {pid} AND ts_ns >= {start_ns} AND ts_ns <= {end_ns}{type_filter} \
             ORDER BY ts_ns LIMIT {limit} OFFSET {offset}"
        );
        let df = ctx.sql(&sql).await?;
        let batches = df.collect().await?;

        let mut events = Vec::new();
        for batch in &batches {
            for row in 0..batch.num_rows() {
                let ts_ns = extract_u64(batch, "ts_ns", row)?;
                let event_type = extract_string(batch, "event_type", row)?;
                let pid = extract_u32(batch, "pid", row)?;
                let stack_trace = extract_option_stack_trace_labels(batch, row)?;
                let custom_payload = match extract_option_u32(batch, "custom_schema_id", row)? {
                    Some(schema_id) => {
                        let payload_raw = extract_option_string(batch, "custom_payload_json", row)?
                            .unwrap_or_else(|| "[]".to_string());
                        let fields = parse_custom_payload_json(
                            &payload_raw,
                            format!("ts_ns={ts_ns}, pid={pid}").as_str(),
                        )?;
                        Some(CustomEventPayload { schema_id, fields })
                    }
                    None => None,
                };
                events.push(EventDetail {
                    ts_ns,
                    latency_ns: None,
                    event_type,
                    pid,
                    stack_trace,
                    custom_payload,
                });
            }
        }

        Ok(EventListResponse {
            events,
            total_in_range,
        })
    }
}

pub use crate::viewer_probe_catalog::ProbeSchemasQuery;

pub async fn initialize(
    parquet_file: std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    backend::initialize(parquet_file).await
}

pub async fn load_trace_file(
    parquet_file: std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    backend::load_trace_file(parquet_file).await
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

pub async fn query_custom_events_debug()
-> Result<CustomEventsDebugResponse, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_custom_events_debug().await
}

pub async fn query_probe_schemas()
-> Result<ProbeSchemasResponse, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_probe_schemas().await
}

pub async fn query_probe_schemas_page(
    query: ProbeSchemasQuery,
) -> Result<ProbeSchemasPageResponse, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_probe_schemas_page(query).await
}

pub async fn query_probe_schema_detail(
    display_name: String,
) -> Result<ProbeSchema, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_probe_schema_detail(display_name).await
}

pub async fn query_io_statistics(
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
) -> Result<IoStatistics, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_io_statistics(start_ns, end_ns, pid).await
}

pub async fn query_memory_statistics(
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
) -> Result<MemoryStatistics, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_memory_statistics(start_ns, end_ns, pid).await
}

pub async fn query_event_list(
    start_ns: u64,
    end_ns: u64,
    pid: u32,
    limit: usize,
    offset: usize,
    event_types: &[String],
) -> Result<EventListResponse, Box<dyn std::error::Error + Send + Sync>> {
    backend::query_event_list(start_ns, end_ns, pid, limit, offset, event_types).await
}
