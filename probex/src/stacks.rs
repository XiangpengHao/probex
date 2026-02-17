use crate::event::Event;
use crate::schema::create_final_schema;
use crate::writer::{
    BATCH_SIZE, PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY, PARQUET_METADATA_STACK_TRACE_FORMAT_KEY,
    STACK_TRACE_FORMAT_SYMBOLIZED_V1,
};
use anyhow::{Context as _, Result, anyhow};
use arrow::{
    array::{
        Array, ArrayRef, ListBuilder, StringArray, StringViewArray, StringViewBuilder, UInt32Array,
        UInt64Array,
    },
    record_batch::{RecordBatch, RecordBatchReader},
};
use aya::maps::{MapData, StackTraceMap};
use parquet::{
    arrow::{ArrowWriter, arrow_reader::ParquetRecordBatchReaderBuilder},
    basic::Compression,
    file::{metadata::KeyValue, properties::WriterProperties},
};
use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use wholesym::{LookupAddress, SymbolManager, SymbolManagerConfig};

pub const STACK_FRAME_LIMIT: usize = 256;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcMapEntry {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct ProcMapInlineSegment {
    pub start_addr: u64,
    pub end_addr: u64,
    pub file_offset: u64,
    pub path: String,
}

pub type ProcMapsSnapshotIndex = HashMap<u32, BTreeMap<u64, Arc<Vec<ProcMapInlineSegment>>>>;

#[derive(Default)]
pub struct ProcMapsSnapshotCollector {
    snapshots: ProcMapsSnapshotIndex,
    total_rows: usize,
}

impl ProcMapsSnapshotCollector {
    pub fn capture(&mut self, tgid: u32, captured_ts_ns: u64, maps: &[ProcMapEntry]) {
        let segments = maps
            .iter()
            .map(|entry| ProcMapInlineSegment {
                start_addr: entry.start,
                end_addr: entry.end,
                file_offset: entry.offset,
                path: entry.path.to_string_lossy().to_string(),
            })
            .collect::<Vec<_>>();
        self.total_rows += segments.len();
        self.snapshots
            .entry(tgid)
            .or_default()
            .insert(captured_ts_ns, Arc::new(segments));
    }

    pub fn total_rows(&self) -> usize {
        self.total_rows
    }

    pub fn snapshot_index(&self) -> &ProcMapsSnapshotIndex {
        &self.snapshots
    }
}

pub fn read_proc_maps(pid: u32) -> Vec<ProcMapEntry> {
    let path = format!("/proc/{pid}/maps");
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    contents.lines().filter_map(parse_proc_map_line).collect()
}

fn parse_proc_map_line(line: &str) -> Option<ProcMapEntry> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let _perms = parts.next()?;
    let offset_hex = parts.next()?;
    let _dev = parts.next()?;
    let _inode = parts.next()?;
    let raw_path = parts.next()?;

    if raw_path.starts_with('[') {
        return None;
    }

    let path = raw_path
        .strip_suffix("(deleted)")
        .map(str::trim_end)
        .unwrap_or(raw_path);
    if !path.starts_with('/') {
        return None;
    }

    let (start_hex, end_hex) = range.split_once('-')?;
    let start = u64::from_str_radix(start_hex, 16).ok()?;
    let end = u64::from_str_radix(end_hex, 16).ok()?;
    let offset = u64::from_str_radix(offset_hex, 16).ok()?;

    Some(ProcMapEntry {
        start,
        end,
        offset,
        path: PathBuf::from(path),
    })
}

pub fn maybe_capture_proc_maps_snapshot(
    tgid: u32,
    captured_ts_ns: u64,
    force_snapshot: bool,
    snapshot_cache: &mut HashMap<u32, Vec<ProcMapEntry>>,
    snapshot_collector: &mut ProcMapsSnapshotCollector,
) {
    if tgid == 0 {
        return;
    }
    let maps = read_proc_maps(tgid);
    if maps.is_empty() {
        return;
    }

    let changed = snapshot_cache.get(&tgid) != Some(&maps);
    if !force_snapshot && !changed {
        return;
    }

    snapshot_collector.capture(tgid, captured_ts_ns, &maps);
    snapshot_cache.insert(tgid, maps);
}

fn find_inline_segments_for_event(
    snapshot_index: &ProcMapsSnapshotIndex,
    tgid: u32,
    ts_ns: u64,
) -> Option<&[ProcMapInlineSegment]> {
    let snapshots = snapshot_index.get(&tgid)?;
    let (_captured_ts_ns, segments) = snapshots.range(..=ts_ns).next_back()?;
    Some(segments.as_slice())
}

pub fn format_stack_frames_hex(frames: &[u64]) -> Option<String> {
    if frames.is_empty() {
        return None;
    }
    Some(
        frames
            .iter()
            .map(|ip| format!("0x{ip:x}"))
            .collect::<Vec<_>>()
            .join(";"),
    )
}

fn is_plausible_user_instruction_ip(ip: u64) -> bool {
    // User-space instruction pointers should never be tiny sentinel values
    // and should stay in the user half of virtual address space.
    (0x1000..(1u64 << 63)).contains(&ip)
}

fn read_stack_frames(
    stack_id: u32,
    is_user_stack: bool,
    stack_traces: &StackTraceMap<MapData>,
) -> Vec<u64> {
    let Ok(stack) = stack_traces.get(&stack_id, 0) else {
        return Vec::new();
    };

    let mut frames: Vec<u64> = stack
        .frames()
        .iter()
        .take(STACK_FRAME_LIMIT)
        .map(|frame| frame.ip)
        .collect();
    if is_user_stack {
        // Aya exposes raw frames as produced by bpf_get_stackid(). Filtering out
        // impossible user IPs here avoids polluting flamegraph roots with junk
        // values when user-space unwinding is partial.
        frames.retain(|ip| is_plausible_user_instruction_ip(*ip));
    }
    frames.reverse();
    frames
}

fn format_kernel_ip(ip: u64, symbols: Option<&BTreeMap<u64, String>>) -> String {
    if let Some(symbols) = symbols
        && let Some((addr, name)) = symbols.range(..=ip).next_back()
    {
        let offset = ip.saturating_sub(*addr);
        return if offset == 0 {
            name.clone()
        } else {
            format!("{name}+0x{offset:x}")
        };
    }
    format!("0x{ip:x}")
}

fn format_kernel_stack_trace(
    frames: &[u64],
    symbols: Option<&BTreeMap<u64, String>>,
) -> Option<String> {
    if frames.is_empty() {
        return None;
    }
    let mut parts = Vec::with_capacity(frames.len() + 1);
    parts.push("[kernel]".to_string());
    parts.extend(frames.iter().map(|ip| format_kernel_ip(*ip, symbols)));
    Some(parts.join(";"))
}

#[derive(Default)]
pub struct MaterializedStack {
    pub stack_frames: Option<String>,
    pub stack_trace: Option<String>,
}

pub type StackCacheKey = (Option<i32>, Option<i32>, Option<&'static str>);
pub type StackTraceCache = HashMap<StackCacheKey, MaterializedStack>;

fn materialize_stacks(
    user_stack_id: Option<i32>,
    kernel_stack_id: Option<i32>,
    stack_kind: Option<&'static str>,
    stack_traces: &StackTraceMap<MapData>,
    kernel_syms: Option<&BTreeMap<u64, String>>,
) -> MaterializedStack {
    let user_frames = user_stack_id
        .map(|stack_id| {
            read_stack_frames(
                u32::try_from(stack_id).expect("stack_id should always be non-negative"),
                true,
                stack_traces,
            )
        })
        .unwrap_or_default();
    let kernel_frames = kernel_stack_id
        .map(|stack_id| {
            read_stack_frames(
                u32::try_from(stack_id).expect("kernel_stack_id should always be non-negative"),
                false,
                stack_traces,
            )
        })
        .unwrap_or_default();

    match stack_kind {
        Some("user") => {
            let stack_frames = format_stack_frames_hex(&user_frames);
            let stack_trace = stack_frames
                .as_ref()
                .map(|frames| format!("[user];{frames}"));
            MaterializedStack {
                stack_frames,
                stack_trace,
            }
        }
        Some("kernel") => MaterializedStack {
            stack_frames: format_stack_frames_hex(&kernel_frames),
            stack_trace: format_kernel_stack_trace(&kernel_frames, kernel_syms),
        },
        Some("both") => MaterializedStack {
            // Keep user frames in hex for later userspace symbolization in viewer.
            stack_frames: format_stack_frames_hex(&user_frames),
            // Keep kernel chain pre-symbolized to avoid per-request kernel lookups.
            stack_trace: format_kernel_stack_trace(&kernel_frames, kernel_syms),
        },
        _ => {
            let stack_frames = format_stack_frames_hex(&user_frames);
            MaterializedStack {
                stack_trace: stack_frames.clone(),
                stack_frames,
            }
        }
    }
}

pub fn enrich_stack_data(
    event: &mut Event,
    stack_traces: &StackTraceMap<MapData>,
    kernel_syms: Option<&BTreeMap<u64, String>>,
    stack_cache: &mut StackTraceCache,
) {
    if event.stack_id.is_none() && event.kernel_stack_id.is_none() {
        return;
    }
    let key = (event.stack_id, event.kernel_stack_id, event.stack_kind);
    if let Some(cached) = stack_cache.get(&key) {
        event.stack_frames = cached.stack_frames.clone();
        event.stack_trace = cached.stack_trace.clone();
        return;
    }

    let materialized = materialize_stacks(
        event.stack_id,
        event.kernel_stack_id,
        event.stack_kind,
        stack_traces,
        kernel_syms,
    );
    event.stack_frames = materialized.stack_frames.clone();
    event.stack_trace = materialized.stack_trace.clone();
    stack_cache.insert(key, materialized);
}

fn read_process_name(pid: u32) -> Option<String> {
    let comm_path = format!("/proc/{pid}/comm");
    std::fs::read_to_string(comm_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn enrich_process_name(event: &mut Event, pid_name_cache: &mut HashMap<u32, Option<String>>) {
    let maybe_name = pid_name_cache
        .entry(event.pid)
        .or_insert_with(|| read_process_name(event.pid))
        .clone();
    event.process_name = maybe_name;
}

// --- Post-processing Symbolization ---

struct ExportUserSymbolizer {
    symbol_manager: SymbolManager,
    symbol_cache: HashMap<(String, u64), Option<Vec<String>>>,
    symbol_map_cache: HashMap<String, Option<wholesym::SymbolMap>>,
}

impl ExportUserSymbolizer {
    fn new() -> Self {
        Self {
            symbol_manager: SymbolManager::with_config(SymbolManagerConfig::default()),
            symbol_cache: HashMap::new(),
            symbol_map_cache: HashMap::new(),
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

    async fn resolve_batch(&mut self, requests: HashMap<String, Vec<u64>>) {
        for (path, addrs) in requests {
            self.ensure_symbol_map_loaded(&path).await;
            if let Some(symbol_map) = self.symbol_map_cache.get(&path).and_then(|m| m.as_ref()) {
                // Filter already cached
                let unresolved: Vec<u64> = addrs
                    .iter()
                    .filter(|&&addr| !self.symbol_cache.contains_key(&(path.clone(), addr)))
                    .copied()
                    .collect();

                for addr in unresolved {
                    let symbol = symbol_map
                        .lookup(LookupAddress::FileOffset(addr))
                        .await
                        .and_then(symbol_labels_from_address_info);
                    self.symbol_cache.insert((path.clone(), addr), symbol);
                }
            } else {
                // If failed to load map, cache None
                for addr in addrs {
                    self.symbol_cache
                        .entry((path.clone(), addr))
                        .or_insert(None);
                }
            }
        }
    }

    fn lookup_cached(&self, path: &str, addr: u64) -> Option<&[String]> {
        self.symbol_cache
            .get(&(path.to_string(), addr))
            .and_then(|v| v.as_deref())
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

#[derive(Default)]
pub struct StackTraceFinalizationStats {
    pub rewritten_rows: usize,
    pub symbolized_user_rows: usize,
    pub symbolized_mixed_rows: usize,
    pub mapped_fallback_frames: usize,
    pub raw_fallback_frames: usize,
}

fn find_segment_for_ip(
    segments: &[ProcMapInlineSegment],
    ip: u64,
) -> Option<&ProcMapInlineSegment> {
    segments
        .iter()
        .find(|segment| ip >= segment.start_addr && ip < segment.end_addr)
}

fn mapped_frame_fallback_label(path: &str, file_offset: u64) -> String {
    format!("{path}+0x{file_offset:x}")
}

fn extract_option_utf8_from_column<'a>(
    column: &'a dyn Array,
    row: usize,
    column_name: &str,
) -> Result<Option<&'a str>> {
    if let Some(arr) = column.as_any().downcast_ref::<StringArray>() {
        return Ok((!arr.is_null(row)).then(|| arr.value(row)));
    }
    if let Some(arr) = column.as_any().downcast_ref::<StringViewArray>() {
        return Ok((!arr.is_null(row)).then(|| arr.value(row)));
    }
    Err(anyhow!("events column {column_name} has unexpected type"))
}

fn sanitize_stack_trace_label(label: &str) -> String {
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

fn parse_stack_trace_labels(stack_trace: &str) -> impl Iterator<Item = String> + '_ {
    stack_trace
        .split(';')
        .filter(|label| !label.is_empty())
        .map(str::to_string)
}

fn parse_kernel_labels_from_stack_trace(stack_trace: &str) -> impl Iterator<Item = String> + '_ {
    stack_trace
        .split(';')
        .filter(|frame| !frame.is_empty())
        .skip_while(|&frame| frame != "[kernel]")
        .map(str::to_string)
}

fn parse_stack_frames_hex(stack_frames: &str) -> Result<Vec<u64>> {
    let mut frames = Vec::new();
    for token in stack_frames.split(';') {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        let hex = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        let ip = u64::from_str_radix(hex, 16)
            .with_context(|| format!("invalid stack frame address '{trimmed}'"))?;
        frames.push(ip);
    }
    Ok(frames)
}

// Structures for analysis phase
enum StackType {
    User,
    Both,
    Other,
}

struct RowAnalysisRequest {
    stack_type: StackType,
    frames_hex: String,
    tgid: u32,
    ts_ns: u64,
    current_stack_trace: Option<String>,
}

struct AnalyzedRow {
    frames: Vec<MappedFrame>,
    kernel_stack: Option<String>,
    fallback_stack_trace: Option<String>, // If parsing failed or no symbolization needed
}

enum MappedFrame {
    Resolved { path: String, offset: u64 },
    Raw { ip: u64 },
}

pub async fn symbolize_stack_traces_into_events_parquet(
    events_output_path: &str,
    snapshot_index: &ProcMapsSnapshotIndex,
    sample_freq_hz: u64,
) -> Result<StackTraceFinalizationStats> {
    let file = File::open(events_output_path)
        .with_context(|| format!("failed to open events file {}", events_output_path))?;
    let reader_builder = ParquetRecordBatchReaderBuilder::try_new(file)
        .with_context(|| format!("failed to create reader for {}", events_output_path))?;
    let mut reader = reader_builder
        .with_batch_size(BATCH_SIZE)
        .build()
        .with_context(|| format!("failed to build reader for {}", events_output_path))?;

    let source_schema = reader.schema();
    let tgid_idx = source_schema
        .index_of("tgid")
        .with_context(|| "events schema missing tgid column")?;
    let ts_ns_idx = source_schema
        .index_of("ts_ns")
        .with_context(|| "events schema missing ts_ns column")?;
    let stack_kind_idx = source_schema
        .index_of("stack_kind")
        .with_context(|| "events schema missing stack_kind column")?;
    let stack_frames_idx = source_schema
        .index_of("stack_frames")
        .with_context(|| "events schema missing stack_frames column")?;
    let stack_trace_idx = source_schema
        .index_of("stack_trace")
        .with_context(|| "events schema missing stack_trace column")?;

    let tmp_output_path = format!("{events_output_path}.probex-tmp");
    let output_file = File::create(&tmp_output_path)
        .with_context(|| format!("failed to create temp output {}", tmp_output_path))?;
    let key_value_metadata = vec![
        KeyValue::new(
            PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY.to_string(),
            sample_freq_hz.to_string(),
        ),
        KeyValue::new(
            PARQUET_METADATA_STACK_TRACE_FORMAT_KEY.to_string(),
            STACK_TRACE_FORMAT_SYMBOLIZED_V1.to_string(),
        ),
    ];
    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .set_key_value_metadata(Some(key_value_metadata))
        .build();
    let final_schema = Arc::new(create_final_schema());
    let mut writer = ArrowWriter::try_new(output_file, final_schema.clone(), Some(props))
        .with_context(|| "failed to create post-process parquet writer")?;

    let mut symbolizer = ExportUserSymbolizer::new();
    let mut stats = StackTraceFinalizationStats::default();

    // Since we can't easily pass the borrowed snapshot_index to spawn tasks with 'static lifetime requirements,
    // and cloning the entire snapshot index might be heavy if many processes/maps,
    // we simply clone the HashMap structure. The values are Arc, so the heavy data is shared.
    let snapshot_index_arc = Arc::new(snapshot_index.clone());

    for batch in &mut reader {
        let batch = batch.with_context(|| "failed to read events batch")?;
        let num_rows = batch.num_rows();

        let tgid_array = batch
            .column(tgid_idx)
            .as_any()
            .downcast_ref::<UInt32Array>()
            .ok_or_else(|| anyhow!("events column tgid has unexpected type"))?;
        let ts_ns_array = batch
            .column(ts_ns_idx)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow!("events column ts_ns has unexpected type"))?;
        let stack_kind_column = batch.column(stack_kind_idx).as_ref();
        let stack_frames_column = batch.column(stack_frames_idx).as_ref();
        let stack_trace_column = batch.column(stack_trace_idx).as_ref();

        // 1. Prepare analysis requests
        let mut requests = Vec::with_capacity(num_rows);
        for row_idx in 0..num_rows {
            let stack_kind =
                extract_option_utf8_from_column(stack_kind_column, row_idx, "stack_kind")?;
            let stack_frames =
                extract_option_utf8_from_column(stack_frames_column, row_idx, "stack_frames")?;
            let current_stack_trace =
                extract_option_utf8_from_column(stack_trace_column, row_idx, "stack_trace")?
                    .map(str::to_string);
            let tgid = tgid_array.value(row_idx);
            let ts_ns = ts_ns_array.value(row_idx);

            let stack_type = match (stack_kind, stack_frames) {
                (Some("user"), Some(frames)) if !frames.is_empty() => StackType::User,
                (Some("both"), Some(frames)) if !frames.is_empty() => StackType::Both,
                _ => StackType::Other,
            };

            requests.push(RowAnalysisRequest {
                stack_type,
                frames_hex: stack_frames.unwrap_or_default().to_string(),
                tgid,
                ts_ns,
                current_stack_trace,
            });
        }

        // 2. Parallel Analysis Phase
        // Determine chunk size based on available parallelism
        let parallelism = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1);
        let chunk_size = requests.len().div_ceil(parallelism);
        let mut tasks = Vec::with_capacity(parallelism);

        for chunk in requests.chunks(chunk_size) {
            // Move chunk and Arc clone to task
            let chunk_requests: Vec<RowAnalysisRequest> = chunk
                .iter()
                .map(|r| RowAnalysisRequest {
                    stack_type: match r.stack_type {
                        StackType::User => StackType::User,
                        StackType::Both => StackType::Both,
                        StackType::Other => StackType::Other,
                    },
                    frames_hex: r.frames_hex.clone(),
                    tgid: r.tgid,
                    ts_ns: r.ts_ns,
                    current_stack_trace: r.current_stack_trace.clone(),
                })
                .collect();

            let snapshot_index_ref = snapshot_index_arc.clone();

            tasks.push(tokio::spawn(async move {
                let mut analyzed_rows = Vec::with_capacity(chunk_requests.len());
                let mut needed_symbols: HashMap<String, Vec<u64>> = HashMap::new();

                for req in chunk_requests {
                    match req.stack_type {
                        StackType::User | StackType::Both => {
                            let frames_res = parse_stack_frames_hex(&req.frames_hex);
                            if let Ok(frames) = frames_res {
                                if frames.is_empty() {
                                    analyzed_rows.push(AnalyzedRow {
                                        frames: vec![],
                                        kernel_stack: None,
                                        fallback_stack_trace: req.current_stack_trace,
                                    });
                                    continue;
                                }

                                let snapshot = if req.tgid == 0 {
                                    None
                                } else {
                                    find_inline_segments_for_event(
                                        &snapshot_index_ref,
                                        req.tgid,
                                        req.ts_ns,
                                    )
                                };

                                let mut mapped_frames = Vec::with_capacity(frames.len());
                                if let Some(segments) = snapshot {
                                    for ip in frames {
                                        if let Some(segment) = find_segment_for_ip(segments, ip) {
                                            let offset = ExportUserSymbolizer::runtime_file_offset(
                                                ip,
                                                segment.start_addr,
                                                segment.file_offset,
                                            );
                                            mapped_frames.push(MappedFrame::Resolved {
                                                path: segment.path.clone(),
                                                offset,
                                            });
                                            needed_symbols
                                                .entry(segment.path.clone())
                                                .or_default()
                                                .push(offset);
                                        } else {
                                            mapped_frames.push(MappedFrame::Raw { ip });
                                        }
                                    }
                                } else {
                                    for ip in frames {
                                        mapped_frames.push(MappedFrame::Raw { ip });
                                    }
                                }

                                analyzed_rows.push(AnalyzedRow {
                                    frames: mapped_frames,
                                    kernel_stack: req.current_stack_trace,
                                    fallback_stack_trace: None,
                                });
                            } else {
                                // Parse error fallback
                                analyzed_rows.push(AnalyzedRow {
                                    frames: vec![],
                                    kernel_stack: None,
                                    fallback_stack_trace: req.current_stack_trace,
                                });
                            }
                        }
                        StackType::Other => {
                            analyzed_rows.push(AnalyzedRow {
                                frames: vec![],
                                kernel_stack: None,
                                fallback_stack_trace: req.current_stack_trace,
                            });
                        }
                    }
                }
                (analyzed_rows, needed_symbols)
            }));
        }

        let mut all_analyzed_rows = Vec::with_capacity(num_rows);
        let mut global_needed_symbols: HashMap<String, Vec<u64>> = HashMap::new();

        for task in tasks {
            let (chunk_analyzed, chunk_symbols) = task.await?;
            all_analyzed_rows.extend(chunk_analyzed);
            for (path, offsets) in chunk_symbols {
                global_needed_symbols
                    .entry(path)
                    .or_default()
                    .extend(offsets);
            }
        }

        // 3. Resolve symbols in batch
        symbolizer.resolve_batch(global_needed_symbols).await;

        // 4. Construct Output
        let mut stack_trace_builder = ListBuilder::new(StringViewBuilder::new());

        for analyzed in all_analyzed_rows.into_iter() {
            stats.rewritten_rows += 1;

            if let Some(fallback) = analyzed.fallback_stack_trace {
                // Just use the fallback
                let labels = parse_stack_trace_labels(&fallback);
                let mut has_items = false;
                for label in labels {
                    let sanitized = sanitize_stack_trace_label(&label);
                    if !sanitized.is_empty() {
                        stack_trace_builder.values().append_value(sanitized);
                        has_items = true;
                    }
                }
                stack_trace_builder.append(has_items);
            } else {
                // Reconstruct from analyzed frames
                let mut has_items = false;
                let has_user_frames = !analyzed.frames.is_empty();
                // Add [user] marker if we have user frames
                if has_user_frames {
                    stack_trace_builder.values().append_value("[user]");
                    has_items = true;
                    stats.symbolized_user_rows += 1;
                }

                for frame in analyzed.frames {
                    match frame {
                        MappedFrame::Resolved { path, offset } => {
                            if let Some(syms) = symbolizer.lookup_cached(&path, offset) {
                                for sym in syms {
                                    stack_trace_builder.values().append_value(sym);
                                }
                            } else {
                                stats.mapped_fallback_frames += 1;
                                stack_trace_builder
                                    .values()
                                    .append_value(mapped_frame_fallback_label(&path, offset));
                            }
                        }
                        MappedFrame::Raw { ip } => {
                            stats.raw_fallback_frames += 1;
                            stack_trace_builder
                                .values()
                                .append_value(format!("0x{ip:x}"));
                        }
                    }
                }

                // Append kernel stack if present (StackType::Both)
                if let Some(kernel_trace) = analyzed.kernel_stack {
                    let kernel_labels = parse_kernel_labels_from_stack_trace(&kernel_trace);
                    let mut added_kernel = false;
                    for label in kernel_labels {
                        stack_trace_builder.values().append_value(label);
                        added_kernel = true;
                        has_items = true;
                    }
                    if added_kernel {
                        stats.symbolized_mixed_rows += 1;
                        // symbolized_user_rows was inc above, dec it to avoid double counting row types?
                        // Actually logic above is simple counters.
                        if has_user_frames {
                            stats.symbolized_user_rows -= 1; // It's mixed, not just user
                        }
                    }
                }

                stack_trace_builder.append(has_items);
            }
        }

        let rewritten_stack_trace_column: ArrayRef = Arc::new(stack_trace_builder.finish());
        let mut final_columns = Vec::with_capacity(final_schema.fields().len());
        for field in final_schema.fields() {
            if field.name() == "stack_trace" {
                final_columns.push(rewritten_stack_trace_column.clone());
                continue;
            }
            let source_idx = source_schema
                .index_of(field.name())
                .with_context(|| format!("events schema missing {} column", field.name()))?;
            final_columns.push(batch.column(source_idx).clone());
        }

        let rewritten_batch = RecordBatch::try_new(final_schema.clone(), final_columns)
            .with_context(|| "failed to construct rewritten events batch")?;
        writer
            .write(&rewritten_batch)
            .with_context(|| "failed to write rewritten events batch")?;
    }

    writer
        .close()
        .with_context(|| "failed to close rewritten events writer")?;
    std::fs::rename(&tmp_output_path, events_output_path).with_context(|| {
        format!(
            "failed to replace {} with post-processed output {}",
            events_output_path, tmp_output_path
        )
    })?;

    Ok(stats)
}

pub fn should_refresh_maps_for_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "syscall_mmap_enter" | "syscall_munmap_enter" | "syscall_brk_enter" | "process_fork"
    )
}
