use crate::event::Event;
use crate::schema::create_final_schema;
use crate::writer::{
    BATCH_SIZE, PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY, PARQUET_METADATA_STACK_TRACE_FORMAT_KEY,
    STACK_TRACE_FORMAT_SYMBOLIZED_V1,
};
use anyhow::{Context as _, Result, anyhow};
use arrow::{
    array::{Array, ArrayRef, ListBuilder, StringArray, StringViewArray, StringViewBuilder, UInt32Array, UInt64Array},
    record_batch::{RecordBatch, RecordBatchReader},
};
use aya::maps::{MapData, StackTraceMap};
use parquet::{
    arrow::{ArrowWriter, arrow_reader::ParquetRecordBatchReaderBuilder},
    basic::Compression,
    file::{metadata::KeyValue, properties::WriterProperties},
};
use std::collections::{BTreeMap, HashMap, HashSet};
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

pub type ProcMapsSnapshotIndex =
    HashMap<u32, BTreeMap<u64, Arc<Vec<ProcMapInlineSegment>>>>;

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

pub fn enrich_process_name(
    event: &mut Event,
    pid_name_cache: &mut HashMap<u32, Option<String>>,
) {
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
struct UserFrameRewriteStats {
    mapped_fallback_frames: usize,
    raw_fallback_frames: usize,
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

async fn symbolize_user_frames_for_export(
    frames: &[u64],
    inline_snapshot: Option<&[ProcMapInlineSegment]>,
    symbolizer: &mut ExportUserSymbolizer,
) -> (Vec<String>, UserFrameRewriteStats) {
    let mut labels = Vec::with_capacity(frames.len() + 1);
    labels.push("[user]".to_string());

    let Some(segments) = inline_snapshot else {
        labels.extend(frames.iter().map(|ip| format!("0x{ip:x}")));
        return (
            labels,
            UserFrameRewriteStats {
                raw_fallback_frames: frames.len(),
                ..Default::default()
            },
        );
    };

    if segments.is_empty() {
        labels.extend(frames.iter().map(|ip| format!("0x{ip:x}")));
        return (
            labels,
            UserFrameRewriteStats {
                raw_fallback_frames: frames.len(),
                ..Default::default()
            },
        );
    }

    let mapped_segments: Vec<Option<&ProcMapInlineSegment>> = frames
        .iter()
        .map(|ip| find_segment_for_ip(segments, *ip))
        .collect();

    let mut frame_symbol_keys: Vec<Option<(String, u64)>> = Vec::with_capacity(frames.len());
    let mut unresolved_by_path: HashMap<String, Vec<u64>> = HashMap::new();

    for (ip, maybe_segment) in frames.iter().zip(mapped_segments.iter()) {
        if let Some(segment) = maybe_segment {
            let file_offset = ExportUserSymbolizer::runtime_file_offset(
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

    let mut stats = UserFrameRewriteStats::default();
    for (ip, maybe_key) in frames.iter().zip(frame_symbol_keys.into_iter()) {
        if let Some((path, addr)) = maybe_key {
            if let Some(symbols) = symbolizer.lookup_symbol_labels(&path, addr) {
                labels.extend(symbols);
            } else {
                stats.mapped_fallback_frames += 1;
                labels.push(mapped_frame_fallback_label(&path, addr));
            }
        } else {
            stats.raw_fallback_frames += 1;
            labels.push(format!("0x{ip:x}"));
        }
    }
    (labels, stats)
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

fn labels_to_stack_trace(labels: Vec<String>) -> Option<String> {
    let cleaned = labels
        .into_iter()
        .map(|label| sanitize_stack_trace_label(&label))
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.join(";"))
    }
}

fn parse_stack_trace_labels(stack_trace: &str) -> Vec<String> {
    stack_trace
        .split(';')
        .filter(|label| !label.is_empty())
        .map(str::to_string)
        .collect()
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

    let tmp_output_path = format!("{events_output_path}.postprocess.tmp");
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

    for batch in &mut reader {
        let batch = batch.with_context(|| "failed to read events batch")?;

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
        let mut stack_trace_builder = ListBuilder::new(StringViewBuilder::new());

        for row_idx in 0..batch.num_rows() {
            stats.rewritten_rows += 1;
            let stack_kind =
                extract_option_utf8_from_column(stack_kind_column, row_idx, "stack_kind")?;
            let stack_frames =
                extract_option_utf8_from_column(stack_frames_column, row_idx, "stack_frames")?;
            let current_stack_trace =
                extract_option_utf8_from_column(stack_trace_column, row_idx, "stack_trace")?;
            let tgid = tgid_array.value(row_idx);
            let ts_ns = ts_ns_array.value(row_idx);
            let rewritten_stack_trace = match (stack_kind, stack_frames) {
                (Some("user"), Some(frames_hex)) if !frames_hex.is_empty() => {
                    let frames = parse_stack_frames_hex(frames_hex)?;
                    if frames.is_empty() {
                        labels_to_stack_trace(
                            current_stack_trace
                                .map(parse_stack_trace_labels)
                                .unwrap_or_default(),
                        )
                    } else {
                        let snapshot = if tgid == 0 {
                            None
                        } else {
                            find_inline_segments_for_event(snapshot_index, tgid, ts_ns)
                        };
                        let (labels, row_stats) =
                            symbolize_user_frames_for_export(&frames, snapshot, &mut symbolizer)
                                .await;
                        stats.symbolized_user_rows += 1;
                        stats.mapped_fallback_frames += row_stats.mapped_fallback_frames;
                        stats.raw_fallback_frames += row_stats.raw_fallback_frames;
                        labels_to_stack_trace(labels)
                    }
                }
                (Some("both"), Some(frames_hex)) if !frames_hex.is_empty() => {
                    let frames = parse_stack_frames_hex(frames_hex)?;
                    if frames.is_empty() {
                        labels_to_stack_trace(
                            current_stack_trace
                                .map(parse_stack_trace_labels)
                                .unwrap_or_default(),
                        )
                    } else {
                        let snapshot = if tgid == 0 {
                            None
                        } else {
                            find_inline_segments_for_event(snapshot_index, tgid, ts_ns)
                        };
                        let (mut labels, row_stats) =
                            symbolize_user_frames_for_export(&frames, snapshot, &mut symbolizer)
                                .await;
                        if let Some(trace) = current_stack_trace {
                            labels.extend(parse_kernel_labels_from_stack_trace(trace));
                        }
                        stats.symbolized_mixed_rows += 1;
                        stats.mapped_fallback_frames += row_stats.mapped_fallback_frames;
                        stats.raw_fallback_frames += row_stats.raw_fallback_frames;
                        labels_to_stack_trace(labels)
                    }
                }
                _ => labels_to_stack_trace(
                    current_stack_trace
                        .map(parse_stack_trace_labels)
                        .unwrap_or_default(),
                ),
            };
            if let Some(rewritten_stack_trace) = rewritten_stack_trace {
                let labels = parse_stack_trace_labels(&rewritten_stack_trace);
                if labels.is_empty() {
                    stack_trace_builder.append(false);
                } else {
                    for label in labels {
                        stack_trace_builder.values().append_value(label);
                    }
                    stack_trace_builder.append(true);
                }
            } else {
                stack_trace_builder.append(false);
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
