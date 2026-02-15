# IO Latency Feature Plan

## Overview

Add comprehensive IO latency tracking to Snitch/Probex, showing latency distributions, size distributions, and statistics for read/write/fsync operations.

### Key Decisions
1. **eBPF**: In-kernel latency matching (single `IoCompleteEvent` emitted on syscall exit)
2. **Syscalls**: Include `read`, `write`, `fsync`, `fdatasync`
3. **Aggregation**: Aggregate by operation type (read/write/fsync/fdatasync), not per-fd/device
4. **Charts**: Use `charming` Rust library (ECharts-based)
5. **UI**: Timeline stays central, flamegraph and IO statistics are parallel tabbed views

---

## 1. eBPF Side

### 1.1 New Data Structures in `probex-common/src/lib.rs`

```rust
// IO operation types
pub const IO_TYPE_READ: u8 = 0;
pub const IO_TYPE_WRITE: u8 = 1;
pub const IO_TYPE_FSYNC: u8 = 2;
pub const IO_TYPE_FDATASYNC: u8 = 3;

// New event type constant
pub const IO_COMPLETE: u8 = 15;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IoCompleteEvent {
    pub header: EventHeader,
    pub fd: u32,
    pub io_type: u8,
    pub _pad: [u8; 3],
    pub request_bytes: u64,    // count arg for read/write, 0 for fsync
    pub actual_bytes: i64,     // ret value (negative = error)
    pub latency_ns: u64,       // exit_ts - enter_ts
}
```

### 1.2 New eBPF Maps in `probex-ebpf/src/main.rs`

```rust
// Track pending IO operations per-CPU to match enter/exit
// Key: (pid, fd, io_type), Value: (enter_ts, request_bytes)
#[map]
static PENDING_IO: PerCpuHashMap<PendingIoKey, PendingIoValue> =
    PerCpuHashMap::with_max_entries(1024, 0);

#[repr(C)]
struct PendingIoKey {
    pid: u32,
    fd: u32,
    io_type: u8,
    _pad: [u8; 3],
}

#[repr(C)]
struct PendingIoValue {
    enter_ts: u64,
    request_bytes: u64,
}
```

### 1.3 New Tracepoint Handlers

```rust
// ========== READ ==========
#[tracepoint]
pub fn sys_enter_read(ctx: TracePointContext) -> u32 {
    handle_io_enter(ctx, IO_TYPE_READ)
}

#[tracepoint]
pub fn sys_exit_read(ctx: TracePointContext) -> u32 {
    handle_io_exit(ctx, IO_TYPE_READ)
}

// ========== WRITE ==========
#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    handle_io_enter(ctx, IO_TYPE_WRITE)
}

#[tracepoint]
pub fn sys_exit_write(ctx: TracePointContext) -> u32 {
    handle_io_exit(ctx, IO_TYPE_WRITE)
}

// ========== FSYNC ==========
#[tracepoint]
pub fn sys_enter_fsync(ctx: TracePointContext) -> u32 {
    handle_io_enter_no_size(ctx, IO_TYPE_FSYNC)
}

#[tracepoint]
pub fn sys_exit_fsync(ctx: TracePointContext) -> u32 {
    handle_io_exit(ctx, IO_TYPE_FSYNC)
}

// ========== FDATASYNC ==========
#[tracepoint]
pub fn sys_enter_fdatasync(ctx: TracePointContext) -> u32 {
    handle_io_enter_no_size(ctx, IO_TYPE_FDATASYNC)
}

#[tracepoint]
pub fn sys_exit_fdatasync(ctx: TracePointContext) -> u32 {
    handle_io_exit(ctx, IO_TYPE_FDATASYNC)
}

// ========== Helper Functions ==========
#[inline(always)]
fn handle_io_enter(ctx: TracePointContext, io_type: u8) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    if !is_traced(pid) {
        return 0;
    }

    // Read syscall args: fd, buf, count
    let fd: u32 = unsafe { ctx.read_at(16) }.unwrap_or(0);
    let count: u64 = unsafe { ctx.read_at(32) }.unwrap_or(0);
    let ts = unsafe { bpf_ktime_get_ns() };

    let key = PendingIoKey { pid, fd, io_type, _pad: [0; 3] };
    let value = PendingIoValue { enter_ts: ts, request_bytes: count };

    let _ = PENDING_IO.insert(&key, &value, 0);
    0
}

#[inline(always)]
fn handle_io_enter_no_size(ctx: TracePointContext, io_type: u8) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    if !is_traced(pid) {
        return 0;
    }

    let fd: u32 = unsafe { ctx.read_at(16) }.unwrap_or(0);
    let ts = unsafe { bpf_ktime_get_ns() };

    let key = PendingIoKey { pid, fd, io_type, _pad: [0; 3] };
    let value = PendingIoValue { enter_ts: ts, request_bytes: 0 };

    let _ = PENDING_IO.insert(&key, &value, 0);
    0
}

#[inline(always)]
fn handle_io_exit(ctx: TracePointContext, io_type: u8) -> u32 {
    let pid = bpf_get_current_pid_tgid() as u32;
    if !is_traced(pid) {
        return 0;
    }

    let fd: u32 = unsafe { ctx.read_at(16) }.unwrap_or(0);
    let ret: i64 = unsafe { ctx.read_at(16) }.unwrap_or(0);
    let exit_ts = unsafe { bpf_ktime_get_ns() };

    let key = PendingIoKey { pid, fd, io_type, _pad: [0; 3] };

    if let Some(pending) = unsafe { PENDING_IO.get(&key) } {
        let latency_ns = exit_ts.saturating_sub(pending.enter_ts);

        // Emit IoCompleteEvent
        if let Some(mut buf) = EVENTS.reserve::<IoCompleteEvent>(0) {
            let event = IoCompleteEvent {
                header: EventHeader {
                    timestamp_ns: exit_ts,
                    pid,
                    tgid: (bpf_get_current_pid_tgid() >> 32) as u32,
                    stack_id: -1,
                    kernel_stack_id: -1,
                    stack_kind: STACK_KIND_NONE,
                    event_type: IO_COMPLETE,
                    cpu: bpf_get_smp_processor_id() as u8,
                    _padding: [0; 5],
                },
                fd,
                io_type,
                _pad: [0; 3],
                request_bytes: pending.request_bytes,
                actual_bytes: ret,
                latency_ns,
            };

            unsafe { buf.write(event) };
            buf.submit(0);
        }

        let _ = PENDING_IO.remove(&key);
    }
    0
}
```

### 1.4 Event Parsing in `probex/src/main.rs`

Add new arm in `parse_event()`:

```rust
IO_COMPLETE => {
    let io_event: IoCompleteEvent = unsafe { ptr::read(data.as_ptr() as *const _) };
    Event::IoComplete {
        header: io_event.header,
        fd: io_event.fd,
        io_type: io_event.io_type,
        request_bytes: io_event.request_bytes,
        actual_bytes: io_event.actual_bytes,
        latency_ns: io_event.latency_ns,
    }
}
```

Add new Parquet columns for io_complete events:
- `io_type`: Utf8 ("read", "write", "fsync", "fdatasync")
- `request_bytes`: UInt64
- `actual_bytes`: Int64
- `latency_ns`: UInt64

---

## 2. Backend Side

### 2.1 New Data Structures in `probex/src/viewer_backend.rs`

```rust
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct LatencyBucket {
    pub min_ns: u64,
    pub max_ns: u64,
    pub count: u64,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IoTypeStats {
    pub operation: String,          // "read", "write", "fsync", "fdatasync"
    pub total_ops: u64,
    pub total_bytes: u64,
    pub avg_latency_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
    pub latency_histogram: Vec<LatencyBucket>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SizeBucket {
    pub min_bytes: u64,
    pub max_bytes: u64,
    pub count: u64,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IoStatistics {
    pub by_operation: Vec<IoTypeStats>,
    pub size_histogram: Vec<SizeBucket>,
    pub total_ops: u64,
    pub total_bytes: u64,
    pub time_range_ns: (u64, u64),
}
```

### 2.2 Bucket Definitions

```rust
fn latency_bucket_ranges() -> Vec<(u64, u64, &'static str)> {
    vec![
        (0, 1_000, "<1μs"),
        (1_000, 10_000, "1-10μs"),
        (10_000, 100_000, "10-100μs"),
        (100_000, 1_000_000, "100μs-1ms"),
        (1_000_000, 10_000_000, "1-10ms"),
        (10_000_000, 100_000_000, "10-100ms"),
        (100_000_000, 1_000_000_000, "100ms-1s"),
        (1_000_000_000, u64::MAX, ">1s"),
    ]
}

fn size_bucket_ranges() -> Vec<(u64, u64, &'static str)> {
    vec![
        (0, 512, "<512B"),
        (512, 4_096, "512B-4KB"),
        (4_096, 16_384, "4-16KB"),
        (16_384, 65_536, "16-64KB"),
        (65_536, 262_144, "64-256KB"),
        (262_144, 1_048_576, "256KB-1MB"),
        (1_048_576, u64::MAX, ">1MB"),
    ]
}
```

### 2.3 Query Function

```rust
pub async fn query_io_statistics(
    ctx: &SessionContext,
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
) -> Result<IoStatistics> {
    let pid_filter = pid.map(|p| format!("AND pid = {}", p)).unwrap_or_default();

    let sql = format!(
        r#"
        SELECT
            io_type,
            latency_ns,
            request_bytes,
            actual_bytes
        FROM trace
        WHERE event_type = 'io_complete'
          AND ts_ns >= {start_ns}
          AND ts_ns <= {end_ns}
          {pid_filter}
        "#
    );

    let df = ctx.sql(&sql).await?;
    let batches = df.collect().await?;

    // Process batches to compute:
    // 1. Per-operation stats (read, write, fsync, fdatasync)
    // 2. Latency histograms per operation
    // 3. Size histogram (combined)
    // 4. Percentiles using sorting

    let mut ops_data: HashMap<String, Vec<(u64, u64)>> = HashMap::new();

    for batch in &batches {
        let io_types = batch.column_by_name("io_type").unwrap();
        let latencies = batch.column_by_name("latency_ns").unwrap();
        let request_bytes = batch.column_by_name("request_bytes").unwrap();
        // Iterate and collect...
    }

    let by_operation: Vec<IoTypeStats> = ops_data
        .into_iter()
        .map(|(op, data)| compute_io_type_stats(op, data))
        .collect();

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
    let total_latency: u64 = data.iter().map(|(l, _)| *l).sum();

    let avg_latency_ns = if total_ops > 0 { total_latency / total_ops } else { 0 };
    let p50_ns = percentile(&data, 50);
    let p95_ns = percentile(&data, 95);
    let p99_ns = percentile(&data, 99);
    let max_ns = data.last().map(|(l, _)| *l).unwrap_or(0);

    let latency_histogram = latency_bucket_ranges()
        .into_iter()
        .map(|(min, max, label)| {
            let count = data.iter()
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

fn percentile(sorted_data: &[(u64, u64)], pct: usize) -> u64 {
    if sorted_data.is_empty() {
        return 0;
    }
    let idx = (sorted_data.len() * pct / 100).min(sorted_data.len() - 1);
    sorted_data[idx].0
}
```

---

## 3. API Endpoint

### 3.1 Add to `probex/src/viewer_server.rs`

```rust
#[derive(Debug, Deserialize)]
pub struct IoStatisticsParams {
    pub start_ns: u64,
    pub end_ns: u64,
    pub pid: Option<u32>,
}

async fn get_io_statistics(
    State(state): State<Arc<ViewerState>>,
    Query(params): Query<IoStatisticsParams>,
) -> Result<Json<IoStatistics>, (StatusCode, String)> {
    query_io_statistics(&state.ctx, params.start_ns, params.end_ns, params.pid)
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

// Add to router:
.route("/api/io_statistics", get(get_io_statistics))
```

### 3.2 Add to `probex-viewer/src/app/api.rs`

```rust
#[derive(Debug, Clone, Deserialize)]
pub struct LatencyBucket {
    pub min_ns: u64,
    pub max_ns: u64,
    pub count: u64,
    pub label: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IoTypeStats {
    pub operation: String,
    pub total_ops: u64,
    pub total_bytes: u64,
    pub avg_latency_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub max_ns: u64,
    pub latency_histogram: Vec<LatencyBucket>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SizeBucket {
    pub min_bytes: u64,
    pub max_bytes: u64,
    pub count: u64,
    pub label: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IoStatistics {
    pub by_operation: Vec<IoTypeStats>,
    pub size_histogram: Vec<SizeBucket>,
    pub total_ops: u64,
    pub total_bytes: u64,
    pub time_range_ns: (u64, u64),
}

pub async fn get_io_statistics(
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
) -> ApiResult<IoStatistics> {
    let mut url = format!(
        "{}/api/io_statistics?start_ns={}&end_ns={}",
        API_BASE, start_ns, end_ns
    );
    if let Some(p) = pid {
        url.push_str(&format!("&pid={}", p));
    }

    let resp = Request::get(&url).send().await?;
    Ok(resp.json().await?)
}
```

---

## 4. Frontend Side

### 4.1 Add `charming` dependency to `probex-viewer/Cargo.toml`

```toml
[dependencies]
charming = "0.3"
```

### 4.2 New Component: `probex-viewer/src/app/components/io_statistics.rs`

```rust
use charming::{
    component::{Axis, Grid, Title},
    element::{AxisType, Tooltip, Trigger},
    series::Bar,
    Chart,
};
use dioxus::prelude::*;

use crate::app::api::IoStatistics;

#[derive(Clone, PartialEq, Props)]
pub struct IoStatisticsCardProps {
    pub io_stats: Option<IoStatistics>,
    pub is_loading: bool,
    pub selected_pid: Option<u32>,
}

#[component]
pub fn IoStatisticsCard(props: IoStatisticsCardProps) -> Element {
    if props.is_loading {
        return rsx! {
            div { class: "flex items-center justify-center h-64",
                div { class: "animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" }
            }
        };
    }

    let Some(stats) = props.io_stats else {
        return rsx! {
            div { class: "text-gray-500 text-center py-8",
                "No IO data available for this time range"
            }
        };
    };

    rsx! {
        div { class: "space-y-6 p-4",
            // Summary stats table
            IoSummaryTable { stats: stats.clone() }

            // Latency histograms per operation type
            for op_stats in stats.by_operation.iter() {
                LatencyHistogramChart {
                    stats: op_stats.clone(),
                    key: "{op_stats.operation}"
                }
            }

            // Size distribution chart
            SizeDistributionChart { buckets: stats.size_histogram.clone() }
        }
    }
}

#[component]
fn IoSummaryTable(stats: IoStatistics) -> Element {
    rsx! {
        div { class: "overflow-x-auto",
            table { class: "min-w-full divide-y divide-gray-200",
                thead { class: "bg-gray-50",
                    tr {
                        th { class: "px-4 py-2 text-left text-xs font-medium text-gray-500 uppercase", "Operation" }
                        th { class: "px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase", "Count" }
                        th { class: "px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase", "Total Bytes" }
                        th { class: "px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase", "Avg" }
                        th { class: "px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase", "P50" }
                        th { class: "px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase", "P95" }
                        th { class: "px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase", "P99" }
                        th { class: "px-4 py-2 text-right text-xs font-medium text-gray-500 uppercase", "Max" }
                    }
                }
                tbody { class: "bg-white divide-y divide-gray-200",
                    for op in stats.by_operation.iter() {
                        tr {
                            td { class: "px-4 py-2 whitespace-nowrap font-medium", "{op.operation}" }
                            td { class: "px-4 py-2 whitespace-nowrap text-right", "{format_count(op.total_ops)}" }
                            td { class: "px-4 py-2 whitespace-nowrap text-right", "{format_bytes(op.total_bytes)}" }
                            td { class: "px-4 py-2 whitespace-nowrap text-right", "{format_latency(op.avg_latency_ns)}" }
                            td { class: "px-4 py-2 whitespace-nowrap text-right", "{format_latency(op.p50_ns)}" }
                            td { class: "px-4 py-2 whitespace-nowrap text-right", "{format_latency(op.p95_ns)}" }
                            td { class: "px-4 py-2 whitespace-nowrap text-right", "{format_latency(op.p99_ns)}" }
                            td { class: "px-4 py-2 whitespace-nowrap text-right", "{format_latency(op.max_ns)}" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn LatencyHistogramChart(stats: crate::app::api::IoTypeStats) -> Element {
    let chart = build_latency_chart(&stats);
    let chart_html = chart.render_html();

    rsx! {
        div { class: "bg-white rounded-lg shadow p-4",
            h3 { class: "text-lg font-medium mb-2 capitalize", "{stats.operation} Latency Distribution" }
            div {
                class: "h-64",
                dangerous_inner_html: "{chart_html}"
            }
        }
    }
}

fn build_latency_chart(stats: &crate::app::api::IoTypeStats) -> Chart {
    let labels: Vec<String> = stats.latency_histogram.iter()
        .map(|b| b.label.clone())
        .collect();

    let values: Vec<u64> = stats.latency_histogram.iter()
        .map(|b| b.count)
        .collect();

    Chart::new()
        .title(Title::new().text(format!("{} Latency", stats.operation)))
        .tooltip(Tooltip::new().trigger(Trigger::Axis))
        .grid(Grid::new().left("10%").right("10%").bottom("15%"))
        .x_axis(
            Axis::new()
                .type_(AxisType::Category)
                .data(labels)
        )
        .y_axis(
            Axis::new()
                .type_(AxisType::Value)
                .name("Count")
        )
        .series(
            Bar::new()
                .name("Operations")
                .data(values)
        )
}

#[component]
fn SizeDistributionChart(buckets: Vec<crate::app::api::SizeBucket>) -> Element {
    let labels: Vec<String> = buckets.iter().map(|b| b.label.clone()).collect();
    let values: Vec<u64> = buckets.iter().map(|b| b.count).collect();

    let chart = Chart::new()
        .title(Title::new().text("IO Size Distribution"))
        .tooltip(Tooltip::new().trigger(Trigger::Axis))
        .grid(Grid::new().left("10%").right("10%").bottom("15%"))
        .x_axis(Axis::new().type_(AxisType::Category).data(labels))
        .y_axis(Axis::new().type_(AxisType::Value).name("Count"))
        .series(Bar::new().name("Operations").data(values));

    let chart_html = chart.render_html();

    rsx! {
        div { class: "bg-white rounded-lg shadow p-4",
            h3 { class: "text-lg font-medium mb-2", "IO Size Distribution" }
            div {
                class: "h-64",
                dangerous_inner_html: "{chart_html}"
            }
        }
    }
}

// Helper formatting functions
fn format_latency(ns: u64) -> String {
    if ns < 1_000 {
        format!("{}ns", ns)
    } else if ns < 1_000_000 {
        format!("{:.1}μs", ns as f64 / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.2}ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:.2}s", ns as f64 / 1_000_000_000.0)
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2}GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

fn format_count(n: u64) -> String {
    if n < 1_000 {
        n.to_string()
    } else if n < 1_000_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    }
}
```

### 4.3 Updated UI Layout in `app.rs`

```rust
// New enum for tab selection
#[derive(Clone, Copy, PartialEq, Default)]
pub enum AnalysisTab {
    #[default]
    Flamegraph,
    IoStatistics,
}

// In TraceViewer component, add new signals:
let mut selected_analysis_tab = use_signal(|| AnalysisTab::Flamegraph);
let mut io_statistics = use_signal::<Option<IoStatistics>>(|| None);

// Resource to fetch IO statistics when tab is selected or range changes
let io_stats_resource = use_resource(move || async move {
    if selected_analysis_tab() != AnalysisTab::IoStatistics {
        return None;
    }
    let range = view_range()?;
    let pid = selected_pid();
    get_io_statistics(range.start_ns, range.end_ns, pid).await.ok()
});

// Update io_statistics signal when resource completes
use_effect(move || {
    if let Some(stats) = io_stats_resource.read().clone().flatten() {
        io_statistics.set(Some(stats));
    }
});
```

### 4.4 Updated Layout Structure

```rust
rsx! {
    div { class: "flex flex-col h-screen",
        // Header
        ViewerHeader { summary: summary() }

        // Main content area - Timeline always visible at top
        div { class: "flex-1 flex flex-col overflow-hidden",

            // Timeline section (always visible, ~40% height)
            div { class: "h-2/5 border-b border-gray-200 overflow-auto",
                ProcessTimeline {
                    // ... existing props
                }
            }

            // Tab bar
            div { class: "flex border-b border-gray-200 bg-gray-50",
                button {
                    class: if selected_analysis_tab() == AnalysisTab::Flamegraph {
                        "px-4 py-2 font-medium text-blue-600 border-b-2 border-blue-600"
                    } else {
                        "px-4 py-2 font-medium text-gray-500 hover:text-gray-700"
                    },
                    onclick: move |_| selected_analysis_tab.set(AnalysisTab::Flamegraph),
                    "Flamegraph"
                }
                button {
                    class: if selected_analysis_tab() == AnalysisTab::IoStatistics {
                        "px-4 py-2 font-medium text-blue-600 border-b-2 border-blue-600"
                    } else {
                        "px-4 py-2 font-medium text-gray-500 hover:text-gray-700"
                    },
                    onclick: move |_| selected_analysis_tab.set(AnalysisTab::IoStatistics),
                    "IO Statistics"
                }
            }

            // Tab content (~60% height)
            div { class: "flex-1 overflow-auto",
                match selected_analysis_tab() {
                    AnalysisTab::Flamegraph => rsx! {
                        EventFlamegraphCard {
                            // ... existing props
                        }
                    },
                    AnalysisTab::IoStatistics => rsx! {
                        IoStatisticsCard {
                            io_stats: io_statistics(),
                            is_loading: io_stats_resource.read().is_none(),
                            selected_pid: selected_pid(),
                        }
                    },
                }
            }
        }
    }
}
```

---

## 5. File Structure Summary

| File | Changes |
|------|---------|
| `probex-common/src/lib.rs` | Add `IoCompleteEvent`, `IO_TYPE_*` constants, `IO_COMPLETE` event type |
| `probex-ebpf/src/main.rs` | Add `PENDING_IO` map, `PendingIoKey`/`Value`, tracepoint handlers for read/write/fsync/fdatasync |
| `probex/src/main.rs` | Parse `IO_COMPLETE` events, add Parquet columns |
| `probex/src/viewer_backend.rs` | Add `IoStatistics` types, `query_io_statistics()` function |
| `probex/src/viewer_server.rs` | Add `/api/io_statistics` endpoint |
| `probex-viewer/Cargo.toml` | Add `charming` dependency |
| `probex-viewer/src/app/api.rs` | Add `IoStatistics` types, `get_io_statistics()` function |
| `probex-viewer/src/app/components/mod.rs` | Add `io_statistics` module |
| `probex-viewer/src/app/components/io_statistics.rs` | New component (`IoStatisticsCard`) |
| `probex-viewer/src/app/app.rs` | Add `AnalysisTab` enum, tab switching UI, layout changes |

---

## 6. Implementation Order

### Phase 1: eBPF Layer
1. Add `IoCompleteEvent` struct and constants to `probex-common/src/lib.rs`
2. Add `PENDING_IO` map and key/value structs to `probex-ebpf/src/main.rs`
3. Implement `handle_io_enter`, `handle_io_enter_no_size`, `handle_io_exit` helpers
4. Add tracepoint handlers for read, write, fsync, fdatasync (enter and exit)
5. Update event parsing in `probex/src/main.rs` to handle `IO_COMPLETE`
6. Add Parquet columns for io_complete events

### Phase 2: Backend Layer
1. Add `IoStatistics`, `IoTypeStats`, `LatencyBucket`, `SizeBucket` structs
2. Implement `latency_bucket_ranges()` and `size_bucket_ranges()` helpers
3. Implement `query_io_statistics()` function
4. Implement `compute_io_type_stats()` and `percentile()` helpers
5. Add API endpoint in `viewer_server.rs`

### Phase 3: Frontend Layer
1. Add `charming` dependency to `Cargo.toml`
2. Add API types and `get_io_statistics()` function to `api.rs`
3. Create `io_statistics.rs` component with:
   - `IoStatisticsCard` (main component)
   - `IoSummaryTable` (statistics table)
   - `LatencyHistogramChart` (per-operation histogram)
   - `SizeDistributionChart` (size distribution)
   - Helper formatting functions
4. Add `AnalysisTab` enum and tab switching UI to `app.rs`
5. Update layout to have timeline at top, tabbed content below

### Phase 4: Polish
1. Error handling and edge cases
2. Loading states and empty states
3. Styling refinements
4. Performance optimization (lazy loading, caching)

---

## 7. UI Mockup

```
┌─────────────────────────────────────────────────────────────────┐
│  Snitch Viewer                                        [Header]  │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Timeline View (Always Visible)                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ [Process bars with event markers, zoom controls]          │  │
│  │ ├─ pid 1234 (main) ════════════════════════════════════   │  │
│  │ ├─ pid 1235 (worker) ══════════════════════════           │  │
│  │ └─ pid 1236 (worker) ════════════════════════════════     │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  [ Flamegraph ]  [ IO Statistics ]                    [Tabs]    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  IO Statistics Content (when tab selected):                     │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │ Operation │ Count │ Total   │ Avg    │ P50   │ P95  │ Max │  │
│  │───────────┼───────┼─────────┼────────┼───────┼──────┼─────│  │
│  │ read      │ 12.5K │ 45.2MB  │ 45μs   │ 32μs  │ 230μs│ 5ms │  │
│  │ write     │ 8.7K  │ 12.1MB  │ 120μs  │ 89μs  │ 890μs│ 23ms│  │
│  │ fsync     │ 156   │ -       │ 4.2ms  │ 2.1ms │ 18ms │ 45ms│  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                 │
│  Read Latency Distribution          Write Latency Distribution  │
│  ┌─────────────────────────┐        ┌─────────────────────────┐ │
│  │     ▄▄                  │        │        ▄▄               │ │
│  │  ▄▄ ██ ▄▄               │        │     ▄▄ ██ ▄▄            │ │
│  │  ██ ██ ██ ▄▄            │        │  ▄▄ ██ ██ ██ ▄▄         │ │
│  │  ██ ██ ██ ██ ▄▄         │        │  ██ ██ ██ ██ ██ ▄▄      │ │
│  └─────────────────────────┘        └─────────────────────────┘ │
│   <1μs 1-10 10-100 100μs-1ms         <1μs 1-10 10-100 ...       │
│                                                                 │
│  IO Size Distribution                                           │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │        ▄▄▄▄                                                 ││
│  │     ▄▄ ████ ▄▄                                              ││
│  │  ▄▄ ██ ████ ██ ▄▄                                           ││
│  └─────────────────────────────────────────────────────────────┘│
│   <512B  512B-4KB  4-16KB  16-64KB  64-256KB  256KB-1MB  >1MB   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```
