use dioxus::prelude::*;

use crate::api::{CumulativeMemoryPoint, IoStatistics, IoTypeStats, MemoryStatistics, SizeBucket};
use crate::app::formatting::{format_bytes, format_count, format_duration};

#[derive(Clone, PartialEq)]
pub struct IoMemoryCardData {
    pub io_stats: Option<IoStatistics>,
    pub io_loading: bool,
    pub mem_stats: Option<MemoryStatistics>,
    pub mem_loading: bool,
}

#[component]
pub fn IoMemoryCard(data: IoMemoryCardData) -> Element {
    let has_io = data.io_stats.as_ref().is_some_and(|s| s.total_ops > 0);
    let has_mem = data.mem_stats.as_ref().is_some_and(|s| s.total_alloc_ops + s.total_free_ops > 0);
    let io_loading = data.io_loading;
    let mem_loading = data.mem_loading;

    if !has_io && !has_mem && !io_loading && !mem_loading {
        return rsx! {
            div { class: "bg-white border border-gray-200 rounded px-2 py-1.5",
                div { class: "text-xs text-gray-400", "No IO or memory data in current scope" }
            }
        };
    }

    if !has_io && !has_mem && (io_loading || mem_loading) {
        return rsx! {
            div { class: "bg-white border border-gray-200 rounded px-2 py-1.5",
                div { class: "flex items-center gap-2 text-xs text-gray-500",
                    span { class: "inline-block w-3 h-3 rounded-full border-2 border-gray-300 border-t-blue-500 animate-spin" }
                    span { "Loading..." }
                }
            }
        };
    }

    rsx! {
        div { class: "grid grid-cols-2 gap-3",
            // Left: IO Statistics
            div { class: "bg-white border border-gray-200 rounded px-2 py-1.5 space-y-2 min-w-0",
                IoSection { stats: data.io_stats, loading: io_loading }
            }
            // Right: Memory Statistics
            div { class: "bg-white border border-gray-200 rounded px-2 py-1.5 space-y-2 min-w-0",
                MemorySection { stats: data.mem_stats, loading: mem_loading }
            }
        }
    }
}

// ---------- IO section (preserved from original) ----------

#[component]
fn IoSection(stats: Option<IoStatistics>, loading: bool) -> Element {
    let Some(stats) = stats else {
        if loading {
            return rsx! {
                LoadingIndicator { label: "Loading IO statistics..." }
            };
        }
        return rsx! {
            div { class: "text-xs text-gray-400", "No IO data" }
        };
    };

    if stats.total_ops == 0 {
        return rsx! {
            div { class: "text-xs text-gray-400", "No IO events" }
        };
    }

    rsx! {
        if loading {
            LoadingIndicator { label: "Updating..." }
        }

        div { class: "text-[11px] text-gray-500 font-medium", "IO" }
        div { class: "text-[11px] text-gray-500",
            "{format_count(stats.total_ops)} ops · {format_bytes(stats.total_bytes)} total"
        }

        IoSummaryTable { operations: stats.by_operation.clone() }

        {
            let latency_ops: Vec<_> = stats.by_operation.iter()
                .filter(|op| !op.latency_histogram.is_empty() && op.total_ops > 0)
                .collect();
            rsx! {
                if !latency_ops.is_empty() {
                    div { class: "grid grid-cols-2 gap-2",
                        for op in latency_ops.iter() {
                            LatencyHistogram { stats: (*op).clone() }
                        }
                    }
                }
            }
        }

        {
            let size_ops: Vec<_> = stats.by_operation.iter()
                .filter(|op| !op.size_histogram.is_empty() && op.total_bytes > 0)
                .collect();
            rsx! {
                if !size_ops.is_empty() {
                    div { class: "grid grid-cols-2 gap-2",
                        for op in size_ops.iter() {
                            SizeDistribution { operation: op.operation.clone(), buckets: op.size_histogram.clone() }
                        }
                    }
                }
            }
        }
    }
}

// ---------- Memory section ----------

#[component]
fn MemorySection(stats: Option<MemoryStatistics>, loading: bool) -> Element {
    let Some(stats) = stats else {
        if loading {
            return rsx! {
                LoadingIndicator { label: "Loading memory statistics..." }
            };
        }
        return rsx! {
            div { class: "text-xs text-gray-400", "No memory data" }
        };
    };

    if stats.total_alloc_ops + stats.total_free_ops == 0 {
        return rsx! {
            div { class: "text-xs text-gray-400", "No memory events" }
        };
    }

    let net_label = format_net_bytes(stats.total_alloc_bytes, stats.total_free_bytes);

    rsx! {
        if loading {
            LoadingIndicator { label: "Updating..." }
        }

        div { class: "text-[11px] text-gray-500 font-medium", "Memory" }

        // Summary: alloc / free / net
        div { class: "text-[11px] text-gray-500",
            "alloc {format_count(stats.total_alloc_ops)} ops · {format_bytes(stats.total_alloc_bytes)} — \
             free {format_count(stats.total_free_ops)} ops · {format_bytes(stats.total_free_bytes)} — \
             net {net_label}"
        }

        // Per-operation table (mmap / munmap / brk)
        IoSummaryTable { operations: stats.by_operation.clone() }

        // Latency histograms for memory ops
        {
            let latency_ops: Vec<_> = stats.by_operation.iter()
                .filter(|op| !op.latency_histogram.is_empty() && op.total_ops > 0)
                .collect();
            rsx! {
                if !latency_ops.is_empty() {
                    div { class: "grid grid-cols-2 gap-2",
                        for op in latency_ops.iter() {
                            LatencyHistogram { stats: (*op).clone() }
                        }
                    }
                }
            }
        }

        // Size distribution
        {
            let size_ops: Vec<_> = stats.by_operation.iter()
                .filter(|op| !op.size_histogram.is_empty() && op.total_bytes > 0)
                .collect();
            rsx! {
                if !size_ops.is_empty() {
                    div { class: "grid grid-cols-2 gap-2",
                        for op in size_ops.iter() {
                            SizeDistribution { operation: op.operation.clone(), buckets: op.size_histogram.clone() }
                        }
                    }
                }
            }
        }

        // Cumulative memory usage chart
        if !stats.cumulative_usage.is_empty() {
            CumulativeMemoryChart { points: stats.cumulative_usage.clone(), time_range_ns: stats.time_range_ns }
        }
    }
}

// ---------- Cumulative memory usage SVG chart ----------

#[component]
fn CumulativeMemoryChart(points: Vec<CumulativeMemoryPoint>, time_range_ns: (u64, u64)) -> Element {
    let (t0, t1) = time_range_ns;
    if t1 <= t0 || points.is_empty() {
        return rsx! {};
    }

    let width: f64 = 400.0;
    let height: f64 = 80.0;
    let pad_y: f64 = 4.0;

    let min_bytes = points.iter().map(|p| p.cumulative_bytes).min().unwrap_or(0);
    let max_bytes = points.iter().map(|p| p.cumulative_bytes).max().unwrap_or(0);
    let byte_range = (max_bytes - min_bytes).max(1) as f64;

    let time_to_x = |ts: u64| -> f64 {
        (ts.saturating_sub(t0) as f64 / (t1 - t0) as f64) * width
    };
    let bytes_to_y = |b: i64| -> f64 {
        let frac = (b - min_bytes) as f64 / byte_range;
        height - pad_y - frac * (height - 2.0 * pad_y)
    };

    // Build SVG path: area fill + line
    let mut line_path = String::new();
    let mut area_path = String::new();
    let baseline_y = bytes_to_y(0_i64.max(min_bytes));

    for (i, p) in points.iter().enumerate() {
        let x = time_to_x(p.ts_ns);
        let y = bytes_to_y(p.cumulative_bytes);
        if i == 0 {
            area_path.push_str(&format!("M{x:.1},{baseline_y:.1} L{x:.1},{y:.1}"));
            line_path.push_str(&format!("M{x:.1},{y:.1}"));
        } else {
            area_path.push_str(&format!(" L{x:.1},{y:.1}"));
            line_path.push_str(&format!(" L{x:.1},{y:.1}"));
        }
    }

    // Close area path
    if let Some(last) = points.last() {
        let last_x = time_to_x(last.ts_ns);
        area_path.push_str(&format!(" L{last_x:.1},{baseline_y:.1} Z"));
    }

    // Y-axis labels
    let max_label = format_signed_bytes(max_bytes);
    let min_label = format_signed_bytes(min_bytes);

    rsx! {
        div { class: "space-y-0.5",
            div { class: "text-[11px] text-gray-500 font-medium", "Cumulative memory" }
            div { class: "relative",
                svg {
                    width: "{width}",
                    height: "{height}",
                    view_box: "0 0 {width} {height}",
                    class: "w-full",
                    // Zero line
                    line {
                        x1: "0",
                        y1: "{baseline_y:.1}",
                        x2: "{width}",
                        y2: "{baseline_y:.1}",
                        stroke: "#e5e7eb",
                        stroke_width: "1",
                        stroke_dasharray: "3,2",
                    }
                    // Area fill
                    path {
                        d: "{area_path}",
                        fill: "#818cf8",
                        fill_opacity: "0.15",
                    }
                    // Line
                    path {
                        d: "{line_path}",
                        fill: "none",
                        stroke: "#6366f1",
                        stroke_width: "1.5",
                    }
                }
                // Y-axis labels overlay
                div { class: "absolute top-0 left-0 text-[9px] text-gray-400 font-mono leading-none pl-0.5",
                    "{max_label}"
                }
                div { class: "absolute bottom-0 left-0 text-[9px] text-gray-400 font-mono leading-none pl-0.5",
                    "{min_label}"
                }
            }
        }
    }
}

// ---------- Shared sub-components ----------

#[component]
fn IoSummaryTable(operations: Vec<IoTypeStats>) -> Element {
    rsx! {
        div { class: "overflow-x-auto",
            table { class: "w-full text-xs",
                thead {
                    tr { class: "text-gray-500 border-b border-gray-100",
                        th { class: "text-left py-0.5 pr-2 font-medium", "Op" }
                        th { class: "text-right py-0.5 px-1.5 font-medium", "Count" }
                        th { class: "text-right py-0.5 px-1.5 font-medium", "Bytes" }
                        th { class: "text-right py-0.5 px-1.5 font-medium", "Avg" }
                        th { class: "text-right py-0.5 px-1.5 font-medium", "P50" }
                        th { class: "text-right py-0.5 px-1.5 font-medium", "P95" }
                        th { class: "text-right py-0.5 px-1.5 font-medium", "P99" }
                        th { class: "text-right py-0.5 pl-1.5 font-medium", "Max" }
                    }
                }
                tbody {
                    for op in operations.iter() {
                        tr { class: "border-b border-gray-50 text-gray-700",
                            td { class: "py-0.5 pr-2 font-mono font-medium", "{op.operation}" }
                            td { class: "py-0.5 px-1.5 text-right font-mono", "{format_count(op.total_ops)}" }
                            td { class: "py-0.5 px-1.5 text-right font-mono", "{format_bytes(op.total_bytes)}" }
                            td { class: "py-0.5 px-1.5 text-right font-mono", "{format_duration(op.avg_latency_ns)}" }
                            td { class: "py-0.5 px-1.5 text-right font-mono", "{format_duration(op.p50_ns)}" }
                            td { class: "py-0.5 px-1.5 text-right font-mono", "{format_duration(op.p95_ns)}" }
                            td { class: "py-0.5 px-1.5 text-right font-mono", "{format_duration(op.p99_ns)}" }
                            td { class: "py-0.5 pl-1.5 text-right font-mono", "{format_duration(op.max_ns)}" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn LatencyHistogram(stats: IoTypeStats) -> Element {
    let max_count = stats
        .latency_histogram
        .iter()
        .map(|b| b.count)
        .max()
        .unwrap_or(1)
        .max(1);

    rsx! {
        div { class: "space-y-0.5",
            div { class: "text-[11px] text-gray-500 font-medium", "{stats.operation} latency" }
            for bucket in stats.latency_histogram.iter() {
                if bucket.count > 0 {
                    BarRow {
                        label: bucket.label.clone(),
                        count: bucket.count,
                        max_count,
                        color: "bg-blue-400",
                    }
                }
            }
        }
    }
}

#[component]
fn SizeDistribution(operation: String, buckets: Vec<SizeBucket>) -> Element {
    let max_count = buckets.iter().map(|b| b.count).max().unwrap_or(1).max(1);

    rsx! {
        div { class: "space-y-0.5",
            div { class: "text-[11px] text-gray-500 font-medium", "{operation} size" }
            for bucket in buckets.iter() {
                if bucket.count > 0 {
                    BarRow {
                        label: bucket.label.clone(),
                        count: bucket.count,
                        max_count,
                        color: "bg-emerald-400",
                    }
                }
            }
        }
    }
}

#[component]
fn BarRow(label: String, count: u64, max_count: u64, color: &'static str) -> Element {
    let width_pct = (count as f64 / max_count as f64 * 100.0).max(0.5);

    rsx! {
        div { class: "flex items-center gap-1 h-4",
            span { class: "text-[10px] text-gray-500 w-16 text-right shrink-0 font-mono", "{label}" }
            div { class: "flex-1 h-3 bg-gray-100 rounded-sm overflow-hidden",
                div {
                    class: "h-full {color} rounded-sm",
                    style: "width: {width_pct}%;",
                }
            }
            span { class: "text-[10px] text-gray-500 w-10 text-right shrink-0 font-mono", "{format_count(count)}" }
        }
    }
}

#[component]
fn LoadingIndicator(label: &'static str) -> Element {
    rsx! {
        div { class: "text-[11px] text-gray-400 flex items-center gap-1",
            span { class: "inline-block w-2.5 h-2.5 rounded-full border-2 border-gray-300 border-t-blue-500 animate-spin" }
            span { "{label}" }
        }
    }
}

// ---------- Helpers ----------

fn format_net_bytes(allocated: u64, freed: u64) -> String {
    if allocated >= freed {
        format!("+{}", format_bytes(allocated - freed))
    } else {
        format!("-{}", format_bytes(freed - allocated))
    }
}

fn format_signed_bytes(bytes: i64) -> String {
    let abs = bytes.unsigned_abs();
    let formatted = format_bytes(abs);
    if bytes >= 0 {
        format!("+{formatted}")
    } else {
        format!("-{formatted}")
    }
}
