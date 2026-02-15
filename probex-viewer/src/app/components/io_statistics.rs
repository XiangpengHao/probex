use dioxus::prelude::*;

use crate::api::{IoStatistics, IoTypeStats, SizeBucket};
use crate::app::formatting::{format_bytes, format_count, format_duration};

#[derive(Clone, PartialEq)]
pub struct IoStatsCardData {
    pub stats: Option<IoStatistics>,
    pub loading: bool,
}

#[component]
pub fn IoStatisticsCard(data: IoStatsCardData) -> Element {
    let IoStatsCardData { stats, loading } = data;

    let Some(stats) = stats else {
        if loading {
            return rsx! {
                div { class: "bg-white border border-gray-200 rounded px-2 py-1.5",
                    div { class: "flex items-center gap-2 text-xs text-gray-500",
                        span { class: "inline-block w-3 h-3 rounded-full border-2 border-gray-300 border-t-blue-500 animate-spin" }
                        span { "Loading IO statistics..." }
                    }
                }
            };
        }
        return rsx! {
            div { class: "bg-white border border-gray-200 rounded px-2 py-1.5",
                div { class: "text-xs text-gray-400", "No IO data in current scope" }
            }
        };
    };

    if stats.total_ops == 0 {
        return rsx! {
            div { class: "bg-white border border-gray-200 rounded px-2 py-1.5",
                div { class: "text-xs text-gray-400", "No IO complete events in current scope" }
            }
        };
    }

    rsx! {
        div { class: "bg-white border border-gray-200 rounded px-2 py-1.5 space-y-2",
            // Loading overlay
            if loading {
                div { class: "text-[11px] text-gray-400 flex items-center gap-1",
                    span { class: "inline-block w-2.5 h-2.5 rounded-full border-2 border-gray-300 border-t-blue-500 animate-spin" }
                    span { "Updating..." }
                }
            }

            // Summary header
            div { class: "text-[11px] text-gray-500",
                "IO: {format_count(stats.total_ops)} ops · {format_bytes(stats.total_bytes)} total"
            }

            // Per-operation stats table
            IoSummaryTable { operations: stats.by_operation.clone() }

            // Latency histograms (one per operation)
            for op in stats.by_operation.iter() {
                if !op.latency_histogram.is_empty() && op.total_ops > 0 {
                    LatencyHistogram { stats: op.clone() }
                }
            }

            // Size distribution
            if !stats.size_histogram.is_empty() {
                SizeDistribution { buckets: stats.size_histogram.clone() }
            }
        }
    }
}

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
fn SizeDistribution(buckets: Vec<SizeBucket>) -> Element {
    let max_count = buckets.iter().map(|b| b.count).max().unwrap_or(1).max(1);

    rsx! {
        div { class: "space-y-0.5",
            div { class: "text-[11px] text-gray-500 font-medium", "Size distribution" }
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
