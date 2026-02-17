use charming::Chart;
use charming::component::{Axis, DataZoom, DataZoomType, Grid, Legend};
use charming::element::{
    AxisLabel, AxisType, Formatter, ItemStyle, JsFunction, LineStyle, TextStyle, Tooltip, Trigger,
};
use charming::series::{Bar, Line};
use dioxus::prelude::*;

use super::echart::EChart;
use crate::api::{EventDetail, IoStatistics, IoTypeStats, MemoryStatistics};
use crate::app::formatting::{format_bytes, format_count, format_duration, format_duration_short};

const OP_COLORS: &[&str] = &[
    "#60a5fa", // blue
    "#f97316", // orange
    "#a78bfa", // purple
    "#34d399", // green
    "#f472b6", // pink
    "#facc15", // yellow
];

fn percentile_value(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

#[derive(Clone, PartialEq)]
pub struct IoMemoryCardData {
    pub io_stats: Option<IoStatistics>,
    pub mem_stats: Option<MemoryStatistics>,
}

#[component]
pub fn IoMemoryCard(data: IoMemoryCardData) -> Element {
    let has_io = data.io_stats.as_ref().is_some_and(|s| s.total_ops > 0);
    let has_mem = data
        .mem_stats
        .as_ref()
        .is_some_and(|s| s.total_alloc_ops + s.total_free_ops > 0);

    if !has_io && !has_mem {
        return rsx! {
            div { class: "bg-white border border-gray-200 rounded px-2 py-1.5",
                div { class: "text-xs text-gray-400", "No IO or memory data in current scope" }
            }
        };
    }

    rsx! {
        div { class: "grid grid-cols-2 gap-2",
            // Left: IO Statistics
            div { class: "bg-white border border-gray-200 rounded px-2 py-1 space-y-1 min-w-0",
                IoSection { stats: data.io_stats }
            }
            // Right: Memory Statistics
            div { class: "bg-white border border-gray-200 rounded px-2 py-1 space-y-1 min-w-0",
                MemorySection { stats: data.mem_stats }
            }
        }
    }
}

// ---------- IO section ----------

#[component]
fn IoSection(stats: Option<IoStatistics>) -> Element {
    let Some(stats) = stats else {
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
        div { class: "text-[11px] text-gray-500 flex gap-1",
            span { class: "font-medium", "IO" }
            span { "{format_count(stats.total_ops)} ops · {format_bytes(stats.total_bytes)} total" }
        }

        IoSummaryTable { operations: stats.by_operation.clone() }
        LatencyCdfChart { operations: stats.by_operation.clone() }
        SizeCdfChart { operations: stats.by_operation.clone() }
    }
}

// ---------- Memory section ----------

#[component]
fn MemorySection(stats: Option<MemoryStatistics>) -> Element {
    let Some(stats) = stats else {
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
        div { class: "text-[11px] text-gray-500 flex gap-1 flex-wrap",
            span { class: "font-medium", "Memory" }
            span {
                "alloc {format_count(stats.total_alloc_ops)} ops · {format_bytes(stats.total_alloc_bytes)} — \
                 free {format_count(stats.total_free_ops)} ops · {format_bytes(stats.total_free_bytes)} — \
                 net {net_label}"
            }
        }

        IoSummaryTable { operations: stats.by_operation.clone() }
        LatencyCdfChart { operations: stats.by_operation.clone() }
        SizeCdfChart { operations: stats.by_operation.clone() }
    }
}

// ---------- Latency CDF + histogram ----------

#[component]
fn LatencyCdfChart(operations: Vec<IoTypeStats>) -> Element {
    let ops: Vec<&IoTypeStats> = operations
        .iter()
        .filter(|op| !op.latencies_ns.is_empty())
        .collect();

    if ops.is_empty() {
        return rsx! {};
    }

    // Find reference operation for histogram bins (priority: io_uring > read > write)
    let priority = ["io_uring", "read", "write"];
    let ref_op = priority
        .iter()
        .find_map(|name| ops.iter().find(|op| op.operation == *name))
        .copied()
        .unwrap_or(ops[0]);

    let global_p95 = percentile_value(&ref_op.latencies_ns, 0.95);
    let global_max = ops
        .iter()
        .filter_map(|op| op.latencies_ns.last())
        .max()
        .copied()
        .unwrap_or(1) as f64;

    // Build CDF points per operation
    let mut series_data: Vec<(String, &str, Vec<Vec<f64>>)> = Vec::new();

    for (i, op) in ops.iter().enumerate() {
        let n = op.latencies_ns.len();
        let step = (n / 2000).max(1);
        let mut points: Vec<Vec<f64>> = Vec::with_capacity(n / step + 2);

        for (j, &lat) in op.latencies_ns.iter().enumerate() {
            if j % step == 0 || j == n - 1 {
                points.push(vec![lat as f64, (j + 1) as f64 / n as f64]);
            }
        }

        let color = OP_COLORS[i % OP_COLORS.len()];
        series_data.push((op.operation.clone(), color, points));
    }

    let end_pct = if global_max > 1.0 {
        ((global_p95 as f64).max(1.0).ln() / global_max.ln() * 100.0).clamp(10.0, 100.0)
    } else {
        100.0
    };

    // JS formatters for nanoseconds
    let label_fmt = JsFunction::new_with_args(
        "v",
        "if(v>=1e9)return(v/1e9).toFixed(1)+'s';\
         if(v>=1e6)return(v/1e6).toFixed(1)+'ms';\
         if(v>=1e3)return(v/1e3).toFixed(0)+'\u{00b5}s';\
         return v+'ns';",
    );

    let tooltip_fmt = JsFunction::new_with_args(
        "ps",
        "var f=function(v){if(v>=1e9)return(v/1e9).toFixed(2)+'s';\
         if(v>=1e6)return(v/1e6).toFixed(2)+'ms';\
         if(v>=1e3)return(v/1e3).toFixed(1)+'\u{00b5}s';\
         return v+'ns';};\
         var s='';\
         for(var i=0;i<ps.length;i++){\
         var p=ps[i];\
         s+=p.marker+' '+p.seriesName+': '+f(p.data[0])+' = '+(p.data[1]*100).toFixed(1)+'%<br/>';}\
         return s;",
    );

    // --- CDF chart ---
    let mut cdf_chart = Chart::new()
        .legend(
            Legend::new()
                .top("0")
                .left("center")
                .text_style(TextStyle::new().font_size(10.0)),
        )
        .grid(
            Grid::new()
                .left("46")
                .right("8")
                .top("24")
                .bottom("28")
                .contain_label(true),
        )
        .x_axis(
            Axis::new().type_(AxisType::Log).axis_label(
                AxisLabel::new()
                    .formatter(Formatter::Function(label_fmt))
                    .font_size(9.0),
            ),
        )
        .y_axis(
            Axis::new().type_(AxisType::Value).min(0).max(1).axis_label(
                AxisLabel::new()
                    .formatter(Formatter::String("{value}".into()))
                    .font_size(9.0),
            ),
        )
        .tooltip(
            Tooltip::new()
                .trigger(Trigger::Axis)
                .formatter(Formatter::Function(tooltip_fmt)),
        )
        .data_zoom(
            DataZoom::new()
                .type_(DataZoomType::Inside)
                .x_axis_index(0)
                .start(0)
                .end(end_pct),
        )
        .animation(false);

    for (name, color, points) in &series_data {
        let line = Line::new()
            .name(name.clone())
            .show_symbol(false)
            .item_style(ItemStyle::new().color(*color))
            .line_style(LineStyle::new().color(*color).width(1.5))
            .data(points.clone());

        cdf_chart = cdf_chart.series(line);
    }

    // --- Histogram ---
    // 9 equal-width bins spanning [0, P90], plus a 10th bucket for P90+
    let p90_val = percentile_value(&ref_op.latencies_ns, 0.90);
    let bin_width = (p90_val as f64 / 9.0).ceil() as u64;
    let boundaries: Vec<u64> = if bin_width == 0 {
        vec![1; 9]
    } else {
        (1..=9).map(|i| bin_width * i).collect()
    };

    let bin_labels: Vec<String> = {
        let mut labels = Vec::with_capacity(10);
        let mut prev = 0u64;
        for &b in &boundaries {
            labels.push(format_duration_short(b));
            prev = b;
        }
        labels.push(format!("{}+", format_duration_short(prev)));
        labels
    };

    let mut hist_chart = Chart::new()
        .legend(Legend::new().show(false))
        .grid(
            Grid::new()
                .left("36")
                .right("4")
                .top("8")
                .bottom("28")
                .contain_label(true),
        )
        .x_axis(
            Axis::new()
                .type_(AxisType::Category)
                .data(bin_labels)
                .axis_label(AxisLabel::new().font_size(8.0).rotate(40)),
        )
        .y_axis(
            Axis::new()
                .type_(AxisType::Value)
                .axis_label(AxisLabel::new().font_size(9.0)),
        )
        .tooltip(Tooltip::new().trigger(Trigger::Axis))
        .animation(false);

    for (i, op) in ops.iter().enumerate() {
        let counts = count_in_bins(&op.latencies_ns, &boundaries);
        let color = OP_COLORS[i % OP_COLORS.len()];
        hist_chart = hist_chart.series(
            Bar::new()
                .name(op.operation.clone())
                .item_style(ItemStyle::new().color(color))
                .data(counts),
        );
    }

    rsx! {
        div { class: "space-y-0.5",
            div { class: "text-[11px] text-gray-500 font-medium", "Latency CDF" }
            div { class: "flex gap-1",
                div { class: "flex-1 min-w-0",
                    EChart { chart: cdf_chart, height: "180px" }
                }
                div { class: "flex-1 min-w-0",
                    EChart { chart: hist_chart, height: "180px" }
                }
            }
        }
    }
}

// ---------- Size CDF + histogram ----------

#[component]
fn SizeCdfChart(operations: Vec<IoTypeStats>) -> Element {
    let ops: Vec<&IoTypeStats> = operations
        .iter()
        .filter(|op| !op.sizes_bytes.is_empty())
        .collect();

    if ops.is_empty() {
        return rsx! {};
    }

    // Find reference operation for histogram bins (priority: io_uring > read > write)
    let priority = ["io_uring", "read", "write"];
    let ref_op = priority
        .iter()
        .find_map(|name| ops.iter().find(|op| op.operation == *name))
        .copied()
        .unwrap_or(ops[0]);

    let global_p95 = percentile_value(&ref_op.sizes_bytes, 0.95);
    let global_max = ops
        .iter()
        .filter_map(|op| op.sizes_bytes.last())
        .max()
        .copied()
        .unwrap_or(1) as f64;

    // Build CDF points per operation
    let mut series_data: Vec<(String, &str, Vec<Vec<f64>>)> = Vec::new();

    for (i, op) in ops.iter().enumerate() {
        let n = op.sizes_bytes.len();
        let step = (n / 2000).max(1);
        let mut points: Vec<Vec<f64>> = Vec::with_capacity(n / step + 2);

        for (j, &sz) in op.sizes_bytes.iter().enumerate() {
            if j % step == 0 || j == n - 1 {
                points.push(vec![sz as f64, (j + 1) as f64 / n as f64]);
            }
        }

        let color = OP_COLORS[i % OP_COLORS.len()];
        series_data.push((op.operation.clone(), color, points));
    }

    let end_pct = if global_max > 1.0 {
        ((global_p95 as f64).max(1.0).ln() / global_max.ln() * 100.0).clamp(10.0, 100.0)
    } else {
        100.0
    };

    // JS formatters for bytes
    let label_fmt = JsFunction::new_with_args(
        "v",
        "if(v>=1073741824)return(v/1073741824).toFixed(1)+'GiB';\
         if(v>=1048576)return(v/1048576).toFixed(1)+'MiB';\
         if(v>=1024)return(v/1024).toFixed(0)+'KiB';\
         return v+'B';",
    );

    let tooltip_fmt = JsFunction::new_with_args(
        "ps",
        "var f=function(v){if(v>=1073741824)return(v/1073741824).toFixed(2)+'GiB';\
         if(v>=1048576)return(v/1048576).toFixed(2)+'MiB';\
         if(v>=1024)return(v/1024).toFixed(1)+'KiB';\
         return v+'B';};\
         var s='';\
         for(var i=0;i<ps.length;i++){\
         var p=ps[i];\
         s+=p.marker+' '+p.seriesName+': '+f(p.data[0])+' = '+(p.data[1]*100).toFixed(1)+'%<br/>';}\
         return s;",
    );

    // --- CDF chart ---
    let mut cdf_chart = Chart::new()
        .legend(
            Legend::new()
                .top("0")
                .left("center")
                .text_style(TextStyle::new().font_size(10.0)),
        )
        .grid(
            Grid::new()
                .left("46")
                .right("8")
                .top("24")
                .bottom("28")
                .contain_label(true),
        )
        .x_axis(
            Axis::new().type_(AxisType::Log).axis_label(
                AxisLabel::new()
                    .formatter(Formatter::Function(label_fmt))
                    .font_size(9.0),
            ),
        )
        .y_axis(
            Axis::new().type_(AxisType::Value).min(0).max(1).axis_label(
                AxisLabel::new()
                    .formatter(Formatter::String("{value}".into()))
                    .font_size(9.0),
            ),
        )
        .tooltip(
            Tooltip::new()
                .trigger(Trigger::Axis)
                .formatter(Formatter::Function(tooltip_fmt)),
        )
        .data_zoom(
            DataZoom::new()
                .type_(DataZoomType::Inside)
                .x_axis_index(0)
                .start(0)
                .end(end_pct),
        )
        .animation(false);

    for (name, color, points) in &series_data {
        let line = Line::new()
            .name(name.clone())
            .show_symbol(false)
            .item_style(ItemStyle::new().color(*color))
            .line_style(LineStyle::new().color(*color).width(1.5))
            .data(points.clone());

        cdf_chart = cdf_chart.series(line);
    }

    // --- Histogram ---
    // 9 equal-width bins spanning [0, P90], plus a 10th bucket for P90+
    let p90_val = percentile_value(&ref_op.sizes_bytes, 0.90);
    let bin_width = (p90_val as f64 / 9.0).ceil() as u64;
    let boundaries: Vec<u64> = if bin_width == 0 {
        vec![1; 9]
    } else {
        (1..=9).map(|i| bin_width * i).collect()
    };

    let bin_labels: Vec<String> = {
        let mut labels = Vec::with_capacity(10);
        let mut prev = 0u64;
        for &b in &boundaries {
            labels.push(format_bytes(b));
            prev = b;
        }
        labels.push(format!("{}+", format_bytes(prev)));
        labels
    };

    let mut hist_chart = Chart::new()
        .legend(Legend::new().show(false))
        .grid(
            Grid::new()
                .left("36")
                .right("4")
                .top("8")
                .bottom("28")
                .contain_label(true),
        )
        .x_axis(
            Axis::new()
                .type_(AxisType::Category)
                .data(bin_labels)
                .axis_label(AxisLabel::new().font_size(8.0).rotate(40)),
        )
        .y_axis(
            Axis::new()
                .type_(AxisType::Value)
                .axis_label(AxisLabel::new().font_size(9.0)),
        )
        .tooltip(Tooltip::new().trigger(Trigger::Axis))
        .animation(false);

    for (i, op) in ops.iter().enumerate() {
        let counts = count_in_bins(&op.sizes_bytes, &boundaries);
        let color = OP_COLORS[i % OP_COLORS.len()];
        hist_chart = hist_chart.series(
            Bar::new()
                .name(op.operation.clone())
                .item_style(ItemStyle::new().color(color))
                .data(counts),
        );
    }

    rsx! {
        div { class: "space-y-0.5",
            div { class: "text-[11px] text-gray-500 font-medium", "Size CDF" }
            div { class: "flex gap-1",
                div { class: "flex-1 min-w-0",
                    EChart { chart: cdf_chart, height: "180px" }
                }
                div { class: "flex-1 min-w-0",
                    EChart { chart: hist_chart, height: "180px" }
                }
            }
        }
    }
}

// ---------- Shared sub-components ----------

#[component]
fn IoSummaryTable(operations: Vec<IoTypeStats>) -> Element {
    let mut selected_event = use_signal(|| None::<(String, EventDetail)>);

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

                            // P50
                            td { class: "py-0.5 px-1.5 text-right font-mono",
                                if let Some(event) = &op.p50_event {
                                    button {
                                        class: "hover:text-blue-600 hover:underline cursor-pointer decoration-dotted underline-offset-2",
                                        onclick: {
                                            let event = event.clone();
                                            let label = format!("P50 for {}", op.operation);
                                            move |_| {
                                                if selected_event().as_ref().is_some_and(|(l, _)| l == &label) {
                                                    selected_event.set(None);
                                                } else {
                                                    selected_event.set(Some((label.clone(), event.clone())));
                                                }
                                            }
                                        },
                                        "{format_duration(event.latency_ns.unwrap_or(0))}"
                                    }
                                } else {
                                    "0s"
                                }
                            }

                            // P95
                            td { class: "py-0.5 px-1.5 text-right font-mono",
                                if let Some(event) = &op.p95_event {
                                    button {
                                        class: "hover:text-blue-600 hover:underline cursor-pointer decoration-dotted underline-offset-2",
                                        onclick: {
                                            let event = event.clone();
                                            let label = format!("P95 for {}", op.operation);
                                            move |_| {
                                                if selected_event().as_ref().is_some_and(|(l, _)| l == &label) {
                                                    selected_event.set(None);
                                                } else {
                                                    selected_event.set(Some((label.clone(), event.clone())));
                                                }
                                            }
                                        },
                                        "{format_duration(event.latency_ns.unwrap_or(0))}"
                                    }
                                } else {
                                    "0s"
                                }
                            }

                            // P99
                            td { class: "py-0.5 px-1.5 text-right font-mono",
                                if let Some(event) = &op.p99_event {
                                    button {
                                        class: "hover:text-blue-600 hover:underline cursor-pointer decoration-dotted underline-offset-2",
                                        onclick: {
                                            let event = event.clone();
                                            let label = format!("P99 for {}", op.operation);
                                            move |_| {
                                                if selected_event().as_ref().is_some_and(|(l, _)| l == &label) {
                                                    selected_event.set(None);
                                                } else {
                                                    selected_event.set(Some((label.clone(), event.clone())));
                                                }
                                            }
                                        },
                                        "{format_duration(event.latency_ns.unwrap_or(0))}"
                                    }
                                } else {
                                    "0s"
                                }
                            }

                            // Max
                            td { class: "py-0.5 pl-1.5 text-right font-mono",
                                if let Some(event) = &op.max_event {
                                    button {
                                        class: "hover:text-blue-600 hover:underline cursor-pointer decoration-dotted underline-offset-2",
                                        onclick: {
                                            let event = event.clone();
                                            let label = format!("Max for {}", op.operation);
                                            move |_| {
                                                if selected_event().as_ref().is_some_and(|(l, _)| l == &label) {
                                                    selected_event.set(None);
                                                } else {
                                                    selected_event.set(Some((label.clone(), event.clone())));
                                                }
                                            }
                                        },
                                        "{format_duration(event.latency_ns.unwrap_or(0))}"
                                    }
                                } else {
                                    "0s"
                                }
                            }
                        }
                    }
                }
            }
        }

        if let Some((label, event)) = selected_event() {
            div { class: "mt-2 p-2 bg-slate-50 border border-slate-200 rounded text-xs animate-in fade-in slide-in-from-top-1 duration-200",
                div { class: "flex justify-between items-start mb-2",
                    div {
                        div { class: "font-medium text-slate-700", "{label}" }
                        div { class: "text-slate-500 text-[10px]",
                            "PID {event.pid} \u{2022} {event.event_type} \u{2022} end timestamp {event.ts_ns}"
                        }
                    }
                    button {
                        class: "text-slate-400 hover:text-slate-600 p-0.5 rounded hover:bg-slate-100",
                        onclick: move |_| selected_event.set(None),
                        "\u{2715}"
                    }
                }
                div { class: "bg-white border border-slate-200 rounded p-2 overflow-x-auto",
                    if let Some(stack) = &event.stack_trace {
                        if stack.is_empty() {
                            div { class: "text-slate-400 italic", "Empty stack trace" }
                        } else {
                            div { class: "font-mono text-[10px] leading-relaxed text-slate-600",
                                for frame in stack {
                                    div { class: "whitespace-nowrap hover:bg-slate-50 px-1 rounded", "{frame}" }
                                }
                            }
                        }
                    } else {
                        div { class: "text-slate-400 italic", "No stack trace captured for this event" }
                    }
                }
            }
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

/// Count values from `sorted` into 10 bins defined by the given 9 percentile boundaries.
fn count_in_bins(sorted: &[u64], boundaries: &[u64]) -> Vec<f64> {
    let mut counts = vec![0u64; 10];
    for &v in sorted {
        let bin = boundaries.iter().position(|&b| v <= b).unwrap_or(9);
        counts[bin] += 1;
    }
    counts.into_iter().map(|c| c as f64).collect()
}

fn format_net_bytes(allocated: u64, freed: u64) -> String {
    if allocated >= freed {
        format!("+{}", format_bytes(allocated - freed))
    } else {
        format!("-{}", format_bytes(freed - allocated))
    }
}
