use std::collections::HashSet;

use dioxus::prelude::*;

use crate::app::formatting::{format_bytes, format_duration, format_net_bytes_signed};
use crate::app::view_model::PidEventSummary;
use crate::server::{LatencySummary, SyscallLatencyStats, TraceSummary};

#[component]
pub fn PidAggregationCard(
    summary: Option<TraceSummary>,
    selected_pid: Option<u32>,
    total_count: usize,
    total_pages: usize,
    current_page: usize,
    pid_summary: PidEventSummary,
    enabled_event_types: HashSet<String>,
    latency_stats: Option<SyscallLatencyStats>,
    on_select_pid: EventHandler<Option<u32>>,
    on_toggle_event_type: EventHandler<String>,
) -> Element {
    let selected_pid_value = selected_pid.map(|pid| pid.to_string()).unwrap_or_default();

    rsx! {
        div { class: "bg-white border border-gray-200 rounded-lg px-2.5 py-2.5 space-y-2",
            div { class: "flex items-center gap-3",
                div { class: "flex items-center gap-2",
                    label { class: "text-xs text-gray-600", "PID:" }
                    select {
                        class: "px-2 py-0.5 border border-gray-200 rounded text-xs bg-white",
                        value: "{selected_pid_value}",
                        onchange: move |evt| {
                            on_select_pid.call(evt.value().parse::<u32>().ok());
                        },
                        option { value: "", "All" }
                        {
                            summary
                                .as_ref()
                                .map(|s| {
                                    s.unique_pids.iter().map(|pid| rsx! {
                                        option { key: "{pid}", value: "{pid}", "{pid}" }
                                    })
                                })
                                .into_iter()
                                .flatten()
                        }
                    }
                }
                div { class: "ml-auto text-xs text-gray-500",
                    "{total_count} events"
                    if total_pages > 1 {
                        " · Page {current_page + 1}/{total_pages}"
                    }
                }
            }

            if let Some(pid) = selected_pid {
                div { class: "border-t border-gray-100 pt-1.5 space-y-1.5",
                    div { class: "flex items-baseline justify-between",
                        span { class: "text-xs font-medium text-gray-700", "PID {pid} Event Aggregation (current range)" }
                        span { class: "text-xs text-gray-500", "{pid_summary.total} total" }
                    }

                    if pid_summary.breakdown.is_empty() {
                        div { class: "text-xs text-gray-400", "No events for this PID in current range" }
                    } else {
                        div { class: "flex flex-wrap gap-2",
                            {pid_summary.breakdown.iter().map(|(event_type, count)| {
                                let enabled = enabled_event_types.contains(event_type);
                                let event_type_clone = event_type.clone();
                                rsx! {
                                    button {
                                        key: "{event_type}",
                                        class: event_badge_class(enabled, event_type),
                                        onclick: move |_| on_toggle_event_type.call(event_type_clone.clone()),
                                        "{event_type}"
                                        span { class: if enabled { "opacity-80" } else { "text-gray-400" }, "{count}" }
                                    }
                                }
                            })}
                        }
                    }

                    if let Some(stats) = latency_stats {
                        div { class: "border-t border-gray-100 pt-1.5",
                            div { class: "grid grid-cols-1 lg:grid-cols-3 gap-2",
                                LatencyChips { label: "read latency", summary: stats.read.clone() }
                                LatencyChips { label: "write latency", summary: stats.write.clone() }

                                div { class: "border border-gray-100 rounded p-2 space-y-1",
                                    div { class: "text-[11px] uppercase tracking-wide text-gray-500", "memory syscall stats" }
                                    div { class: "flex flex-wrap gap-1 text-[11px]",
                                        StatChip { text: format!("events {}", pid_summary.memory_event_total) }
                                        StatChip { text: format!("mmap {}", pid_summary.mmap_enter) }
                                        StatChip { text: format!("munmap {}", pid_summary.munmap_enter) }
                                        StatChip { text: format!("brk {}", pid_summary.brk_enter) }
                                        StatChip { text: format!("alloc {}", format_bytes(stats.mmap_alloc_bytes)) }
                                        StatChip { text: format!("free {}", format_bytes(stats.munmap_free_bytes)) }
                                        StatChip {
                                            text: format!(
                                                "net {}",
                                                format_net_bytes_signed(stats.mmap_alloc_bytes, stats.munmap_free_bytes)
                                            ),
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn LatencyChips(label: &'static str, summary: LatencySummary) -> Element {
    rsx! {
        div { class: "border border-gray-100 rounded p-1.5 space-y-1",
            div { class: "text-[11px] uppercase tracking-wide text-gray-500", "{label}" }
            if summary.count == 0 {
                div { class: "text-xs text-gray-400", "No complete pairs" }
            } else {
                div { class: "flex flex-wrap gap-1 text-[11px]",
                    StatChip { text: format!("cnt {}", summary.count) }
                    StatChip { text: format!("avg {}", format_duration(summary.avg_ns)) }
                    StatChip { text: format!("p50 {}", format_duration(summary.p50_ns)) }
                    StatChip { text: format!("p95 {}", format_duration(summary.p95_ns)) }
                    StatChip { text: format!("max {}", format_duration(summary.max_ns)) }
                }
            }
        }
    }
}

#[component]
fn StatChip(text: String) -> Element {
    rsx! {
        span { class: "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700", "{text}" }
    }
}

fn event_badge_class(enabled: bool, event_type: &str) -> String {
    if enabled {
        format!(
            "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium border {} bg-transparent hover:bg-gray-50",
            event_badge_tone(event_type)
        )
    } else {
        "inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11px] font-medium border border-gray-200 text-gray-500 bg-transparent hover:bg-gray-50".to_string()
    }
}

fn event_badge_tone(event_type: &str) -> &'static str {
    match event_type {
        "sched_switch" => "border-blue-300 text-blue-700",
        "process_fork" => "border-green-300 text-green-700",
        "process_exit" => "border-red-300 text-red-700",
        "page_fault" => "border-amber-300 text-amber-700",
        _ if event_type.contains("syscall") => "border-indigo-300 text-indigo-700",
        _ => "border-gray-300 text-gray-700",
    }
}
