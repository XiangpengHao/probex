use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

use dioxus::prelude::*;
use dioxus::web::WebEventExt;

use crate::api::EventMarker;

// Static empty maps to avoid allocations when process_events is None
static EMPTY_EVENTS_MAP: LazyLock<HashMap<u32, Vec<EventMarker>>> = LazyLock::new(HashMap::new);
static EMPTY_CPU_COUNTS_MAP: LazyLock<HashMap<u32, Vec<u16>>> = LazyLock::new(HashMap::new);

use super::event_list::EventListCard;
use super::flamegraph::{
    EventFlamegraphCard, FlamegraphCardData, FlamegraphCardScope, FlamegraphCardSelection,
};
use super::io_statistics::{IoStatisticsCard, IoStatsCardData};
use crate::api::{
    EventFlamegraphResponse, HistogramResponse, IoStatistics, ProcessEventsResponse,
    ProcessLifetime, SyscallLatencyStats, TraceSummary,
};
use crate::app::formatting::{
    format_bytes, format_duration, format_duration_short, format_net_bytes_signed,
    get_event_marker_color,
};
use crate::app::view_model::PidEventSummary;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AnalysisTab {
    Flamegraph,
    IoStatistics,
    Events,
}

impl AnalysisTab {
    fn class(self, active: AnalysisTab) -> &'static str {
        if self == active {
            "px-2 py-0.5 text-xs font-medium text-blue-600 border-b-2 border-blue-600"
        } else {
            "px-2 py-0.5 text-xs font-medium text-gray-500 hover:text-gray-700"
        }
    }
}

#[derive(Clone, PartialEq)]
pub struct ProcessTimelineData {
    pub processes: Vec<ProcessLifetime>,
    pub process_events: Option<ProcessEventsResponse>,
    pub histogram: Option<HistogramResponse>,
    pub summary: TraceSummary,
    pub pid_summary: PidEventSummary,
    pub latency_stats: Option<SyscallLatencyStats>,
    pub selected_flame_event_type: String,
    pub flame_event_type_options: Vec<String>,
    pub flamegraph: Option<EventFlamegraphResponse>,
    pub flamegraph_loading: bool,
    pub io_statistics: Option<IoStatistics>,
    pub io_statistics_loading: bool,
}

#[derive(Clone, PartialEq)]
pub struct ProcessTimelineSelection {
    pub enabled_event_types: HashSet<String>,
    pub selected_pid: Option<u32>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProcessTimelineRange {
    pub full_start_ns: u64,
    pub full_end_ns: u64,
    pub view_start_ns: u64,
    pub view_end_ns: u64,
}

#[derive(Clone, PartialEq)]
pub struct ProcessTimelineActions {
    pub on_select_pid: EventHandler<u32>,
    pub on_select_pid_option: EventHandler<Option<u32>>,
    pub on_focus_process: EventHandler<(u32, u64, u64)>,
    pub on_change_range: EventHandler<(u64, u64)>,
    pub on_toggle_event_type: EventHandler<String>,
    pub on_select_flame_event_type: EventHandler<String>,
}

#[component]
pub fn ProcessTimeline(
    data: ProcessTimelineData,
    selection: ProcessTimelineSelection,
    range: ProcessTimelineRange,
    actions: ProcessTimelineActions,
) -> Element {
    let mut collapsed_nodes = use_signal(HashSet::<u32>::new);
    let process_bar_drag_state = use_signal(|| Option::<ProcessBarDragState>::None);
    let process_bar_drag_preview = use_signal(|| Option::<ProcessBarDragPreview>::None);
    let process_bar_width_px = use_signal(|| 0.0f64);
    // Hover time for cross-hair line between timeline overview and process bars
    let mut hover_time_ns = use_signal(|| Option::<u64>::None);
    let mut analysis_tab = use_signal(|| AnalysisTab::Flamegraph);

    let full_duration_ns = range.full_end_ns.saturating_sub(range.full_start_ns);
    let full_duration = full_duration_ns as f64;
    let view_duration_ns = range.view_end_ns.saturating_sub(range.view_start_ns);
    if full_duration == 0.0 || data.processes.is_empty() {
        return rsx! {};
    }

    let collapsed_set = collapsed_nodes();
    let tree = build_process_tree(&data.processes, &collapsed_set, range);
    if tree.visible_process_rows.is_empty() {
        return rsx! {};
    }

    let has_collapsible_nodes = !tree.collapsible_nodes.is_empty();
    let all_tree_expanded = tree
        .collapsible_nodes
        .iter()
        .all(|pid| !collapsed_set.contains(pid));
    let all_tree_collapsed = tree
        .collapsible_nodes
        .iter()
        .all(|pid| collapsed_set.contains(pid));

    // Extract process events data - use references where possible
    let (events_map, cpu_sample_counts_map, cpu_sample_bucket_count) = data
        .process_events
        .as_ref()
        .map(|pe| {
            (
                &pe.events_by_pid,
                &pe.cpu_sample_counts_by_pid,
                pe.cpu_sample_bucket_count,
            )
        })
        .unwrap_or((&EMPTY_EVENTS_MAP, &EMPTY_CPU_COUNTS_MAP, 0));
    let sample_frequency_hz = data.summary.cpu_sample_frequency_hz;
    let stats = data.latency_stats.clone().unwrap_or_default();
    let has_read_stats = stats.read.count > 0;
    let has_write_stats = stats.write.count > 0;
    let has_io_uring_stats = stats.io_uring.count > 0;
    let has_mem_stats = stats.mmap_alloc_bytes > 0 || stats.munmap_free_bytes > 0;
    let active_process_bar_drag_preview = process_bar_drag_preview();
    let on_select_pid = actions.on_select_pid;
    let on_select_pid_option = actions.on_select_pid_option;
    let on_focus_process = actions.on_focus_process;
    let on_change_range = actions.on_change_range;
    let on_toggle_event_type = actions.on_toggle_event_type;
    let on_select_flame_event_type = actions.on_select_flame_event_type;

    rsx! {
        div { class: "bg-white border border-gray-200 rounded-lg p-2.5",
            div { class: "flex items-center justify-between mb-1.5",
                span { class: "text-sm font-medium text-gray-700", "Process Lifetimes" }
                div { class: "flex items-center gap-3",
                    span { class: "text-xs text-gray-400", "{tree.visible_in_range_count} in view · {tree.sorted_processes.len()} total" }
                    if has_collapsible_nodes {
                        button {
                            class: "text-xs text-gray-500 hover:text-gray-700 underline disabled:opacity-40 disabled:no-underline",
                            disabled: all_tree_expanded,
                            onclick: move |_| collapsed_nodes.set(HashSet::new()),
                            "Expand"
                        }
                        button {
                            class: "text-xs text-gray-500 hover:text-gray-700 underline disabled:opacity-40 disabled:no-underline",
                            disabled: all_tree_collapsed,
                            onclick: {
                                let collapse_targets = tree.collapsible_nodes.clone();
                                move |_| {
                                    let mut all_collapsed = HashSet::new();
                                    for pid in &collapse_targets {
                                        all_collapsed.insert(*pid);
                                    }
                                    collapsed_nodes.set(all_collapsed);
                                }
                            },
                            "Collapse"
                        }
                    }
                }
            }

            div { class: "space-y-1 mb-1.5",
                div { class: "flex justify-between text-xs text-gray-400",
                    span { "0" }
                    span { "{format_duration(full_duration_ns)}" }
                }
                TimelineOverview {
                    data: TimelineOverviewData {
                        histogram: data.histogram.clone(),
                        enabled_types: selection.enabled_event_types.clone(),
                    },
                    range: TimelineOverviewRange {
                        full_start_ns: range.full_start_ns,
                        full_end_ns: range.full_end_ns,
                        view_start_ns: range.view_start_ns,
                        view_end_ns: range.view_end_ns,
                    },
                    on_change_range,
                    on_hover_time: EventHandler::new(move |time: Option<u64>| {
                        hover_time_ns.set(time);
                    }),
                }
            }

            // Compact controls row: PID selector + time range + stats + navigation
            div { class: "flex items-center gap-2 mb-1.5 flex-wrap",
                // PID selector
                div { class: "flex items-center gap-1.5 shrink-0",
                    span { class: "text-xs text-gray-500", "PID" }
                    select {
                        class: "px-1.5 py-0.5 border border-gray-200 rounded text-xs bg-white min-w-[70px]",
                        value: selection.selected_pid.map(|p| p.to_string()).unwrap_or_default(),
                        onchange: move |evt| {
                            on_select_pid_option.call(evt.value().parse::<u32>().ok());
                        },
                        option { value: "", "All" }
                        {data.summary.unique_pids.iter().map(|pid| rsx! {
                            option { key: "{pid}", value: "{pid}", "{pid}" }
                        })}
                    }
                    {
                        let ev_count = if selection.selected_pid.is_some() {
                            data.pid_summary.total
                        } else {
                            data.summary.total_events
                        };
                        rsx! { span { class: "text-xs text-gray-400", "{ev_count} ev" } }
                    }
                }

                div { class: "w-px h-4 bg-gray-200 shrink-0" }

                // Time range display
                div { class: "text-xs text-gray-600 shrink-0",
                    span { class: "font-mono", "{format_duration(range.view_start_ns - range.full_start_ns)}" }
                    span { class: "text-gray-400 mx-1", "→" }
                    span { class: "font-mono", "{format_duration(range.view_end_ns - range.full_start_ns)}" }
                    span { class: "text-gray-400 ml-1", "({format_duration(view_duration_ns)})" }
                }

                // Navigation buttons
                div { class: "flex items-center gap-0.5 ml-auto shrink-0",
                    button {
                        class: "px-1.5 py-0.5 text-xs bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: range.view_start_ns <= range.full_start_ns,
                        onclick: move |_| {
                            let shift_ns = view_duration_ns / 4;
                            let (new_start, new_end) = shift_window(
                                range.full_start_ns,
                                range.full_end_ns,
                                range.view_start_ns,
                                range.view_end_ns,
                                shift_ns,
                                true,
                            );
                            on_change_range.call((new_start, new_end));
                        },
                        "◀"
                    }
                    button {
                        class: "px-1.5 py-0.5 text-xs bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: range.view_end_ns >= range.full_end_ns,
                        onclick: move |_| {
                            let shift_ns = view_duration_ns / 4;
                            let (new_start, new_end) = shift_window(
                                range.full_start_ns,
                                range.full_end_ns,
                                range.view_start_ns,
                                range.view_end_ns,
                                shift_ns,
                                false,
                            );
                            on_change_range.call((new_start, new_end));
                        },
                        "▶"
                    }
                    button {
                        class: "px-1.5 py-0.5 text-xs bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: view_duration_ns < 1000,
                        onclick: move |_| {
                            let new_duration_ns = view_duration_ns / 2;
                            let (new_start, new_end) = zoom_window_to_duration(
                                range.full_start_ns,
                                range.full_end_ns,
                                range.view_start_ns,
                                range.view_end_ns,
                                new_duration_ns,
                            );
                            on_change_range.call((new_start, new_end));
                        },
                        "+"
                    }
                    button {
                        class: "px-1.5 py-0.5 text-xs bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: view_duration_ns >= full_duration_ns,
                        onclick: move |_| {
                            let new_duration_ns = (view_duration_ns * 2).min(full_duration_ns);
                            let (new_start, new_end) = zoom_window_to_duration(
                                range.full_start_ns,
                                range.full_end_ns,
                                range.view_start_ns,
                                range.view_end_ns,
                                new_duration_ns,
                            );
                            on_change_range.call((new_start, new_end));
                        },
                        "−"
                    }
                    button {
                        class: "px-1.5 py-0.5 text-xs bg-gray-100 hover:bg-gray-200 rounded",
                        onclick: move |_| {
                            on_change_range.call((range.full_start_ns, range.full_end_ns))
                        },
                        "Reset"
                    }
                }
            }

            // Event type badges row (always rendered to avoid layout flicker)
            div { class: "flex flex-wrap items-center gap-1 mb-1.5 min-h-[1.5rem]",
                if !data.pid_summary.breakdown.is_empty() {
                    {data.pid_summary.breakdown.iter().map(|(event_type, count)| {
                        let enabled = selection.enabled_event_types.contains(event_type);
                        let event_type_clone = event_type.clone();
                        let badge_class = event_badge_class(enabled, event_type);
                        rsx! {
                            button {
                                key: "{event_type}",
                                class: badge_class,
                                onclick: move |_| {
                                    on_toggle_event_type.call(event_type_clone.clone());
                                },
                                "{event_type}"
                                span { class: if enabled { "opacity-70" } else { "text-gray-400" }, " {count}" }
                            }
                        }
                    })}
                } else {
                    span { class: "text-xs text-gray-400", "No event badges in this range" }
                }
            }

            // Latency stats row (always rendered to avoid layout flicker)
            div { class: "flex flex-wrap items-center gap-4 text-xs text-gray-600 mb-1.5 min-h-[1.25rem]",
                span { class: "whitespace-nowrap",
                    span { class: "text-gray-400", "read " }
                    if has_read_stats {
                        span { class: "text-gray-400", "{stats.read.count}× " }
                        span { class: "text-gray-400", "avg/p50/p95/max " }
                        "{format_duration(stats.read.avg_ns)}/{format_duration(stats.read.p50_ns)}/{format_duration(stats.read.p95_ns)}/{format_duration(stats.read.max_ns)}"
                    } else {
                        span { class: "text-gray-400", "—" }
                    }
                }
                span { class: "whitespace-nowrap",
                    span { class: "text-gray-400", "write " }
                    if has_write_stats {
                        span { class: "text-gray-400", "{stats.write.count}× " }
                        span { class: "text-gray-400", "avg/p50/p95/max " }
                        "{format_duration(stats.write.avg_ns)}/{format_duration(stats.write.p50_ns)}/{format_duration(stats.write.p95_ns)}/{format_duration(stats.write.max_ns)}"
                    } else {
                        span { class: "text-gray-400", "—" }
                    }
                }
                span { class: "whitespace-nowrap",
                    span { class: "text-gray-400", "io_uring " }
                    if has_io_uring_stats {
                        span { class: "text-gray-400", "{stats.io_uring.count}× " }
                        span { class: "text-gray-400", "avg/p50/p95/max " }
                        "{format_duration(stats.io_uring.avg_ns)}/{format_duration(stats.io_uring.p50_ns)}/{format_duration(stats.io_uring.p95_ns)}/{format_duration(stats.io_uring.max_ns)}"
                    } else {
                        span { class: "text-gray-400", "—" }
                    }
                }
                span { class: "whitespace-nowrap",
                    span { class: "text-gray-400", "mem +/−/net " }
                    if has_mem_stats {
                        "{format_bytes(stats.mmap_alloc_bytes)}/{format_bytes(stats.munmap_free_bytes)}/{format_net_bytes_signed(stats.mmap_alloc_bytes, stats.munmap_free_bytes)}"
                    } else {
                        span { class: "text-gray-400", "—" }
                    }
                }
            }

            div { class: "flex items-center mb-1",
                div { class: "w-56 shrink-0" }
                div { class: "flex-1 flex justify-between text-xs text-gray-400",
                    span { "{format_duration(range.view_start_ns - range.full_start_ns)}" }
                    span { "{format_duration(range.view_end_ns - range.full_start_ns)}" }
                }
                div { class: "w-20 shrink-0" }
            }

            // Process rows with hover crosshair overlay
            div { class: "relative",
                // Hover time crosshair line overlay - positioned over the bar area
                if let Some(hover_ns) = hover_time_ns() {
                    if hover_ns >= range.view_start_ns && hover_ns <= range.view_end_ns {
                        {
                            let view_duration = (range.view_end_ns - range.view_start_ns) as f64;
                            let hover_pct = ((hover_ns - range.view_start_ns) as f64
                                / view_duration
                                * 100.0)
                                .clamp(0.0, 100.0);
                            rsx! {
                                // Container matching the bar area (between w-56 label and w-20 duration columns)
                                div {
                                    class: "absolute top-0 bottom-0 pointer-events-none z-10",
                                    style: "left: 224px; right: 80px;",
                                    div {
                                        class: "absolute top-0 bottom-0 w-px bg-gray-400/70",
                                        style: "left: {hover_pct}%;",
                                    }
                                }
                            }
                        }
                    }
                }

                div { class: if tree.visible_process_rows.len() > 15 { "space-y-0.5 max-h-[72vh] overflow-y-auto" } else { "space-y-0.5" },
                {tree.visible_process_rows.iter().map(|(proc, tree_pos)| {
                    let depth = tree_pos.ancestor_is_last.len();

                    let view_duration_ns = range.view_end_ns.saturating_sub(range.view_start_ns).max(1);
                    let view_duration = view_duration_ns as f64;
                    let bar_start = proc.start_ns.max(range.view_start_ns);
                    let bar_end = proc.end_ns.unwrap_or(range.full_end_ns).min(range.view_end_ns);
                    let in_view = bar_start < bar_end;
                    let visible_duration_ns = if in_view { bar_end - bar_start } else { 0 };

                    let left_pct = if in_view {
                        ((bar_start - range.view_start_ns) as f64 / view_duration * 100.0)
                            .clamp(0.0, 100.0)
                    } else {
                        0.0
                    };
                    let width_pct = if in_view {
                        (visible_duration_ns as f64 / view_duration * 100.0)
                            .max(0.5)
                            .min(100.0 - left_pct)
                    } else {
                        0.0
                    };

                    let bar_color = if proc.did_exit {
                        if proc.exit_code == Some(0) {
                            "bg-emerald-50"
                        } else {
                            "bg-rose-50"
                        }
                    } else {
                        "bg-slate-100"
                    };

                    let has_children = tree_pos.has_children;
                    let is_collapsed = collapsed_set.contains(&proc.pid);
                    let collapsed_count = tree_pos.descendant_count;
                    let pid = proc.pid;
                    let process_name = proc.process_name.as_deref().unwrap_or("unknown");
                    let is_selected = selection.selected_pid == Some(proc.pid);
                    let row_class = if is_selected {
                        "flex items-center gap-2 h-7 group bg-blue-50 border border-blue-200 rounded"
                    } else {
                        "flex items-center gap-2 h-7 group hover:bg-gray-50 rounded"
                    };
                    let process_label_class =
                        "cursor-pointer overflow-hidden px-1 py-0.5 min-w-0";
                    let process_start_ns = proc.start_ns;
                    let process_end_ns = proc.end_ns.unwrap_or(range.full_end_ns);
                    let focus_end_ns = if process_end_ns > process_start_ns {
                        process_end_ns
                    } else {
                        (process_start_ns + 1).min(range.full_end_ns)
                    };
                    let event_markers: Vec<CanvasEventMarker> = events_map
                        .get(&proc.pid)
                        .map(|events| {
                            events
                                .iter()
                                .filter(|e| {
                                    selection.enabled_event_types.contains(&e.event_type)
                                        && e.ts_ns >= range.view_start_ns
                                        && e.ts_ns <= range.view_end_ns
                                })
                                .map(|event| {
                                    let pct = ((event.ts_ns - range.view_start_ns) as f64 / view_duration
                                        * 100.0)
                                        .clamp(0.0, 100.0);
                                    CanvasEventMarker {
                                        pct,
                                        color_hex: get_event_marker_color(&event.event_type),
                                    }
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let cpu_usage_points = cpu_sample_counts_map
                        .get(&proc.pid)
                        .map(|bucket_counts| {
                            build_cpu_usage_points(
                                bucket_counts,
                                cpu_sample_bucket_count,
                                sample_frequency_hz,
                                view_duration_ns,
                            )
                        })
                        .unwrap_or_default();
                    let fork_pct = if proc.was_forked
                        && proc.start_ns >= range.view_start_ns
                        && proc.start_ns <= range.view_end_ns
                    {
                        Some(left_pct)
                    } else {
                        None
                    };
                    let exit_marker = if proc.did_exit {
                        if let Some(end) = proc.end_ns {
                            if end >= range.view_start_ns && end <= range.view_end_ns {
                                let exit_pct =
                                    ((end - range.view_start_ns) as f64 / view_duration * 100.0)
                                        .max(0.0);
                                Some((exit_pct, proc.exit_code == Some(0)))
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    // Build tree line prefixes
                    let tree_pos_clone = tree_pos.clone();
                    let row_is_selected = is_selected;
                    let flame_event_type_options_for_row = data.flame_event_type_options.clone();
                    let selected_flame_event_type_for_row = data.selected_flame_event_type.clone();
                    let flamegraph_for_row = data.flamegraph.clone();
                    let flamegraph_loading_for_row = data.flamegraph_loading;
                    let io_statistics_for_row = data.io_statistics.clone();
                    let io_statistics_loading_for_row = data.io_statistics_loading;

                    rsx! {
                        div {
                            key: "{proc.pid}",
                            class: "space-y-1",

                            div { class: "{row_class}",
                                div {
                                    class: "w-56 shrink-0 flex items-center",
                                    style: "font-variant-numeric: tabular-nums;",
                                    title: "{process_name} (PID {proc.pid})",

                                    // Tree structure lines
                                    div { class: "flex items-center h-full shrink-0",
                                        // Draw ancestor columns (│ or space)
                                        {tree_pos_clone.ancestor_is_last.iter().enumerate().map(|(i, is_last)| {
                                            rsx! {
                                                span {
                                                    key: "{i}",
                                                    class: "inline-block w-4 text-center text-gray-300 select-none",
                                                    style: "font-family: monospace;",
                                                    if *is_last { " " } else { "│" }
                                                }
                                            }
                                        })}

                                        // Draw branch connector for this node (├ or └)
                                        if depth > 0 {
                                            span {
                                                class: "inline-block w-4 text-center text-gray-300 select-none",
                                                style: "font-family: monospace;",
                                                if tree_pos_clone.is_last_child { "└" } else { "├" }
                                            }
                                        }
                                    }

                                    // Expand/collapse button or spacer
                                    if has_children {
                                        button {
                                            class: "inline-flex items-center justify-center w-5 h-5 text-xs font-bold text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded shrink-0",
                                            title: if is_collapsed { "Expand children" } else { "Collapse children" },
                                            onclick: move |_| {
                                                let mut collapsed = collapsed_nodes();
                                                if collapsed.contains(&pid) {
                                                    collapsed.remove(&pid);
                                                } else {
                                                    collapsed.insert(pid);
                                                }
                                                collapsed_nodes.set(collapsed);
                                            },
                                            if is_collapsed { "▶" } else { "▼" }
                                        }
                                    } else {
                                        span { class: "inline-block w-5 shrink-0" }
                                    }

                                    // Process info
                                    div {
                                        class: process_label_class,
                                        onclick: move |_| on_select_pid.call(pid),
                                        div { class: "flex items-center gap-1",
                                            if is_selected {
                                                span { class: "inline-block w-1.5 h-1.5 rounded-full bg-blue-600 shrink-0" }
                                            }
                                            span { class: "text-xs text-gray-700 truncate",
                                                "{process_name}"
                                            }
                                            if is_collapsed && collapsed_count > 0 {
                                                span { class: "text-[10px] text-gray-400 bg-gray-100 px-1 rounded shrink-0",
                                                    "+{collapsed_count}"
                                                }
                                            }
                                        }
                                        div { class: "text-[10px] font-mono text-gray-400 whitespace-nowrap",
                                            "PID {proc.pid}"
                                        }
                                    }
                                }

                                div {
                                    class: "flex-1 relative h-5 bg-gray-100 rounded overflow-hidden",
                                    onmounted: {
                                        let mut process_bar_width_px = process_bar_width_px;
                                        move |evt| async move {
                                            if let Ok(rect) = evt.data().get_client_rect().await
                                                && rect.width() > 0.0
                                            {
                                                process_bar_width_px.set(rect.width());
                                            }
                                        }
                                    },
                                    onresize: {
                                        let mut process_bar_width_px = process_bar_width_px;
                                        move |evt| {
                                            if let Ok(size) = evt.data().get_border_box_size()
                                                && size.width > 0.0
                                            {
                                                process_bar_width_px.set(size.width);
                                            }
                                        }
                                    },
                                    onmousedown: {
                                        let mut drag_state_sig = process_bar_drag_state;
                                        let mut drag_preview_sig = process_bar_drag_preview;
                                        let bar_width_sig = process_bar_width_px;
                                        move |evt: MouseEvent| {
                                            evt.prevent_default();
                                            let bar_width = bar_width_sig();
                                            if bar_width <= 0.0 {
                                                return;
                                            }

                                            let client_x = evt.client_coordinates().x;
                                            let bar_left_client_x = client_x - evt.element_coordinates().x;

                                            drag_state_sig.set(Some(ProcessBarDragState {
                                                pid,
                                                bar_left_client_x,
                                                bar_width_px: bar_width,
                                                anchor_client_x: client_x,
                                            }));
                                            drag_preview_sig.set(None);
                                        }
                                    },
                                    onmousemove: {
                                        let drag_state_sig = process_bar_drag_state;
                                        let mut drag_preview_sig = process_bar_drag_preview;
                                        move |evt: MouseEvent| {
                                            let Some(drag_state) = drag_state_sig() else {
                                                return;
                                            };
                                            if drag_state.pid != pid {
                                                return;
                                            }
                                            let moved_px = (evt.client_coordinates().x
                                                - drag_state.anchor_client_x)
                                                .abs();
                                            if moved_px < PROCESS_BAR_SELECTION_THRESHOLD_PX {
                                                return;
                                            }
                                            if let Some(preview) = build_process_bar_drag_preview(
                                                drag_state,
                                                evt.client_coordinates().x,
                                                range.view_start_ns,
                                                range.view_end_ns,
                                            ) && drag_preview_sig() != Some(preview)
                                            {
                                                drag_preview_sig.set(Some(preview));
                                            }
                                        }
                                    },
                                    onmouseleave: {
                                        let mut drag_state_sig = process_bar_drag_state;
                                        let drag_preview_sig = process_bar_drag_preview;
                                        move |_| {
                                            if drag_preview_sig().is_none()
                                                && drag_state_sig().map(|s| s.pid) == Some(pid)
                                            {
                                                drag_state_sig.set(None);
                                            }
                                        }
                                    },
                                    if in_view {
                                        div {
                                            class: "absolute top-0 bottom-0 {bar_color} rounded",
                                            style: "left: {left_pct}%; width: {width_pct}%;",
                                        }
                                    }

                                    if let Some(selection) = active_process_bar_drag_preview
                                        .filter(|preview| preview.pid == pid)
                                    {
                                        div {
                                            class: "absolute top-0 bottom-0 bg-blue-400/20 border border-blue-500/70 rounded-sm pointer-events-none z-[6]",
                                            style: "left: {selection.start_pct}%; width: {(selection.end_pct - selection.start_pct).max(0.2)}%;",
                                        }
                                    }

                                    ProcessActivityCanvas {
                                        usage_points: cpu_usage_points,
                                        event_markers,
                                        fork_pct,
                                        exit_pct: exit_marker.map(|(pct, _)| pct),
                                        exit_ok: exit_marker.map(|(_, ok)| ok).unwrap_or(false),
                                    }

                                    div {
                                        class: "absolute inset-0 cursor-pointer",
                                        onclick: {
                                            let mut process_bar_drag_state = process_bar_drag_state;
                                            let mut process_bar_drag_preview = process_bar_drag_preview;
                                            move |evt: MouseEvent| {
                                                process_bar_drag_state.set(None);
                                                process_bar_drag_preview.set(None);
                                                if evt.data().trigger_button() == Some(dioxus::html::input_data::MouseButton::Primary) {
                                                    let detail = evt.data().as_web_event().detail();
                                                    if detail == 2 {
                                                        on_focus_process.call((pid, process_start_ns, focus_end_ns));
                                                    } else if detail == 1 {
                                                        on_select_pid.call(pid);
                                                    }
                                                }
                                            }
                                        },
                                    }
                                }

                                div { class: "w-20 text-xs text-gray-400 shrink-0 truncate",
                                    if !in_view {
                                        "—"
                                    } else if proc.did_exit {
                                        if proc.exit_code == Some(0) {
                                            "✓ {format_duration_short(visible_duration_ns)}"
                                        } else {
                                            "✗ {format_duration_short(visible_duration_ns)}"
                                        }
                                    } else {
                                        "{format_duration_short(visible_duration_ns)}"
                                    }
                                }
                            }

                            if row_is_selected {
                                div { class: "ml-56 pl-2 space-y-1",
                                    // Tab bar
                                    div { class: "flex items-center gap-0.5 border-b border-gray-200",
                                        button {
                                            class: AnalysisTab::Flamegraph.class(analysis_tab()),
                                            onclick: move |_| analysis_tab.set(AnalysisTab::Flamegraph),
                                            "Flamegraph"
                                        }
                                        button {
                                            class: AnalysisTab::IoStatistics.class(analysis_tab()),
                                            onclick: move |_| analysis_tab.set(AnalysisTab::IoStatistics),
                                            "IO Statistics"
                                        }
                                        button {
                                            class: AnalysisTab::Events.class(analysis_tab()),
                                            onclick: move |_| analysis_tab.set(AnalysisTab::Events),
                                            "Events"
                                        }
                                    }

                                    // Tab content
                                    match analysis_tab() {
                                        AnalysisTab::Flamegraph => rsx! {
                                            EventFlamegraphCard {
                                                selection: FlamegraphCardSelection {
                                                    selected_event_type: selected_flame_event_type_for_row,
                                                    event_type_options: flame_event_type_options_for_row,
                                                },
                                                scope: FlamegraphCardScope {
                                                    selected_pid: Some(proc.pid),
                                                    full_start_ns: range.full_start_ns,
                                                    view_start_ns: range.view_start_ns,
                                                    view_end_ns: range.view_end_ns,
                                                },
                                                data: FlamegraphCardData {
                                                    flamegraph: flamegraph_for_row,
                                                    loading: flamegraph_loading_for_row,
                                                },
                                                on_select_event_type: move |event_type| {
                                                    on_select_flame_event_type.call(event_type);
                                                },
                                            }
                                        },
                                        AnalysisTab::IoStatistics => rsx! {
                                            IoStatisticsCard {
                                                data: IoStatsCardData {
                                                    stats: io_statistics_for_row,
                                                    loading: io_statistics_loading_for_row,
                                                },
                                            }
                                        },
                                        AnalysisTab::Events => rsx! {
                                            EventListCard {
                                                pid: proc.pid,
                                                view_start_ns: range.view_start_ns,
                                                view_end_ns: range.view_end_ns,
                                                full_start_ns: range.full_start_ns,
                                            }
                                        },
                                    }
                                }
                            }
                        }
                    }
                })}
                }
            }

            // Continue selection while cursor leaves the process bar.
            if active_process_bar_drag_preview.is_some() {
                div {
                    class: "fixed inset-0 z-50 cursor-ew-resize",
                    onmousemove: {
                        let drag_state_sig = process_bar_drag_state;
                        let mut drag_preview_sig = process_bar_drag_preview;
                        move |evt: MouseEvent| {
                            let Some(drag_state) = drag_state_sig() else {
                                return;
                            };
                            if let Some(preview) = build_process_bar_drag_preview(
                                drag_state,
                                evt.client_coordinates().x,
                                range.view_start_ns,
                                range.view_end_ns,
                            ) && drag_preview_sig() != Some(preview)
                            {
                                drag_preview_sig.set(Some(preview));
                            }
                        }
                    },
                    onmouseup: {
                        let mut process_bar_drag_state = process_bar_drag_state;
                        let mut process_bar_drag_preview = process_bar_drag_preview;
                        move |_| {
                            if let Some(preview) = process_bar_drag_preview() {
                                on_select_pid_option.call(Some(preview.pid));
                                on_change_range.call((preview.start_ns, preview.end_ns));
                            }
                            process_bar_drag_state.set(None);
                            process_bar_drag_preview.set(None);
                        }
                    },
                }
            }
        }
    }
}

/// What part of the timeline window is being dragged.
#[derive(Clone, Copy, PartialEq)]
enum DragKind {
    LeftEdge,
    RightEdge,
    Pan,
}

/// State captured at the start of a drag gesture.
#[derive(Clone, Copy)]
struct DragState {
    kind: DragKind,
    /// Mouse X in client coordinates at drag start.
    start_client_x: f64,
    /// Container width in pixels (estimated at drag start).
    container_width: f64,
    /// View start offset (ns from full_start) at drag start.
    initial_start_offset: u64,
    /// View end offset (ns from full_start) at drag start.
    initial_end_offset: u64,
}

const PROCESS_BAR_SELECTION_THRESHOLD_PX: f64 = 3.0;

#[derive(Clone, Copy)]
struct ProcessBarDragState {
    pid: u32,
    bar_left_client_x: f64,
    bar_width_px: f64,
    anchor_client_x: f64,
}

#[derive(Clone, Copy, PartialEq)]
struct ProcessBarDragPreview {
    pid: u32,
    start_pct: f64,
    end_pct: f64,
    start_ns: u64,
    end_ns: u64,
}

#[derive(Clone, PartialEq)]
struct TimelineOverviewData {
    histogram: Option<HistogramResponse>,
    enabled_types: HashSet<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct TimelineOverviewRange {
    full_start_ns: u64,
    full_end_ns: u64,
    view_start_ns: u64,
    view_end_ns: u64,
}

// ─── Geometry helpers (pure functions, no signals) ───────────────────────────

/// Minimum selected window as a fraction of full range (0.5%).
const MIN_WINDOW_FRAC: f64 = 0.005;
/// Visual handle width in pixels.
const HANDLE_WIDTH_PX: f64 = 10.0;
/// Hit-test padding outside the visual handle edge (px).
const HANDLE_HIT_PAD_PX: f64 = 10.0;
/// Minimum visual width for the selected window in percent (auto-zoom threshold).
/// If the selection is smaller than this, the visual representation is expanded
/// symmetrically so handles remain visible and draggable.
const MIN_VISUAL_WIDTH_PCT: f64 = 4.0;
/// Wheel zoom factor per 100px of scroll delta.
const WHEEL_ZOOM_SPEED: f64 = 0.15;

/// Convert a nanosecond offset (from full_start) to a percentage of the container.
fn ns_to_pct(offset_ns: u64, full_range: f64) -> f64 {
    if full_range <= 0.0 {
        0.0
    } else {
        (offset_ns as f64 / full_range * 100.0).clamp(0.0, 100.0)
    }
}

/// Convert an element-relative X coordinate to a nanosecond offset from full_start.
fn px_to_offset_ns(element_x: f64, container_width: f64, full_range_ns: u64) -> u64 {
    if container_width <= 0.0 {
        return 0;
    }
    let frac = (element_x / container_width).clamp(0.0, 1.0);
    (frac * full_range_ns as f64).round() as u64
}

/// Classify where a click lands relative to the current selection window.
fn classify_hit(
    element_x: f64,
    container_width: f64,
    left_pct: f64,
    width_pct: f64,
) -> Option<DragKind> {
    if container_width <= 0.0 {
        return None;
    }
    let left_px = left_pct / 100.0 * container_width;
    let right_px = (left_pct + width_pct) / 100.0 * container_width;

    // Expanded hit areas for handles
    let in_left =
        element_x >= left_px - HANDLE_HIT_PAD_PX && element_x <= left_px + HANDLE_WIDTH_PX;
    let in_right =
        element_x >= right_px - HANDLE_WIDTH_PX && element_x <= right_px + HANDLE_HIT_PAD_PX;

    if in_left {
        Some(DragKind::LeftEdge)
    } else if in_right {
        Some(DragKind::RightEdge)
    } else if element_x > left_px + HANDLE_WIDTH_PX && element_x < right_px - HANDLE_WIDTH_PX {
        Some(DragKind::Pan)
    } else if element_x < left_px {
        Some(DragKind::LeftEdge)
    } else {
        Some(DragKind::RightEdge)
    }
}

/// Compute new (start_ns, end_ns) from a drag delta.
fn compute_drag_range(
    d: DragState,
    current_client_x: f64,
    full_start_ns: u64,
    full_range_ns: u64,
    min_window_ns: u64,
) -> (u64, u64) {
    let cw = d.container_width;
    if cw <= 0.0 {
        return (
            full_start_ns + d.initial_start_offset,
            full_start_ns + d.initial_end_offset,
        );
    }
    let dx_frac = (current_client_x - d.start_client_x) / cw;
    let dx_ns = (dx_frac * full_range_ns as f64).round() as i64;

    match d.kind {
        DragKind::Pan => {
            let window_ns = d.initial_end_offset.saturating_sub(d.initial_start_offset);
            let max_start = full_range_ns.saturating_sub(window_ns);
            let new_start =
                (d.initial_start_offset as i64 + dx_ns).clamp(0, max_start as i64) as u64;
            (
                full_start_ns + new_start,
                full_start_ns + new_start + window_ns,
            )
        }
        DragKind::LeftEdge => {
            let max_start = d.initial_end_offset.saturating_sub(min_window_ns);
            let new_start =
                (d.initial_start_offset as i64 + dx_ns).clamp(0, max_start as i64) as u64;
            (
                full_start_ns + new_start,
                full_start_ns + d.initial_end_offset,
            )
        }
        DragKind::RightEdge => {
            let min_end = d.initial_start_offset + min_window_ns;
            let new_end = (d.initial_end_offset as i64 + dx_ns)
                .clamp(min_end as i64, full_range_ns as i64) as u64;
            (
                full_start_ns + d.initial_start_offset,
                full_start_ns + new_end,
            )
        }
    }
}

/// Snap the edge to the click position when clicking in a dimmed region.
fn snap_edge_to_click(
    kind: DragKind,
    click_offset_ns: u64,
    view_start_offset: u64,
    view_end_offset: u64,
    min_window_ns: u64,
    full_range_ns: u64,
) -> (u64, u64) {
    match kind {
        DragKind::LeftEdge => {
            let new_start = click_offset_ns.min(view_end_offset.saturating_sub(min_window_ns));
            (new_start, view_end_offset)
        }
        DragKind::RightEdge => {
            let new_end = click_offset_ns
                .max(view_start_offset + min_window_ns)
                .min(full_range_ns);
            (view_start_offset, new_end)
        }
        DragKind::Pan => (view_start_offset, view_end_offset),
    }
}

/// Compute a zoomed range centered on a given nanosecond offset.
fn zoom_at_point(
    center_offset_ns: u64,
    current_start_offset: u64,
    current_end_offset: u64,
    full_range_ns: u64,
    min_window_ns: u64,
    zoom_factor: f64, // < 1.0 = zoom in, > 1.0 = zoom out
) -> (u64, u64) {
    let current_window = current_end_offset.saturating_sub(current_start_offset);
    let new_window =
        ((current_window as f64 * zoom_factor).round() as u64).clamp(min_window_ns, full_range_ns);

    // Keep the cursor position stable: the cursor's fractional position within
    // the window should remain constant after zoom.
    let cursor_frac = if current_window > 0 {
        (center_offset_ns.saturating_sub(current_start_offset)) as f64 / current_window as f64
    } else {
        0.5
    };
    let new_start_raw =
        (center_offset_ns as i64 - (cursor_frac * new_window as f64).round() as i64).max(0) as u64;
    let max_start = full_range_ns.saturating_sub(new_window);
    let new_start = new_start_raw.min(max_start);
    (new_start, new_start + new_window)
}

// ─── TimelineOverview component ──────────────────────────────────────────────

#[component]
fn TimelineOverview(
    data: TimelineOverviewData,
    range: TimelineOverviewRange,
    on_change_range: EventHandler<(u64, u64)>,
    on_hover_time: EventHandler<Option<u64>>,
) -> Element {
    let TimelineOverviewData {
        histogram,
        enabled_types,
    } = data;
    let TimelineOverviewRange {
        full_start_ns,
        full_end_ns,
        view_start_ns,
        view_end_ns,
    } = range;

    let full_range_ns = full_end_ns.saturating_sub(full_start_ns);
    let full_range = full_range_ns as f64;
    if full_range == 0.0 {
        return rsx! {};
    }

    // ── Signals ──────────────────────────────────────────────────────────────
    let mut drag = use_signal(|| Option::<DragState>::None);
    let mut drag_preview_range = use_signal(|| Option::<(u64, u64)>::None);
    let mut container_width_px = use_signal(|| 0.0f64);
    let mut hover_x_pct = use_signal(|| Option::<f64>::None);
    let mut last_mousedown_ts = use_signal(|| 0.0f64);

    let min_window_ns = ((full_range_ns as f64 * MIN_WINDOW_FRAC) as u64).max(1);

    // ── Derived layout values ────────────────────────────────────────────────
    let (display_start_ns, display_end_ns) =
        drag_preview_range().unwrap_or((view_start_ns, view_end_ns));
    let start_offset = display_start_ns.saturating_sub(full_start_ns);
    let end_offset = display_end_ns.saturating_sub(full_start_ns);
    let raw_left_pct = ns_to_pct(start_offset, full_range);
    let raw_width_pct = (end_offset.saturating_sub(start_offset)) as f64 / full_range * 100.0;

    // Auto-zoom: if the selection is too narrow to see/grab, expand the visual
    // representation symmetrically around the selection center.
    let (view_left_pct, view_width_pct) = if raw_width_pct < MIN_VISUAL_WIDTH_PCT {
        let center = raw_left_pct + raw_width_pct / 2.0;
        let new_left = (center - MIN_VISUAL_WIDTH_PCT / 2.0).max(0.0);
        let new_left = new_left.min(100.0 - MIN_VISUAL_WIDTH_PCT);
        (new_left, MIN_VISUAL_WIDTH_PCT)
    } else {
        (raw_left_pct, raw_width_pct)
    };

    let right_pct = (view_left_pct + view_width_pct).min(100.0);
    let right_dim_pct = (100.0 - right_pct).max(0.0);

    // Histogram background
    let histogram_area_path = histogram
        .as_ref()
        .and_then(|h| build_overview_histogram_area_path(h, &enabled_types));

    // ── Drag state derived values ────────────────────────────────────────────
    let is_dragging = drag().is_some();
    let drag_kind = drag().map(|d| d.kind);
    let drag_overlay_cursor = match drag_kind {
        Some(DragKind::Pan) => "grabbing",
        _ => "ew-resize",
    };

    // Whether the view covers the full range (nothing to reset to)
    let is_full_range = view_start_ns <= full_start_ns && view_end_ns >= full_end_ns;

    // ── Event handler: commit range ──────────────────────────────────────────
    let mut commit_drag = move || {
        if let Some((start, end)) = drag_preview_range() {
            on_change_range.call((start, end));
        }
        drag.set(None);
        drag_preview_range.set(None);
    };

    let container_cursor = if is_dragging {
        drag_overlay_cursor
    } else {
        "crosshair"
    };

    rsx! {
        div {
            class: "relative h-14 bg-gray-100 rounded-lg overflow-hidden select-none",
            style: "cursor: {container_cursor};",

            // ── Measure container width ──────────────────────────────────────
            onmounted: move |evt| async move {
                if let Ok(rect) = evt.data().get_client_rect().await {
                    container_width_px.set(rect.width());
                }
            },
            onresize: move |evt| {
                if let Ok(size) = evt.data().get_border_box_size()
                    && size.width > 0.0
                {
                    container_width_px.set(size.width);
                }
            },

            // ── Mouse down: start drag or detect double-click ─────────────
            onmousedown: move |evt: MouseEvent| {
                evt.prevent_default();

                // Detect double-click: two mousedowns within 300ms.
                let now = evt.as_web_event().time_stamp();
                let prev = last_mousedown_ts();
                last_mousedown_ts.set(now);
                if (now - prev) < 300.0 && !is_full_range {
                    // Double-click: cancel any in-progress drag and reset.
                    drag.set(None);
                    drag_preview_range.set(None);
                    on_change_range.call((full_start_ns, full_end_ns));
                    return;
                }

                let cw = container_width_px();
                let element_x = evt.element_coordinates().x;
                let Some(kind) = classify_hit(element_x, cw, view_left_pct, view_width_pct) else {
                    return;
                };

                // Check if click is in a dimmed region and snap edge
                let left_px = view_left_pct / 100.0 * cw;
                let right_px = right_pct / 100.0 * cw;
                let in_dimmed = element_x < left_px || element_x > right_px;

                let (snap_start, snap_end) = if in_dimmed && cw > 0.0 {
                    let click_offset = px_to_offset_ns(element_x, cw, full_range_ns);
                    snap_edge_to_click(
                        kind,
                        click_offset,
                        start_offset,
                        end_offset,
                        min_window_ns,
                        full_range_ns,
                    )
                } else {
                    (start_offset, end_offset)
                };

                drag_preview_range.set(Some((
                    full_start_ns + snap_start,
                    full_start_ns + snap_end,
                )));
                drag.set(Some(DragState {
                    kind,
                    start_client_x: evt.client_coordinates().x,
                    container_width: cw,
                    initial_start_offset: snap_start,
                    initial_end_offset: snap_end,
                }));
            },

            // ── Mouse move: update hover indicator + drag preview ────────────
            onmousemove: move |evt: MouseEvent| {
                let cw = container_width_px();
                if cw > 0.0 {
                    let element_x = evt.element_coordinates().x;
                    let pct = (element_x / cw * 100.0).clamp(0.0, 100.0);
                    if hover_x_pct() != Some(pct) {
                        hover_x_pct.set(Some(pct));
                    }
                    let hover_frac = (element_x / cw).clamp(0.0, 1.0);
                    let hover_ns = full_start_ns + (hover_frac * full_range).round() as u64;
                    on_hover_time.call(Some(hover_ns));
                }

                if let Some(d) = drag() {
                    let (start, end) =
                        compute_drag_range(d, evt.client_coordinates().x, full_start_ns, full_range_ns, min_window_ns);
                    if drag_preview_range() != Some((start, end)) {
                        drag_preview_range.set(Some((start, end)));
                    }
                }
            },

            // ── Mouse leave: clear hover ─────────────────────────────────────
            onmouseleave: move |_| {
                hover_x_pct.set(None);
                on_hover_time.call(None);
            },

            // ── Mouse up on the container itself (backup for non-overlay) ────
            onmouseup: move |_| {
                if drag().is_some() {
                    commit_drag();
                }
            },

            // ── Wheel: zoom in/out centered on cursor ────────────────────────
            onwheel: move |evt| {
                let cw = container_width_px();
                if cw <= 0.0 { return; }
                let raw_event = evt.as_web_event();
                raw_event.prevent_default();
                let delta_y = raw_event.delta_y();

                let element_x = evt.element_coordinates().x;
                let cursor_offset = px_to_offset_ns(element_x, cw, full_range_ns);
                // Normalize delta: positive = zoom out, negative = zoom in
                let zoom_factor = 1.0 + (delta_y / 100.0) * WHEEL_ZOOM_SPEED;
                let (new_start, new_end) = zoom_at_point(
                    cursor_offset,
                    start_offset,
                    end_offset,
                    full_range_ns,
                    min_window_ns,
                    zoom_factor,
                );
                on_change_range.call((full_start_ns + new_start, full_start_ns + new_end));
            },

            // ── Layer 0: Histogram background ────────────────────────────────
            if let Some(area_path) = histogram_area_path {
                svg {
                    class: "absolute inset-0 w-full h-full pointer-events-none",
                    view_box: "0 0 100 100",
                    preserve_aspect_ratio: "none",
                    path {
                        d: "{area_path}",
                        fill: "rgba(107, 114, 128, 0.4)",
                        stroke: "none",
                    }
                }
            }

            // ── Layer 1: Dimmed regions outside selection ────────────────────
            div {
                class: "absolute top-0 bottom-0 left-0 bg-gray-900/30 pointer-events-none",
                style: "width: {view_left_pct}%;",
            }
            div {
                class: "absolute top-0 bottom-0 right-0 bg-gray-900/30 pointer-events-none",
                style: "width: {right_dim_pct}%;",
            }

            // ── Layer 2: Selected window border (top + bottom) ───────────────
            div {
                class: "absolute top-0 h-[2px] bg-blue-500/80 pointer-events-none z-10",
                style: "left: {view_left_pct}%; width: {view_width_pct}%;",
            }
            div {
                class: "absolute bottom-0 h-[2px] bg-blue-500/80 pointer-events-none z-10",
                style: "left: {view_left_pct}%; width: {view_width_pct}%;",
            }

            // ── Layer 3: Left handle ─────────────────────────────────────────
            div {
                class: "absolute top-0 bottom-0 pointer-events-none z-20 flex items-center justify-center",
                style: "left: {view_left_pct}%; width: {HANDLE_WIDTH_PX}px;",
                div {
                    class: if is_dragging && drag_kind == Some(DragKind::LeftEdge) {
                        "w-full h-full rounded-l-md bg-blue-600 shadow-md flex items-center justify-center"
                    } else {
                        "w-full h-full rounded-l-md bg-blue-500 hover:bg-blue-600 shadow-sm hover:shadow-md flex items-center justify-center transition-colors duration-100"
                    },
                    div { class: "flex flex-col gap-[3px] items-center",
                        div { class: "w-[3px] h-[3px] rounded-full bg-white/80" }
                        div { class: "w-[3px] h-[3px] rounded-full bg-white/80" }
                        div { class: "w-[3px] h-[3px] rounded-full bg-white/80" }
                    }
                }
            }

            // ── Layer 3: Right handle ────────────────────────────────────────
            div {
                class: "absolute top-0 bottom-0 pointer-events-none z-20 flex items-center justify-center",
                style: "left: calc({right_pct}% - {HANDLE_WIDTH_PX}px); width: {HANDLE_WIDTH_PX}px;",
                div {
                    class: if is_dragging && drag_kind == Some(DragKind::RightEdge) {
                        "w-full h-full rounded-r-md bg-blue-600 shadow-md flex items-center justify-center"
                    } else {
                        "w-full h-full rounded-r-md bg-blue-500 hover:bg-blue-600 shadow-sm hover:shadow-md flex items-center justify-center transition-colors duration-100"
                    },
                    div { class: "flex flex-col gap-[3px] items-center",
                        div { class: "w-[3px] h-[3px] rounded-full bg-white/80" }
                        div { class: "w-[3px] h-[3px] rounded-full bg-white/80" }
                        div { class: "w-[3px] h-[3px] rounded-full bg-white/80" }
                    }
                }
            }

            // ── Layer 4: Hover vertical indicator ────────────────────────────
            if let Some(hx) = hover_x_pct() {
                if !is_dragging {
                    div {
                        class: "absolute top-0 bottom-0 pointer-events-none z-15",
                        style: "left: {hx}%; width: 1px; background: rgba(59, 130, 246, 0.5);",
                    }
                }
            }

            // ── Layer 5: Full-viewport drag overlay ──────────────────────────
            // Captures mouse events globally so drag continues outside the bar.
            if is_dragging {
                div {
                    class: "fixed inset-0 z-50",
                    style: "cursor: {drag_overlay_cursor};",
                    onmousemove: move |evt: MouseEvent| {
                        let Some(d) = drag() else { return };
                        let (start, end) =
                            compute_drag_range(d, evt.client_coordinates().x, full_start_ns, full_range_ns, min_window_ns);
                        if drag_preview_range() != Some((start, end)) {
                            drag_preview_range.set(Some((start, end)));
                        }
                    },
                    onmouseup: move |_| {
                        if drag().is_some() {
                            commit_drag();
                        }
                    },
                }
            }
        }
    }
}

#[derive(Clone, PartialEq)]
struct CanvasEventMarker {
    pct: f64,
    color_hex: &'static str,
}

#[component]
fn ProcessActivityCanvas(
    usage_points: Vec<f64>,
    event_markers: Vec<CanvasEventMarker>,
    fork_pct: Option<f64>,
    exit_pct: Option<f64>,
    exit_ok: bool,
) -> Element {
    let (usage_area_path, usage_line_path) = build_usage_paths(&usage_points);
    let marker_paths = build_vertical_marker_paths(&event_markers);

    rsx! {
        svg {
            class: "absolute inset-0 w-full h-full pointer-events-none",
            view_box: "0 0 100 100",
            preserve_aspect_ratio: "none",

            if let Some(area_path) = usage_area_path {
                path {
                    d: "{area_path}",
                    fill: "rgba(30, 64, 175, 0.18)",
                    stroke: "none",
                }
            }

            if let Some(line_path) = usage_line_path {
                path {
                    d: "{line_path}",
                    fill: "none",
                    stroke: "rgba(30, 64, 175, 0.7)",
                    stroke_width: "0.9",
                    vector_effect: "non-scaling-stroke",
                }
            }

            {marker_paths.iter().map(|(color_hex, path_data)| {
                rsx! {
                    path {
                        key: "{color_hex}",
                        d: "{path_data}",
                        fill: "none",
                        stroke: "{color_hex}",
                        stroke_width: "0.45",
                        vector_effect: "non-scaling-stroke",
                    }
                }
            })}

            if let Some(fork_x) = fork_pct {
                line {
                    x1: "{fork_x.clamp(0.0, 100.0)}",
                    y1: "0",
                    x2: "{fork_x.clamp(0.0, 100.0)}",
                    y2: "100",
                    stroke: "#16a34a",
                    stroke_width: "0.9",
                    vector_effect: "non-scaling-stroke",
                }
            }

            if let Some(exit_x) = exit_pct {
                line {
                    x1: "{exit_x.clamp(0.0, 100.0)}",
                    y1: "0",
                    x2: "{exit_x.clamp(0.0, 100.0)}",
                    y2: "100",
                    stroke: if exit_ok { "#16a34a" } else { "#dc2626" },
                    stroke_width: "0.9",
                    vector_effect: "non-scaling-stroke",
                }
            }
        }
    }
}

fn fit_window_to_bounds(
    full_start_ns: u64,
    full_end_ns: u64,
    window_start_ns: u64,
    window_duration_ns: u64,
) -> (u64, u64) {
    let full_duration_ns = full_end_ns.saturating_sub(full_start_ns);
    if full_duration_ns == 0 {
        return (full_start_ns, full_end_ns);
    }

    let duration_ns = window_duration_ns.max(1).min(full_duration_ns);
    let max_start_ns = full_end_ns.saturating_sub(duration_ns);
    let start_ns = window_start_ns.clamp(full_start_ns, max_start_ns);
    (start_ns, start_ns + duration_ns)
}

fn shift_window(
    full_start_ns: u64,
    full_end_ns: u64,
    view_start_ns: u64,
    view_end_ns: u64,
    shift_ns: u64,
    shift_left: bool,
) -> (u64, u64) {
    let window_duration_ns = view_end_ns.saturating_sub(view_start_ns);
    let shifted_start_ns = if shift_left {
        view_start_ns.saturating_sub(shift_ns)
    } else {
        view_start_ns.saturating_add(shift_ns)
    };

    fit_window_to_bounds(
        full_start_ns,
        full_end_ns,
        shifted_start_ns,
        window_duration_ns,
    )
}

fn zoom_window_to_duration(
    full_start_ns: u64,
    full_end_ns: u64,
    view_start_ns: u64,
    view_end_ns: u64,
    new_duration_ns: u64,
) -> (u64, u64) {
    let current_duration_ns = view_end_ns.saturating_sub(view_start_ns);
    let center_ns = view_start_ns.saturating_add(current_duration_ns / 2);
    let target_duration_ns = new_duration_ns.max(1);
    let centered_start_ns = center_ns.saturating_sub(target_duration_ns / 2);

    fit_window_to_bounds(
        full_start_ns,
        full_end_ns,
        centered_start_ns,
        target_duration_ns,
    )
}

fn build_overview_histogram_area_path(
    histogram: &HistogramResponse,
    enabled_types: &HashSet<String>,
) -> Option<String> {
    if histogram.buckets.is_empty() {
        return None;
    }

    let counts = histogram
        .buckets
        .iter()
        .map(|bucket| {
            bucket
                .counts_by_type
                .iter()
                .filter(|(event_type, _)| enabled_types.contains(*event_type))
                .map(|(_, count)| *count as f64)
                .sum::<f64>()
        })
        .collect::<Vec<_>>();

    let max_count = counts.iter().copied().fold(0.0f64, f64::max);
    if max_count <= 0.0 {
        return None;
    }

    let bucket_count = counts.len() as f64;
    let mut area_path = String::from("M0 100");

    for (idx, count) in counts.iter().enumerate() {
        let x_left = idx as f64 / bucket_count * 100.0;
        let x_right = (idx as f64 + 1.0) / bucket_count * 100.0;
        let mut height_pct = (count / max_count * 100.0).clamp(0.0, 100.0);
        if *count > 0.0 {
            height_pct = height_pct.max(1.0);
        }
        let y = 100.0 - height_pct;
        area_path.push_str(&format!("L{:.3} {:.3}L{:.3} {:.3}", x_left, y, x_right, y));
    }

    area_path.push_str("L100 100Z");
    Some(area_path)
}

fn build_process_bar_drag_preview(
    drag_state: ProcessBarDragState,
    current_client_x: f64,
    view_start_ns: u64,
    view_end_ns: u64,
) -> Option<ProcessBarDragPreview> {
    if drag_state.bar_width_px <= 0.0 || view_end_ns <= view_start_ns {
        return None;
    }

    let view_duration_ns = view_end_ns - view_start_ns;
    let anchor_frac = ((drag_state.anchor_client_x - drag_state.bar_left_client_x)
        / drag_state.bar_width_px)
        .clamp(0.0, 1.0);
    let current_frac = ((current_client_x - drag_state.bar_left_client_x)
        / drag_state.bar_width_px)
        .clamp(0.0, 1.0);

    let start_frac = anchor_frac.min(current_frac);
    let end_frac = anchor_frac.max(current_frac);
    let start_ns = view_start_ns + ((view_duration_ns as f64) * start_frac).round() as u64;
    let mut end_ns = view_start_ns + ((view_duration_ns as f64) * end_frac).round() as u64;
    if end_ns <= start_ns {
        end_ns = (start_ns + 1).min(view_end_ns);
    }
    if end_ns <= start_ns {
        return None;
    }

    Some(ProcessBarDragPreview {
        pid: drag_state.pid,
        start_pct: start_frac * 100.0,
        end_pct: end_frac * 100.0,
        start_ns,
        end_ns,
    })
}

fn build_usage_paths(usage_points: &[f64]) -> (Option<String>, Option<String>) {
    if usage_points.is_empty() {
        return (None, None);
    }

    let point_count = usage_points.len();
    let mut line_path = String::new();
    let mut area_path = String::new();
    let mut last_x = 0.0;

    for (idx, usage) in usage_points.iter().enumerate() {
        let x = ((idx as f64) + 0.5) / point_count as f64 * 100.0;
        let y = 100.0 - usage.clamp(0.0, 100.0);
        last_x = x;
        if idx == 0 {
            line_path = format!("M{:.3} {:.3}", x, y);
            area_path = format!("M{:.3} 100L{:.3} {:.3}", x, x, y);
        } else {
            line_path.push_str(&format!("L{:.3} {:.3}", x, y));
            area_path.push_str(&format!("L{:.3} {:.3}", x, y));
        }
    }

    area_path.push_str(&format!("L{:.3} 100Z", last_x));
    (Some(area_path), Some(line_path))
}

fn build_vertical_marker_paths(markers: &[CanvasEventMarker]) -> Vec<(&'static str, String)> {
    let mut grouped: HashMap<&'static str, Vec<f64>> = HashMap::new();
    for marker in markers {
        grouped
            .entry(marker.color_hex)
            .or_default()
            .push(marker.pct.clamp(0.0, 100.0));
    }

    let mut grouped_vec: Vec<(&'static str, Vec<f64>)> = grouped.into_iter().collect();
    grouped_vec.sort_by(|a, b| a.0.cmp(b.0));

    grouped_vec
        .into_iter()
        .map(|(color_hex, mut points)| {
            points.sort_by(|a, b| a.total_cmp(b));
            let mut path_data = String::new();
            for x in points {
                path_data.push_str(&format!("M{:.3} 0V100", x));
            }
            (color_hex, path_data)
        })
        .collect()
}

fn build_cpu_usage_points(
    bucket_counts: &[u16],
    bucket_count: usize,
    sample_frequency_hz: u64,
    view_duration_ns: u64,
) -> Vec<f64> {
    if bucket_count == 0 || bucket_counts.is_empty() {
        return Vec::new();
    }

    let clamped_bucket_count = bucket_count.min(bucket_counts.len());
    let bucket_size_ns = view_duration_ns.max(1).div_ceil(bucket_count as u64).max(1);
    let expected_samples_per_bucket =
        (sample_frequency_hz as f64 * (bucket_size_ns as f64 / 1_000_000_000.0)).max(0.001);

    bucket_counts
        .iter()
        .take(clamped_bucket_count)
        .map(|count| ((*count as f64 / expected_samples_per_bucket) * 100.0).clamp(0.0, 100.0))
        .collect()
}

fn event_badge_class(enabled: bool, event_type: &str) -> String {
    if enabled {
        format!(
            "inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border {} bg-transparent hover:bg-gray-50",
            event_badge_tone(event_type)
        )
    } else {
        "inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border border-gray-200 text-gray-400 bg-transparent hover:bg-gray-50".to_string()
    }
}

fn event_badge_tone(event_type: &str) -> &'static str {
    match event_type {
        "sched_switch" => "border-blue-300 text-blue-700",
        "process_fork" => "border-green-300 text-green-700",
        "process_exit" => "border-red-300 text-red-700",
        "page_fault" => "border-amber-300 text-amber-700",
        _ if event_type.contains("read") => "border-sky-300 text-sky-700",
        _ if event_type.contains("write") => "border-orange-300 text-orange-700",
        _ if event_type.contains("mmap")
            || event_type.contains("munmap")
            || event_type.contains("brk") =>
        {
            "border-purple-300 text-purple-700"
        }
        _ if event_type.contains("syscall") => "border-indigo-300 text-indigo-700",
        _ => "border-gray-300 text-gray-700",
    }
}

/// Tree position info for rendering tree lines
#[derive(Clone)]
struct TreePosition {
    /// For each ancestor level, whether that ancestor was the last child at its level
    /// This determines whether to draw │ (not last) or space (last) for each column
    ancestor_is_last: Vec<bool>,
    /// Whether this node is the last child of its parent
    is_last_child: bool,
    /// Whether this node has children
    has_children: bool,
    /// Number of total descendants (for collapse badge)
    descendant_count: usize,
}

struct ProcessTreeModel {
    sorted_processes: Vec<ProcessLifetime>,
    visible_process_rows: Vec<(ProcessLifetime, TreePosition)>,
    collapsible_nodes: Vec<u32>,
    visible_in_range_count: usize,
}

fn build_process_tree(
    processes: &[ProcessLifetime],
    collapsed_nodes: &HashSet<u32>,
    range: ProcessTimelineRange,
) -> ProcessTreeModel {
    let mut sorted_processes = processes.to_vec();
    sorted_processes.sort_by_key(|p| p.start_ns);

    let process_by_pid: HashMap<u32, &ProcessLifetime> =
        sorted_processes.iter().map(|p| (p.pid, p)).collect();

    let mut children_map: HashMap<u32, Vec<u32>> = HashMap::new();
    let mut root_pids: Vec<u32> = Vec::new();

    for proc in &sorted_processes {
        if let Some(parent_pid) = proc.parent_pid {
            if process_by_pid.contains_key(&parent_pid) {
                children_map.entry(parent_pid).or_default().push(proc.pid);
            } else {
                root_pids.push(proc.pid);
            }
        } else {
            root_pids.push(proc.pid);
        }
    }

    for children in children_map.values_mut() {
        children.sort_by_key(|pid| process_by_pid.get(pid).map(|p| p.start_ns).unwrap_or(0));
    }
    root_pids.sort_by_key(|pid| process_by_pid.get(pid).map(|p| p.start_ns).unwrap_or(0));

    let mut ordered_pid_rows: Vec<(u32, TreePosition)> = Vec::with_capacity(sorted_processes.len());
    let root_count = root_pids.len();
    for (idx, root_pid) in root_pids.iter().enumerate() {
        let is_last_root = idx == root_count - 1;
        append_visible_rows(
            *root_pid,
            &children_map,
            collapsed_nodes,
            Vec::new(),
            is_last_root,
            &mut ordered_pid_rows,
        );
    }

    let visible_process_rows = ordered_pid_rows
        .iter()
        .filter_map(|(pid, tree_pos)| {
            process_by_pid
                .get(pid)
                .map(|proc| ((*proc).clone(), tree_pos.clone()))
        })
        .collect::<Vec<_>>();

    let visible_in_range_count = sorted_processes
        .iter()
        .filter(|proc| {
            let process_end = proc.end_ns.unwrap_or(range.full_end_ns);
            proc.start_ns <= range.view_end_ns && process_end >= range.view_start_ns
        })
        .count();

    let collapsible_nodes = children_map
        .iter()
        .filter_map(|(pid, children)| (!children.is_empty()).then_some(*pid))
        .collect();

    ProcessTreeModel {
        sorted_processes,
        visible_process_rows,
        collapsible_nodes,
        visible_in_range_count,
    }
}

fn count_descendants(pid: u32, children_map: &HashMap<u32, Vec<u32>>) -> usize {
    let mut count = 0;
    if let Some(children) = children_map.get(&pid) {
        count += children.len();
        for child in children {
            count += count_descendants(*child, children_map);
        }
    }
    count
}

fn append_visible_rows(
    pid: u32,
    children_map: &HashMap<u32, Vec<u32>>,
    collapsed_nodes: &HashSet<u32>,
    ancestor_is_last: Vec<bool>,
    is_last_child: bool,
    out: &mut Vec<(u32, TreePosition)>,
) {
    let has_children = children_map
        .get(&pid)
        .map(|c| !c.is_empty())
        .unwrap_or(false);
    let descendant_count = if collapsed_nodes.contains(&pid) {
        count_descendants(pid, children_map)
    } else {
        0
    };

    out.push((
        pid,
        TreePosition {
            ancestor_is_last: ancestor_is_last.clone(),
            is_last_child,
            has_children,
            descendant_count,
        },
    ));

    if collapsed_nodes.contains(&pid) {
        return;
    }
    if let Some(children) = children_map.get(&pid) {
        let child_count = children.len();
        for (i, child) in children.iter().enumerate() {
            let is_last = i == child_count - 1;
            let mut child_ancestor_is_last = ancestor_is_last.clone();
            child_ancestor_is_last.push(is_last_child);
            append_visible_rows(
                *child,
                children_map,
                collapsed_nodes,
                child_ancestor_is_last,
                is_last,
                out,
            );
        }
    }
}
