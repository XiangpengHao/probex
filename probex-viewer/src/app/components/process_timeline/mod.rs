mod process_activity;
mod process_tree;
mod timeline_overview;

use process_activity::{
    CanvasEventMarker, PROCESS_BAR_SELECTION_THRESHOLD_PX, ProcessActivityCanvas,
    ProcessBarDragPreview, ProcessBarDragState, build_cpu_usage_points,
    build_process_bar_drag_preview,
};
use process_tree::{build_process_tree, event_badge_class};
use timeline_overview::{
    TimelineOverview, TimelineOverviewData, TimelineOverviewRange, shift_window,
    zoom_window_to_duration,
};

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
use super::io_statistics::{IoMemoryCard, IoMemoryCardData};
use crate::api::{
    EventFlamegraphResponse, HistogramResponse, IoStatistics, MemoryStatistics,
    ProcessEventsResponse, ProcessLifetime, SyscallLatencyStats, TraceSummary,
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
    pub memory_statistics: Option<MemoryStatistics>,
    pub memory_statistics_loading: bool,
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
    let mut stats_expanded = use_signal(|| false);

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
                    span { class: "text-gray-400 mx-1", "\u{2192}" }
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
                        "\u{25C0}"
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
                        "\u{25B6}"
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
                        "\u{2212}"
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

            // Latency stats row — clickable to expand aggregate IO/Memory detail
            div {
                class: "cursor-pointer rounded hover:bg-gray-50 transition-colors duration-100 mb-1.5",
                onclick: move |_| stats_expanded.set(!stats_expanded()),
                div { class: "flex flex-wrap items-center gap-4 text-xs text-gray-600 min-h-[1.25rem]",
                    // Chevron indicator
                    span { class: "text-gray-400 text-[10px] shrink-0 w-3",
                        if stats_expanded() { "\u{25BC}" } else { "\u{25B6}" }
                    }
                    span { class: "whitespace-nowrap",
                        span { class: "text-gray-400", "read " }
                        if has_read_stats {
                            span { class: "text-gray-400", "{stats.read.count}\u{00D7} " }
                            span { class: "text-gray-400", "avg/p50/p95/max " }
                            "{format_duration(stats.read.avg_ns)}/{format_duration(stats.read.p50_ns)}/{format_duration(stats.read.p95_ns)}/{format_duration(stats.read.max_ns)}"
                        } else {
                            span { class: "text-gray-400", "\u{2014}" }
                        }
                    }
                    span { class: "whitespace-nowrap",
                        span { class: "text-gray-400", "write " }
                        if has_write_stats {
                            span { class: "text-gray-400", "{stats.write.count}\u{00D7} " }
                            span { class: "text-gray-400", "avg/p50/p95/max " }
                            "{format_duration(stats.write.avg_ns)}/{format_duration(stats.write.p50_ns)}/{format_duration(stats.write.p95_ns)}/{format_duration(stats.write.max_ns)}"
                        } else {
                            span { class: "text-gray-400", "\u{2014}" }
                        }
                    }
                    span { class: "whitespace-nowrap",
                        span { class: "text-gray-400", "io_uring " }
                        if has_io_uring_stats {
                            span { class: "text-gray-400", "{stats.io_uring.count}\u{00D7} " }
                            span { class: "text-gray-400", "avg/p50/p95/max " }
                            "{format_duration(stats.io_uring.avg_ns)}/{format_duration(stats.io_uring.p50_ns)}/{format_duration(stats.io_uring.p95_ns)}/{format_duration(stats.io_uring.max_ns)}"
                        } else {
                            span { class: "text-gray-400", "\u{2014}" }
                        }
                    }
                    span { class: "whitespace-nowrap",
                        span { class: "text-gray-400", "mem +/\u{2212}/net " }
                        if has_mem_stats {
                            "{format_bytes(stats.mmap_alloc_bytes)}/{format_bytes(stats.munmap_free_bytes)}/{format_net_bytes_signed(stats.mmap_alloc_bytes, stats.munmap_free_bytes)}"
                        } else {
                            span { class: "text-gray-400", "\u{2014}" }
                        }
                    }
                }
            }

            // Expanded aggregate IO/Memory card
            if stats_expanded() {
                div { class: "mb-1.5",
                    IoMemoryCard {
                        data: IoMemoryCardData {
                            io_stats: data.io_statistics.clone(),
                            io_loading: data.io_statistics_loading,
                            mem_stats: data.memory_statistics.clone(),
                            mem_loading: data.memory_statistics_loading,
                        },
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
                    let memory_statistics_for_row = data.memory_statistics.clone();
                    let memory_statistics_loading_for_row = data.memory_statistics_loading;

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
                                        // Draw ancestor columns (| or space)
                                        {tree_pos_clone.ancestor_is_last.iter().enumerate().map(|(i, is_last)| {
                                            rsx! {
                                                span {
                                                    key: "{i}",
                                                    class: "inline-block w-4 text-center text-gray-300 select-none",
                                                    style: "font-family: monospace;",
                                                    if *is_last { " " } else { "\u{2502}" }
                                                }
                                            }
                                        })}

                                        // Draw branch connector for this node
                                        if depth > 0 {
                                            span {
                                                class: "inline-block w-4 text-center text-gray-300 select-none",
                                                style: "font-family: monospace;",
                                                if tree_pos_clone.is_last_child { "\u{2514}" } else { "\u{251C}" }
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
                                            if is_collapsed { "\u{25B6}" } else { "\u{25BC}" }
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
                                        "\u{2014}"
                                    } else if proc.did_exit {
                                        if proc.exit_code == Some(0) {
                                            "\u{2713} {format_duration_short(visible_duration_ns)}"
                                        } else {
                                            "\u{2717} {format_duration_short(visible_duration_ns)}"
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
                                            "IO / Memory"
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
                                            IoMemoryCard {
                                                data: IoMemoryCardData {
                                                    io_stats: io_statistics_for_row,
                                                    io_loading: io_statistics_loading_for_row,
                                                    mem_stats: memory_statistics_for_row,
                                                    mem_loading: memory_statistics_loading_for_row,
                                                },
                                            }
                                        },
                                        AnalysisTab::Events => rsx! {
                                            EventListCard {
                                                pid: proc.pid,
                                                view_start_ns: range.view_start_ns,
                                                view_end_ns: range.view_end_ns,
                                                full_start_ns: range.full_start_ns,
                                                event_types: selection.enabled_event_types.iter().cloned().collect::<Vec<String>>(),
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
