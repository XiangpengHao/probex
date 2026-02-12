use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;

use super::flamegraph::EventFlamegraphCard;
use crate::app::formatting::{
    format_bytes, format_duration, format_duration_short, format_net_bytes_signed,
    get_event_marker_color,
};
use crate::app::view_model::PidEventSummary;
use crate::server::{
    EventFlamegraphResponse, EventMarker, HistogramResponse, ProcessEventsResponse,
    ProcessLifetime, SyscallLatencyStats, TraceSummary,
};

#[component]
pub fn ProcessTimeline(
    processes: Vec<ProcessLifetime>,
    process_events: Option<ProcessEventsResponse>,
    enabled_event_types: HashSet<String>,
    selected_pid: Option<u32>,
    full_start_ns: u64,
    full_end_ns: u64,
    view_start_ns: u64,
    view_end_ns: u64,
    histogram: Option<HistogramResponse>,
    // PID aggregation data
    summary: Option<TraceSummary>,
    pid_summary: PidEventSummary,
    latency_stats: Option<SyscallLatencyStats>,
    total_event_count: usize,
    selected_flame_event_type: Option<String>,
    flame_event_type_options: Vec<String>,
    flamegraph: Option<EventFlamegraphResponse>,
    flamegraph_loading: bool,
    // Event handlers
    on_select_pid: EventHandler<u32>,
    on_select_pid_option: EventHandler<Option<u32>>,
    on_focus_process: EventHandler<(u32, u64, u64)>,
    on_change_range: EventHandler<(u64, u64, bool)>,
    on_toggle_event_type: EventHandler<String>,
    on_select_flame_event_type: EventHandler<Option<String>>,
) -> Element {
    let mut collapsed_nodes = use_signal(HashSet::<u32>::new);

    let full_duration_ns = full_end_ns.saturating_sub(full_start_ns);
    let full_duration = full_duration_ns as f64;
    let view_duration_ns = view_end_ns.saturating_sub(view_start_ns);
    if full_duration == 0.0 || processes.is_empty() {
        return rsx! {};
    }

    let mut sorted_processes = processes.clone();
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

    let collapsed_set = collapsed_nodes();
    let mut ordered_pid_rows: Vec<(u32, TreePosition)> = Vec::with_capacity(sorted_processes.len());
    let root_count = root_pids.len();
    for (i, root_pid) in root_pids.iter().enumerate() {
        let is_last_root = i == root_count - 1;
        append_visible_rows(
            *root_pid,
            0,
            &children_map,
            &collapsed_set,
            Vec::new(),
            is_last_root,
            &mut ordered_pid_rows,
        );
    }

    let all_process_rows: Vec<(&ProcessLifetime, TreePosition)> = ordered_pid_rows
        .iter()
        .filter_map(|(pid, tree_pos)| {
            process_by_pid
                .get(pid)
                .map(|proc| (*proc, tree_pos.clone()))
        })
        .collect();

    let visible_in_range_count = sorted_processes
        .iter()
        .filter(|p| {
            let p_end = p.end_ns.unwrap_or(full_end_ns);
            p.start_ns <= view_end_ns && p_end >= view_start_ns
        })
        .count();

    let visible_process_rows = all_process_rows.clone();
    let collapsible_nodes: Vec<u32> = children_map
        .iter()
        .filter_map(|(pid, children)| (!children.is_empty()).then_some(*pid))
        .collect();
    let has_collapsible_nodes = !collapsible_nodes.is_empty();
    let all_tree_expanded = collapsible_nodes
        .iter()
        .all(|pid| !collapsed_set.contains(pid));
    let all_tree_collapsed = collapsible_nodes
        .iter()
        .all(|pid| collapsed_set.contains(pid));

    if visible_process_rows.is_empty() {
        return rsx! {};
    }

    let events_map = process_events
        .as_ref()
        .map(|pe| &pe.events_by_pid)
        .cloned()
        .unwrap_or_default();
    let stats = latency_stats.unwrap_or_default();
    let has_read_stats = stats.read.count > 0;
    let has_write_stats = stats.write.count > 0;
    let has_mem_stats = stats.mmap_alloc_bytes > 0 || stats.munmap_free_bytes > 0;

    rsx! {
        div { class: "bg-white border border-gray-200 rounded-lg p-2.5",
            div { class: "flex items-center justify-between mb-1.5",
                span { class: "text-sm font-medium text-gray-700", "Process Lifetimes" }
                div { class: "flex items-center gap-3",
                    span { class: "text-xs text-gray-400", "{visible_in_range_count} in view · {sorted_processes.len()} total" }
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
                                let collapse_targets = collapsible_nodes.clone();
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
                    histogram,
                    full_start_ns,
                    full_end_ns,
                    view_start_ns,
                    view_end_ns,
                    enabled_types: enabled_event_types.clone(),
                    on_change_range,
                }
            }

            // Compact controls row: PID selector + time range + stats + navigation
            div { class: "flex items-center gap-2 mb-1.5 flex-wrap",
                // PID selector
                div { class: "flex items-center gap-1.5 shrink-0",
                    span { class: "text-xs text-gray-500", "PID" }
                    select {
                        class: "px-1.5 py-0.5 border border-gray-200 rounded text-xs bg-white min-w-[70px]",
                        value: selected_pid.map(|p| p.to_string()).unwrap_or_default(),
                        onchange: move |evt| {
                            on_select_pid_option.call(evt.value().parse::<u32>().ok());
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
                    span { class: "text-xs text-gray-400", "{total_event_count} ev" }
                }

                div { class: "w-px h-4 bg-gray-200 shrink-0" }

                // Time range display
                div { class: "text-xs text-gray-600 shrink-0",
                    span { class: "font-mono", "{format_duration(view_start_ns - full_start_ns)}" }
                    span { class: "text-gray-400 mx-1", "→" }
                    span { class: "font-mono", "{format_duration(view_end_ns - full_start_ns)}" }
                    span { class: "text-gray-400 ml-1", "({format_duration(view_duration_ns)})" }
                }

                // Navigation buttons
                div { class: "flex items-center gap-0.5 ml-auto shrink-0",
                    button {
                        class: "px-1.5 py-0.5 text-xs bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: view_start_ns <= full_start_ns,
                        onclick: move |_| {
                            let shift = view_duration_ns / 4;
                            let new_start = view_start_ns.saturating_sub(shift).max(full_start_ns);
                            let new_end = (new_start + view_duration_ns).min(full_end_ns);
                            on_change_range.call((new_start, new_end, true));
                        },
                        "◀"
                    }
                    button {
                        class: "px-1.5 py-0.5 text-xs bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: view_end_ns >= full_end_ns,
                        onclick: move |_| {
                            let shift = view_duration_ns / 4;
                            let new_end = (view_end_ns + shift).min(full_end_ns);
                            let new_start = new_end.saturating_sub(view_duration_ns).max(full_start_ns);
                            on_change_range.call((new_start, new_end, true));
                        },
                        "▶"
                    }
                    button {
                        class: "px-1.5 py-0.5 text-xs bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: view_duration_ns < 1000,
                        onclick: move |_| {
                            let center = view_start_ns + view_duration_ns / 2;
                            let new_duration = view_duration_ns / 2;
                            let new_start = center.saturating_sub(new_duration / 2).max(full_start_ns);
                            let new_end = (new_start + new_duration).min(full_end_ns);
                            on_change_range.call((new_start, new_end, true));
                        },
                        "+"
                    }
                    button {
                        class: "px-1.5 py-0.5 text-xs bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: view_duration_ns >= full_duration_ns,
                        onclick: move |_| {
                            let center = view_start_ns + view_duration_ns / 2;
                            let new_duration = (view_duration_ns * 2).min(full_duration_ns);
                            let new_start = center.saturating_sub(new_duration / 2).max(full_start_ns);
                            let new_end = (new_start + new_duration).min(full_end_ns);
                            let new_start = new_end.saturating_sub(new_duration).max(full_start_ns);
                            on_change_range.call((new_start, new_end, true));
                        },
                        "−"
                    }
                    button {
                        class: "px-1.5 py-0.5 text-xs bg-gray-100 hover:bg-gray-200 rounded",
                        onclick: move |_| on_change_range.call((full_start_ns, full_end_ns, true)),
                        "Reset"
                    }
                }
            }

            // Event type badges row (always rendered to avoid layout flicker)
            div { class: "flex flex-wrap items-center gap-1 mb-1.5 min-h-[1.5rem]",
                if selected_pid.is_some() && !pid_summary.breakdown.is_empty() {
                    {pid_summary.breakdown.iter().map(|(event_type, count)| {
                        let enabled = enabled_event_types.contains(event_type);
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
                } else if selected_pid.is_some() {
                    span { class: "text-xs text-gray-400", "No event badges for selected PID in this range" }
                } else {
                    span { class: "text-xs text-gray-400", "Select a PID to enable event badges and flamegraph filters" }
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
                    span { "{format_duration(view_start_ns - full_start_ns)}" }
                    span { "{format_duration(view_end_ns - full_start_ns)}" }
                }
                div { class: "w-20 shrink-0" }
            }

            div { class: if all_process_rows.len() > 15 { "space-y-0.5 max-h-[72vh] overflow-y-auto" } else { "space-y-0.5" },
                {visible_process_rows.iter().map(|(proc, tree_pos)| {
                    let depth = tree_pos.ancestor_is_last.len();

                    let view_duration_ns = view_end_ns.saturating_sub(view_start_ns).max(1);
                    let view_duration = view_duration_ns as f64;
                    let bar_start = proc.start_ns.max(view_start_ns);
                    let bar_end = proc.end_ns.unwrap_or(full_end_ns).min(view_end_ns);
                    let in_view = bar_start < bar_end;
                    let visible_duration_ns = if in_view { bar_end - bar_start } else { 0 };

                    let left_pct = if in_view {
                        ((bar_start - view_start_ns) as f64 / view_duration * 100.0)
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
                            "bg-green-200"
                        } else {
                            "bg-red-200"
                        }
                    } else {
                        "bg-blue-200"
                    };

                    let has_children = tree_pos.has_children;
                    let is_collapsed = collapsed_set.contains(&proc.pid);
                    let collapsed_count = tree_pos.descendant_count;
                    let pid = proc.pid;
                    let process_name = proc.process_name.as_deref().unwrap_or("unknown");
                    let is_selected = selected_pid == Some(proc.pid);
                    let process_label_class = if is_selected {
                        "cursor-pointer overflow-hidden bg-blue-50 border border-blue-200 rounded px-1 py-0.5 min-w-0"
                    } else {
                        "cursor-pointer hover:bg-gray-50 overflow-hidden px-1 py-0.5 min-w-0"
                    };
                    let process_start_ns = proc.start_ns;
                    let process_end_ns = proc.end_ns.unwrap_or(full_end_ns);
                    let focus_end_ns = if process_end_ns > process_start_ns {
                        process_end_ns
                    } else {
                        (process_start_ns + 1).min(full_end_ns)
                    };
                    let pid_events: Vec<&EventMarker> = events_map
                        .get(&proc.pid)
                        .map(|events| {
                            events
                                .iter()
                                .filter(|e| {
                                    enabled_event_types.contains(&e.event_type)
                                        && e.ts_ns >= view_start_ns
                                        && e.ts_ns <= view_end_ns
                                })
                                .collect()
                        })
                        .unwrap_or_default();

                    // Build tree line prefixes
                    let tree_pos_clone = tree_pos.clone();
                    let row_is_selected = is_selected;
                    let flame_event_type_options_for_row = flame_event_type_options.clone();
                    let selected_flame_event_type_for_row = selected_flame_event_type.clone();
                    let flamegraph_for_row = flamegraph.clone();
                    let flamegraph_loading_for_row = flamegraph_loading;

                    rsx! {
                        div {
                            key: "{proc.pid}",
                            class: "space-y-1",

                            div { class: "flex items-center gap-2 h-7 group",
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

                                div { class: "flex-1 relative h-5 bg-gray-100 rounded overflow-hidden",
                                    if in_view {
                                        div {
                                            class: "absolute top-0 bottom-0 {bar_color} rounded",
                                            style: "left: {left_pct}%; width: {width_pct}%;",
                                        }
                                    }

                                    {pid_events.iter().map(|event| {
                                        let event_pct = ((event.ts_ns - view_start_ns) as f64 / view_duration * 100.0)
                                            .clamp(0.0, 100.0);
                                        let event_color = get_event_marker_color(&event.event_type);

                                        rsx! {
                                            div {
                                                key: "{event.ts_ns}",
                                                class: "absolute top-0 bottom-0 w-px {event_color}",
                                                style: "left: {event_pct}%;",
                                                title: "{event.event_type} @ {format_duration(event.ts_ns - full_start_ns)}",
                                            }
                                        }
                                    })}

                                    if proc.was_forked && proc.start_ns >= view_start_ns && proc.start_ns <= view_end_ns {
                                        div {
                                            class: "absolute top-0 bottom-0 w-1 bg-green-600",
                                            style: "left: {left_pct}%;",
                                            title: "Fork from PID {proc.parent_pid.unwrap_or(0)}",
                                        }
                                    }

                                    if proc.did_exit {
                                        if let Some(end) = proc.end_ns {
                                            if end >= view_start_ns && end <= view_end_ns {
                                                {
                                                    let exit_pct = ((end - view_start_ns) as f64 / view_duration * 100.0).max(0.0);
                                                    let exit_color = if proc.exit_code == Some(0) { "bg-green-600" } else { "bg-red-600" };
                                                    rsx! {
                                                        div {
                                                            class: "absolute top-0 bottom-0 w-1 {exit_color}",
                                                            style: "left: {exit_pct}%;",
                                                            title: "Exit code: {proc.exit_code.unwrap_or(0)}",
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    div {
                                        class: "absolute inset-0 cursor-pointer",
                                        onclick: move |_| on_select_pid.call(pid),
                                        ondoubleclick: move |_| on_focus_process.call((pid, process_start_ns, focus_end_ns)),
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
                                div { class: "ml-56 pl-2",
                                    EventFlamegraphCard {
                                        selected_event_type: selected_flame_event_type_for_row,
                                        event_type_options: flame_event_type_options_for_row,
                                        selected_pid: Some(proc.pid),
                                        full_start_ns,
                                        view_start_ns,
                                        view_end_ns,
                                        on_select_event_type: move |event_type| {
                                            on_select_flame_event_type.call(event_type);
                                        },
                                        flamegraph: flamegraph_for_row,
                                        loading: flamegraph_loading_for_row,
                                    }
                                }
                            }
                        }
                    }
                })}
            }
        }
    }
}

#[component]
fn TimelineOverview(
    histogram: Option<HistogramResponse>,
    full_start_ns: u64,
    full_end_ns: u64,
    view_start_ns: u64,
    view_end_ns: u64,
    enabled_types: HashSet<String>,
    on_change_range: EventHandler<(u64, u64, bool)>,
) -> Element {
    let full_range_ns = full_end_ns.saturating_sub(full_start_ns);
    let full_range = full_range_ns as f64;
    if full_range == 0.0 {
        return rsx! {};
    }

    let min_window_ns = (full_range_ns / 200).max(1);
    let drag_step_ns = (full_range_ns / 2500).max(1);
    let window_ns = view_end_ns.saturating_sub(view_start_ns).max(min_window_ns);
    let max_window_start_offset = full_range_ns.saturating_sub(window_ns);
    let view_left_pct = ((view_start_ns - full_start_ns) as f64 / full_range * 100.0).max(0.0);
    let view_width_pct = ((view_end_ns - view_start_ns) as f64 / full_range * 100.0).max(0.5);

    let max_count = histogram
        .as_ref()
        .map(|h| {
            h.buckets
                .iter()
                .map(|b| {
                    b.counts_by_type
                        .iter()
                        .filter(|(event_type, _)| enabled_types.contains(*event_type))
                        .map(|(_, count)| *count)
                        .sum::<usize>()
                })
                .max()
                .unwrap_or(1)
        })
        .unwrap_or(1)
        .max(1);

    rsx! {
        div { class: "relative h-10 bg-gray-100 rounded overflow-hidden",
            if let Some(h) = histogram {
                div { class: "absolute inset-0 flex items-end",
                    {h.buckets.iter().map(|bucket| {
                        let count: usize = bucket
                            .counts_by_type
                            .iter()
                            .filter(|(event_type, _)| enabled_types.contains(*event_type))
                            .map(|(_, count)| *count)
                            .sum();
                        let height_pct = (count as f64 / max_count as f64 * 100.0).max(1.0);

                        rsx! {
                            div {
                                key: "{bucket.bucket_start_ns}",
                                class: "flex-1 bg-gray-300",
                                style: "height: {height_pct}%;",
                            }
                        }
                    })}
                }
            }

            div {
                class: "absolute top-0 bottom-0 bg-blue-500 opacity-25 border-x-2 border-blue-600",
                style: "left: {view_left_pct}%; width: {view_width_pct}%;",
            }

            input {
                r#type: "range",
                class: "timeline-window-slider",
                style: "--window-thumb-width: {view_width_pct}%;",
                min: "0",
                max: "{max_window_start_offset}",
                step: "{drag_step_ns}",
                value: "{view_start_ns.saturating_sub(full_start_ns)}",
                disabled: max_window_start_offset == 0,
                oninput: move |evt| {
                    if let Ok(offset) = evt.value().parse::<u64>() {
                        let start = (full_start_ns + offset).min(full_end_ns.saturating_sub(window_ns));
                        let end = start.saturating_add(window_ns).min(full_end_ns);
                        on_change_range.call((start, end, false));
                    }
                },
                onchange: move |evt| {
                    if let Ok(offset) = evt.value().parse::<u64>() {
                        let start = (full_start_ns + offset).min(full_end_ns.saturating_sub(window_ns));
                        let end = start.saturating_add(window_ns).min(full_end_ns);
                        on_change_range.call((start, end, true));
                    }
                },
            }

            input {
                r#type: "range",
                class: "timeline-range-slider",
                min: "0",
                max: "{full_range_ns}",
                step: "{drag_step_ns}",
                value: "{view_start_ns.saturating_sub(full_start_ns)}",
                oninput: move |evt| {
                    if let Ok(offset) = evt.value().parse::<u64>() {
                        let max_start = view_end_ns.saturating_sub(min_window_ns).max(full_start_ns);
                        let start = (full_start_ns + offset).min(max_start);
                        on_change_range.call((start, view_end_ns, false));
                    }
                },
                onchange: move |evt| {
                    if let Ok(offset) = evt.value().parse::<u64>() {
                        let max_start = view_end_ns.saturating_sub(min_window_ns).max(full_start_ns);
                        let start = (full_start_ns + offset).min(max_start);
                        on_change_range.call((start, view_end_ns, true));
                    }
                },
            }

            input {
                r#type: "range",
                class: "timeline-range-slider",
                min: "0",
                max: "{full_range_ns}",
                step: "{drag_step_ns}",
                value: "{view_end_ns.saturating_sub(full_start_ns)}",
                oninput: move |evt| {
                    if let Ok(offset) = evt.value().parse::<u64>() {
                        let min_end = (view_start_ns + min_window_ns).min(full_end_ns);
                        let end = (full_start_ns + offset).max(min_end).min(full_end_ns);
                        on_change_range.call((view_start_ns, end, false));
                    }
                },
                onchange: move |evt| {
                    if let Ok(offset) = evt.value().parse::<u64>() {
                        let min_end = (view_start_ns + min_window_ns).min(full_end_ns);
                        let end = (full_start_ns + offset).max(min_end).min(full_end_ns);
                        on_change_range.call((view_start_ns, end, true));
                    }
                },
            }
        }
    }
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
    depth: usize,
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
                depth + 1,
                children_map,
                collapsed_nodes,
                child_ancestor_is_last,
                is_last,
                out,
            );
        }
    }
}
