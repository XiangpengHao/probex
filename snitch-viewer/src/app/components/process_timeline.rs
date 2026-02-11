use std::collections::{HashMap, HashSet};

use dioxus::prelude::*;

use crate::app::formatting::{format_duration, format_duration_short, get_event_marker_color};
use crate::server::{EventMarker, HistogramResponse, ProcessEventsResponse, ProcessLifetime};

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
    on_select_pid: EventHandler<u32>,
    on_focus_process: EventHandler<(u32, u64, u64)>,
    on_change_range: EventHandler<(u64, u64, bool)>,
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
    let mut ordered_pid_rows: Vec<(u32, usize)> = Vec::with_capacity(sorted_processes.len());
    for root_pid in &root_pids {
        append_visible_rows(
            *root_pid,
            0,
            &children_map,
            &collapsed_set,
            &mut ordered_pid_rows,
        );
    }

    let all_process_rows: Vec<(&ProcessLifetime, usize)> = ordered_pid_rows
        .iter()
        .filter_map(|(pid, depth)| process_by_pid.get(pid).map(|proc| (*proc, *depth)))
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

    rsx! {
        div { class: "bg-white border border-gray-200 rounded-lg p-3",
            div { class: "flex items-center justify-between mb-2",
                span { class: "text-sm font-medium text-gray-700", "Process Lifetimes" }
                div { class: "flex items-center gap-3",
                    span { class: "text-xs text-gray-400", "{visible_in_range_count} active in view · {sorted_processes.len()} total" }
                    if has_collapsible_nodes {
                        button {
                            class: "text-xs text-gray-600 hover:text-gray-800 underline disabled:opacity-40 disabled:no-underline",
                            disabled: all_tree_expanded,
                            onclick: move |_| collapsed_nodes.set(HashSet::new()),
                            "Expand all"
                        }
                        button {
                            class: "text-xs text-gray-600 hover:text-gray-800 underline disabled:opacity-40 disabled:no-underline",
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
                            "Collapse all"
                        }
                    }
                }
            }

            div { class: "space-y-1 mb-2",
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
                    on_change_range: on_change_range.clone(),
                }
            }

            div { class: "flex items-center justify-between mb-2",
                div { class: "text-sm text-gray-700",
                    span { class: "font-mono", "{format_duration(view_start_ns - full_start_ns)}" }
                    span { class: "text-gray-400 mx-2", "→" }
                    span { class: "font-mono", "{format_duration(view_end_ns - full_start_ns)}" }
                    span { class: "text-gray-400 ml-2", "({format_duration(view_duration_ns)})" }
                }

                div { class: "flex items-center gap-1",
                    button {
                        class: "px-2 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
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
                        class: "px-2 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                        disabled: view_end_ns >= full_end_ns,
                        onclick: move |_| {
                            let shift = view_duration_ns / 4;
                            let new_end = (view_end_ns + shift).min(full_end_ns);
                            let new_start = new_end.saturating_sub(view_duration_ns).max(full_start_ns);
                            on_change_range.call((new_start, new_end, true));
                        },
                        "▶"
                    }

                    div { class: "w-px h-5 bg-gray-200 mx-1" }

                    button {
                        class: "px-2 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
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
                        class: "px-2 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
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

                    div { class: "w-px h-5 bg-gray-200 mx-1" }

                    button {
                        class: "px-2 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded",
                        onclick: move |_| on_change_range.call((full_start_ns, full_end_ns, true)),
                        "Reset"
                    }
                }
            }

            div { class: "flex items-center mb-1",
                div { class: "w-52 shrink-0" }
                div { class: "flex-1 flex justify-between text-xs text-gray-400",
                    span { "{format_duration(view_start_ns - full_start_ns)}" }
                    span { "{format_duration(view_end_ns - full_start_ns)}" }
                }
                div { class: "w-24 shrink-0" }
            }

            div { class: if all_process_rows.len() > 15 { "space-y-1 max-h-[72vh] overflow-y-auto" } else { "space-y-1" },
                {visible_process_rows.iter().map(|(proc, depth)| {
                    let indent = (*depth).min(6);

                    let view_duration_ns = view_end_ns.saturating_sub(view_start_ns).max(1);
                    let view_duration = view_duration_ns as f64;
                    let bar_start = proc.start_ns.max(view_start_ns);
                    let bar_end = proc.end_ns.unwrap_or(full_end_ns).min(view_end_ns);
                    let in_view = bar_start < bar_end;
                    let visible_duration_ns = if in_view { bar_end - bar_start } else { 0 };

                    let left_pct = if in_view {
                        ((bar_start - view_start_ns) as f64 / view_duration * 100.0)
                            .max(0.0)
                            .min(100.0)
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

                    let has_parent = proc.parent_pid.is_some();
                    let has_children = children_map
                        .get(&proc.pid)
                        .map(|children| !children.is_empty())
                        .unwrap_or(false);
                    let is_collapsed = collapsed_set.contains(&proc.pid);
                    let pid = proc.pid;
                    let process_name = proc.process_name.as_deref().unwrap_or("unknown");
                    let is_selected = selected_pid == Some(proc.pid);
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

                    rsx! {
                        div {
                            key: "{proc.pid}",
                            class: "flex items-center gap-3 h-10 group",

                            div {
                                class: "w-52 shrink-0 overflow-hidden",
                                style: "padding-left: {indent * 8}px; font-variant-numeric: tabular-nums;",
                                title: "{process_name} (PID {proc.pid})",
                                div { class: "flex items-start justify-end gap-1.5",
                                    if has_children {
                                        button {
                                            class: "inline-flex items-center justify-center w-5 h-5 text-base leading-none font-semibold text-gray-500 hover:text-gray-700 hover:bg-gray-100 rounded",
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
                                            if is_collapsed { "▸" } else { "▾" }
                                        }
                                    } else {
                                        span { class: "inline-flex w-5 h-5" }
                                    }
                                    div {
                                        class: if is_selected {
                                            "cursor-pointer overflow-hidden bg-blue-50 border border-blue-200 rounded px-1.5 py-0.5"
                                        } else {
                                            "cursor-pointer hover:text-blue-600 overflow-hidden"
                                        },
                                        onclick: move |_| on_select_pid.call(pid),
                                        div { class: "text-sm text-gray-700 text-right truncate leading-tight",
                                            if is_selected {
                                                span { class: "inline-block w-1.5 h-1.5 rounded-full bg-blue-600 mr-1 align-middle" }
                                            }
                                            if has_parent { "└ " }
                                            "{process_name}"
                                        }
                                        div { class: "text-xs font-mono text-gray-500 text-right whitespace-nowrap leading-tight",
                                            "PID {proc.pid}"
                                        }
                                    }
                                }
                            }

                            div { class: "flex-1 relative h-8 bg-gray-100 rounded overflow-hidden",
                                if in_view {
                                    div {
                                        class: "absolute top-0 bottom-0 {bar_color} rounded",
                                        style: "left: {left_pct}%; width: {width_pct}%;",
                                    }
                                }

                                {pid_events.iter().map(|event| {
                                    let event_pct = ((event.ts_ns - view_start_ns) as f64 / view_duration * 100.0)
                                        .max(0.0)
                                        .min(100.0);
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

                            div { class: "w-24 text-sm text-gray-400 shrink-0 truncate",
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

fn append_visible_rows(
    pid: u32,
    depth: usize,
    children_map: &HashMap<u32, Vec<u32>>,
    collapsed_nodes: &HashSet<u32>,
    out: &mut Vec<(u32, usize)>,
) {
    out.push((pid, depth));
    if collapsed_nodes.contains(&pid) {
        return;
    }
    if let Some(children) = children_map.get(&pid) {
        for child in children {
            append_visible_rows(*child, depth + 1, children_map, collapsed_nodes, out);
        }
    }
}
