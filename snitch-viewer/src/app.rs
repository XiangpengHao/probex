//! UI components for snitch-viewer.
//!
//! Provides a timeline-based visualization with time range selection,
//! event type filters, process lifetimes, and paginated event table.

use dioxus::prelude::*;
use std::collections::{HashMap, HashSet};

use crate::server::{
    EventFilters, EventMarker, EventTypeCounts, EventsResponse, HistogramResponse, ProcessEventsResponse,
    ProcessLifetime, ProcessLifetimesResponse, TraceEvent, TraceSummary, get_event_type_counts,
    get_events, get_histogram, get_process_events, get_process_lifetimes, get_summary,
};

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

const RESULTS_PER_PAGE: usize = 50;
const HISTOGRAM_BUCKETS: usize = 80;

#[component]
pub fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        main { class: "min-h-screen bg-gray-50 text-gray-900",
            TraceViewer {}
        }
    }
}

#[component]
fn TraceViewer() -> Element {
    // Core data
    let mut summary = use_signal(|| Option::<TraceSummary>::None);
    let mut events_response = use_signal(|| Option::<EventsResponse>::None);
    let mut histogram = use_signal(|| Option::<HistogramResponse>::None);
    let mut event_type_counts = use_signal(|| Option::<EventTypeCounts>::None);
    let mut process_lifetimes = use_signal(|| Option::<ProcessLifetimesResponse>::None);
    let mut process_events = use_signal(|| Option::<ProcessEventsResponse>::None);

    // Loading/error state
    let mut loading = use_signal(|| true);
    let mut error_msg = use_signal(|| Option::<String>::None);

    // Time range state
    let mut view_start_ns = use_signal(|| 0u64);
    let mut view_end_ns = use_signal(|| 0u64);

    // Filter state
    let mut enabled_event_types = use_signal(|| HashSet::<String>::new());
    let mut selected_pid = use_signal(|| String::new());
    let mut current_page = use_signal(|| 0usize);

    // Load summary on mount
    let _ = use_resource(move || async move {
        match get_summary().await {
            Ok(s) => {
                view_start_ns.set(s.min_ts_ns);
                view_end_ns.set(s.max_ts_ns);
                let all_types: HashSet<String> = s.event_types.iter().cloned().collect();
                enabled_event_types.set(all_types);
                summary.set(Some(s));
            }
            Err(e) => error_msg.set(Some(format!("Failed to load summary: {}", e))),
        }
    });

    // Load process lifetimes on mount
    let _ = use_resource(move || async move {
        match get_process_lifetimes().await {
            Ok(p) => process_lifetimes.set(Some(p)),
            Err(e) => log::error!("Process lifetimes error: {}", e),
        }
    });

    // Load histogram when summary is ready
    let _ = use_resource(move || async move {
        let start = view_start_ns();
        let end = view_end_ns();
        if start == 0 && end == 0 {
            return;
        }
        if let Some(ref s) = summary() {
            match get_histogram(s.min_ts_ns, s.max_ts_ns, HISTOGRAM_BUCKETS).await {
                Ok(h) => histogram.set(Some(h)),
                Err(e) => log::error!("Histogram error: {}", e),
            }
        }
    });

    // Load event type counts when view range changes
    let _ = use_resource(move || async move {
        let start = view_start_ns();
        let end = view_end_ns();
        if start == 0 && end == 0 {
            return;
        }
        match get_event_type_counts(Some(start), Some(end)).await {
            Ok(c) => event_type_counts.set(Some(c)),
            Err(e) => log::error!("Event type counts error: {}", e),
        }
    });

    // Load process events when view range changes
    let _ = use_resource(move || async move {
        let start = view_start_ns();
        let end = view_end_ns();
        if start == 0 && end == 0 {
            return;
        }
        // Limit to 100 events per PID for performance
        match get_process_events(start, end, 100).await {
            Ok(pe) => process_events.set(Some(pe)),
            Err(e) => log::error!("Process events error: {}", e),
        }
    });

    // Load events when filters change
    let do_search = move |reset_page: bool| {
        let types: Vec<String> = enabled_event_types().into_iter().collect();
        let pid_str = selected_pid();
        let page = if reset_page { 0 } else { current_page() };
        let start = view_start_ns();
        let end = view_end_ns();

        spawn(async move {
            loading.set(true);
            error_msg.set(None);
            if reset_page {
                current_page.set(0);
            }

            let filters = EventFilters {
                event_type: None,
                event_types: types,
                pid: pid_str.parse::<u32>().ok(),
                start_ns: Some(start),
                end_ns: Some(end),
                limit: RESULTS_PER_PAGE,
                offset: page * RESULTS_PER_PAGE,
            };

            match get_events(filters).await {
                Ok(response) => events_response.set(Some(response)),
                Err(e) => {
                    error_msg.set(Some(format!("Failed to load events: {}", e)));
                    events_response.set(None);
                }
            }
            loading.set(false);
        });
    };

    // Initial load
    let _ = use_resource(move || {
        let do_search = do_search.clone();
        async move {
            if summary().is_some() {
                do_search(true);
            }
        }
    });

    let summary_data = summary();
    let response = events_response();
    let hist_data = histogram();
    let type_counts = event_type_counts();
    let proc_lifetimes = process_lifetimes();
    let proc_events = process_events();

    let (events, total_count) = match &response {
        Some(r) => (r.events.clone(), r.total_count),
        None => (Vec::new(), 0),
    };

    let total_pages = (total_count + RESULTS_PER_PAGE - 1) / RESULTS_PER_PAGE;

    // Time navigation helpers
    let full_start = summary_data.as_ref().map(|s| s.min_ts_ns).unwrap_or(0);
    let full_end = summary_data.as_ref().map(|s| s.max_ts_ns).unwrap_or(0);
    let full_duration = full_end.saturating_sub(full_start);
    let view_duration = view_end_ns().saturating_sub(view_start_ns());

    rsx! {
        // Header
        header { class: "bg-white border-b border-gray-200 px-6 py-3",
            div { class: "max-w-7xl mx-auto flex items-center justify-between",
                h1 { class: "text-lg font-semibold text-gray-900", "Snitch Trace Viewer" }
                if let Some(ref s) = summary_data {
                    div { class: "flex gap-6 text-sm",
                        StatBadge { label: "Events", value: format!("{}", s.total_events) }
                        StatBadge { label: "Duration", value: format_duration(full_duration) }
                        StatBadge { label: "PIDs", value: format!("{}", s.unique_pids.len()) }
                    }
                }
            }
        }

        div { class: "max-w-7xl mx-auto px-4 py-4 space-y-3",
            if let Some(err) = error_msg() {
                div { class: "bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg text-sm", "{err}" }
            }

            // Event Type Filters
            if let Some(ref s) = summary_data {
                div { class: "bg-white border border-gray-200 rounded-lg p-3",
                    div { class: "flex items-center gap-3 flex-wrap",
                        span { class: "text-sm font-medium text-gray-600", "Filter:" }
                        {s.event_types.iter().map(|t| {
                            let enabled = enabled_event_types().contains(t);
                            let count = type_counts.as_ref()
                                .and_then(|c| c.counts.get(t))
                                .copied()
                                .unwrap_or(0);
                            let t_clone = t.clone();
                            let color = get_event_color(t);

                            rsx! {
                                button {
                                    key: "{t}",
                                    class: if enabled {
                                        format!("inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium {} text-white", color)
                                    } else {
                                        "inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-gray-100 text-gray-500 hover:bg-gray-200".to_string()
                                    },
                                    onclick: move |_| {
                                        let mut types = enabled_event_types();
                                        if types.contains(&t_clone) {
                                            types.remove(&t_clone);
                                        } else {
                                            types.insert(t_clone.clone());
                                        }
                                        enabled_event_types.set(types);
                                        do_search(true);
                                    },
                                    "{t}"
                                    span { class: if enabled { "opacity-70" } else { "text-gray-400" },
                                        "({count})"
                                    }
                                }
                            }
                        })}

                        div { class: "ml-auto flex gap-2 text-xs",
                            button {
                                class: "text-gray-500 hover:text-gray-700 underline",
                                onclick: move |_| {
                                    if let Some(ref s) = summary() {
                                        enabled_event_types.set(s.event_types.iter().cloned().collect());
                                        do_search(true);
                                    }
                                },
                                "All"
                            }
                            button {
                                class: "text-gray-500 hover:text-gray-700 underline",
                                onclick: move |_| {
                                    enabled_event_types.set(HashSet::new());
                                    do_search(true);
                                },
                                "None"
                            }
                        }
                    }
                }
            }

            // Process Timeline
            if let (Some(s), Some(p)) = (&summary_data, &proc_lifetimes) {
                ProcessTimeline {
                    processes: p.processes.clone(),
                    process_events: proc_events.clone(),
                    enabled_event_types: enabled_event_types(),
                    full_start_ns: s.min_ts_ns,
                    full_end_ns: s.max_ts_ns,
                    view_start_ns: view_start_ns(),
                    view_end_ns: view_end_ns(),
                    on_select_pid: move |pid: u32| {
                        selected_pid.set(pid.to_string());
                        do_search(true);
                    },
                }
            }

            // Timeline Overview + Controls
            if let Some(ref s) = summary_data {
                div { class: "bg-white border border-gray-200 rounded-lg p-3 space-y-3",
                    // Overview bar
                    div { class: "space-y-1",
                        div { class: "flex justify-between text-xs text-gray-400",
                            span { "0" }
                            span { "{format_duration(full_duration)}" }
                        }
                        TimelineOverview {
                            histogram: hist_data.clone(),
                            full_start_ns: s.min_ts_ns,
                            full_end_ns: s.max_ts_ns,
                            view_start_ns: view_start_ns(),
                            view_end_ns: view_end_ns(),
                            enabled_types: enabled_event_types(),
                        }
                    }

                    // Time controls
                    div { class: "flex items-center justify-between",
                        div { class: "text-sm text-gray-700",
                            span { class: "font-mono", "{format_duration(view_start_ns() - full_start)}" }
                            span { class: "text-gray-400 mx-2", "→" }
                            span { class: "font-mono", "{format_duration(view_end_ns() - full_start)}" }
                            span { class: "text-gray-400 ml-2", "({format_duration(view_duration)})" }
                        }

                        div { class: "flex items-center gap-1",
                            button {
                                class: "px-2 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                                disabled: view_start_ns() <= full_start,
                                onclick: move |_| {
                                    let shift = view_duration / 4;
                                    let new_start = view_start_ns().saturating_sub(shift).max(full_start);
                                    let new_end = new_start + view_duration;
                                    view_start_ns.set(new_start);
                                    view_end_ns.set(new_end.min(full_end));
                                    do_search(true);
                                },
                                "◀"
                            }
                            button {
                                class: "px-2 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                                disabled: view_end_ns() >= full_end,
                                onclick: move |_| {
                                    let shift = view_duration / 4;
                                    let new_end = (view_end_ns() + shift).min(full_end);
                                    let new_start = new_end.saturating_sub(view_duration);
                                    view_start_ns.set(new_start.max(full_start));
                                    view_end_ns.set(new_end);
                                    do_search(true);
                                },
                                "▶"
                            }

                            div { class: "w-px h-5 bg-gray-200 mx-1" }

                            button {
                                class: "px-2 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                                disabled: view_duration < 1000,
                                onclick: move |_| {
                                    let center = view_start_ns() + view_duration / 2;
                                    let new_duration = view_duration / 2;
                                    let new_start = center.saturating_sub(new_duration / 2).max(full_start);
                                    let new_end = (new_start + new_duration).min(full_end);
                                    view_start_ns.set(new_start);
                                    view_end_ns.set(new_end);
                                    do_search(true);
                                },
                                "+"
                            }
                            button {
                                class: "px-2 py-1 text-sm bg-gray-100 hover:bg-gray-200 rounded disabled:opacity-40",
                                disabled: view_duration >= full_duration,
                                onclick: move |_| {
                                    let center = view_start_ns() + view_duration / 2;
                                    let new_duration = (view_duration * 2).min(full_duration);
                                    let new_start = center.saturating_sub(new_duration / 2).max(full_start);
                                    let new_end = (new_start + new_duration).min(full_end);
                                    let new_start = new_end.saturating_sub(new_duration).max(full_start);
                                    view_start_ns.set(new_start);
                                    view_end_ns.set(new_end);
                                    do_search(true);
                                },
                                "−"
                            }

                            div { class: "w-px h-5 bg-gray-200 mx-1" }

                            button {
                                class: "px-2 py-1 text-xs bg-gray-100 hover:bg-gray-200 rounded",
                                onclick: move |_| {
                                    view_start_ns.set(full_start);
                                    view_end_ns.set(full_end);
                                    do_search(true);
                                },
                                "Reset"
                            }
                        }
                    }
                }
            }

            // PID Filter + Results count
            div { class: "flex items-center gap-4 bg-white border border-gray-200 rounded-lg px-3 py-2",
                div { class: "flex items-center gap-2",
                    label { class: "text-sm text-gray-600", "PID:" }
                    select {
                        class: "px-2 py-1 border border-gray-200 rounded text-sm bg-white",
                        value: "{selected_pid}",
                        onchange: move |evt| {
                            selected_pid.set(evt.value());
                            do_search(true);
                        },
                        option { value: "", "All" }
                        {summary_data.as_ref().map(|s| s.unique_pids.iter().map(|p| rsx! {
                            option { key: "{p}", value: "{p}", "{p}" }
                        })).into_iter().flatten()}
                    }
                }
                div { class: "ml-auto text-sm text-gray-500",
                    "{total_count} events"
                    if total_pages > 1 {
                        " · Page {current_page() + 1}/{total_pages}"
                    }
                }
            }

            // Event Table
            div { class: "bg-white border border-gray-200 rounded-lg overflow-hidden",
                if loading() {
                    div { class: "p-8 text-center text-gray-400", "Loading..." }
                } else if events.is_empty() {
                    div { class: "p-8 text-center text-gray-400", "No events in this range" }
                } else {
                    table { class: "w-full text-sm",
                        thead {
                            tr { class: "bg-gray-50 border-b border-gray-200 text-left text-xs font-medium text-gray-500 uppercase",
                                th { class: "px-3 py-2", "Time" }
                                th { class: "px-3 py-2", "Type" }
                                th { class: "px-3 py-2", "PID" }
                                th { class: "px-3 py-2", "CPU" }
                                th { class: "px-3 py-2", "Details" }
                            }
                        }
                        tbody {
                            {events.iter().enumerate().map(|(idx, event)| {
                                let relative_ns = event.ts_ns.saturating_sub(full_start);
                                let ts_str = format_duration(relative_ns);
                                let details = format_event_details(event);
                                let color = get_event_text_color(&event.event_type);

                                rsx! {
                                    tr {
                                        key: "{idx}",
                                        class: "border-b border-gray-100 hover:bg-gray-50",
                                        td { class: "px-3 py-1.5 font-mono text-xs text-gray-500", "{ts_str}" }
                                        td { class: "px-3 py-1.5 text-xs font-medium {color}", "{event.event_type}" }
                                        td { class: "px-3 py-1.5 font-mono text-xs", "{event.pid}" }
                                        td { class: "px-3 py-1.5 font-mono text-xs", "{event.cpu}" }
                                        td { class: "px-3 py-1.5 font-mono text-xs text-gray-600 truncate max-w-xs", "{details}" }
                                    }
                                }
                            })}
                        }
                    }
                }
            }

            // Pagination
            if total_pages > 1 {
                div { class: "flex justify-center gap-2",
                    button {
                        class: "px-3 py-1.5 text-sm border border-gray-200 rounded bg-white hover:bg-gray-50 disabled:opacity-40",
                        disabled: current_page() == 0,
                        onclick: move |_| {
                            current_page.set(current_page().saturating_sub(1));
                            do_search(false);
                        },
                        "← Prev"
                    }
                    button {
                        class: "px-3 py-1.5 text-sm border border-gray-200 rounded bg-white hover:bg-gray-50 disabled:opacity-40",
                        disabled: current_page() + 1 >= total_pages,
                        onclick: move |_| {
                            current_page.set(current_page() + 1);
                            do_search(false);
                        },
                        "Next →"
                    }
                }
            }
        }
    }
}

#[component]
fn StatBadge(label: String, value: String) -> Element {
    rsx! {
        div { class: "flex items-center gap-1.5",
            span { class: "text-gray-400", "{label}" }
            span { class: "font-medium text-gray-900", "{value}" }
        }
    }
}

/// Process Timeline visualization showing process lifetimes as horizontal bars
#[component]
fn ProcessTimeline(
    processes: Vec<ProcessLifetime>,
    process_events: Option<ProcessEventsResponse>,
    enabled_event_types: HashSet<String>,
    full_start_ns: u64,
    full_end_ns: u64,
    view_start_ns: u64,
    view_end_ns: u64,
    on_select_pid: EventHandler<u32>,
) -> Element {
    let mut expanded = use_signal(|| false);

    let full_duration = full_end_ns.saturating_sub(full_start_ns) as f64;
    if full_duration == 0.0 || processes.is_empty() {
        return rsx! {};
    }

    // Build parent-child hierarchy for indentation
    let parent_map: HashMap<u32, u32> = processes
        .iter()
        .filter_map(|p| p.parent_pid.map(|parent| (p.pid, parent)))
        .collect();

    // Calculate depth for each process (how many ancestors)
    fn get_depth(pid: u32, parent_map: &HashMap<u32, u32>, cache: &mut HashMap<u32, usize>) -> usize {
        if let Some(&d) = cache.get(&pid) {
            return d;
        }
        let depth = if let Some(&parent) = parent_map.get(&pid) {
            1 + get_depth(parent, parent_map, cache)
        } else {
            0
        };
        cache.insert(pid, depth);
        depth
    }

    let mut depth_cache: HashMap<u32, usize> = HashMap::new();

    // Sort processes: by start time
    let mut sorted_processes = processes.clone();
    sorted_processes.sort_by_key(|p| p.start_ns);

    // Filter to only processes visible in the view range
    let all_visible: Vec<&ProcessLifetime> = sorted_processes
        .iter()
        .filter(|p| {
            let p_end = p.end_ns.unwrap_or(full_end_ns);
            p.start_ns <= view_end_ns && p_end >= view_start_ns
        })
        .collect();

    let visible_processes: Vec<&ProcessLifetime> = if expanded() {
        all_visible.clone()
    } else {
        all_visible.iter().take(10).copied().collect()
    };

    let has_more = all_visible.len() > 10;
    let showing_all = expanded() || all_visible.len() <= 10;

    if visible_processes.is_empty() {
        return rsx! {};
    }

    // Get events map
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
                    span { class: "text-xs text-gray-400", "{all_visible.len()} processes in view" }
                    if has_more {
                        button {
                            class: "text-xs text-blue-600 hover:text-blue-800 underline",
                            onclick: move |_| expanded.set(!expanded()),
                            if expanded() { "Collapse" } else { "Show all" }
                        }
                    }
                }
            }

            // Time axis labels
            div { class: "flex justify-between text-xs text-gray-400 mb-1 ml-16",
                span { "{format_duration(view_start_ns - full_start_ns)}" }
                span { "{format_duration(view_end_ns - full_start_ns)}" }
            }

            // Process rows
            div { class: if expanded() && all_visible.len() > 15 { "space-y-1 max-h-96 overflow-y-auto" } else { "space-y-1" },
                {visible_processes.iter().map(|proc| {
                    let depth = get_depth(proc.pid, &parent_map, &mut depth_cache);
                    let indent = depth.min(4);

                    let view_duration = (view_end_ns - view_start_ns) as f64;
                    let bar_start = proc.start_ns.max(view_start_ns);
                    let bar_end = proc.end_ns.unwrap_or(full_end_ns).min(view_end_ns);

                    let left_pct = ((bar_start - view_start_ns) as f64 / view_duration * 100.0).max(0.0);
                    let width_pct = ((bar_end - bar_start) as f64 / view_duration * 100.0).max(0.5).min(100.0 - left_pct);

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
                    let pid = proc.pid;

                    // Get events for this PID
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
                            class: "flex items-center gap-2 h-5 group",

                            div {
                                class: "w-14 text-xs font-mono text-gray-600 text-right shrink-0 cursor-pointer hover:text-blue-600",
                                style: "padding-left: {indent * 8}px",
                                onclick: move |_| on_select_pid.call(pid),
                                if has_parent { "└ " }
                                "{proc.pid}"
                            }

                            div { class: "flex-1 relative h-4 bg-gray-100 rounded overflow-hidden",
                                // Process lifetime bar (lighter color as background)
                                div {
                                    class: "absolute top-0 bottom-0 {bar_color} rounded",
                                    style: "left: {left_pct}%; width: {width_pct}%;",
                                }

                                // Event markers
                                {pid_events.iter().map(|event| {
                                    let event_pct = ((event.ts_ns - view_start_ns) as f64 / view_duration * 100.0).max(0.0).min(100.0);
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

                                // Fork marker
                                if proc.was_forked && proc.start_ns >= view_start_ns && proc.start_ns <= view_end_ns {
                                    div {
                                        class: "absolute top-0 bottom-0 w-1 bg-green-600",
                                        style: "left: {left_pct}%;",
                                        title: "Fork from PID {proc.parent_pid.unwrap_or(0)}",
                                    }
                                }

                                // Exit marker
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

                                // Clickable overlay
                                div {
                                    class: "absolute inset-0 cursor-pointer",
                                    onclick: move |_| on_select_pid.call(pid),
                                }
                            }

                            div { class: "w-20 text-xs text-gray-400 shrink-0 truncate",
                                if proc.did_exit {
                                    if proc.exit_code == Some(0) {
                                        "✓ {format_duration_short(bar_end - bar_start)}"
                                    } else {
                                        "✗ {format_duration_short(bar_end - bar_start)}"
                                    }
                                } else {
                                    "{format_duration_short(bar_end - bar_start)}"
                                }
                            }
                        }
                    }
                })}
            }

            if !showing_all {
                div { class: "text-xs text-gray-400 mt-2 text-center",
                    "Showing 10 of {all_visible.len()} processes · "
                    button {
                        class: "text-blue-600 hover:text-blue-800 underline",
                        onclick: move |_| expanded.set(true),
                        "Show all"
                    }
                }
            }
        }
    }
}

fn get_event_marker_color(event_type: &str) -> &'static str {
    match event_type {
        "sched_switch" => "bg-blue-600",
        "process_fork" => "bg-green-600",
        "process_exit" => "bg-red-600",
        "page_fault" => "bg-orange-500",
        _ if event_type.contains("syscall") => "bg-purple-600",
        _ => "bg-gray-600",
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
) -> Element {
    let full_range = (full_end_ns - full_start_ns) as f64;
    if full_range == 0.0 {
        return rsx! {};
    }

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
                        .filter(|(t, _)| enabled_types.contains(*t))
                        .map(|(_, c)| *c)
                        .sum::<usize>()
                })
                .max()
                .unwrap_or(1)
        })
        .unwrap_or(1)
        .max(1);

    rsx! {
        div { class: "relative h-10 bg-gray-100 rounded overflow-hidden",
            // Histogram bars
            if let Some(ref h) = histogram {
                div { class: "absolute inset-0 flex items-end",
                    {h.buckets.iter().map(|bucket| {
                        let count: usize = bucket.counts_by_type
                            .iter()
                            .filter(|(t, _)| enabled_types.contains(*t))
                            .map(|(_, c)| *c)
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

            // Current view window
            div {
                class: "absolute top-0 bottom-0 bg-blue-500 opacity-25 border-x-2 border-blue-600",
                style: "left: {view_left_pct}%; width: {view_width_pct}%;",
            }
        }
    }
}

fn get_event_color(event_type: &str) -> &'static str {
    match event_type {
        "sched_switch" => "bg-blue-500",
        "process_fork" => "bg-green-500",
        "process_exit" => "bg-red-500",
        "page_fault" => "bg-orange-500",
        _ if event_type.contains("syscall") => "bg-purple-500",
        _ => "bg-gray-500",
    }
}

fn get_event_text_color(event_type: &str) -> &'static str {
    match event_type {
        "sched_switch" => "text-blue-600",
        "process_fork" => "text-green-600",
        "process_exit" => "text-red-600",
        "page_fault" => "text-orange-600",
        _ if event_type.contains("syscall") => "text-purple-600",
        _ => "text-gray-600",
    }
}

fn format_duration(ns: u64) -> String {
    let us = ns as f64 / 1_000.0;
    let ms = ns as f64 / 1_000_000.0;
    let s = ns as f64 / 1_000_000_000.0;

    if s >= 1.0 {
        format!("{:.2}s", s)
    } else if ms >= 1.0 {
        format!("{:.2}ms", ms)
    } else if us >= 1.0 {
        format!("{:.1}µs", us)
    } else {
        format!("{}ns", ns)
    }
}

fn format_duration_short(ns: u64) -> String {
    let us = ns as f64 / 1_000.0;
    let ms = ns as f64 / 1_000_000.0;
    let s = ns as f64 / 1_000_000_000.0;

    if s >= 1.0 {
        format!("{:.1}s", s)
    } else if ms >= 1.0 {
        format!("{:.0}ms", ms)
    } else if us >= 1.0 {
        format!("{:.0}µs", us)
    } else {
        format!("{}ns", ns)
    }
}

fn format_event_details(event: &TraceEvent) -> String {
    match event.event_type.as_str() {
        "sched_switch" => {
            let prev = event.prev_pid.map(|p| p.to_string()).unwrap_or_default();
            let next = event.next_pid.map(|p| p.to_string()).unwrap_or_default();
            format!("{} → {}", prev, next)
        }
        "process_fork" => {
            let parent = event.parent_pid.map(|p| p.to_string()).unwrap_or_default();
            let child = event.child_pid.map(|p| p.to_string()).unwrap_or_default();
            format!("{} → {}", parent, child)
        }
        "process_exit" => {
            format!("exit: {}", event.exit_code.unwrap_or(0))
        }
        "page_fault" => {
            let addr = event.address.map(|a| format!("0x{:x}", a)).unwrap_or_default();
            format!("@ {}", addr)
        }
        "syscall_read_enter" | "syscall_write_enter" => {
            format!("fd:{} len:{}", event.fd.unwrap_or(-1), event.count.unwrap_or(0))
        }
        "syscall_read_exit" | "syscall_write_exit" => {
            format!("ret:{}", event.ret.unwrap_or(0))
        }
        _ => String::new(),
    }
}
