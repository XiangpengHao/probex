//! UI entry point for snitch-viewer.
//!
//! Keeps reactive state + server querying in one place and delegates rendering
//! to focused components.

mod components;
mod formatting;
mod view_model;

use std::collections::HashSet;

use components::{EventsTable, Pager, ProcessTimeline, ViewerHeader};
use dioxus::prelude::*;
use view_model::build_pid_event_summary;

use crate::server::{
    EventFlamegraphResponse, EventTypeCounts, EventsResponse, HistogramResponse,
    ProcessEventsResponse, ProcessLifetimesResponse, TraceSummary, get_event_flamegraph,
    get_events, get_histogram, get_pid_event_type_counts, get_process_events,
    get_process_lifetimes, get_summary, get_syscall_latency_stats,
};

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

const RESULTS_PER_PAGE: usize = 50;
const HISTOGRAM_BUCKETS: usize = 80;
const MAX_FLAME_STACKS: usize = 5000;

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
    let mut summary = use_signal(|| Option::<TraceSummary>::None);
    let mut events_response = use_signal(|| Option::<EventsResponse>::None);
    let mut histogram = use_signal(|| Option::<HistogramResponse>::None);
    let mut selected_pid_event_counts = use_signal(|| Option::<EventTypeCounts>::None);
    let mut syscall_latency_stats = use_signal(|| None);
    let mut event_flamegraph = use_signal(|| Option::<EventFlamegraphResponse>::None);
    let mut flamegraph_loading = use_signal(|| false);
    let mut process_lifetimes = use_signal(|| Option::<ProcessLifetimesResponse>::None);
    let mut process_events = use_signal(|| Option::<ProcessEventsResponse>::None);

    let mut loading = use_signal(|| true);
    let mut error_msg = use_signal(|| Option::<String>::None);

    let mut view_start_ns = use_signal(|| 0u64);
    let mut view_end_ns = use_signal(|| 0u64);
    let mut is_dragging_range = use_signal(|| false);

    let mut enabled_event_types = use_signal(HashSet::<String>::new);
    let mut selected_pid = use_signal(|| Option::<u32>::None);
    let mut selected_flame_event_type = use_signal(|| Some("cpu_sample".to_string()));
    let mut current_page = use_signal(|| 0usize);

    use_resource(move || async move {
        match get_summary().await {
            Ok(s) => {
                view_start_ns.set(s.min_ts_ns);
                view_end_ns.set(s.max_ts_ns);
                let mut default_event_types: HashSet<String> =
                    s.event_types.iter().cloned().collect();
                if default_event_types.len() > 1 {
                    default_event_types.remove("cpu_sample");
                }
                enabled_event_types.set(default_event_types);
                summary.set(Some(s));
            }
            Err(e) => error_msg.set(Some(format!("Failed to load summary: {}", e))),
        }
    });

    use_resource(move || async move {
        match get_process_lifetimes().await {
            Ok(lifetimes) => process_lifetimes.set(Some(lifetimes)),
            Err(e) => log::error!("Process lifetimes error: {}", e),
        }
    });

    use_resource(move || async move {
        if let Some(s) = summary() {
            match get_histogram(s.min_ts_ns, s.max_ts_ns, HISTOGRAM_BUCKETS).await {
                Ok(data) => histogram.set(Some(data)),
                Err(e) => log::error!("Histogram error: {}", e),
            }
        }
    });

    use_resource(move || async move {
        let start = view_start_ns();
        let end = view_end_ns();
        if is_dragging_range() || (start == 0 && end == 0) {
            return;
        }

        match get_process_events(start, end, 100).await {
            Ok(events) => process_events.set(Some(events)),
            Err(e) => log::error!("Process events error: {}", e),
        }
    });

    use_resource(move || async move {
        let start = view_start_ns();
        let end = view_end_ns();
        let pid = selected_pid();
        let selected_event_type = selected_flame_event_type();
        if is_dragging_range() || (start == 0 && end == 0) {
            return;
        }

        if let (Some(pid), Some(event_type)) = (pid, selected_event_type) {
            flamegraph_loading.set(true);
            match get_event_flamegraph(start, end, Some(pid), event_type, MAX_FLAME_STACKS).await {
                Ok(data) => event_flamegraph.set(Some(data)),
                Err(e) => log::error!("Event flamegraph error: {}", e),
            }
            flamegraph_loading.set(false);
        } else {
            flamegraph_loading.set(false);
            event_flamegraph.set(None);
        }
    });

    use_resource(move || async move {
        let start = view_start_ns();
        let end = view_end_ns();
        if is_dragging_range() || (start == 0 && end == 0) {
            return;
        }

        if let Some(pid) = selected_pid() {
            match get_pid_event_type_counts(pid, Some(start), Some(end)).await {
                Ok(counts) => selected_pid_event_counts.set(Some(counts)),
                Err(e) => log::error!("Selected PID event counts error: {}", e),
            }
        } else {
            selected_pid_event_counts.set(None);
        }
    });

    use_resource(move || async move {
        let start = view_start_ns();
        let end = view_end_ns();
        if is_dragging_range() || (start == 0 && end == 0) {
            return;
        }

        if let Some(pid) = selected_pid() {
            match get_syscall_latency_stats(start, end, Some(pid)).await {
                Ok(stats) => syscall_latency_stats.set(Some(stats)),
                Err(e) => log::error!("Syscall latency stats error: {}", e),
            }
        } else {
            syscall_latency_stats.set(None);
        }
    });

    let do_search = move |reset_page: bool| {
        let event_types: Vec<String> = enabled_event_types().into_iter().collect();
        let pid = selected_pid();
        let page = if reset_page { 0 } else { current_page() };
        let start = view_start_ns();
        let end = view_end_ns();

        spawn(async move {
            loading.set(true);
            error_msg.set(None);
            if reset_page {
                current_page.set(0);
            }

            let filters = crate::server::EventFilters {
                event_type: None,
                event_types,
                pid,
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

    use_resource(move || async move {
        if summary().is_some() {
            do_search(true);
        }
    });

    let summary_data = summary();
    let hist_data = histogram();
    let response = events_response();
    let events = response
        .as_ref()
        .map(|response| response.events.clone())
        .unwrap_or_default();
    let total_count = response
        .as_ref()
        .map(|response| response.total_count)
        .unwrap_or(0);
    let total_pages = total_count.div_ceil(RESULTS_PER_PAGE);

    let selected_pid_counts = selected_pid_event_counts();
    let pid_summary = build_pid_event_summary(selected_pid_counts.as_ref());
    let selected_pid_value = selected_pid();
    let selected_flame_event_type_value = selected_flame_event_type();

    let full_start = summary_data.as_ref().map(|s| s.min_ts_ns).unwrap_or(0);
    let full_end = summary_data.as_ref().map(|s| s.max_ts_ns).unwrap_or(0);
    let full_duration = full_end.saturating_sub(full_start);

    let mut flame_event_type_options: Vec<String> =
        if selected_pid_value.is_some() && !pid_summary.breakdown.is_empty() {
            pid_summary
                .breakdown
                .iter()
                .map(|(event_type, _)| event_type.clone())
                .collect()
        } else {
            summary_data
                .as_ref()
                .map(|summary| summary.event_types.clone())
                .unwrap_or_default()
        };
    if let Some(selected_event_type) = &selected_flame_event_type_value
        && !flame_event_type_options
            .iter()
            .any(|event_type| event_type == selected_event_type)
    {
        flame_event_type_options.push(selected_event_type.clone());
    }
    flame_event_type_options.sort();
    flame_event_type_options.dedup();

    rsx! {
        ViewerHeader { summary: summary_data.clone() }

        div { class: "w-full px-3 sm:px-4 lg:px-6 py-3 space-y-2",
            if let Some(err) = error_msg() {
                div { class: "bg-red-50 border border-red-200 text-red-700 px-3 py-2 rounded-lg text-xs", "{err}" }
            }

            if let (Some(summary), Some(lifetimes)) = (summary_data.clone(), process_lifetimes()) {
                ProcessTimeline {
                    processes: lifetimes.processes,
                    process_events: process_events(),
                    enabled_event_types: enabled_event_types(),
                    selected_pid: selected_pid_value,
                    full_start_ns: summary.min_ts_ns,
                    full_end_ns: summary.max_ts_ns,
                    view_start_ns: view_start_ns(),
                    view_end_ns: view_end_ns(),
                    histogram: hist_data,
                    // PID aggregation data
                    summary: summary_data.clone(),
                    pid_summary: pid_summary.clone(),
                    latency_stats: syscall_latency_stats(),
                    total_event_count: total_count,
                    selected_flame_event_type: selected_flame_event_type_value.clone(),
                    flame_event_type_options,
                    flamegraph: event_flamegraph(),
                    flamegraph_loading: flamegraph_loading(),
                    // Event handlers
                    on_select_pid: move |pid: u32| {
                        let next_pid = if selected_pid() == Some(pid) {
                            None
                        } else {
                            Some(pid)
                        };
                        selected_pid.set(next_pid);
                        do_search(true);
                    },
                    on_select_pid_option: move |pid: Option<u32>| {
                        selected_pid.set(pid);
                        do_search(true);
                    },
                    on_focus_process: move |(pid, start, end): (u32, u64, u64)| {
                        selected_pid.set(Some(pid));
                        view_start_ns.set(start);
                        view_end_ns.set(end);
                        do_search(true);
                    },
                    on_change_range: move |(start, end, commit): (u64, u64, bool)| {
                        let drag_step_ns = (full_duration / 2000).max(1);
                        if !commit {
                            let start_delta = start.abs_diff(view_start_ns());
                            let end_delta = end.abs_diff(view_end_ns());
                            if start_delta < drag_step_ns && end_delta < drag_step_ns {
                                return;
                            }
                            is_dragging_range.set(true);
                        } else {
                            is_dragging_range.set(false);
                        }

                        view_start_ns.set(start);
                        view_end_ns.set(end);
                        if commit {
                            do_search(true);
                        }
                    },
                    on_toggle_event_type: move |event_type: String| {
                        let mut types = enabled_event_types();
                        if types.contains(&event_type) {
                            types.remove(&event_type);
                        } else {
                            types.insert(event_type);
                        }
                        enabled_event_types.set(types);
                        do_search(true);
                    },
                    on_select_flame_event_type: move |event_type: Option<String>| {
                        selected_flame_event_type.set(event_type);
                    },
                }
            }

            EventsTable {
                events,
                loading: loading(),
                full_start_ns: full_start,
            }

            Pager {
                total_pages,
                current_page: current_page(),
                on_prev: move |_| {
                    current_page.set(current_page().saturating_sub(1));
                    do_search(false);
                },
                on_next: move |_| {
                    current_page.set(current_page() + 1);
                    do_search(false);
                },
            }
        }
    }
}
