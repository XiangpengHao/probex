//! UI entry point for snitch-viewer.
//!
//! Keeps reactive state + server querying in one place and delegates rendering
//! to focused components.

mod components;
mod formatting;
mod view_model;

use std::collections::HashSet;

use components::{
    ProcessTimeline, ProcessTimelineActions, ProcessTimelineData, ProcessTimelineRange,
    ProcessTimelineSelection, ViewerHeader,
};
use dioxus::prelude::*;
use view_model::{
    ViewRange, build_flame_event_type_options, build_pid_event_summary, next_view_range,
};

use crate::server::{
    EventFlamegraphResponse, EventTypeCounts, HistogramResponse, ProcessEventsResponse,
    ProcessLifetimesResponse, TraceSummary, get_event_flamegraph, get_event_type_counts,
    get_histogram, get_pid_event_type_counts, get_process_events, get_process_lifetimes,
    get_summary, get_syscall_latency_stats,
};

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

const HISTOGRAM_BUCKETS: usize = 80;
const MAX_FLAME_STACKS: usize = 5000;
const MAX_PROCESS_MARKERS_PER_PID: usize = 500;

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
    let mut histogram = use_signal(|| Option::<HistogramResponse>::None);
    let mut selected_pid_event_counts = use_signal(|| Option::<EventTypeCounts>::None);
    let mut syscall_latency_stats = use_signal(|| None);
    let mut event_flamegraph = use_signal(|| Option::<EventFlamegraphResponse>::None);
    let mut flamegraph_loading = use_signal(|| false);
    let mut process_lifetimes = use_signal(|| Option::<ProcessLifetimesResponse>::None);
    let mut process_events = use_signal(|| Option::<ProcessEventsResponse>::None);

    let mut error_msg = use_signal(|| Option::<String>::None);

    let mut view_range = use_signal(|| Option::<ViewRange>::None);

    let mut enabled_event_types = use_signal(HashSet::<String>::new);
    let mut selected_pid = use_signal(|| Option::<u32>::None);
    let mut selected_flame_event_type = use_signal(|| Some("cpu_sample".to_string()));

    use_resource(move || async move {
        match get_summary().await {
            Ok(s) => {
                if let Some(range) = ViewRange::new(s.min_ts_ns, s.max_ts_ns) {
                    view_range.set(Some(range));
                }
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
        let Some(range) = view_range() else {
            return;
        };

        match get_process_events(range.start_ns, range.end_ns, MAX_PROCESS_MARKERS_PER_PID).await {
            Ok(events) => process_events.set(Some(events)),
            Err(e) => log::error!("Process events error: {}", e),
        }
    });

    use_resource(move || async move {
        let Some(range) = view_range() else {
            return;
        };
        let pid = selected_pid();
        let selected_event_type = selected_flame_event_type();

        if let (Some(pid), Some(event_type)) = (pid, selected_event_type) {
            flamegraph_loading.set(true);
            match get_event_flamegraph(
                range.start_ns,
                range.end_ns,
                Some(pid),
                event_type,
                MAX_FLAME_STACKS,
            )
            .await
            {
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
        let Some(range) = view_range() else {
            return;
        };

        if let Some(pid) = selected_pid() {
            match get_pid_event_type_counts(pid, Some(range.start_ns), Some(range.end_ns)).await {
                Ok(counts) => selected_pid_event_counts.set(Some(counts)),
                Err(e) => log::error!("Selected PID event counts error: {}", e),
            }
        } else {
            match get_event_type_counts(Some(range.start_ns), Some(range.end_ns)).await {
                Ok(counts) => selected_pid_event_counts.set(Some(counts)),
                Err(e) => log::error!("Event counts error: {}", e),
            }
        }
    });

    use_resource(move || async move {
        let Some(range) = view_range() else {
            return;
        };

        match get_syscall_latency_stats(range.start_ns, range.end_ns, selected_pid()).await {
            Ok(stats) => syscall_latency_stats.set(Some(stats)),
            Err(e) => log::error!("Syscall latency stats error: {}", e),
        }
    });

    let summary_data = summary();
    let hist_data = histogram();

    let selected_pid_counts = selected_pid_event_counts();
    let pid_summary = build_pid_event_summary(selected_pid_counts.as_ref());
    let selected_pid_value = selected_pid();
    let selected_flame_event_type_value = selected_flame_event_type();

    let flame_event_type_options = build_flame_event_type_options(
        summary_data.as_ref(),
        selected_pid_value,
        &pid_summary,
        selected_flame_event_type_value.as_deref(),
    );

    rsx! {
        ViewerHeader { summary: summary_data.clone() }

        div { class: "w-full px-3 sm:px-4 lg:px-6 py-3 space-y-2",
            if let Some(err) = error_msg() {
                div { class: "bg-red-50 border border-red-200 text-red-700 px-3 py-2 rounded-lg text-xs", "{err}" }
            }

            if let (Some(summary), Some(lifetimes), Some(range)) =
                (summary_data.clone(), process_lifetimes(), view_range())
            {
                ProcessTimeline {
                    data: ProcessTimelineData {
                        processes: lifetimes.processes,
                        process_events: process_events(),
                        histogram: hist_data,
                        summary: summary_data.clone(),
                        pid_summary: pid_summary.clone(),
                        latency_stats: syscall_latency_stats(),
                        selected_flame_event_type: selected_flame_event_type_value.clone(),
                        flame_event_type_options,
                        flamegraph: event_flamegraph(),
                        flamegraph_loading: flamegraph_loading(),
                    },
                    selection: ProcessTimelineSelection {
                        enabled_event_types: enabled_event_types(),
                        selected_pid: selected_pid_value,
                    },
                    range: ProcessTimelineRange {
                        full_start_ns: summary.min_ts_ns,
                        full_end_ns: summary.max_ts_ns,
                        view_start_ns: range.start_ns,
                        view_end_ns: range.end_ns,
                    },
                    actions: ProcessTimelineActions {
                        on_select_pid: EventHandler::new(move |pid: u32| {
                            let next_pid = if selected_pid() == Some(pid) {
                                None
                            } else {
                                Some(pid)
                            };
                            selected_pid.set(next_pid);
                        }),
                        on_select_pid_option: EventHandler::new(move |pid: Option<u32>| {
                            selected_pid.set(pid);
                        }),
                        on_focus_process: EventHandler::new(
                            move |(pid, start, end): (u32, u64, u64)| {
                                selected_pid.set(Some(pid));
                                if let Some(next_range) = next_view_range(view_range(), start, end)
                                {
                                    view_range.set(Some(next_range));
                                }
                            },
                        ),
                        on_change_range: EventHandler::new(move |(start, end): (u64, u64)| {
                            if let Some(next_range) = next_view_range(view_range(), start, end) {
                                view_range.set(Some(next_range));
                            }
                        }),
                        on_toggle_event_type: EventHandler::new(move |event_type: String| {
                            let mut types = enabled_event_types();
                            if types.contains(&event_type) {
                                types.remove(&event_type);
                            } else {
                                types.insert(event_type);
                            }
                            enabled_event_types.set(types);
                        }),
                        on_select_flame_event_type: EventHandler::new(
                            move |event_type: Option<String>| {
                                selected_flame_event_type.set(event_type);
                            },
                        ),
                    },
                }
            }
        }
    }
}
