//! UI components for snitch-viewer.
//!
//! Provides a paginated event table with filtering capabilities.

use dioxus::prelude::*;

use crate::server::{get_events, get_summary, EventFilters, EventsResponse, TraceEvent, TraceSummary};
use crate::{FAVICON, TAILWIND_CSS};

const RESULTS_PER_PAGE: usize = 50;

#[component]
pub fn App() -> Element {
    rsx! {
        document::Link { rel: "icon", href: FAVICON }
        document::Link { rel: "stylesheet", href: TAILWIND_CSS }
        main { class: "min-h-screen bg-gray-100 text-gray-800",
            TraceViewer {}
        }
    }
}

#[component]
fn TraceViewer() -> Element {
    let mut events_response = use_signal(|| Option::<EventsResponse>::None);
    let mut summary = use_signal(|| Option::<TraceSummary>::None);
    let mut loading = use_signal(|| true);
    let mut error_msg = use_signal(|| Option::<String>::None);

    // Filter state
    let mut selected_event_type = use_signal(|| String::new());
    let mut selected_pid = use_signal(|| String::new());
    let mut current_page = use_signal(|| 0usize);

    // Load summary on mount
    let _ = use_resource(move || async move {
        match get_summary().await {
            Ok(s) => summary.set(Some(s)),
            Err(e) => error_msg.set(Some(format!("Failed to load summary: {}", e))),
        }
    });

    // Load events when filters change
    let do_search = move |reset_page: bool| {
        let event_type = selected_event_type();
        let pid_str = selected_pid();
        let page = if reset_page { 0 } else { current_page() };

        spawn(async move {
            loading.set(true);
            error_msg.set(None);
            if reset_page {
                current_page.set(0);
            }

            let filters = EventFilters {
                event_type: if event_type.is_empty() {
                    None
                } else {
                    Some(event_type)
                },
                pid: pid_str.parse::<u32>().ok(),
                limit: RESULTS_PER_PAGE,
                offset: page * RESULTS_PER_PAGE,
            };

            match get_events(filters).await {
                Ok(response) => {
                    events_response.set(Some(response));
                }
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
            do_search(true);
        }
    });

    let summary_data = summary();
    let response = events_response();

    let (events, total_count) = match &response {
        Some(r) => (r.events.clone(), r.total_count),
        None => (Vec::new(), 0),
    };

    let total_pages = (total_count + RESULTS_PER_PAGE - 1) / RESULTS_PER_PAGE;
    let showing_from = if total_count == 0 {
        0
    } else {
        current_page() * RESULTS_PER_PAGE + 1
    };
    let showing_to = ((current_page() + 1) * RESULTS_PER_PAGE).min(total_count);

    // Get available event types and PIDs from summary
    let event_types = summary_data
        .as_ref()
        .map(|s| s.event_types.clone())
        .unwrap_or_default();
    let unique_pids = summary_data
        .as_ref()
        .map(|s| s.unique_pids.clone())
        .unwrap_or_default();

    // Calculate duration if we have time range
    let duration_str = summary_data
        .as_ref()
        .map(|s| {
            if s.max_ts_ns > s.min_ts_ns {
                let duration_ns = s.max_ts_ns - s.min_ts_ns;
                let duration_ms = duration_ns as f64 / 1_000_000.0;
                if duration_ms < 1000.0 {
                    format!("{:.2} ms", duration_ms)
                } else {
                    format!("{:.2} s", duration_ms / 1000.0)
                }
            } else {
                "N/A".to_string()
            }
        })
        .unwrap_or_else(|| "Loading...".to_string());

    rsx! {
        header { class: "bg-slate-700 text-white px-8 py-4 flex items-center justify-between flex-wrap gap-4",
            h1 { class: "text-2xl font-semibold", "Snitch Trace Viewer" }
            if let Some(s) = &summary_data {
                div { class: "flex gap-8 text-sm",
                    span { class: "flex gap-2",
                        strong { "Total Events: " }
                        "{s.total_events}"
                    }
                    span { class: "flex gap-2",
                        strong { "Duration: " }
                        "{duration_str}"
                    }
                    span { class: "flex gap-2",
                        strong { "PIDs: " }
                        "{s.unique_pids.len()}"
                    }
                }
            }
        }

        div { class: "max-w-7xl mx-auto p-6",
            if let Some(err) = error_msg() {
                div { class: "bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded mb-4", "{err}" }
            }

            // Filters
            div { class: "flex items-center gap-6 mb-4 p-4 bg-white rounded shadow-sm flex-wrap",
                div { class: "flex items-center gap-2",
                    label { class: "font-medium text-sm", "Event Type:" }
                    select {
                        class: "px-3 py-1.5 border border-gray-300 rounded text-sm min-w-[150px]",
                        value: "{selected_event_type}",
                        onchange: move |evt| {
                            selected_event_type.set(evt.value());
                            do_search(true);
                        },
                        option { value: "", "All" }
                        {event_types.iter().map(|t| rsx! {
                            option { value: "{t}", "{t}" }
                        })}
                    }
                }
                div { class: "flex items-center gap-2",
                    label { class: "font-medium text-sm", "PID:" }
                    select {
                        class: "px-3 py-1.5 border border-gray-300 rounded text-sm min-w-[150px]",
                        value: "{selected_pid}",
                        onchange: move |evt| {
                            selected_pid.set(evt.value());
                            do_search(true);
                        },
                        option { value: "", "All" }
                        {unique_pids.iter().map(|p| rsx! {
                            option { value: "{p}", "{p}" }
                        })}
                    }
                }
                div { class: "ml-auto text-gray-500 text-sm",
                    "Showing {showing_from}-{showing_to} of {total_count}"
                }
            }

            // Event table
            if loading() {
                div { class: "text-center py-12 text-gray-500 bg-white rounded", "Loading..." }
            } else if events.is_empty() {
                div { class: "text-center py-12 text-gray-500 bg-white rounded", "No events found." }
            } else {
                div { class: "bg-white rounded shadow-sm overflow-x-auto",
                    table { class: "w-full text-sm",
                        thead {
                            tr { class: "bg-gray-50 text-gray-600",
                                th { class: "px-4 py-2 text-left font-semibold", "Timestamp" }
                                th { class: "px-4 py-2 text-left font-semibold", "Type" }
                                th { class: "px-4 py-2 text-left font-semibold", "PID" }
                                th { class: "px-4 py-2 text-left font-semibold", "CPU" }
                                th { class: "px-4 py-2 text-left font-semibold", "Details" }
                            }
                        }
                        tbody {
                            {events.iter().enumerate().map(|(idx, event)| {
                                let base_ts = summary_data.as_ref().map(|s| s.min_ts_ns).unwrap_or(0);
                                rsx! {
                                    EventRow {
                                        key: "{idx}",
                                        event: event.clone(),
                                        base_ts: base_ts,
                                    }
                                }
                            })}
                        }
                    }
                }

                // Pagination
                if total_pages > 1 {
                    div { class: "flex items-center justify-center gap-4 mt-4 py-4",
                        button {
                            class: "px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:bg-gray-300 disabled:cursor-not-allowed",
                            disabled: current_page() == 0,
                            onclick: move |_| {
                                current_page.set(current_page().saturating_sub(1));
                                do_search(false);
                            },
                            "Prev"
                        }
                        span { class: "text-gray-600 text-sm",
                            "Page {current_page() + 1} of {total_pages}"
                        }
                        button {
                            class: "px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600 disabled:bg-gray-300 disabled:cursor-not-allowed",
                            disabled: current_page() + 1 >= total_pages,
                            onclick: move |_| {
                                current_page.set(current_page() + 1);
                                do_search(false);
                            },
                            "Next"
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn EventRow(event: TraceEvent, base_ts: u64) -> Element {
    // Format timestamp as relative time from base
    let relative_ns = event.ts_ns.saturating_sub(base_ts);
    let relative_ms = relative_ns as f64 / 1_000_000.0;
    let ts_str = if relative_ms < 1000.0 {
        format!("{:.3} ms", relative_ms)
    } else {
        format!("{:.3} s", relative_ms / 1000.0)
    };

    // Format details based on event type
    let details = format_event_details(&event);

    // Color class based on event type
    let type_color = match event.event_type.as_str() {
        "sched_switch" => "text-blue-500",
        "process_fork" => "text-green-600",
        "process_exit" => "text-red-500",
        "page_fault" => "text-orange-500",
        _ if event.event_type.contains("syscall") => "text-purple-500",
        _ => "text-gray-700",
    };

    rsx! {
        tr { class: "border-b border-gray-100 hover:bg-gray-50",
            td { class: "px-4 py-2 font-mono text-gray-500 whitespace-nowrap", "{ts_str}" }
            td { class: "px-4 py-2 font-medium {type_color}", "{event.event_type}" }
            td { class: "px-4 py-2 font-mono", "{event.pid}" }
            td { class: "px-4 py-2 font-mono", "{event.cpu}" }
            td { class: "px-4 py-2 font-mono text-xs text-gray-600", "{details}" }
        }
    }
}

fn format_event_details(event: &TraceEvent) -> String {
    match event.event_type.as_str() {
        "sched_switch" => {
            let prev = event.prev_pid.map(|p| p.to_string()).unwrap_or_default();
            let next = event.next_pid.map(|p| p.to_string()).unwrap_or_default();
            let state = event.prev_state.unwrap_or(0);
            format!("{} -> {} (state: {})", prev, next, state)
        }
        "process_fork" => {
            let parent = event.parent_pid.map(|p| p.to_string()).unwrap_or_default();
            let child = event.child_pid.map(|p| p.to_string()).unwrap_or_default();
            format!("parent: {} -> child: {}", parent, child)
        }
        "process_exit" => {
            let code = event.exit_code.unwrap_or(0);
            format!("exit_code: {}", code)
        }
        "page_fault" => {
            let addr = event
                .address
                .map(|a| format!("0x{:x}", a))
                .unwrap_or_default();
            let err = event.error_code.unwrap_or(0);
            format!("addr: {} err: {}", addr, err)
        }
        "syscall_read_enter" | "syscall_write_enter" => {
            let fd = event.fd.unwrap_or(-1);
            let count = event.count.unwrap_or(0);
            format!("fd: {} count: {}", fd, count)
        }
        "syscall_read_exit" | "syscall_write_exit" => {
            let ret = event.ret.unwrap_or(0);
            format!("ret: {}", ret)
        }
        _ => String::new(),
    }
}
