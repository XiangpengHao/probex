//! UI entry point for probex-viewer.
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

use crate::api::{
    CustomEventsDebugResponse, CustomProbeSpec, EventFlamegraphResponse, EventTypeCounts,
    HistogramResponse, ProcessEventsResponse, ProcessLifetimesResponse, StartTraceRequest,
    TraceDebugInfo, TraceDebugStepStatus, TraceRunStatus, TraceSummary, get_custom_events_debug,
    get_event_flamegraph, get_event_type_counts, get_histogram, get_pid_event_type_counts,
    get_process_events, get_process_lifetimes, get_summary, get_syscall_latency_stats,
    get_trace_debug_info, get_trace_run_status, load_trace_file, start_trace_run, stop_trace_run,
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
    let mut reload_nonce = use_signal(|| 0u64);

    let mut trace_program = use_signal(String::new);
    let mut trace_args = use_signal(String::new);
    let mut trace_output = use_signal(|| "trace.parquet".to_string());
    let mut trace_sample_freq = use_signal(|| "999".to_string());
    let custom_probes = use_signal(Vec::<CustomProbeSpec>::new);
    let mut trace_run_status = use_signal(|| TraceRunStatus::Idle);
    let mut trace_status_sequence = use_signal(|| 0u64);
    let trace_last_loaded_run_id = use_signal(|| Option::<u64>::None);
    let mut trace_error = use_signal(|| Option::<String>::None);
    let mut trace_poller_active = use_signal(|| false);
    let mut trace_starting = use_signal(|| false);
    let mut show_trace_debug = use_signal(|| false);
    let mut trace_debug_info = use_signal(|| Option::<TraceDebugInfo>::None);
    let mut trace_debug_loading = use_signal(|| false);
    let mut trace_debug_error = use_signal(|| Option::<String>::None);
    let mut custom_events_debug = use_signal(|| Option::<CustomEventsDebugResponse>::None);
    let mut custom_events_debug_loading = use_signal(|| false);
    let mut custom_events_debug_error = use_signal(|| Option::<String>::None);

    use_resource(move || async move {
        match get_trace_run_status(None, Some(0)).await {
            Ok(response) => {
                trace_status_sequence.set(response.sequence);
                trace_run_status.set(response.status.clone());
                if matches!(response.status, TraceRunStatus::Running { .. })
                    && !trace_poller_active()
                {
                    trace_poller_active.set(true);
                    spawn_trace_status_poller(
                        trace_status_sequence,
                        trace_run_status,
                        trace_last_loaded_run_id,
                        trace_error,
                        trace_poller_active,
                        summary,
                        histogram,
                        selected_pid_event_counts,
                        syscall_latency_stats,
                        event_flamegraph,
                        process_lifetimes,
                        process_events,
                        selected_pid,
                        reload_nonce,
                    );
                }
            }
            Err(error) => trace_error.set(Some(format!("Failed to query trace status: {error}"))),
        }
    });

    use_resource(move || async move {
        let _refresh = reload_nonce();
        match get_summary().await {
            Ok(s) => {
                let Some(range) = ViewRange::new(s.min_ts_ns, s.max_ts_ns) else {
                    error_msg.set(Some(
                        "Invalid summary range: max_ts_ns must be >= min_ts_ns".to_string(),
                    ));
                    return;
                };
                view_range.set(Some(range));
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
        let _refresh = reload_nonce();
        match get_process_lifetimes().await {
            Ok(lifetimes) => process_lifetimes.set(Some(lifetimes)),
            Err(e) => log::error!("Process lifetimes error: {}", e),
        }
    });

    use_resource(move || async move {
        let _refresh = reload_nonce();
        if let Some(s) = summary() {
            match get_histogram(s.min_ts_ns, s.max_ts_ns, HISTOGRAM_BUCKETS).await {
                Ok(data) => histogram.set(Some(data)),
                Err(e) => log::error!("Histogram error: {}", e),
            }
        }
    });

    use_resource(move || async move {
        let _refresh = reload_nonce();
        let Some(range) = view_range() else {
            return;
        };

        match get_process_events(range.start_ns, range.end_ns, MAX_PROCESS_MARKERS_PER_PID).await {
            Ok(events) => process_events.set(Some(events)),
            Err(e) => log::error!("Process events error: {}", e),
        }
    });

    use_resource(move || async move {
        let _refresh = reload_nonce();
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
        let _refresh = reload_nonce();
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
        let _refresh = reload_nonce();
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
    let trace_debug_snapshot = trace_debug_info();
    let startup_status_text = startup_phase_text(trace_debug_snapshot.as_ref());
    let trace_status_text = match trace_run_status() {
        TraceRunStatus::Idle => {
            if trace_starting() {
                startup_status_text.clone()
            } else {
                "Idle".to_string()
            }
        }
        TraceRunStatus::Running { run_id, .. } => format!("Running (#{run_id})"),
        TraceRunStatus::Finished {
            run_id,
            success,
            exit_code,
            ..
        } => {
            if success {
                format!("Finished (#{run_id}, exit {exit_code})")
            } else {
                format!("Failed (#{run_id}, exit {exit_code})")
            }
        }
    };
    let is_trace_busy =
        trace_starting() || matches!(trace_run_status(), TraceRunStatus::Running { .. });
    let is_trace_running = matches!(trace_run_status(), TraceRunStatus::Running { .. });
    let start_button_class = if is_trace_busy {
        "px-2 py-1 rounded border border-gray-200 bg-gray-100 text-gray-400 text-xs cursor-not-allowed"
    } else {
        "px-2 py-1 rounded border border-blue-200 bg-blue-50 text-blue-700 text-xs cursor-pointer hover:bg-blue-100 hover:border-blue-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300"
    };
    let stop_button_class = if is_trace_running {
        "px-2 py-1 rounded border border-red-200 bg-red-50 text-red-700 text-xs cursor-pointer hover:bg-red-100 hover:border-red-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-red-300"
    } else {
        "px-2 py-1 rounded border border-gray-200 bg-gray-100 text-gray-400 text-xs cursor-not-allowed"
    };

    rsx! {
        ViewerHeader {
            summary: summary_data.clone(),
            custom_probes,
        }

        div { class: "w-full px-3 sm:px-4 lg:px-6 py-3 space-y-2",
            if let Some(err) = error_msg() {
                div { class: "bg-red-50 border border-red-200 text-red-700 px-3 py-2 rounded-lg text-xs", "{err}" }
            }
            div { class: "bg-white border border-gray-200 rounded-lg px-3 py-2 space-y-2",
                div { class: "flex items-center justify-between gap-2 flex-wrap",
                    h2 { class: "text-xs font-semibold text-gray-700", "Trace Command" }
                    div { class: "flex items-center gap-1.5",
                        if is_trace_busy {
                            span { class: "inline-block h-2.5 w-2.5 rounded-full border-2 border-blue-300 border-t-blue-600 animate-spin" }
                        }
                        span { class: if is_trace_busy { "text-[11px] text-blue-700" } else { "text-[11px] text-gray-500" }, "{trace_status_text}" }
                    }
                }
                div { class: "grid grid-cols-1 lg:grid-cols-4 gap-2",
                    input {
                        class: "px-2 py-1 border border-gray-200 rounded text-xs bg-white",
                        r#type: "text",
                        value: "{trace_program}",
                        placeholder: "Program (e.g. sleep)",
                        oninput: move |evt| trace_program.set(evt.value()),
                    }
                    input {
                        class: "px-2 py-1 border border-gray-200 rounded text-xs bg-white",
                        r#type: "text",
                        value: "{trace_args}",
                        placeholder: "Args (space-separated, e.g. 5)",
                        oninput: move |evt| trace_args.set(evt.value()),
                    }
                    input {
                        class: "px-2 py-1 border border-gray-200 rounded text-xs bg-white",
                        r#type: "text",
                        value: "{trace_output}",
                        placeholder: "Output parquet (e.g. trace.parquet)",
                        oninput: move |evt| trace_output.set(evt.value()),
                    }
                    input {
                        class: "px-2 py-1 border border-gray-200 rounded text-xs bg-white",
                        r#type: "number",
                        min: "1",
                        value: "{trace_sample_freq}",
                        placeholder: "Sample Hz",
                        oninput: move |evt| trace_sample_freq.set(evt.value()),
                    }
                }
                div { class: "flex items-center gap-2 flex-wrap",
                    button {
                        class: "{start_button_class}",
                        disabled: is_trace_busy,
                        onclick: move |_| {
                            if is_trace_busy {
                                return;
                            }
                            let parsed_sample = match trace_sample_freq().trim().parse::<u64>() {
                                Ok(v) if v > 0 => v,
                                _ => {
                                    trace_error.set(Some("Sample Hz must be a positive integer".to_string()));
                                    return;
                                }
                            };
                            let program = trace_program().trim().to_string();
                            if program.is_empty() {
                                trace_error.set(Some("Program must not be empty".to_string()));
                                return;
                            }
                            let output_parquet = trace_output().trim().to_string();
                            if output_parquet.is_empty() {
                                trace_error.set(Some("Output parquet must not be empty".to_string()));
                                return;
                            }
                            let args = trace_args()
                                .split_whitespace()
                                .map(str::to_string)
                                .collect::<Vec<_>>();
                            let selected_custom_probes = custom_probes();
                            trace_starting.set(true);
                            trace_error.set(None);
                            spawn(async move {
                                while trace_starting() {
                                    match get_trace_debug_info().await {
                                        Ok(debug) => {
                                            trace_debug_info.set(Some(debug));
                                            trace_debug_error.set(None);
                                        }
                                        Err(error) => {
                                            trace_debug_error.set(Some(format!("Failed to load trace debug info: {error}")));
                                            break;
                                        }
                                    }
                                    let _ = get_trace_run_status(None, Some(250)).await;
                                }
                            });
                            spawn(async move {
                                match start_trace_run(StartTraceRequest {
                                    program,
                                    args,
                                    output_parquet,
                                    sample_freq_hz: parsed_sample,
                                    custom_probes: selected_custom_probes,
                                }).await {
                                    Ok(response) => {
                                        trace_starting.set(false);
                                        trace_status_sequence.set(response.sequence);
                                        let status = response.status;
                                        let should_poll = matches!(status, TraceRunStatus::Running { .. });
                                        trace_run_status.set(status);
                                        if should_poll && !trace_poller_active() {
                                            trace_poller_active.set(true);
                                            spawn_trace_status_poller(
                                                trace_status_sequence,
                                                trace_run_status,
                                                trace_last_loaded_run_id,
                                                trace_error,
                                                trace_poller_active,
                                                summary,
                                                histogram,
                                                selected_pid_event_counts,
                                                syscall_latency_stats,
                                                event_flamegraph,
                                                process_lifetimes,
                                                process_events,
                                                selected_pid,
                                                reload_nonce,
                                            );
                                        }
                                    }
                                    Err(error) => {
                                        trace_starting.set(false);
                                        trace_error.set(Some(format!("Failed to start trace: {error}")));
                                    }
                                }
                            });
                        },
                        if is_trace_running {
                            "Tracing..."
                        } else if trace_starting() {
                            "Starting..."
                        } else {
                            "Start Trace"
                        }
                    }
                    button {
                        class: "px-2 py-1 rounded border border-gray-200 bg-white text-gray-700 text-xs cursor-pointer hover:bg-gray-50 hover:border-gray-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gray-300",
                        onclick: move |_| {
                            spawn(async move {
                                match get_trace_run_status(None, Some(0)).await {
                                    Ok(response) => {
                                        trace_status_sequence.set(response.sequence);
                                        let status = response.status;
                                        let should_poll = matches!(status, TraceRunStatus::Running { .. });
                                        trace_run_status.set(status);
                                        if should_poll && !trace_poller_active() {
                                            trace_poller_active.set(true);
                                            spawn_trace_status_poller(
                                                trace_status_sequence,
                                                trace_run_status,
                                                trace_last_loaded_run_id,
                                                trace_error,
                                                trace_poller_active,
                                                summary,
                                                histogram,
                                                selected_pid_event_counts,
                                                syscall_latency_stats,
                                                event_flamegraph,
                                                process_lifetimes,
                                                process_events,
                                                selected_pid,
                                                reload_nonce,
                                            );
                                        }
                                    }
                                    Err(error) => trace_error.set(Some(format!("Failed to refresh trace status: {error}"))),
                                }
                            });
                        },
                        "Refresh Status"
                    }
                    button {
                        class: "{stop_button_class}",
                        disabled: !is_trace_running,
                        onclick: move |_| {
                            if !is_trace_running {
                                return;
                            }
                            spawn(async move {
                                match stop_trace_run().await {
                                    Ok(response) => {
                                        trace_status_sequence.set(response.sequence);
                                        trace_run_status.set(response.status);
                                    }
                                    Err(error) => trace_error.set(Some(format!("Failed to stop trace: {error}"))),
                                }
                            });
                        },
                        "Stop Trace"
                    }
                    button {
                        class: "px-2 py-1 rounded border border-emerald-200 bg-emerald-50 text-emerald-700 text-xs cursor-pointer hover:bg-emerald-100 hover:border-emerald-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-emerald-300",
                        onclick: move |_| {
                            let parquet = trace_output().trim().to_string();
                            if parquet.is_empty() {
                                trace_error.set(Some("Output parquet must not be empty".to_string()));
                                return;
                            }
                            spawn(async move {
                                match load_trace_file(parquet).await {
                                    Ok(next_summary) => {
                                        summary.set(Some(next_summary));
                                        histogram.set(None);
                                        selected_pid_event_counts.set(None);
                                        syscall_latency_stats.set(None);
                                        event_flamegraph.set(None);
                                        process_lifetimes.set(None);
                                        process_events.set(None);
                                        selected_pid.set(None);
                                        reload_nonce.set(reload_nonce().wrapping_add(1));
                                    }
                                    Err(error) => trace_error.set(Some(format!("Failed to load trace file: {error}"))),
                                }
                            });
                        },
                        "Load Parquet"
                    }
                    button {
                        class: if show_trace_debug() {
                            "px-2 py-1 rounded border border-violet-300 bg-violet-100 text-violet-800 text-xs cursor-pointer hover:bg-violet-200 hover:border-violet-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet-300"
                        } else {
                            "px-2 py-1 rounded border border-violet-200 bg-violet-50 text-violet-700 text-xs cursor-pointer hover:bg-violet-100 hover:border-violet-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-violet-300"
                        },
                        onclick: move |_| {
                            let next_open = !show_trace_debug();
                            show_trace_debug.set(next_open);
                            if !next_open {
                                return;
                            }
                            trace_debug_loading.set(true);
                            custom_events_debug_loading.set(true);
                            trace_debug_error.set(None);
                            custom_events_debug_error.set(None);
                            spawn(async move {
                                match get_trace_debug_info().await {
                                    Ok(debug) => trace_debug_info.set(Some(debug)),
                                    Err(error) => trace_debug_error.set(Some(format!("Failed to load trace debug info: {error}"))),
                                }
                                trace_debug_loading.set(false);
                            });
                            spawn(async move {
                                match get_custom_events_debug().await {
                                    Ok(events) => custom_events_debug.set(Some(events)),
                                    Err(error) => custom_events_debug_error.set(Some(format!("Failed to load custom events debug data: {error}"))),
                                }
                                custom_events_debug_loading.set(false);
                            });
                        },
                        if show_trace_debug() { "Hide Debug" } else { "Debug" }
                    }
                    if show_trace_debug() {
                        button {
                            class: "px-2 py-1 rounded border border-gray-200 bg-white text-gray-700 text-xs cursor-pointer hover:bg-gray-50 hover:border-gray-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-gray-300",
                            disabled: trace_debug_loading() || custom_events_debug_loading(),
                            onclick: move |_| {
                                trace_debug_loading.set(true);
                                custom_events_debug_loading.set(true);
                                trace_debug_error.set(None);
                                custom_events_debug_error.set(None);
                                spawn(async move {
                                    match get_trace_debug_info().await {
                                        Ok(debug) => trace_debug_info.set(Some(debug)),
                                        Err(error) => trace_debug_error.set(Some(format!("Failed to refresh trace debug info: {error}"))),
                                    }
                                    trace_debug_loading.set(false);
                                });
                                spawn(async move {
                                    match get_custom_events_debug().await {
                                        Ok(events) => custom_events_debug.set(Some(events)),
                                        Err(error) => custom_events_debug_error.set(Some(format!("Failed to refresh custom events debug data: {error}"))),
                                    }
                                    custom_events_debug_loading.set(false);
                                });
                            },
                            if trace_debug_loading() || custom_events_debug_loading() { "Refreshing..." } else { "Refresh Debug" }
                        }
                    }
                }
                if trace_starting() && !is_trace_running {
                    div { class: "text-[11px] text-blue-700", "{startup_status_text}" }
                }
                if let Some(err) = trace_error() {
                    div { class: "text-[11px] text-red-700", "{err}" }
                }
                if show_trace_debug() {
                    div { class: "rounded border border-violet-200 bg-violet-50/40 p-2 space-y-2",
                        div { class: "flex items-center justify-between gap-2",
                            span { class: "text-xs font-medium text-violet-900", "Trace Debug" }
                            if trace_debug_loading() {
                                span { class: "inline-block h-3 w-3 rounded-full border-2 border-violet-300 border-t-violet-600 animate-spin" }
                            }
                        }
                        if let Some(err) = trace_debug_error() {
                            div { class: "text-[11px] text-red-700", "{err}" }
                        }
                        if let Some(info) = trace_debug_info() {
                            if let Some(last_error) = info.last_error {
                                div { class: "text-[11px] text-red-700 space-y-1",
                                    "Last runtime error: "
                                    pre { class: "max-h-28 overflow-auto rounded border border-red-200 bg-red-50 p-2 text-[10px] leading-4 text-red-800 font-mono whitespace-pre-wrap break-words", "{last_error}" }
                                }
                            }
                            div { class: "space-y-1",
                                span { class: "text-[11px] font-medium text-gray-700", "Steps" }
                                div { class: "space-y-1",
                                    {info.steps.iter().map(|step| rsx! {
                                        div { key: "{step.step}", class: "flex items-start justify-between gap-2 rounded border border-violet-100 bg-white px-2 py-1",
                                            div { class: "text-[11px] text-gray-800 font-mono truncate", "{step.step}" }
                                            div { class: "shrink-0 text-[10px]",
                                                span { class: debug_step_badge_class(&step.status), "{debug_step_badge_text(&step.status)}" }
                                            }
                                        }
                                        if let Some(detail) = &step.detail {
                                            pre { class: "max-h-40 overflow-auto rounded border border-violet-100 bg-violet-50 px-2 py-1 text-[10px] leading-4 text-gray-700 font-mono whitespace-pre-wrap break-words", "{detail}" }
                                        }
                                    })}
                                }
                            }
                            div { class: "space-y-1",
                                span { class: "text-[11px] font-medium text-gray-700", "Generated Rust (preview)" }
                                pre { class: "max-h-56 overflow-auto rounded border border-violet-100 bg-white p-2 text-[10px] leading-4 text-gray-700 font-mono", "{info.generated_rust_code}" }
                            }
                        } else if !trace_debug_loading() {
                            div { class: "text-[11px] text-gray-500", "No debug data yet. Start a trace or click Refresh Debug." }
                        }

                        div { class: "space-y-1 pt-1",
                            div { class: "flex items-center justify-between gap-2",
                                span { class: "text-[11px] font-medium text-gray-700", "Custom Events (debug)" }
                                if custom_events_debug_loading() {
                                    span { class: "inline-block h-3 w-3 rounded-full border-2 border-violet-300 border-t-violet-600 animate-spin" }
                                }
                            }
                            if let Some(err) = custom_events_debug_error() {
                                div { class: "text-[11px] text-red-700", "{err}" }
                            }
                            if let Some(events) = custom_events_debug() {
                                div { class: "text-[11px] text-gray-600", "{events.shown} shown (limit {events.limit})" }
                                if events.events.is_empty() {
                                    div { class: "text-[11px] text-gray-500", "No custom events found in loaded trace." }
                                } else {
                                    div { class: "max-h-64 overflow-auto space-y-1 pr-1",
                                        {events.events.iter().enumerate().map(|(idx, event)| rsx! {
                                            div { key: "{idx}-{event.ts_ns}-{event.pid}", class: "rounded border border-violet-100 bg-white p-2 space-y-1",
                                                div { class: "flex items-center justify-between gap-2 text-[10px] text-gray-700",
                                                    span { class: "font-mono font-medium text-violet-700", "{event.event_type}" }
                                                    span { class: "font-mono text-gray-500", "ts={event.ts_ns}" }
                                                }
                                                div { class: "flex items-center gap-2 text-[10px] text-gray-600 flex-wrap",
                                                    span { class: "font-mono", "pid={event.pid}" }
                                                    span { class: "font-mono", "tgid={event.tgid}" }
                                                    span { class: "font-mono", "schema={event.schema_id}" }
                                                    if let Some(name) = &event.process_name {
                                                        span { class: "font-mono text-gray-500", "{name}" }
                                                    }
                                                }
                                                if event.fields.is_empty() {
                                                    div { class: "text-[10px] text-gray-500", "No recorded fields." }
                                                } else {
                                                    div { class: "flex items-center gap-1 flex-wrap",
                                                        {event.fields.iter().map(|field| rsx! {
                                                            span { key: "{field.field_id}-{field.name}", class: "inline-flex items-center gap-1 rounded border border-blue-200 bg-blue-50 px-1.5 py-0.5 text-[10px] text-blue-800 font-mono",
                                                                "{field.name}="
                                                                span { class: "text-blue-900", "{field.display_value}" }
                                                            }
                                                        })}
                                                    }
                                                }
                                            }
                                        })}
                                    }
                                }
                            } else if !custom_events_debug_loading() {
                                div { class: "text-[11px] text-gray-500", "Open Debug or click Refresh Debug to load custom events." }
                            }
                        }
                    }
                }
                if let TraceRunStatus::Finished {
                    output_parquet,
                    error,
                    ..
                } = trace_run_status() {
                    div { class: "text-[11px] text-gray-600",
                        "Last output: "
                        span { class: "font-mono", "{output_parquet}" }
                    }
                    if let Some(error) = error {
                        div { class: "text-[11px] text-red-700", "{error}" }
                    }
                }
            }

            if let (Some(summary), Some(lifetimes), Some(range)) =
                (summary_data.clone(), process_lifetimes(), view_range())
            {
                ProcessTimeline {
                    data: ProcessTimelineData {
                        processes: lifetimes.processes,
                        process_events: process_events(),
                        histogram: hist_data,
                        summary: summary.clone(),
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

#[allow(clippy::too_many_arguments)]
fn spawn_trace_status_poller(
    mut trace_status_sequence: Signal<u64>,
    mut trace_run_status: Signal<TraceRunStatus>,
    mut trace_last_loaded_run_id: Signal<Option<u64>>,
    mut trace_error: Signal<Option<String>>,
    mut trace_poller_active: Signal<bool>,
    mut summary: Signal<Option<TraceSummary>>,
    mut histogram: Signal<Option<HistogramResponse>>,
    mut selected_pid_event_counts: Signal<Option<EventTypeCounts>>,
    mut syscall_latency_stats: Signal<Option<crate::api::SyscallLatencyStats>>,
    mut event_flamegraph: Signal<Option<EventFlamegraphResponse>>,
    mut process_lifetimes: Signal<Option<ProcessLifetimesResponse>>,
    mut process_events: Signal<Option<ProcessEventsResponse>>,
    mut selected_pid: Signal<Option<u32>>,
    mut reload_nonce: Signal<u64>,
) {
    spawn(async move {
        loop {
            let last_sequence = trace_status_sequence();
            match get_trace_run_status(Some(last_sequence), Some(2_000)).await {
                Ok(response) => {
                    trace_status_sequence.set(response.sequence);
                    let status = response.status;
                    if let TraceRunStatus::Finished {
                        run_id,
                        success,
                        output_parquet,
                        ..
                    } = &status
                        && *success
                        && trace_last_loaded_run_id() != Some(*run_id)
                    {
                        match load_trace_file(output_parquet.clone()).await {
                            Ok(next_summary) => {
                                summary.set(Some(next_summary));
                                histogram.set(None);
                                selected_pid_event_counts.set(None);
                                syscall_latency_stats.set(None);
                                event_flamegraph.set(None);
                                process_lifetimes.set(None);
                                process_events.set(None);
                                selected_pid.set(None);
                                trace_last_loaded_run_id.set(Some(*run_id));
                                reload_nonce.set(reload_nonce().wrapping_add(1));
                            }
                            Err(error) => trace_error.set(Some(format!(
                                "Trace finished but failed to auto-load parquet: {error}"
                            ))),
                        }
                    }

                    let keep_polling = matches!(status, TraceRunStatus::Running { .. });
                    trace_run_status.set(status);
                    if !keep_polling {
                        trace_poller_active.set(false);
                        break;
                    }
                }
                Err(error) => {
                    trace_error.set(Some(format!("Failed to query trace status: {error}")));
                    trace_poller_active.set(false);
                    break;
                }
            }
        }
    });
}

fn debug_step_badge_class(status: &TraceDebugStepStatus) -> &'static str {
    match status {
        TraceDebugStepStatus::Pending => "px-1.5 py-0.5 rounded bg-gray-100 text-gray-700",
        TraceDebugStepStatus::Running => "px-1.5 py-0.5 rounded bg-blue-100 text-blue-700",
        TraceDebugStepStatus::Success => "px-1.5 py-0.5 rounded bg-emerald-100 text-emerald-700",
        TraceDebugStepStatus::Failed => "px-1.5 py-0.5 rounded bg-red-100 text-red-700",
        TraceDebugStepStatus::Skipped => "px-1.5 py-0.5 rounded bg-amber-100 text-amber-700",
    }
}

fn debug_step_badge_text(status: &TraceDebugStepStatus) -> &'static str {
    match status {
        TraceDebugStepStatus::Pending => "pending",
        TraceDebugStepStatus::Running => "running",
        TraceDebugStepStatus::Success => "ok",
        TraceDebugStepStatus::Failed => "failed",
        TraceDebugStepStatus::Skipped => "skipped",
    }
}

fn debug_step_label(step: &str) -> &'static str {
    match step {
        "validate_custom_probes" => "Validating probes...",
        "generate_rust_code" => "Generating eBPF source...",
        "build_generated_ebpf" => "Building eBPF object...",
        "load_ebpf" => "Loading eBPF...",
        "attach_probes" => "Attaching probes...",
        "spawn_target" => "Starting target process...",
        "trace_loop" => "Starting trace loop...",
        _ => "Starting trace...",
    }
}

fn startup_phase_text(info: Option<&TraceDebugInfo>) -> String {
    let Some(info) = info else {
        return "Starting trace...".to_string();
    };

    if let Some(step) = info
        .steps
        .iter()
        .find(|step| matches!(step.status, TraceDebugStepStatus::Failed))
    {
        return format!(
            "Failed during {}",
            debug_step_label(&step.step).trim_end_matches("...")
        );
    }
    if let Some(step) = info
        .steps
        .iter()
        .find(|step| matches!(step.status, TraceDebugStepStatus::Running))
    {
        return debug_step_label(&step.step).to_string();
    }
    if let Some(step) = info
        .steps
        .iter()
        .find(|step| matches!(step.status, TraceDebugStepStatus::Pending))
    {
        return debug_step_label(&step.step).to_string();
    }

    "Starting trace...".to_string()
}
