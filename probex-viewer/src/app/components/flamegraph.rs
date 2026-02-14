use dioxus::prelude::*;

use crate::api::EventFlamegraphResponse;
use crate::app::formatting::format_duration_short;

#[derive(Clone, PartialEq)]
pub struct FlamegraphCardSelection {
    pub selected_event_type: Option<String>,
    pub event_type_options: Vec<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FlamegraphCardScope {
    pub selected_pid: Option<u32>,
    pub full_start_ns: u64,
    pub view_start_ns: u64,
    pub view_end_ns: u64,
}

#[derive(Clone, PartialEq)]
pub struct FlamegraphCardData {
    pub flamegraph: Option<EventFlamegraphResponse>,
    pub loading: bool,
}

#[component]
pub fn EventFlamegraphCard(
    selection: FlamegraphCardSelection,
    scope: FlamegraphCardScope,
    data: FlamegraphCardData,
    on_select_event_type: EventHandler<Option<String>>,
) -> Element {
    let FlamegraphCardSelection {
        selected_event_type,
        event_type_options,
    } = selection;
    let FlamegraphCardScope {
        selected_pid,
        full_start_ns,
        view_start_ns,
        view_end_ns,
    } = scope;
    let FlamegraphCardData {
        flamegraph,
        loading,
    } = data;

    let event_type = selected_event_type.unwrap_or_default();
    let flamegraph_data = flamegraph.unwrap_or_default();
    let total = flamegraph_data.total_samples;
    let svg_doc = flamegraph_data.svg.unwrap_or_default();
    let framed_svg_doc = frame_flamegraph_svg(&svg_doc);
    let iframe_height_px = initial_iframe_height_px(&svg_doc);
    let iframe_style = format!("line-height:0;height:{iframe_height_px}px;");
    let range_width = view_end_ns.saturating_sub(view_start_ns);
    let start_offset = view_start_ns.saturating_sub(full_start_ns);
    let end_offset = view_end_ns.saturating_sub(full_start_ns);
    let pid_scope = selected_pid
        .map(|pid| format!("PID {pid}"))
        .unwrap_or_else(|| "All PIDs".to_string());
    let sample_label = if total > 0 {
        format!("{total} samples")
    } else {
        "0 samples".to_string()
    };
    let selected_event_label = if event_type.is_empty() {
        "none".to_string()
    } else {
        event_type.clone()
    };

    rsx! {
        div { class: "bg-white border border-gray-200 rounded px-2 py-1.5 space-y-1.5",
            div { class: "flex flex-wrap items-center gap-2",
                label { class: "text-xs text-gray-600", "Flamegraph event:" }
                select {
                    class: "px-2 py-0.5 border border-gray-200 rounded text-xs bg-white min-w-[14rem]",
                    value: "{event_type}",
                    onchange: move |evt| {
                        let value = evt.value();
                        if value.is_empty() {
                            on_select_event_type.call(None);
                        } else {
                            on_select_event_type.call(Some(value));
                        }
                    },
                    option { value: "", "None" }
                    {event_type_options.into_iter().map(|event_name| rsx! {
                        option { key: "{event_name}", value: "{event_name}", "{event_name}" }
                    })}
                }
                div { class: "ml-auto text-[11px] text-gray-500 flex flex-wrap items-center gap-x-1.5",
                    span { "{sample_label}" }
                    span { "·" }
                    span { "Scope: {pid_scope} · T+{format_duration_short(start_offset)}..T+{format_duration_short(end_offset)} (width {format_duration_short(range_width)})" }
                    span { "·" }
                    span {
                        "Event: "
                        span { class: "font-mono text-gray-700", "{selected_event_label}" }
                    }
                }
            }

            if event_type.is_empty() {
                div { class: "text-xs text-gray-400", "Select an event type to build a flamegraph for the current scope" }
            } else if !framed_svg_doc.is_empty() {
                // Show existing flamegraph with loading overlay when updating
                div { class: "relative w-full border border-gray-100 rounded bg-white overflow-hidden",
                    iframe {
                        class: "w-full block border-0 bg-white box-border",
                        style: "{iframe_style}",
                        srcdoc: "{framed_svg_doc}",
                    }
                    if loading {
                        div { class: "absolute inset-0 bg-white/70 flex items-center justify-center",
                            div { class: "flex items-center gap-2 text-xs text-gray-600 bg-white px-3 py-2 rounded shadow-sm border border-gray-200",
                                span { class: "inline-block w-3 h-3 rounded-full border-2 border-gray-300 border-t-blue-500 animate-spin" }
                                span { "Updating flamegraph..." }
                            }
                        }
                    }
                }
            } else if loading {
                // Initial load with no existing data
                div { class: "w-full border border-gray-100 rounded bg-white p-3 space-y-2",
                    div { class: "flex items-center gap-2 text-xs text-gray-500",
                        span { class: "inline-block w-3 h-3 rounded-full border-2 border-gray-300 border-t-blue-500 animate-spin" }
                        span { "Building flamegraph..." }
                    }
                    div { class: "h-20 rounded bg-gray-100 animate-pulse" }
                }
            } else if total == 0 {
                div { class: "text-xs text-gray-400", "No stack samples in current scope" }
            }
        }
    }
}

fn frame_flamegraph_svg(svg_doc: &str) -> String {
    if svg_doc.is_empty() {
        return String::new();
    }

    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"/><style>\
         html,body{{margin:0;padding:0;width:100%;overflow:hidden;background:#fff;\
         font-family:ui-sans-serif,system-ui,-apple-system,\"Segoe UI\",sans-serif;font-size:12px;}}\
         svg{{display:block;width:100% !important;max-width:100%;height:auto !important;}}\
         svg text{{font-family:ui-sans-serif,system-ui,-apple-system,\"Segoe UI\",sans-serif !important;\
         font-size:12px !important;}}\
         </style></head><body>{svg}<script>\
         (function(){{\
           function resizeFrame(){{\
             var svg = document.querySelector('svg');\
             var frame = window.frameElement;\
             if (!svg || !frame) return;\
             var height = Math.ceil(svg.getBoundingClientRect().height);\
             if (height > 0) {{\
               frame.style.height = height + 'px';\
             }}\
           }}\
           window.addEventListener('load', function(){{\
             resizeFrame();\
             requestAnimationFrame(resizeFrame);\
             requestAnimationFrame(function(){{ requestAnimationFrame(resizeFrame); }});\
           }});\
           window.addEventListener('resize', resizeFrame);\
           if (window.ResizeObserver) {{\
             new ResizeObserver(resizeFrame).observe(document.body);\
           }}\
         }})();\
         </script></body></html>",
        svg = svg_doc
    )
}

fn initial_iframe_height_px(svg_doc: &str) -> u64 {
    parse_svg_dimension(svg_doc, "height")
        .filter(|height| *height > 0.0)
        .map(|height| height.ceil() as u64)
        .unwrap_or(240)
}

fn parse_svg_dimension(svg_doc: &str, attribute: &str) -> Option<f64> {
    let marker = format!("{attribute}=\"");
    let start = svg_doc.find(&marker)? + marker.len();
    let value_tail = &svg_doc[start..];
    let end = value_tail.find('"')?;
    parse_svg_number(&value_tail[..end])
}

fn parse_svg_number(value: &str) -> Option<f64> {
    let trimmed = value.trim();
    let numeric_prefix: String = trimmed
        .chars()
        .take_while(|c| c.is_ascii_digit() || matches!(*c, '.' | '-' | '+'))
        .collect();
    if numeric_prefix.is_empty() {
        return None;
    }
    numeric_prefix.parse::<f64>().ok()
}
