use dioxus::prelude::*;

use crate::api::TraceSummary;
use crate::app::formatting::format_duration;

#[component]
pub fn ViewerHeader(summary: Option<TraceSummary>) -> Element {
    let duration = summary
        .as_ref()
        .map(|s| s.max_ts_ns.saturating_sub(s.min_ts_ns))
        .unwrap_or(0);

    rsx! {
        header { class: "bg-white border-b border-gray-200 px-3 sm:px-4 lg:px-6 py-2",
            div { class: "w-full flex items-center justify-between",
                h1 { class: "text-lg font-semibold text-gray-900", "Probex Trace Viewer" }
                if let Some(s) = summary {
                    div { class: "flex gap-4 text-xs",
                        StatBadge { label: "Events", value: format!("{}", s.total_events) }
                        StatBadge { label: "Duration", value: format_duration(duration) }
                        StatBadge { label: "PIDs", value: format!("{}", s.unique_pids.len()) }
                        if let Some(freq_hz) = s.cpu_sample_frequency_hz {
                            StatBadge { label: "Sample Hz", value: format!("{}", freq_hz) }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn StatBadge(label: &'static str, value: String) -> Element {
    rsx! {
        div { class: "flex items-center gap-1.5",
            span { class: "text-gray-400", "{label}" }
            span { class: "font-medium text-gray-900", "{value}" }
        }
    }
}
