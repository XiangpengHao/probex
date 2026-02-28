use dioxus::prelude::*;

use super::probe_catalog::ProbeCatalog;
use crate::api::{CustomProbeSpec, TraceSummary};
use crate::app::formatting::format_duration;

#[component]
pub fn ViewerHeader(
    summary: Option<TraceSummary>,
    custom_probes: Signal<Vec<CustomProbeSpec>>,
) -> Element {
    let duration = summary
        .as_ref()
        .map(|s| s.max_ts_ns.saturating_sub(s.min_ts_ns))
        .unwrap_or(0);

    rsx! {
        header { class: "bg-white border-b border-gray-200 px-3 sm:px-4 lg:px-6 py-2 space-y-1.5",
            div { class: "w-full flex items-center justify-between gap-4",
                h1 { class: "text-lg font-semibold text-gray-900 shrink-0", "Probex Trace Viewer" }
                if let Some(s) = summary {
                    div { class: "flex gap-4 text-xs flex-wrap justify-end",
                        StatBadge { label: "Events", value: format!("{}", s.total_events) }
                        StatBadge { label: "Duration", value: format_duration(duration) }
                        StatBadge { label: "PIDs", value: format!("{}", s.unique_pids.len()) }
                        StatBadge { label: "Sample Hz", value: format!("{}", s.cpu_sample_frequency_hz) }
                    }
                }
            }
            ProbeCatalog { custom_probes }
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
