//! UI entry point for probex-viewer.

mod components;
mod formatting;
pub(crate) mod view_model;

use components::{ProcessTimeline, ViewerHeader};
use dioxus::prelude::*;
use view_model::ViewRange;

use crate::api::{
    HistogramResponse, ProcessLifetimesResponse, TraceSummary,
    get_histogram, get_process_lifetimes, get_summary,
};

const FAVICON: Asset = asset!("/assets/favicon.ico");
const TAILWIND_CSS: Asset = asset!("/assets/tailwind.css");

pub(crate) const HISTOGRAM_BUCKETS: usize = 80;
pub(crate) const MAX_FLAME_STACKS: usize = 5000;
pub(crate) const MAX_PROCESS_MARKERS_PER_PID: usize = 500;

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
    let mut process_lifetimes = use_signal(|| Option::<ProcessLifetimesResponse>::None);
    let mut error_msg = use_signal(|| Option::<String>::None);

    // Non-optional after initialization — only render children once set.
    let mut view_range = use_signal(|| Option::<ViewRange>::None);
    let selected_pid = use_signal(|| Option::<u32>::None);

    use_resource(move || async move {
        match get_summary().await {
            Ok(s) => {
                let Some(range) = ViewRange::new(s.min_ts_ns, s.max_ts_ns) else {
                    error_msg.set(Some(
                        "Invalid summary range: max_ts_ns must be >= min_ts_ns".to_string(),
                    ));
                    return;
                };
                view_range.set(Some(range));
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

    let summary_data = summary();
    let hist_data = histogram();

    rsx! {
        ViewerHeader { summary: summary_data.clone() }

        div { class: "w-full px-3 sm:px-4 lg:px-6 py-3 space-y-2",
            if let Some(err) = error_msg() {
                div { class: "bg-red-50 border border-red-200 text-red-700 px-3 py-2 rounded-lg text-xs", "{err}" }
            }

            if let (Some(summary), Some(lifetimes), Some(_)) =
                (summary_data, process_lifetimes(), view_range())
            {
                ProcessTimeline {
                    summary,
                    processes: lifetimes.processes,
                    histogram: hist_data,
                    view_range,
                    selected_pid,
                }
            }
        }
    }
}
