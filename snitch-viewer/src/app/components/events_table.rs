use dioxus::prelude::*;

use crate::app::formatting::{format_duration, format_event_details, get_event_text_color};
use crate::server::TraceEvent;

#[component]
pub fn EventsTable(events: Vec<TraceEvent>, loading: bool, full_start_ns: u64) -> Element {
    rsx! {
        div { class: "bg-white border border-gray-200 rounded-lg overflow-hidden",
            if loading {
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
                            let relative_ns = event.ts_ns.saturating_sub(full_start_ns);
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
    }
}
