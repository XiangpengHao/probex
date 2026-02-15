use dioxus::prelude::*;

use crate::api::{EventListResponse, get_event_list};
use crate::app::formatting::format_duration_short;

const PAGE_SIZE: usize = 50;

#[component]
pub fn EventListCard(
    pid: ReadSignal<u32>,
    view_start_ns: ReadSignal<u64>,
    view_end_ns: ReadSignal<u64>,
    full_start_ns: ReadSignal<u64>,
    event_types: ReadSignal<Vec<String>>,
) -> Element {
    let mut events = use_signal(|| Option::<EventListResponse>::None);
    let mut loading = use_signal(|| false);
    let mut page = use_signal(|| 0usize);
    let mut expanded_idx = use_signal(|| Option::<usize>::None);

    use_resource(move || async move {
        let p = page();
        let start = view_start_ns();
        let end = view_end_ns();
        let pid_val = pid();
        let types = event_types();
        loading.set(true);
        expanded_idx.set(None);
        match get_event_list(start, end, pid_val, PAGE_SIZE, p * PAGE_SIZE, &types).await {
            Ok(data) => events.set(Some(data)),
            Err(e) => {
                log::error!("Event list error: {}", e);
                events.set(None);
            }
        }
        loading.set(false);
    });

    let ev = events();

    if loading() && ev.is_none() {
        return rsx! {
            div { class: "bg-white border border-gray-200 rounded px-2 py-1.5",
                div { class: "flex items-center gap-2 text-xs text-gray-500",
                    span { class: "inline-block w-3 h-3 rounded-full border-2 border-gray-300 border-t-blue-500 animate-spin" }
                    span { "Loading events..." }
                }
            }
        };
    }

    let Some(data) = ev else {
        return rsx! {
            div { class: "bg-white border border-gray-200 rounded px-2 py-1.5",
                div { class: "text-xs text-gray-400", "No events in current scope" }
            }
        };
    };

    if data.total_in_range == 0 {
        return rsx! {
            div { class: "bg-white border border-gray-200 rounded px-2 py-1.5",
                div { class: "text-xs text-gray-400", "No events in current scope" }
            }
        };
    }

    let current_page = page();
    let total_pages = data.total_in_range.div_ceil(PAGE_SIZE);
    let expanded = expanded_idx();

    rsx! {
        div { class: "bg-white border border-gray-200 rounded px-2 py-1.5 space-y-1",
            if loading() {
                div { class: "text-[11px] text-gray-400 flex items-center gap-1",
                    span { class: "inline-block w-2.5 h-2.5 rounded-full border-2 border-gray-300 border-t-blue-500 animate-spin" }
                    span { "Updating..." }
                }
            }

            // Header with total and pagination
            div { class: "flex items-center justify-between",
                div { class: "text-[11px] text-gray-500",
                    "Events: {data.total_in_range} in range"
                }
                div { class: "flex items-center gap-1",
                    button {
                        class: "px-1.5 py-0.5 text-[11px] rounded border border-gray-200 text-gray-600 disabled:opacity-30",
                        disabled: current_page == 0,
                        onclick: move |_| page.set(current_page - 1),
                        "←"
                    }
                    span { class: "text-[11px] text-gray-500", "{current_page + 1}/{total_pages}" }
                    button {
                        class: "px-1.5 py-0.5 text-[11px] rounded border border-gray-200 text-gray-600 disabled:opacity-30",
                        disabled: current_page + 1 >= total_pages,
                        onclick: move |_| page.set(current_page + 1),
                        "→"
                    }
                }
            }

            // Event table
            div { class: "overflow-x-auto",
                table { class: "w-full text-xs",
                    thead {
                        tr { class: "text-gray-500 border-b border-gray-100",
                            th { class: "text-left py-0.5 pr-2 font-medium", "Offset" }
                            th { class: "text-left py-0.5 px-1.5 font-medium", "Type" }
                            th { class: "text-left py-0.5 pl-1.5 font-medium", "Stack" }
                        }
                    }
                    tbody {
                        for (idx, event) in data.events.iter().enumerate() {
                            {
                                let offset_ns = event.ts_ns.saturating_sub(full_start_ns());
                                let formatted_offset = format_duration_short(offset_ns);
                                let event_type = event.event_type.clone();
                                let top_frame = event.stack_trace.as_ref()
                                    .and_then(|st| st.first().cloned())
                                    .unwrap_or_else(|| "—".to_string());
                                let is_expanded = expanded == Some(idx);
                                let stack_trace = event.stack_trace.clone();

                                rsx! {
                                    tr {
                                        class: "border-b border-gray-50 text-gray-700 cursor-pointer hover:bg-gray-50",
                                        onclick: move |_| {
                                            if expanded_idx() == Some(idx) {
                                                expanded_idx.set(None);
                                            } else {
                                                expanded_idx.set(Some(idx));
                                            }
                                        },
                                        td { class: "py-0.5 pr-2 font-mono", "{formatted_offset}" }
                                        td { class: "py-0.5 px-1.5 font-mono", "{event_type}" }
                                        td { class: "py-0.5 pl-1.5 font-mono truncate max-w-xs", "{top_frame}" }
                                    }
                                    if is_expanded {
                                        tr {
                                            td { colspan: "3",
                                                if let Some(ref st) = stack_trace {
                                                    if st.is_empty() {
                                                        div { class: "text-[11px] text-gray-400 px-2 py-1", "No stack trace available" }
                                                    } else {
                                                        div { class: "bg-gray-50 border-l-2 border-blue-300 px-2 py-1",
                                                            for (i, frame) in st.iter().enumerate() {
                                                                div { class: "text-[11px] font-mono text-gray-600 truncate", "{i}: {frame}" }
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    div { class: "text-[11px] text-gray-400 px-2 py-1", "No stack trace available" }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
