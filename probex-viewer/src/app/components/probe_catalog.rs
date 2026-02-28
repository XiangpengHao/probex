use dioxus::prelude::*;
use gloo_timers::future::TimeoutFuture;
use std::collections::{HashMap, HashSet};

use crate::api::{
    CustomProbeFieldRef, CustomProbeFilter, CustomProbeFilterOp, CustomProbeSpec, ProbeSchema,
    ProbeSchemaKind, get_probe_schema_detail, get_probe_schemas_page,
};

const PAGE_SIZE: usize = 400;
const DEFAULT_KIND_FILTERS: &[&str] = &["tracepoint", "fentry", "fexit"];

#[derive(Clone, Default)]
struct MockFilterRule {
    field_key: String,
    operator: String,
    value: String,
}

#[derive(Clone, Default)]
struct MockProbeConfig {
    record_fields: Vec<String>,
    record_stack_trace: bool,
    filters: Vec<MockFilterRule>,
}

#[component]
pub fn ProbeCatalog(custom_probes: Signal<Vec<CustomProbeSpec>>) -> Element {
    let mut search_query = use_signal(String::new);
    let mut selected_kinds = use_signal(|| {
        DEFAULT_KIND_FILTERS
            .iter()
            .map(|v| (*v).to_string())
            .collect::<HashSet<String>>()
    });

    let mut selected_probes = use_signal(Vec::<String>::new);
    let mut selected_probe_schemas = use_signal(HashMap::<String, ProbeSchema>::new);
    let mut active_editor_probe = use_signal(|| Option::<String>::None);
    let mut probe_configs = use_signal(HashMap::<String, MockProbeConfig>::new);
    let mut expanded_probes = use_signal(HashSet::<String>::new);
    let mut detail_loading = use_signal(HashSet::<String>::new);

    let mut probes = use_signal(Vec::<ProbeSchema>::new);
    let mut probes_total = use_signal(|| 0usize);
    let mut probes_loading = use_signal(|| false);
    let mut backend_loading = use_signal(|| false);
    let mut has_more_pages = use_signal(|| false);
    let mut page_offset = use_signal(|| 0usize);
    let mut page_request_in_flight = use_signal(|| false);
    let mut backend_refresh_scheduled = use_signal(|| false);
    let mut scroll_load_armed = use_signal(|| true);
    let mut last_scroll_top = use_signal(|| 0.0f64);
    let mut probe_error = use_signal(|| Option::<String>::None);
    let mut refresh_nonce = use_signal(|| 0u64);
    let mut catalog_initialized = use_signal(|| false);

    use_resource(move || async move {
        if !catalog_initialized() {
            return;
        }
        let _refresh = refresh_nonce();
        page_request_in_flight.set(true);
        probes_loading.set(true);
        probe_error.set(None);
        let offset = page_offset();
        if offset == 0 {
            probes.set(Vec::new());
            probes_total.set(0);
            has_more_pages.set(false);
            backend_loading.set(false);
            scroll_load_armed.set(true);
            last_scroll_top.set(0.0);
        }

        let query = if search_query().trim().is_empty() {
            None
        } else {
            Some(search_query().trim().to_string())
        };
        let mut values = selected_kinds().into_iter().collect::<Vec<_>>();
        values.sort_unstable();
        if values.is_empty() {
            probes.set(Vec::new());
            probes_total.set(0);
            has_more_pages.set(false);
            backend_loading.set(false);
            scroll_load_armed.set(true);
            last_scroll_top.set(0.0);
            probes_loading.set(false);
            page_request_in_flight.set(false);
            return;
        }
        let kinds = Some(values.join(","));
        let source = None;

        let page = get_probe_schemas_page(query, None, kinds, source, offset, PAGE_SIZE).await;

        let page = match page {
            Ok(page) => page,
            Err(error) => {
                probe_error.set(Some(error));
                probes_loading.set(false);
                page_request_in_flight.set(false);
                return;
            }
        };

        backend_loading.set(page.is_loading);
        probes_total.set(page.total);
        has_more_pages.set(page.has_more);

        if offset == 0 {
            probes.set(page.probes);
        } else if !page.probes.is_empty() {
            let mut merged = probes.peek().clone();
            merged.extend(page.probes);
            probes.set(merged);
        }

        probes_loading.set(false);
        page_request_in_flight.set(false);
    });

    use_effect(move || {
        if !catalog_initialized() || !backend_loading() || backend_refresh_scheduled() {
            return;
        }
        backend_refresh_scheduled.set(true);
        spawn(async move {
            TimeoutFuture::new(900).await;
            backend_refresh_scheduled.set(false);
            if catalog_initialized()
                && backend_loading()
                && !probes_loading()
                && !page_request_in_flight()
            {
                refresh_nonce.set(refresh_nonce().wrapping_add(1));
            }
        });
    });

    let selected_probe_set: HashSet<String> = selected_probes().iter().cloned().collect();
    let probes_snapshot = probes();
    let selected_probes_snapshot = selected_probes();

    use_effect(move || {
        let selected = selected_probes();
        let schemas = selected_probe_schemas();
        let configs = probe_configs();
        custom_probes.set(build_custom_probe_specs(&selected, &schemas, &configs));
    });

    rsx! {
        details { class: "rounded border border-gray-200 bg-gray-50 px-2 py-1",
            ontoggle: move |_| {
                if !catalog_initialized() {
                    catalog_initialized.set(true);
                }
            },
            summary {
                class: "cursor-pointer text-xs text-gray-700 select-none",
                onclick: move |_| {
                    if !catalog_initialized() {
                        catalog_initialized.set(true);
                    }
                },
                "Custom Probes"
            }

            div { class: "mt-1 grid grid-cols-1 lg:grid-cols-5 gap-2",
                div { class: "lg:col-span-2 xl:col-span-2 rounded border border-gray-200 bg-white p-2 space-y-2",
                    div { class: "flex items-center justify-between gap-2 flex-wrap",
                        span { class: "text-xs font-medium text-gray-700", "All Probes" }
                        div { class: "flex items-center gap-2",
                            span { class: "text-[11px] text-gray-500", "{probes_snapshot.len()} loaded / {probes_total()} matched" }
                            if probes_loading() || backend_loading() {
                                span { class: "inline-block h-3 w-3 rounded-full border-2 border-blue-300 border-t-blue-600 animate-spin" }
                            }
                        }
                    }

                    div { class: "grid grid-cols-1 gap-2",
                        input {
                            class: "px-2 py-1 border border-gray-200 rounded text-xs bg-white",
                            r#type: "text",
                            value: "{search_query}",
                            placeholder: "Search (backend)",
                            oninput: move |evt| {
                                search_query.set(evt.value());
                                page_offset.set(0);
                            },
                        }
                    }

                    div { class: "flex items-center gap-1.5 flex-wrap",
                        FilterChip {
                            label: "tracepoint",
                            active: selected_kinds().contains("tracepoint"),
                            active_class: kind_filter_active_class("tracepoint"),
                            onclick: EventHandler::new(move |_| {
                                toggle_kind_filter(&mut selected_kinds, "tracepoint");
                                page_offset.set(0);
                            }),
                        }
                        FilterChip {
                            label: "fentry",
                            active: selected_kinds().contains("fentry"),
                            active_class: kind_filter_active_class("fentry"),
                            onclick: EventHandler::new(move |_| {
                                toggle_kind_filter(&mut selected_kinds, "fentry");
                                page_offset.set(0);
                            }),
                        }
                        FilterChip {
                            label: "fexit",
                            active: selected_kinds().contains("fexit"),
                            active_class: kind_filter_active_class("fexit"),
                            onclick: EventHandler::new(move |_| {
                                toggle_kind_filter(&mut selected_kinds, "fexit");
                                page_offset.set(0);
                            }),
                        }
                    }

                    if let Some(err) = probe_error() {
                        div { class: "rounded border border-red-200 bg-red-50 px-2 py-1 text-[11px] text-red-700",
                            "Failed to load probes: {err}"
                        }
                    }

                    if backend_loading() && !probes_loading() {
                        div { class: "flex items-center justify-between rounded border border-blue-200 bg-blue-50 px-2 py-1 text-[11px] text-blue-700",
                            span { "Backend is still indexing probes. Results are progressively loading." }
                            button {
                                class: "px-2 py-0.5 rounded border border-blue-200 bg-white text-blue-700",
                                onclick: move |_| refresh_nonce.set(refresh_nonce().wrapping_add(1)),
                                "Refresh"
                            }
                        }
                    }

                    div {
                        class: "max-h-[70vh] overflow-y-auto space-y-1 pr-1",
                        onscroll: move |evt: Event<dioxus::html::ScrollData>| {
                            if !has_more_pages() || probes_loading() || page_request_in_flight() {
                                return;
                            }
                            let data = evt.data();
                            let scroll_top = data.scroll_top();
                            if scroll_top + 4.0 < last_scroll_top() && !scroll_load_armed() {
                                // Rearm only on explicit upward scroll movement.
                                scroll_load_armed.set(true);
                            }
                            last_scroll_top.set(scroll_top);

                            let remaining_px = data.scroll_height() as f64
                                - (scroll_top + data.client_height() as f64);
                            if remaining_px <= 180.0 {
                                if !scroll_load_armed() {
                                    return;
                                }
                                let next_offset = probes().len();
                                if next_offset > page_offset() {
                                    page_request_in_flight.set(true);
                                    page_offset.set(next_offset);
                                    scroll_load_armed.set(false);
                                }
                            }
                        },
                        if probes_snapshot.is_empty() && !probes_loading() {
                            div { class: "text-[11px] text-gray-500 px-1 py-2", "No probes match current backend filters." }
                        }
                        {probes_snapshot.iter().map(|probe| {
                            let is_selected = selected_probe_set.contains(&probe.display_name);
                            let is_expanded = expanded_probes().contains(&probe.display_name);
                            let detail_is_loading = detail_loading().contains(&probe.display_name);
                            rsx! {
                                div { key: "{probe.display_name}", class: "rounded border border-gray-200 bg-gray-50 p-1.5",
                                    div { class: "flex items-center justify-between gap-2",
                                        div { class: "min-w-0",
                                            div { class: "font-mono text-[11px] text-gray-800 truncate", "{probe.display_name}" }
                                            div { class: "text-[10px] text-gray-500 flex items-center gap-1.5",
                                                span { class: kind_badge_class(&probe.kind), "{kind_label(&probe.kind)}" }
                                                span { "{probe.target}" }
                                                if !probe.fields.is_empty() {
                                                    span { "{probe.fields.len()} fields" }
                                                } else if !probe.args.is_empty() {
                                                    span { "{probe.args.len()} args" }
                                                }
                                            }
                                        }
                                        div { class: "flex items-center gap-1",
                                            button {
                                                class: "px-1.5 py-0.5 text-[11px] rounded border border-gray-200 bg-white text-gray-600",
                                                onclick: {
                                                    let id = probe.display_name.clone();
                                                    move |_| {
                                                        let will_expand = !expanded_probes().contains(&id);
                                                        let mut expanded = expanded_probes();
                                                        if expanded.contains(&id) {
                                                            expanded.remove(&id);
                                                        } else {
                                                            expanded.insert(id.clone());
                                                        }
                                                        expanded_probes.set(expanded);

                                                        if will_expand {
                                                            let needs_detail = probes()
                                                                .iter()
                                                                .find(|p| p.display_name == id)
                                                                .map(|p| p.fields.is_empty() && p.args.is_empty() && p.return_type.is_none())
                                                                .unwrap_or(false);
                                                            if needs_detail {
                                                                let mut loading = detail_loading();
                                                                loading.insert(id.clone());
                                                                detail_loading.set(loading);

                                                                let detail_id = id.clone();
                                                                spawn(async move {
                                                                    let result = get_probe_schema_detail(detail_id.clone()).await;
                                                                    let mut loading = detail_loading();
                                                                    loading.remove(&detail_id);
                                                                    detail_loading.set(loading);

                                                                    match result {
                                                                        Ok(detail) => {
                                                                            let mut items = probes();
                                                                            if let Some(slot) = items.iter_mut().find(|p| p.display_name == detail_id) {
                                                                                *slot = detail.clone();
                                                                            }
                                                                            probes.set(items);
                                                                            let mut schemas = selected_probe_schemas();
                                                                            if schemas.contains_key(&detail_id) {
                                                                                schemas.insert(detail_id.clone(), detail.clone());
                                                                                selected_probe_schemas.set(schemas);
                                                                            }
                                                                        }
                                                                        Err(error) => probe_error.set(Some(error)),
                                                                    }
                                                                });
                                                            }
                                                        }
                                                    }
                                                },
                                                if is_expanded { "Hide" } else { "Fields" }
                                            }
                                            button {
                                                class: if is_selected {
                                                    "px-1.5 py-0.5 text-[11px] rounded border border-green-200 bg-green-50 text-green-700"
                                                } else {
                                                    "px-1.5 py-0.5 text-[11px] rounded border border-blue-200 bg-blue-50 text-blue-700"
                                                },
                                                onclick: {
                                                    let id = probe.display_name.clone();
                                                    let probe_clone = probe.clone();
                                                    move |_| {
                                                        let mut selected = selected_probes();
                                                        if selected.iter().any(|item| item == &id) {
                                                            selected.retain(|item| item != &id);
                                                            let mut schemas = selected_probe_schemas();
                                                            schemas.remove(&id);
                                                            selected_probe_schemas.set(schemas);
                                                            let mut configs = probe_configs();
                                                            configs.remove(&id);
                                                            probe_configs.set(configs);
                                                            if active_editor_probe().as_deref() == Some(id.as_str()) {
                                                                active_editor_probe.set(None);
                                                            }
                                                        } else {
                                                            selected.push(id.clone());
                                                            let mut schemas = selected_probe_schemas();
                                                            schemas.insert(id.clone(), probe_clone.clone());
                                                            selected_probe_schemas.set(schemas);
                                                            if active_editor_probe().is_none() {
                                                                active_editor_probe.set(Some(id.clone()));
                                                            }
                                                            let needs_detail = selected_probe_schemas()
                                                                .get(&id)
                                                                .map(|p| p.kind == ProbeSchemaKind::Tracepoint && p.fields.is_empty())
                                                                .unwrap_or(true);
                                                            if needs_detail {
                                                                let detail_id = id.clone();
                                                                spawn(async move {
                                                                    match get_probe_schema_detail(detail_id.clone()).await {
                                                                        Ok(detail) => {
                                                                            let mut items = probes();
                                                                            if let Some(slot) = items.iter_mut().find(|p| p.display_name == detail_id) {
                                                                                *slot = detail.clone();
                                                                            }
                                                                            probes.set(items);
                                                                            let mut schemas = selected_probe_schemas();
                                                                            if schemas.contains_key(&detail_id) {
                                                                                schemas.insert(detail_id, detail);
                                                                                selected_probe_schemas.set(schemas);
                                                                            }
                                                                        }
                                                                        Err(error) => probe_error.set(Some(error)),
                                                                    }
                                                                });
                                                            }
                                                        }
                                                        selected_probes.set(selected);
                                                    }
                                                },
                                                if is_selected { "Added" } else { "+ Add" }
                                            }
                                        }
                                    }
                                    if is_expanded {
                                        div { class: "mt-1 border-t border-gray-200 pt-1 space-y-0.5",
                                            if detail_is_loading {
                                                div { class: "text-[10px] text-blue-600 flex items-center gap-1",
                                                    span { class: "inline-block h-2.5 w-2.5 rounded-full border-2 border-blue-300 border-t-blue-600 animate-spin" }
                                                    "Loading field details..."
                                                }
                                            } else if probe.kind == ProbeSchemaKind::Tracepoint {
                                                if probe.fields.is_empty() {
                                                    div { class: "text-[10px] text-gray-500", "No field payload for this tracepoint." }
                                                } else {
                                                    {probe.fields.iter().map(|field| rsx! {
                                                        div { key: "{probe.display_name}:{field.name}:{field.offset}", class: "font-mono text-[10px] text-gray-600",
                                                            "{field.field_type} {field.name}"
                                                            span { class: "text-gray-400", " @+{field.offset} ({field.size}B)" }
                                                        }
                                                    })}
                                                }
                                            } else if probe.return_type.is_none() && probe.args.is_empty() {
                                                div { class: "text-[10px] text-gray-500", "No BTF signature available for this probe." }
                                            } else {
                                                div { class: "font-mono text-[10px] text-gray-600",
                                                    "returns "
                                                    span { class: "text-gray-800", "{probe.return_type.clone().unwrap_or_else(|| \"unknown\".to_string())}" }
                                                }
                                                if probe.args.is_empty() {
                                                    div { class: "text-[10px] text-gray-500", "No arguments." }
                                                } else {
                                                    {probe.args.iter().enumerate().map(|(idx, arg)| rsx! {
                                                        div { key: "{probe.display_name}:{idx}:{arg.name}", class: "font-mono text-[10px] text-gray-600",
                                                            "{arg.arg_type} {arg.name}"
                                                        }
                                                    })}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        })}
                        if has_more_pages() && probes_loading() {
                            div { class: "py-1 text-[11px] text-blue-600 flex items-center gap-1",
                                span { class: "inline-block h-2.5 w-2.5 rounded-full border-2 border-blue-300 border-t-blue-600 animate-spin" }
                                "Loading more probes..."
                            }
                        }
                    }
                }

                div { class: "lg:col-span-3 xl:col-span-3 rounded border border-gray-200 bg-white p-2 space-y-2",
                    div { class: "flex items-center justify-between",
                        span { class: "text-xs font-medium text-gray-700", "Selected Probes" }
                        span { class: "text-[11px] text-gray-500", "{selected_probes_snapshot.len()}" }
                    }
                    if selected_probes_snapshot.is_empty() {
                        div { class: "text-[11px] text-gray-500", "Click + Add on any probe, then click a selected probe to edit." }
                    } else {
                        div { class: "max-h-[40vh] overflow-y-auto space-y-1 pr-1",
                            {selected_probes_snapshot.iter().map(|id| {
                                let is_active = active_editor_probe().as_deref() == Some(id.as_str());
                                let cfg = probe_configs().get(id).cloned().unwrap_or_default();
                                let options = selected_probe_schemas()
                                    .get(id)
                                    .map(mock_filter_field_options)
                                    .unwrap_or_default();
                                rsx! {
                                    div { key: "{id}", class: if is_active {
                                        "flex items-center justify-between gap-2 rounded border border-indigo-300 bg-indigo-50 px-1.5 py-1"
                                    } else {
                                        "flex items-center justify-between gap-2 rounded border border-gray-200 bg-gray-50 px-1.5 py-1"
                                    },
                                        div { class: "min-w-0 flex-1 space-y-0.5",
                                            button {
                                                class: if is_active {
                                                    "font-mono text-[10px] text-indigo-800 truncate text-left cursor-pointer"
                                                } else {
                                                    "font-mono text-[10px] text-gray-700 truncate text-left cursor-pointer"
                                                },
                                                onclick: {
                                                    let id = id.clone();
                                                    move |_| {
                                                        active_editor_probe.set(Some(id.clone()));
                                                        if let Some(found) = probes().iter().find(|p| p.display_name == id) {
                                                            let mut schemas = selected_probe_schemas();
                                                            schemas.insert(id.clone(), found.clone());
                                                            selected_probe_schemas.set(schemas);
                                                        }
                                                        let needs_detail = selected_probe_schemas()
                                                            .get(&id)
                                                            .map(|p| p.kind == ProbeSchemaKind::Tracepoint && p.fields.is_empty())
                                                            .unwrap_or(true);
                                                        if needs_detail {
                                                            let detail_id = id.clone();
                                                            spawn(async move {
                                                                match get_probe_schema_detail(detail_id.clone()).await {
                                                                    Ok(detail) => {
                                                                        let mut items = probes();
                                                                        if let Some(slot) = items.iter_mut().find(|p| p.display_name == detail_id) {
                                                                            *slot = detail.clone();
                                                                        }
                                                                        probes.set(items);
                                                                        let mut schemas = selected_probe_schemas();
                                                                        schemas.insert(detail_id, detail);
                                                                        selected_probe_schemas.set(schemas);
                                                                    }
                                                                    Err(error) => probe_error.set(Some(error)),
                                                                }
                                                            });
                                                        }
                                                    }
                                                },
                                                "{id}"
                                            }
                                            div { class: "flex items-center gap-1 flex-wrap",
                                                if cfg.record_stack_trace {
                                                    span { class: "px-1 py-0.5 rounded bg-slate-100 text-slate-700 text-[9px]", "stack" }
                                                }
                                                {cfg.record_fields.iter().map(|field_key| rsx! {
                                                    span { key: "{id}:rec:{field_key}", class: "px-1 py-0.5 rounded bg-emerald-100 text-emerald-700 text-[9px] max-w-[12rem] truncate",
                                                        "{field_key_display(&options, field_key)}"
                                                    }
                                                })}
                                                {cfg.filters.iter().enumerate().map(|(idx, rule)| rsx! {
                                                    span { key: "{id}:filt:{idx}", class: "px-1 py-0.5 rounded bg-amber-100 text-amber-700 text-[9px] max-w-[14rem] truncate",
                                                        "{format_filter_preview(&options, rule)}"
                                                    }
                                                })}
                                            }
                                        }
                                        button {
                                            class: "px-1.5 py-0.5 text-[10px] rounded border border-gray-200 bg-white text-gray-600 shrink-0 cursor-pointer",
                                            onclick: {
                                                let id = id.clone();
                                                move |_| {
                                                    let mut selected = selected_probes();
                                                    selected.retain(|item| item != &id);
                                                    selected_probes.set(selected);
                                                    let mut schemas = selected_probe_schemas();
                                                    schemas.remove(&id);
                                                    selected_probe_schemas.set(schemas);
                                                    let mut configs = probe_configs();
                                                    configs.remove(&id);
                                                    probe_configs.set(configs);
                                                    if active_editor_probe().as_deref() == Some(id.as_str()) {
                                                        active_editor_probe.set(None);
                                                    }
                                                }
                                            },
                                            "Remove"
                                        }
                                    }
                                }
                            })}
                        }
                        button {
                            class: "px-2 py-0.5 text-[11px] rounded border border-gray-200 bg-white text-gray-600 cursor-pointer",
                            onclick: move |_| {
                                selected_probes.set(Vec::new());
                                selected_probe_schemas.set(HashMap::new());
                                probe_configs.set(HashMap::new());
                                active_editor_probe.set(None);
                            },
                            "Clear all"
                        }
                    }

                    div { class: "border-t border-gray-200 pt-2 space-y-2",
                        span { class: "text-xs font-medium text-gray-700", "Probe Editor" }
                        if let Some(active_id) = active_editor_probe() {
                            if let Some(schema) = selected_probe_schemas().get(&active_id).cloned() {
                                {
                                    let options = mock_filter_field_options(&schema);
                                    let config = probe_configs().get(&active_id).cloned().unwrap_or_default();
                                    rsx! {
                                        div { class: "text-[11px] text-gray-600",
                                            span { class: "font-mono text-gray-700", "{active_id}" }
                                        }

                                        div { class: "space-y-1",
                                            div { class: "flex items-center justify-between",
                                                span { class: "text-[11px] font-medium text-gray-700", "What To Record" }
                                                span { class: "text-[10px] text-gray-500", "{config.record_fields.len()}" }
                                            }
                                            label { class: "flex items-center gap-2 text-[11px] text-gray-700 cursor-pointer",
                                                input {
                                                    r#type: "checkbox",
                                                    checked: config.record_stack_trace,
                                                    oninput: {
                                                        let active_id = active_id.clone();
                                                        move |evt| {
                                                            let mut all = probe_configs();
                                                            let cfg = all.entry(active_id.clone()).or_default();
                                                            cfg.record_stack_trace = evt.checked();
                                                            probe_configs.set(all);
                                                        }
                                                    },
                                                }
                                                span { "Stack trace" }
                                            }
                                            if options.is_empty() {
                                                div { class: "text-[11px] text-gray-500", "No fields available for this probe." }
                                            } else {
                                                div { class: "space-y-1",
                                                    {options.iter().map(|opt| {
                                                        let disabled_reason =
                                                            unsupported_option_reason(&schema, &options, &opt.key);
                                                        let disabled = disabled_reason.is_some();
                                                        let is_ret_forbidden = is_fentry_ret_option(&schema, &opt.key);
                                                        let disabled_reason_text = disabled_reason
                                                            .clone()
                                                            .unwrap_or_else(|| "unsupported field".to_string());
                                                        let checked = !disabled
                                                            && config.record_fields.iter().any(|key| key == &opt.key);
                                                        rsx! {
                                                            label {
                                                                key: "{active_id}:record:{opt.key}",
                                                                class: if disabled {
                                                                    if is_ret_forbidden {
                                                                        "flex items-center justify-between gap-2 rounded border border-gray-200 bg-gray-50 px-2 py-1 text-[10px] text-gray-400 cursor-not-allowed line-through"
                                                                    } else {
                                                                        "flex items-center justify-between gap-2 rounded border border-amber-300 bg-amber-50 px-2 py-1 text-[10px] text-amber-800 cursor-not-allowed"
                                                                    }
                                                                } else {
                                                                    "flex items-center justify-between gap-2 rounded border border-gray-200 bg-gray-50 px-2 py-1 text-[10px] text-gray-700 cursor-pointer"
                                                                },
                                                                input {
                                                                    r#type: "checkbox",
                                                                    checked,
                                                                    disabled,
                                                                    onclick: {
                                                                        let active_id = active_id.clone();
                                                                        let key = opt.key.clone();
                                                                        let disabled = disabled;
                                                                        move |_| {
                                                                            if disabled {
                                                                                return;
                                                                            }
                                                                            let mut all = probe_configs();
                                                                            let cfg = all.entry(active_id.clone()).or_default();
                                                                            if cfg.record_fields.iter().any(|item| item == &key) {
                                                                                cfg.record_fields.retain(|item| item != &key);
                                                                            } else {
                                                                                cfg.record_fields.push(key.clone());
                                                                            }
                                                                            probe_configs.set(all);
                                                                        }
                                                                    },
                                                                }
                                                                div { class: "min-w-0 flex items-center gap-1",
                                                                    span { class: "font-mono truncate", "{opt.label} [{opt.field_type}]" }
                                                                    if disabled {
                                                                        span {
                                                                            class: "inline-flex items-center rounded-full bg-amber-200 text-amber-900 px-1 py-0.5 text-[9px] font-semibold",
                                                                            title: "{disabled_reason_text}",
                                                                            "!"
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    })}
                                                }
                                            }
                                        }

                                        div { class: "space-y-1",
                                            div { class: "flex items-center justify-between",
                                                span { class: "text-[11px] font-medium text-gray-700", "Filters" }
                                                span { class: "text-[10px] text-gray-500", "{config.filters.len()}" }
                                            }
                                            if config.filters.is_empty() {
                                                div { class: "text-[11px] text-gray-500", "No filters configured." }
                                            } else {
                                                div { class: "space-y-1",
                                                    {config.filters.iter().enumerate().map(|(idx, rule)| {
                                                        let selected_ty = options
                                                            .iter()
                                                            .find(|opt| opt.key == rule.field_key && opt.is_supported)
                                                            .map(|opt| opt.field_type.clone())
                                                            .unwrap_or_else(|| "u64".to_string());
                                                        let kind = infer_filter_kind(&selected_ty);
                                                        let operators = filter_operators(kind);
                                                        let active_op = if operators.iter().any(|op| *op == rule.operator.as_str()) {
                                                            rule.operator.clone()
                                                        } else {
                                                            operators[0].to_string()
                                                        };
                                                        let needs_value = operator_needs_value(&active_op);
                                                        rsx! {
                                                            div { key: "{active_id}:filter:{idx}", class: "rounded border border-gray-200 bg-gray-50 p-1 space-y-1",
                                                                div { class: "grid grid-cols-1 gap-1",
                                                                    select {
                                                                        class: "px-2 py-1 border border-gray-200 rounded text-xs bg-white",
                                                                        value: "{rule.field_key}",
                                                                        oninput: {
                                                                            let active_id = active_id.clone();
                                                                            let options = options.clone();
                                                                            move |evt| {
                                                                                let next_key = evt.value();
                                                                                let mut all = probe_configs();
                                                                                if let Some(cfg) = all.get_mut(&active_id)
                                                                                    && let Some(filter) = cfg.filters.get_mut(idx)
                                                                                {
                                                                                    filter.field_key = next_key.clone();
                                                                                    let next_kind = options
                                                                                        .iter()
                                                                                        .find(|opt| opt.key == next_key && opt.is_supported)
                                                                                        .map(|opt| infer_filter_kind(&opt.field_type))
                                                                                        .unwrap_or(MockFilterKind::Integer);
                                                                                    filter.operator = filter_operators(next_kind)[0].to_string();
                                                                                }
                                                                                probe_configs.set(all);
                                                                            }
                                                                        },
                                                                        {options.iter().map(|opt| rsx! {
                                                                            option {
                                                                                key: "{active_id}:filter-opt:{idx}:{opt.key}",
                                                                                value: "{opt.key}",
                                                                                disabled: !opt.is_supported,
                                                                                "{opt.label} [{opt.field_type}]"
                                                                            }
                                                                        })}
                                                                    }
                                                                    div { class: "flex items-center gap-1",
                                                                        select {
                                                                            class: "flex-1 px-2 py-1 border border-gray-200 rounded text-xs bg-white",
                                                                            value: "{active_op}",
                                                                            oninput: {
                                                                                let active_id = active_id.clone();
                                                                                move |evt| {
                                                                                    let mut all = probe_configs();
                                                                                    if let Some(cfg) = all.get_mut(&active_id)
                                                                                        && let Some(filter) = cfg.filters.get_mut(idx)
                                                                                    {
                                                                                        filter.operator = evt.value();
                                                                                    }
                                                                                    probe_configs.set(all);
                                                                                }
                                                                            },
                                                                            {operators.iter().map(|op| rsx! {
                                                                                option { key: "{active_id}:filter-op:{idx}:{op}", value: "{op}", "{op}" }
                                                                            })}
                                                                        }
                                                                        button {
                                                                            class: "px-1.5 py-1 text-[10px] rounded border border-gray-200 bg-white text-gray-600 cursor-pointer",
                                                                            onclick: {
                                                                                let active_id = active_id.clone();
                                                                                move |_| {
                                                                                    let mut all = probe_configs();
                                                                                    if let Some(cfg) = all.get_mut(&active_id)
                                                                                        && idx < cfg.filters.len()
                                                                                    {
                                                                                        cfg.filters.remove(idx);
                                                                                    }
                                                                                    probe_configs.set(all);
                                                                                }
                                                                            },
                                                                            "Remove"
                                                                        }
                                                                    }
                                                                    if needs_value {
                                                                        input {
                                                                            class: "px-2 py-1 border border-gray-200 rounded text-xs bg-white",
                                                                            r#type: "text",
                                                                            value: "{rule.value}",
                                                                            placeholder: filter_value_placeholder(kind),
                                                                            oninput: {
                                                                                let active_id = active_id.clone();
                                                                                move |evt| {
                                                                                    let mut all = probe_configs();
                                                                                    if let Some(cfg) = all.get_mut(&active_id)
                                                                                        && let Some(filter) = cfg.filters.get_mut(idx)
                                                                                    {
                                                                                        filter.value = evt.value();
                                                                                    }
                                                                                    probe_configs.set(all);
                                                                                }
                                                                            },
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    })}
                                                }
                                            }
                                            button {
                                                class: "px-2 py-1 text-[11px] rounded border border-gray-200 bg-white text-gray-700 cursor-pointer",
                                                disabled: !options.iter().any(|opt| opt.is_supported),
                                                onclick: {
                                                    let active_id = active_id.clone();
                                                    let options = options.clone();
                                                    move |_| {
                                                        let Some(first) = options.iter().find(|opt| opt.is_supported).cloned() else {
                                                            return;
                                                        };
                                                        let kind = infer_filter_kind(&first.field_type);
                                                        let mut all = probe_configs();
                                                        let cfg = all.entry(active_id.clone()).or_default();
                                                        cfg.filters.push(MockFilterRule {
                                                            field_key: first.key,
                                                            operator: filter_operators(kind)[0].to_string(),
                                                            value: String::new(),
                                                        });
                                                        probe_configs.set(all);
                                                    }
                                                },
                                                "Add Filter"
                                            }
                                        }
                                    }
                                }
                            } else {
                                div { class: "text-[11px] text-gray-500", "Selected probe schema is not loaded. Click the probe row again to load details." }
                            }
                        } else {
                            div { class: "text-[11px] text-gray-500", "Click a selected probe to edit its recording fields and filters." }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn FilterChip(
    label: &'static str,
    active: bool,
    active_class: &'static str,
    onclick: EventHandler<MouseEvent>,
) -> Element {
    rsx! {
        button {
            class: if active {
                format!("px-2 py-0.5 text-[11px] rounded border {active_class}")
            } else {
                "px-2 py-0.5 text-[11px] rounded border border-gray-200 bg-white text-gray-600"
            },
            onclick,
            "{label}"
        }
    }
}

fn toggle_kind_filter(signal: &mut Signal<HashSet<String>>, kind: &str) {
    let mut current = signal();
    if current.contains(kind) {
        current.remove(kind);
    } else {
        current.insert(kind.to_string());
    }
    signal.set(current);
}

fn kind_filter_active_class(kind: &str) -> &'static str {
    match kind {
        "tracepoint" => "border-slate-200 bg-slate-100 text-slate-700",
        "fentry" => "border-sky-200 bg-sky-100 text-sky-700",
        "fexit" => "border-cyan-200 bg-cyan-100 text-cyan-700",
        _ => "border-blue-200 bg-blue-50 text-blue-700",
    }
}

fn kind_label(kind: &ProbeSchemaKind) -> &'static str {
    match kind {
        ProbeSchemaKind::Tracepoint => "tracepoint",
        ProbeSchemaKind::Fentry => "fentry",
        ProbeSchemaKind::Fexit => "fexit",
    }
}

fn kind_badge_class(kind: &ProbeSchemaKind) -> &'static str {
    match kind {
        ProbeSchemaKind::Tracepoint => {
            "inline-flex items-center px-1.5 py-0.5 rounded bg-slate-100 text-slate-700"
        }
        ProbeSchemaKind::Fentry => {
            "inline-flex items-center px-1.5 py-0.5 rounded bg-sky-100 text-sky-700"
        }
        ProbeSchemaKind::Fexit => {
            "inline-flex items-center px-1.5 py-0.5 rounded bg-cyan-100 text-cyan-700"
        }
    }
}

#[derive(Clone)]
struct MockFieldOption {
    key: String,
    label: String,
    field_type: String,
    is_supported: bool,
    unsupported_reason: Option<String>,
}

#[derive(Clone, Copy)]
enum MockFilterKind {
    Integer,
    Boolean,
    StringLike,
    Address,
}

fn mock_filter_field_options(probe: &ProbeSchema) -> Vec<MockFieldOption> {
    let mut options = Vec::new();
    for field in &probe.fields {
        options.push(MockFieldOption {
            key: format!("field:{}", field.name),
            label: format!("field {}", field.name),
            field_type: field.field_type.clone(),
            is_supported: field.is_supported,
            unsupported_reason: field.unsupported_reason.clone(),
        });
    }
    for arg in &probe.args {
        options.push(MockFieldOption {
            key: format!("arg:{}", arg.name),
            label: format!("arg {}", arg.name),
            field_type: arg.arg_type.clone(),
            is_supported: arg.is_supported,
            unsupported_reason: arg.unsupported_reason.clone(),
        });
    }
    if let Some(ret) = &probe.return_type {
        let unsupported_reason = probe.return_unsupported_reason.clone();
        options.push(MockFieldOption {
            key: "ret".to_string(),
            label: "ret".to_string(),
            field_type: ret.clone(),
            is_supported: probe.return_supported,
            unsupported_reason,
        });
    }
    options
}

fn is_fentry_ret_option(schema: &ProbeSchema, key: &str) -> bool {
    schema.kind == ProbeSchemaKind::Fentry && key == "ret"
}

fn unsupported_option_reason(
    schema: &ProbeSchema,
    options: &[MockFieldOption],
    key: &str,
) -> Option<String> {
    if is_fentry_ret_option(schema, key) {
        return Some("fentry probes cannot use return value".to_string());
    }
    options.iter().find(|opt| opt.key == key).and_then(|opt| {
        (!opt.is_supported).then(|| {
            opt.unsupported_reason
                .clone()
                .unwrap_or_else(|| "unsupported field type".to_string())
        })
    })
}

fn infer_filter_kind(ty: &str) -> MockFilterKind {
    let lowered = ty.to_ascii_lowercase();
    if lowered.contains("bool") {
        return MockFilterKind::Boolean;
    }
    if lowered.contains("char") && lowered.contains('*') {
        return MockFilterKind::StringLike;
    }
    if lowered.contains("string") {
        return MockFilterKind::StringLike;
    }
    if lowered.contains('*')
        || lowered.contains("ptr")
        || lowered.contains("addr")
        || lowered.contains("void *")
    {
        return MockFilterKind::Address;
    }
    MockFilterKind::Integer
}

fn filter_operators(kind: MockFilterKind) -> &'static [&'static str] {
    match kind {
        MockFilterKind::Integer => &["==", "!=", ">", ">=", "<", "<="],
        MockFilterKind::Boolean => &["==", "!="],
        MockFilterKind::StringLike => &["==", "!=", "contains", "starts_with", "ends_with"],
        MockFilterKind::Address => &["==", "!=", "is_null", "is_not_null"],
    }
}

fn operator_needs_value(operator: &str) -> bool {
    !matches!(operator, "is_null" | "is_not_null")
}

fn filter_value_placeholder(kind: MockFilterKind) -> &'static str {
    match kind {
        MockFilterKind::Integer => "e.g. 42",
        MockFilterKind::Boolean => "true or false",
        MockFilterKind::StringLike => "text",
        MockFilterKind::Address => "e.g. 0x0",
    }
}

fn field_key_display(options: &[MockFieldOption], key: &str) -> String {
    options
        .iter()
        .find(|opt| opt.key == key)
        .map(|opt| opt.label.clone())
        .unwrap_or_else(|| key.to_string())
}

fn format_filter_preview(options: &[MockFieldOption], rule: &MockFilterRule) -> String {
    let field = field_key_display(options, &rule.field_key);
    if operator_needs_value(&rule.operator) {
        if rule.value.is_empty() {
            format!("{field} {} ?", rule.operator)
        } else {
            format!("{field} {} {}", rule.operator, rule.value)
        }
    } else {
        format!("{field} {}", rule.operator)
    }
}

fn build_custom_probe_specs(
    selected: &[String],
    schemas: &HashMap<String, ProbeSchema>,
    configs: &HashMap<String, MockProbeConfig>,
) -> Vec<CustomProbeSpec> {
    let mut specs = Vec::with_capacity(selected.len());
    for probe_display_name in selected {
        let Some(schema) = schemas.get(probe_display_name) else {
            continue;
        };
        let cfg = configs.get(probe_display_name).cloned().unwrap_or_default();
        let options = mock_filter_field_options(schema);

        let mut record_fields = Vec::new();
        for key in &cfg.record_fields {
            if unsupported_option_reason(schema, &options, key).is_some() {
                continue;
            }
            if let Some(field_ref) = parse_field_ref(key) {
                record_fields.push(field_ref);
            }
        }

        let mut filters = Vec::new();
        for rule in &cfg.filters {
            if unsupported_option_reason(schema, &options, &rule.field_key).is_some() {
                continue;
            }
            let Some(field) = parse_field_ref(&rule.field_key) else {
                continue;
            };
            let Some(op) = parse_filter_op(&rule.operator) else {
                continue;
            };
            let value = if operator_needs_value(&rule.operator) {
                Some(rule.value.clone())
            } else {
                None
            };
            filters.push(CustomProbeFilter { field, op, value });
        }

        specs.push(CustomProbeSpec {
            probe_display_name: probe_display_name.clone(),
            record_fields,
            record_stack_trace: cfg.record_stack_trace,
            filters,
        });
    }
    specs
}

fn parse_field_ref(key: &str) -> Option<CustomProbeFieldRef> {
    if let Some(name) = key.strip_prefix("field:") {
        return Some(CustomProbeFieldRef::Field {
            name: name.to_string(),
        });
    }
    if let Some(name) = key.strip_prefix("arg:") {
        return Some(CustomProbeFieldRef::Arg {
            name: name.to_string(),
        });
    }
    if key == "ret" {
        return Some(CustomProbeFieldRef::Return);
    }
    None
}

fn parse_filter_op(value: &str) -> Option<CustomProbeFilterOp> {
    match value {
        "==" => Some(CustomProbeFilterOp::Eq),
        "!=" => Some(CustomProbeFilterOp::Ne),
        ">" => Some(CustomProbeFilterOp::Gt),
        ">=" => Some(CustomProbeFilterOp::Ge),
        "<" => Some(CustomProbeFilterOp::Lt),
        "<=" => Some(CustomProbeFilterOp::Le),
        "contains" => Some(CustomProbeFilterOp::Contains),
        "starts_with" => Some(CustomProbeFilterOp::StartsWith),
        "ends_with" => Some(CustomProbeFilterOp::EndsWith),
        "is_null" => Some(CustomProbeFilterOp::IsNull),
        "is_not_null" => Some(CustomProbeFilterOp::IsNotNull),
        _ => None,
    }
}
