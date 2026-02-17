use std::collections::HashSet;

use dioxus::prelude::*;
use dioxus::web::WebEventExt;

use crate::api::HistogramResponse;

// ─── Types ───────────────────────────────────────────────────────────────────

/// What part of the timeline window is being dragged.
#[derive(Clone, Copy, PartialEq)]
enum DragKind {
    LeftEdge,
    RightEdge,
    Pan,
}

/// State captured at the start of a drag gesture.
#[derive(Clone, Copy)]
struct DragState {
    kind: DragKind,
    /// Mouse X in client coordinates at drag start.
    start_client_x: f64,
    /// Container width in pixels (estimated at drag start).
    container_width: f64,
    /// View start offset (ns from full_start) at drag start.
    initial_start_offset: u64,
    /// View end offset (ns from full_start) at drag start.
    initial_end_offset: u64,
}

#[derive(Clone, PartialEq)]
pub(super) struct TimelineOverviewData {
    pub histogram: Option<HistogramResponse>,
    pub enabled_types: HashSet<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct TimelineOverviewRange {
    pub full_start_ns: u64,
    pub full_end_ns: u64,
    pub view_start_ns: u64,
    pub view_end_ns: u64,
}

// ─── Geometry helpers (pure functions, no signals) ───────────────────────────

/// Minimum selected window as a fraction of full range (0.5%).
const MIN_WINDOW_FRAC: f64 = 0.005;
/// Visual handle width in pixels.
const HANDLE_WIDTH_PX: f64 = 10.0;
/// Hit-test padding outside the visual handle edge (px).
const HANDLE_HIT_PAD_PX: f64 = 10.0;
/// Minimum visual width for the selected window in percent (auto-zoom threshold).
/// If the selection is smaller than this, the visual representation is expanded
/// symmetrically so handles remain visible and draggable.
const MIN_VISUAL_WIDTH_PCT: f64 = 4.0;
/// Wheel zoom factor per 100px of scroll delta.
const WHEEL_ZOOM_SPEED: f64 = 0.15;

/// Convert a nanosecond offset (from full_start) to a percentage of the container.
fn ns_to_pct(offset_ns: u64, full_range: f64) -> f64 {
    if full_range <= 0.0 {
        0.0
    } else {
        (offset_ns as f64 / full_range * 100.0).clamp(0.0, 100.0)
    }
}

/// Convert an element-relative X coordinate to a nanosecond offset from full_start.
fn px_to_offset_ns(element_x: f64, container_width: f64, full_range_ns: u64) -> u64 {
    if container_width <= 0.0 {
        return 0;
    }
    let frac = (element_x / container_width).clamp(0.0, 1.0);
    (frac * full_range_ns as f64).round() as u64
}

/// Classify where a click lands relative to the current selection window.
fn classify_hit(
    element_x: f64,
    container_width: f64,
    left_pct: f64,
    width_pct: f64,
) -> Option<DragKind> {
    if container_width <= 0.0 {
        return None;
    }
    let left_px = left_pct / 100.0 * container_width;
    let right_px = (left_pct + width_pct) / 100.0 * container_width;

    // Expanded hit areas for handles
    let in_left =
        element_x >= left_px - HANDLE_HIT_PAD_PX && element_x <= left_px + HANDLE_WIDTH_PX;
    let in_right =
        element_x >= right_px - HANDLE_WIDTH_PX && element_x <= right_px + HANDLE_HIT_PAD_PX;

    if in_left {
        Some(DragKind::LeftEdge)
    } else if in_right {
        Some(DragKind::RightEdge)
    } else if element_x > left_px + HANDLE_WIDTH_PX && element_x < right_px - HANDLE_WIDTH_PX {
        Some(DragKind::Pan)
    } else if element_x < left_px {
        Some(DragKind::LeftEdge)
    } else {
        Some(DragKind::RightEdge)
    }
}

/// Compute new (start_ns, end_ns) from a drag delta.
fn compute_drag_range(
    d: DragState,
    current_client_x: f64,
    full_start_ns: u64,
    full_range_ns: u64,
    min_window_ns: u64,
) -> (u64, u64) {
    let cw = d.container_width;
    if cw <= 0.0 {
        return (
            full_start_ns + d.initial_start_offset,
            full_start_ns + d.initial_end_offset,
        );
    }
    let dx_frac = (current_client_x - d.start_client_x) / cw;
    let dx_ns = (dx_frac * full_range_ns as f64).round() as i64;

    match d.kind {
        DragKind::Pan => {
            let window_ns = d.initial_end_offset.saturating_sub(d.initial_start_offset);
            let max_start = full_range_ns.saturating_sub(window_ns);
            let new_start =
                (d.initial_start_offset as i64 + dx_ns).clamp(0, max_start as i64) as u64;
            (
                full_start_ns + new_start,
                full_start_ns + new_start + window_ns,
            )
        }
        DragKind::LeftEdge => {
            let max_start = d.initial_end_offset.saturating_sub(min_window_ns);
            let new_start =
                (d.initial_start_offset as i64 + dx_ns).clamp(0, max_start as i64) as u64;
            (
                full_start_ns + new_start,
                full_start_ns + d.initial_end_offset,
            )
        }
        DragKind::RightEdge => {
            let min_end = d.initial_start_offset + min_window_ns;
            let new_end = (d.initial_end_offset as i64 + dx_ns)
                .clamp(min_end as i64, full_range_ns as i64) as u64;
            (
                full_start_ns + d.initial_start_offset,
                full_start_ns + new_end,
            )
        }
    }
}

/// Snap the edge to the click position when clicking in a dimmed region.
fn snap_edge_to_click(
    kind: DragKind,
    click_offset_ns: u64,
    view_start_offset: u64,
    view_end_offset: u64,
    min_window_ns: u64,
    full_range_ns: u64,
) -> (u64, u64) {
    match kind {
        DragKind::LeftEdge => {
            let new_start = click_offset_ns.min(view_end_offset.saturating_sub(min_window_ns));
            (new_start, view_end_offset)
        }
        DragKind::RightEdge => {
            let new_end = click_offset_ns
                .max(view_start_offset + min_window_ns)
                .min(full_range_ns);
            (view_start_offset, new_end)
        }
        DragKind::Pan => (view_start_offset, view_end_offset),
    }
}

/// Compute a zoomed range centered on a given nanosecond offset.
fn zoom_at_point(
    center_offset_ns: u64,
    current_start_offset: u64,
    current_end_offset: u64,
    full_range_ns: u64,
    min_window_ns: u64,
    zoom_factor: f64, // < 1.0 = zoom in, > 1.0 = zoom out
) -> (u64, u64) {
    let current_window = current_end_offset.saturating_sub(current_start_offset);
    let new_window =
        ((current_window as f64 * zoom_factor).round() as u64).clamp(min_window_ns, full_range_ns);

    // Keep the cursor position stable: the cursor's fractional position within
    // the window should remain constant after zoom.
    let cursor_frac = if current_window > 0 {
        (center_offset_ns.saturating_sub(current_start_offset)) as f64 / current_window as f64
    } else {
        0.5
    };
    let new_start_raw =
        (center_offset_ns as i64 - (cursor_frac * new_window as f64).round() as i64).max(0) as u64;
    let max_start = full_range_ns.saturating_sub(new_window);
    let new_start = new_start_raw.min(max_start);
    (new_start, new_start + new_window)
}

// ─── TimelineOverview component ──────────────────────────────────────────────

#[component]
pub(super) fn TimelineOverview(
    data: TimelineOverviewData,
    range: TimelineOverviewRange,
    on_change_range: EventHandler<(u64, u64)>,
    on_hover_time: EventHandler<Option<u64>>,
) -> Element {
    let TimelineOverviewData {
        histogram,
        enabled_types,
    } = data;
    let TimelineOverviewRange {
        full_start_ns,
        full_end_ns,
        view_start_ns,
        view_end_ns,
    } = range;

    let full_range_ns = full_end_ns.saturating_sub(full_start_ns);
    let full_range = full_range_ns as f64;
    if full_range == 0.0 {
        return rsx! {};
    }

    // ── Signals ──────────────────────────────────────────────────────────────
    let mut drag = use_signal(|| Option::<DragState>::None);
    let mut drag_preview_range = use_signal(|| Option::<(u64, u64)>::None);
    let mut container_width_px = use_signal(|| 0.0f64);
    let mut hover_x_pct = use_signal(|| Option::<f64>::None);
    let mut last_mousedown_ts = use_signal(|| 0.0f64);

    let min_window_ns = ((full_range_ns as f64 * MIN_WINDOW_FRAC) as u64).max(1);

    // ── Derived layout values ────────────────────────────────────────────────
    let (display_start_ns, display_end_ns) =
        drag_preview_range().unwrap_or((view_start_ns, view_end_ns));
    let start_offset = display_start_ns.saturating_sub(full_start_ns);
    let end_offset = display_end_ns.saturating_sub(full_start_ns);
    let raw_left_pct = ns_to_pct(start_offset, full_range);
    let raw_width_pct = (end_offset.saturating_sub(start_offset)) as f64 / full_range * 100.0;

    // Auto-zoom: if the selection is too narrow to see/grab, expand the visual
    // representation symmetrically around the selection center.
    let (view_left_pct, view_width_pct) = if raw_width_pct < MIN_VISUAL_WIDTH_PCT {
        let center = raw_left_pct + raw_width_pct / 2.0;
        let new_left = (center - MIN_VISUAL_WIDTH_PCT / 2.0).max(0.0);
        let new_left = new_left.min(100.0 - MIN_VISUAL_WIDTH_PCT);
        (new_left, MIN_VISUAL_WIDTH_PCT)
    } else {
        (raw_left_pct, raw_width_pct)
    };

    let right_pct = (view_left_pct + view_width_pct).min(100.0);
    let right_dim_pct = (100.0 - right_pct).max(0.0);

    // Histogram background
    let histogram_area_path = histogram
        .as_ref()
        .and_then(|h| build_overview_histogram_area_path(h, &enabled_types));

    // ── Drag state derived values ────────────────────────────────────────────
    let is_dragging = drag().is_some();
    let drag_kind = drag().map(|d| d.kind);
    let drag_overlay_cursor = match drag_kind {
        Some(DragKind::Pan) => "grabbing",
        _ => "ew-resize",
    };

    // Whether the view covers the full range (nothing to reset to)
    let is_full_range = view_start_ns <= full_start_ns && view_end_ns >= full_end_ns;

    // ── Event handler: commit range ──────────────────────────────────────────
    let mut commit_drag = move || {
        if let Some((start, end)) = drag_preview_range() {
            on_change_range.call((start, end));
        }
        drag.set(None);
        drag_preview_range.set(None);
    };

    let container_cursor = if is_dragging {
        drag_overlay_cursor
    } else {
        "crosshair"
    };

    rsx! {
        div {
            class: "relative h-14 bg-gray-100 rounded-lg overflow-hidden select-none",
            style: "cursor: {container_cursor};",

            // ── Measure container width ──────────────────────────────────────
            onmounted: move |evt| async move {
                if let Ok(rect) = evt.data().get_client_rect().await {
                    container_width_px.set(rect.width());
                }
            },
            onresize: move |evt| {
                if let Ok(size) = evt.data().get_border_box_size()
                    && size.width > 0.0
                {
                    container_width_px.set(size.width);
                }
            },

            // ── Mouse down: start drag or detect double-click ─────────────
            onmousedown: move |evt: MouseEvent| {
                evt.prevent_default();

                // Detect double-click: two mousedowns within 300ms.
                let now = evt.as_web_event().time_stamp();
                let prev = last_mousedown_ts();
                last_mousedown_ts.set(now);
                if (now - prev) < 300.0 && !is_full_range {
                    // Double-click: cancel any in-progress drag and reset.
                    drag.set(None);
                    drag_preview_range.set(None);
                    on_change_range.call((full_start_ns, full_end_ns));
                    return;
                }

                let cw = container_width_px();
                let element_x = evt.element_coordinates().x;
                let Some(kind) = classify_hit(element_x, cw, view_left_pct, view_width_pct) else {
                    return;
                };

                // Check if click is in a dimmed region and snap edge
                let left_px = view_left_pct / 100.0 * cw;
                let right_px = right_pct / 100.0 * cw;
                let in_dimmed = element_x < left_px || element_x > right_px;

                let (snap_start, snap_end) = if in_dimmed && cw > 0.0 {
                    let click_offset = px_to_offset_ns(element_x, cw, full_range_ns);
                    snap_edge_to_click(
                        kind,
                        click_offset,
                        start_offset,
                        end_offset,
                        min_window_ns,
                        full_range_ns,
                    )
                } else {
                    (start_offset, end_offset)
                };

                drag_preview_range.set(Some((
                    full_start_ns + snap_start,
                    full_start_ns + snap_end,
                )));
                drag.set(Some(DragState {
                    kind,
                    start_client_x: evt.client_coordinates().x,
                    container_width: cw,
                    initial_start_offset: snap_start,
                    initial_end_offset: snap_end,
                }));
            },

            // ── Mouse move: update hover indicator + drag preview ────────────
            onmousemove: move |evt: MouseEvent| {
                let cw = container_width_px();
                if cw > 0.0 {
                    let element_x = evt.element_coordinates().x;
                    let pct = (element_x / cw * 100.0).clamp(0.0, 100.0);
                    if hover_x_pct() != Some(pct) {
                        hover_x_pct.set(Some(pct));
                    }
                    let hover_frac = (element_x / cw).clamp(0.0, 1.0);
                    let hover_ns = full_start_ns + (hover_frac * full_range).round() as u64;
                    on_hover_time.call(Some(hover_ns));
                }

                if let Some(d) = drag() {
                    let (start, end) =
                        compute_drag_range(d, evt.client_coordinates().x, full_start_ns, full_range_ns, min_window_ns);
                    if drag_preview_range() != Some((start, end)) {
                        drag_preview_range.set(Some((start, end)));
                    }
                }
            },

            // ── Mouse leave: clear hover ─────────────────────────────────────
            onmouseleave: move |_| {
                hover_x_pct.set(None);
                on_hover_time.call(None);
            },

            // ── Mouse up on the container itself (backup for non-overlay) ────
            onmouseup: move |_| {
                if drag().is_some() {
                    commit_drag();
                }
            },

            // ── Wheel: zoom in/out centered on cursor ────────────────────────
            onwheel: move |evt| {
                let cw = container_width_px();
                if cw <= 0.0 { return; }
                let raw_event = evt.as_web_event();
                raw_event.prevent_default();
                let delta_y = raw_event.delta_y();

                let element_x = evt.element_coordinates().x;
                let cursor_offset = px_to_offset_ns(element_x, cw, full_range_ns);
                // Normalize delta: positive = zoom out, negative = zoom in
                let zoom_factor = 1.0 + (delta_y / 100.0) * WHEEL_ZOOM_SPEED;
                let (new_start, new_end) = zoom_at_point(
                    cursor_offset,
                    start_offset,
                    end_offset,
                    full_range_ns,
                    min_window_ns,
                    zoom_factor,
                );
                on_change_range.call((full_start_ns + new_start, full_start_ns + new_end));
            },

            // ── Layer 0: Histogram background ────────────────────────────────
            if let Some(area_path) = histogram_area_path {
                svg {
                    class: "absolute inset-0 w-full h-full pointer-events-none",
                    view_box: "0 0 100 100",
                    preserve_aspect_ratio: "none",
                    path {
                        d: "{area_path}",
                        fill: "rgba(107, 114, 128, 0.4)",
                        stroke: "none",
                    }
                }
            }

            // ── Layer 1: Dimmed regions outside selection ────────────────────
            div {
                class: "absolute top-0 bottom-0 left-0 bg-gray-900/30 pointer-events-none",
                style: "width: {view_left_pct}%;",
            }
            div {
                class: "absolute top-0 bottom-0 right-0 bg-gray-900/30 pointer-events-none",
                style: "width: {right_dim_pct}%;",
            }

            // ── Layer 2: Selected window border (top + bottom) ───────────────
            div {
                class: "absolute top-0 h-[2px] bg-blue-500/80 pointer-events-none z-10",
                style: "left: {view_left_pct}%; width: {view_width_pct}%;",
            }
            div {
                class: "absolute bottom-0 h-[2px] bg-blue-500/80 pointer-events-none z-10",
                style: "left: {view_left_pct}%; width: {view_width_pct}%;",
            }

            // ── Layer 3: Left handle ─────────────────────────────────────────
            div {
                class: "absolute top-0 bottom-0 pointer-events-none z-20 flex items-center justify-center",
                style: "left: {view_left_pct}%; width: {HANDLE_WIDTH_PX}px;",
                div {
                    class: if is_dragging && drag_kind == Some(DragKind::LeftEdge) {
                        "w-full h-full rounded-l-md bg-blue-600 shadow-md flex items-center justify-center"
                    } else { "w-full h-full rounded-l-md bg-blue-500 hover:bg-blue-600 shadow-sm hover:shadow-md flex items-center justify-center transition-colors duration-100" },
                    div { class: "flex flex-col gap-[3px] items-center",
                        div { class: "w-[3px] h-[3px] rounded-full bg-white/80" }
                        div { class: "w-[3px] h-[3px] rounded-full bg-white/80" }
                        div { class: "w-[3px] h-[3px] rounded-full bg-white/80" }
                    }
                }
            }

            // ── Layer 3: Right handle ────────────────────────────────────────
            div {
                class: "absolute top-0 bottom-0 pointer-events-none z-20 flex items-center justify-center",
                style: "left: calc({right_pct}% - {HANDLE_WIDTH_PX}px); width: {HANDLE_WIDTH_PX}px;",
                div {
                    class: if is_dragging && drag_kind == Some(DragKind::RightEdge) {
                        "w-full h-full rounded-r-md bg-blue-600 shadow-md flex items-center justify-center"
                    } else { "w-full h-full rounded-r-md bg-blue-500 hover:bg-blue-600 shadow-sm hover:shadow-md flex items-center justify-center transition-colors duration-100" },
                    div { class: "flex flex-col gap-[3px] items-center",
                        div { class: "w-[3px] h-[3px] rounded-full bg-white/80" }
                        div { class: "w-[3px] h-[3px] rounded-full bg-white/80" }
                        div { class: "w-[3px] h-[3px] rounded-full bg-white/80" }
                    }
                }
            }

            // ── Layer 4: Hover vertical indicator ────────────────────────────
            if let Some(hx) = hover_x_pct() {
                if !is_dragging {
                    div {
                        class: "absolute top-0 bottom-0 pointer-events-none z-15",
                        style: "left: {hx}%; width: 1px; background: rgba(59, 130, 246, 0.5);",
                    }
                }
            }

            // ── Layer 5: Full-viewport drag overlay ──────────────────────────
            // Captures mouse events globally so drag continues outside the bar.
            if is_dragging {
                div {
                    class: "fixed inset-0 z-50",
                    style: "cursor: {drag_overlay_cursor};",
                    onmousemove: move |evt: MouseEvent| {
                        let Some(d) = drag() else { return };
                        let (start, end) =
                            compute_drag_range(d, evt.client_coordinates().x, full_start_ns, full_range_ns, min_window_ns);
                        if drag_preview_range() != Some((start, end)) {
                            drag_preview_range.set(Some((start, end)));
                        }
                    },
                    onmouseup: move |_| {
                        if drag().is_some() {
                            commit_drag();
                        }
                    },
                }
            }
        }
    }
}

// ─── Histogram path builder ──────────────────────────────────────────────────

fn build_overview_histogram_area_path(
    histogram: &HistogramResponse,
    enabled_types: &HashSet<String>,
) -> Option<String> {
    if histogram.buckets.is_empty() {
        return None;
    }

    let counts = histogram
        .buckets
        .iter()
        .map(|bucket| {
            bucket
                .counts_by_type
                .iter()
                .filter(|(event_type, _)| enabled_types.contains(*event_type))
                .map(|(_, count)| *count as f64)
                .sum::<f64>()
        })
        .collect::<Vec<_>>();

    let max_count = counts.iter().copied().fold(0.0f64, f64::max);
    if max_count <= 0.0 {
        return None;
    }

    let bucket_count = counts.len() as f64;
    let mut area_path = String::from("M0 100");

    for (idx, count) in counts.iter().enumerate() {
        let x_left = idx as f64 / bucket_count * 100.0;
        let x_right = (idx as f64 + 1.0) / bucket_count * 100.0;
        let mut height_pct = (count / max_count * 100.0).clamp(0.0, 100.0);
        if *count > 0.0 {
            height_pct = height_pct.max(1.0);
        }
        let y = 100.0 - height_pct;
        area_path.push_str(&format!("L{:.3} {:.3}L{:.3} {:.3}", x_left, y, x_right, y));
    }

    area_path.push_str("L100 100Z");
    Some(area_path)
}

// ─── Navigation helpers ─────────────────────────────────────────────────────

fn fit_window_to_bounds(
    full_start_ns: u64,
    full_end_ns: u64,
    window_start_ns: u64,
    window_duration_ns: u64,
) -> (u64, u64) {
    let full_duration_ns = full_end_ns.saturating_sub(full_start_ns);
    if full_duration_ns == 0 {
        return (full_start_ns, full_end_ns);
    }

    let duration_ns = window_duration_ns.max(1).min(full_duration_ns);
    let max_start_ns = full_end_ns.saturating_sub(duration_ns);
    let start_ns = window_start_ns.clamp(full_start_ns, max_start_ns);
    (start_ns, start_ns + duration_ns)
}

pub(super) fn shift_window(
    full_start_ns: u64,
    full_end_ns: u64,
    view_start_ns: u64,
    view_end_ns: u64,
    shift_ns: u64,
    shift_left: bool,
) -> (u64, u64) {
    let window_duration_ns = view_end_ns.saturating_sub(view_start_ns);
    let shifted_start_ns = if shift_left {
        view_start_ns.saturating_sub(shift_ns)
    } else {
        view_start_ns.saturating_add(shift_ns)
    };

    fit_window_to_bounds(
        full_start_ns,
        full_end_ns,
        shifted_start_ns,
        window_duration_ns,
    )
}

pub(super) fn zoom_window_to_duration(
    full_start_ns: u64,
    full_end_ns: u64,
    view_start_ns: u64,
    view_end_ns: u64,
    new_duration_ns: u64,
) -> (u64, u64) {
    let current_duration_ns = view_end_ns.saturating_sub(view_start_ns);
    let center_ns = view_start_ns.saturating_add(current_duration_ns / 2);
    let target_duration_ns = new_duration_ns.max(1);
    let centered_start_ns = center_ns.saturating_sub(target_duration_ns / 2);

    fit_window_to_bounds(
        full_start_ns,
        full_end_ns,
        centered_start_ns,
        target_duration_ns,
    )
}
