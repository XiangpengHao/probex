use std::collections::HashMap;

use dioxus::prelude::*;

pub(super) const PROCESS_BAR_SELECTION_THRESHOLD_PX: f64 = 3.0;

#[derive(Clone, Copy)]
pub(super) struct ProcessBarDragState {
    pub pid: u32,
    pub bar_left_client_x: f64,
    pub bar_width_px: f64,
    pub anchor_client_x: f64,
}

#[derive(Clone, Copy, PartialEq)]
pub(super) struct ProcessBarDragPreview {
    pub pid: u32,
    pub start_pct: f64,
    pub end_pct: f64,
    pub start_ns: u64,
    pub end_ns: u64,
}

#[derive(Clone, PartialEq)]
pub(super) struct CanvasEventMarker {
    pub pct: f64,
    pub color_hex: &'static str,
}

#[component]
pub(super) fn ProcessActivityCanvas(
    usage_points: Vec<f64>,
    event_markers: Vec<CanvasEventMarker>,
    fork_pct: Option<f64>,
    exit_pct: Option<f64>,
    exit_ok: bool,
) -> Element {
    let (usage_area_path, usage_line_path) = build_usage_paths(&usage_points);
    let marker_paths = build_vertical_marker_paths(&event_markers);

    rsx! {
        svg {
            class: "absolute inset-0 w-full h-full pointer-events-none",
            view_box: "0 0 100 100",
            preserve_aspect_ratio: "none",

            if let Some(area_path) = usage_area_path {
                path {
                    d: "{area_path}",
                    fill: "rgba(107, 114, 128, 0.12)",
                    stroke: "none",
                }
            }

            if let Some(line_path) = usage_line_path {
                path {
                    d: "{line_path}",
                    fill: "none",
                    stroke: "rgba(107, 114, 128, 0.35)",
                    stroke_width: "0.8",
                    vector_effect: "non-scaling-stroke",
                }
            }

            {marker_paths.iter().map(|(color_hex, path_data)| {
                rsx! {
                    path {
                        key: "{color_hex}",
                        d: "{path_data}",
                        fill: "none",
                        stroke: "{color_hex}",
                        stroke_width: "0.45",
                        vector_effect: "non-scaling-stroke",
                    }
                }
            })}

            if let Some(fork_x) = fork_pct {
                line {
                    x1: "{fork_x.clamp(0.0, 100.0)}",
                    y1: "0",
                    x2: "{fork_x.clamp(0.0, 100.0)}",
                    y2: "100",
                    stroke: "#16a34a",
                    stroke_width: "0.9",
                    vector_effect: "non-scaling-stroke",
                }
            }

            if let Some(exit_x) = exit_pct {
                line {
                    x1: "{exit_x.clamp(0.0, 100.0)}",
                    y1: "0",
                    x2: "{exit_x.clamp(0.0, 100.0)}",
                    y2: "100",
                    stroke: if exit_ok { "#16a34a" } else { "#dc2626" },
                    stroke_width: "0.9",
                    vector_effect: "non-scaling-stroke",
                }
            }
        }
    }
}

pub(super) fn build_process_bar_drag_preview(
    drag_state: ProcessBarDragState,
    current_client_x: f64,
    view_start_ns: u64,
    view_end_ns: u64,
) -> Option<ProcessBarDragPreview> {
    if drag_state.bar_width_px <= 0.0 || view_end_ns <= view_start_ns {
        return None;
    }

    let view_duration_ns = view_end_ns - view_start_ns;
    let anchor_frac = ((drag_state.anchor_client_x - drag_state.bar_left_client_x)
        / drag_state.bar_width_px)
        .clamp(0.0, 1.0);
    let current_frac = ((current_client_x - drag_state.bar_left_client_x)
        / drag_state.bar_width_px)
        .clamp(0.0, 1.0);

    let start_frac = anchor_frac.min(current_frac);
    let end_frac = anchor_frac.max(current_frac);
    let start_ns = view_start_ns + ((view_duration_ns as f64) * start_frac).round() as u64;
    let mut end_ns = view_start_ns + ((view_duration_ns as f64) * end_frac).round() as u64;
    if end_ns <= start_ns {
        end_ns = (start_ns + 1).min(view_end_ns);
    }
    if end_ns <= start_ns {
        return None;
    }

    Some(ProcessBarDragPreview {
        pid: drag_state.pid,
        start_pct: start_frac * 100.0,
        end_pct: end_frac * 100.0,
        start_ns,
        end_ns,
    })
}

fn build_usage_paths(usage_points: &[f64]) -> (Option<String>, Option<String>) {
    if usage_points.is_empty() {
        return (None, None);
    }

    let point_count = usage_points.len();
    let mut line_path = String::new();
    let mut area_path = String::new();
    let mut last_x = 0.0;

    for (idx, usage) in usage_points.iter().enumerate() {
        let x = ((idx as f64) + 0.5) / point_count as f64 * 100.0;
        let y = 100.0 - usage.clamp(0.0, 100.0);
        last_x = x;
        if idx == 0 {
            line_path = format!("M{:.3} {:.3}", x, y);
            area_path = format!("M{:.3} 100L{:.3} {:.3}", x, x, y);
        } else {
            line_path.push_str(&format!("L{:.3} {:.3}", x, y));
            area_path.push_str(&format!("L{:.3} {:.3}", x, y));
        }
    }

    area_path.push_str(&format!("L{:.3} 100Z", last_x));
    (Some(area_path), Some(line_path))
}

fn build_vertical_marker_paths(markers: &[CanvasEventMarker]) -> Vec<(&'static str, String)> {
    let mut grouped: HashMap<&'static str, Vec<f64>> = HashMap::new();
    for marker in markers {
        grouped
            .entry(marker.color_hex)
            .or_default()
            .push(marker.pct.clamp(0.0, 100.0));
    }

    let mut grouped_vec: Vec<(&'static str, Vec<f64>)> = grouped.into_iter().collect();
    grouped_vec.sort_by(|a, b| a.0.cmp(b.0));

    grouped_vec
        .into_iter()
        .map(|(color_hex, mut points)| {
            points.sort_by(|a, b| a.total_cmp(b));
            let mut path_data = String::new();
            for x in points {
                path_data.push_str(&format!("M{:.3} 0V100", x));
            }
            (color_hex, path_data)
        })
        .collect()
}

pub(super) fn build_cpu_usage_points(
    bucket_counts: &[u16],
    bucket_count: usize,
    sample_frequency_hz: u64,
    view_duration_ns: u64,
) -> Vec<f64> {
    if bucket_count == 0 || bucket_counts.is_empty() {
        return Vec::new();
    }

    let clamped_bucket_count = bucket_count.min(bucket_counts.len());
    let bucket_size_ns = view_duration_ns.max(1).div_ceil(bucket_count as u64).max(1);
    let expected_samples_per_bucket =
        (sample_frequency_hz as f64 * (bucket_size_ns as f64 / 1_000_000_000.0)).max(0.001);

    bucket_counts
        .iter()
        .take(clamped_bucket_count)
        .map(|count| ((*count as f64 / expected_samples_per_bucket) * 100.0).clamp(0.0, 100.0))
        .collect()
}
