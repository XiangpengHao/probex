pub fn get_event_marker_color(event_type: &str) -> &'static str {
    match event_type {
        "sched_switch" => "#2563eb",
        "process_fork" => "#16a34a",
        "process_exit" => "#dc2626",
        "page_fault" => "#f97316",
        _ if event_type.contains("syscall") => "#7c3aed",
        _ => "#4b5563",
    }
}

pub fn format_duration(ns: u64) -> String {
    let us = ns as f64 / 1_000.0;
    let ms = ns as f64 / 1_000_000.0;
    let s = ns as f64 / 1_000_000_000.0;

    if s >= 1.0 {
        format!("{:.2}s", s)
    } else if ms >= 1.0 {
        format!("{:.2}ms", ms)
    } else if us >= 1.0 {
        format!("{:.1}µs", us)
    } else {
        format!("{}ns", ns)
    }
}

pub fn format_duration_short(ns: u64) -> String {
    let us = ns as f64 / 1_000.0;
    let ms = ns as f64 / 1_000_000.0;
    let s = ns as f64 / 1_000_000_000.0;

    if s >= 1.0 {
        format!("{:.1}s", s)
    } else if ms >= 1.0 {
        format!("{:.0}ms", ms)
    } else if us >= 1.0 {
        format!("{:.0}µs", us)
    } else {
        format!("{}ns", ns)
    }
}

pub fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0usize;

    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{} {}", bytes, UNITS[unit])
    } else {
        format!("{:.2} {}", value, UNITS[unit])
    }
}

pub fn format_net_bytes_signed(allocated: u64, freed: u64) -> String {
    if allocated >= freed {
        format!("+{}", format_bytes(allocated - freed))
    } else {
        format!("-{}", format_bytes(freed - allocated))
    }
}
