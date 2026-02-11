use crate::server::TraceEvent;

pub fn get_event_marker_color(event_type: &str) -> &'static str {
    match event_type {
        "sched_switch" => "bg-blue-600",
        "process_fork" => "bg-green-600",
        "process_exit" => "bg-red-600",
        "page_fault" => "bg-orange-500",
        _ if event_type.contains("syscall") => "bg-purple-600",
        _ => "bg-gray-600",
    }
}

pub fn get_event_text_color(event_type: &str) -> &'static str {
    match event_type {
        "sched_switch" => "text-blue-600",
        "process_fork" => "text-green-600",
        "process_exit" => "text-red-600",
        "page_fault" => "text-orange-600",
        _ if event_type.contains("syscall") => "text-purple-600",
        _ => "text-gray-600",
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

pub fn format_event_details(event: &TraceEvent) -> String {
    match event.event_type.as_str() {
        "sched_switch" => {
            let prev = event.prev_pid.map(|p| p.to_string()).unwrap_or_default();
            let next = event.next_pid.map(|p| p.to_string()).unwrap_or_default();
            format!("{} → {}", prev, next)
        }
        "process_fork" => {
            let parent = event.parent_pid.map(|p| p.to_string()).unwrap_or_default();
            let child = event.child_pid.map(|p| p.to_string()).unwrap_or_default();
            format!("{} → {}", parent, child)
        }
        "process_exit" => {
            format!("exit: {}", event.exit_code.unwrap_or(0))
        }
        "page_fault" => {
            let addr = event
                .address
                .map(|a| format!("0x{:x}", a))
                .unwrap_or_default();
            format!("@ {}", addr)
        }
        "syscall_read_enter" | "syscall_write_enter" => {
            format!(
                "fd:{} len:{}",
                event.fd.unwrap_or(-1),
                event.count.unwrap_or(0)
            )
        }
        "syscall_read_exit" | "syscall_write_exit" => {
            format!("ret:{}", event.ret.unwrap_or(0))
        }
        "syscall_mmap_enter" => {
            let addr = event
                .address
                .map(|a| format!("0x{:x}", a))
                .unwrap_or_default();
            format!("addr:{} len:{}", addr, event.count.unwrap_or(0))
        }
        "syscall_mmap_exit" => {
            format!("ret:{}", event.ret.unwrap_or(0))
        }
        "syscall_munmap_enter" => {
            let addr = event
                .address
                .map(|a| format!("0x{:x}", a))
                .unwrap_or_default();
            format!("addr:{} len:{}", addr, event.count.unwrap_or(0))
        }
        "syscall_munmap_exit" => {
            format!("ret:{}", event.ret.unwrap_or(0))
        }
        "syscall_brk_enter" => {
            let addr = event
                .address
                .map(|a| format!("0x{:x}", a))
                .unwrap_or_default();
            format!("brk:{}", addr)
        }
        "syscall_brk_exit" => {
            format!("ret:{}", event.ret.unwrap_or(0))
        }
        _ => String::new(),
    }
}
