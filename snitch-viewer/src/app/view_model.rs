use crate::api::{EventTypeCounts, TraceSummary};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ViewRange {
    pub start_ns: u64,
    pub end_ns: u64,
}

impl ViewRange {
    pub fn new(start_ns: u64, end_ns: u64) -> Option<Self> {
        (end_ns >= start_ns).then_some(Self { start_ns, end_ns })
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct PidEventSummary {
    pub breakdown: Vec<(String, usize)>,
    pub total: usize,
    pub memory_event_total: usize,
    pub mmap_enter: usize,
    pub munmap_enter: usize,
    pub brk_enter: usize,
}

pub fn build_pid_event_summary(counts: Option<&EventTypeCounts>) -> PidEventSummary {
    let mut breakdown: Vec<(String, usize)> = counts
        .map(|counts| {
            counts
                .counts
                .iter()
                .map(|(event_type, count)| (event_type.clone(), *count))
                .collect()
        })
        .unwrap_or_default();
    breakdown.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

    let total = breakdown.iter().map(|(_, count)| *count).sum();
    let mmap_enter = lookup_count(counts, "syscall_mmap_enter");
    let munmap_enter = lookup_count(counts, "syscall_munmap_enter");
    let brk_enter = lookup_count(counts, "syscall_brk_enter");
    let memory_event_total = [
        "syscall_mmap_enter",
        "syscall_mmap_exit",
        "syscall_munmap_enter",
        "syscall_munmap_exit",
        "syscall_brk_enter",
        "syscall_brk_exit",
    ]
    .iter()
    .map(|event_type| lookup_count(counts, event_type))
    .sum();

    PidEventSummary {
        breakdown,
        total,
        memory_event_total,
        mmap_enter,
        munmap_enter,
        brk_enter,
    }
}

pub fn next_view_range(
    current_range: Option<ViewRange>,
    next_start_ns: u64,
    next_end_ns: u64,
) -> Option<ViewRange> {
    let next_range = ViewRange::new(next_start_ns, next_end_ns)?;
    (current_range != Some(next_range)).then_some(next_range)
}

pub fn build_flame_event_type_options(
    summary: Option<&TraceSummary>,
    selected_pid: Option<u32>,
    pid_summary: &PidEventSummary,
    selected_event_type: Option<&str>,
) -> Vec<String> {
    let mut options: Vec<String> = if selected_pid.is_some() && !pid_summary.breakdown.is_empty() {
        pid_summary
            .breakdown
            .iter()
            .map(|(event_type, _)| event_type.clone())
            .collect()
    } else {
        summary.map(|s| s.event_types.clone()).unwrap_or_default()
    };

    if let Some(event_type) = selected_event_type
        && !options.iter().any(|candidate| candidate == event_type)
    {
        options.push(event_type.to_string());
    }

    options.sort();
    options.dedup();
    options
}

fn lookup_count(counts: Option<&EventTypeCounts>, event_type: &str) -> usize {
    counts
        .and_then(|counts| counts.counts.get(event_type).copied())
        .unwrap_or(0)
}
