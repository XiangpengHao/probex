use crate::server::EventTypeCounts;

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

fn lookup_count(counts: Option<&EventTypeCounts>, event_type: &str) -> usize {
    counts
        .and_then(|counts| counts.counts.get(event_type).copied())
        .unwrap_or(0)
}
