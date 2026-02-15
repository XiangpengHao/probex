#![cfg_attr(not(feature = "std"), no_std)]

/// Event types for kernel-userspace communication
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventType {
    SchedSwitch = 0,
    ProcessFork = 1,
    ProcessExit = 2,
    PageFault = 3,
    SyscallReadEnter = 4,
    SyscallReadExit = 5,
    SyscallWriteEnter = 6,
    SyscallWriteExit = 7,
    SyscallMmapEnter = 8,
    SyscallMmapExit = 9,
    SyscallMunmapEnter = 10,
    SyscallMunmapExit = 11,
    SyscallBrkEnter = 12,
    SyscallBrkExit = 13,
    SyscallIoUringSetupEnter = 14,
    SyscallIoUringSetupExit = 15,
    SyscallIoUringEnterEnter = 16,
    SyscallIoUringEnterExit = 17,
    SyscallIoUringRegisterEnter = 18,
    SyscallIoUringRegisterExit = 19,
    CpuSample = 20,
    SyscallFsyncEnter = 21,
    SyscallFsyncExit = 22,
    SyscallFdatasyncEnter = 23,
    SyscallFdatasyncExit = 24,
    IoUringComplete = 25,
}

impl TryFrom<u8> for EventType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EventType::SchedSwitch),
            1 => Ok(EventType::ProcessFork),
            2 => Ok(EventType::ProcessExit),
            3 => Ok(EventType::PageFault),
            4 => Ok(EventType::SyscallReadEnter),
            5 => Ok(EventType::SyscallReadExit),
            6 => Ok(EventType::SyscallWriteEnter),
            7 => Ok(EventType::SyscallWriteExit),
            8 => Ok(EventType::SyscallMmapEnter),
            9 => Ok(EventType::SyscallMmapExit),
            10 => Ok(EventType::SyscallMunmapEnter),
            11 => Ok(EventType::SyscallMunmapExit),
            12 => Ok(EventType::SyscallBrkEnter),
            13 => Ok(EventType::SyscallBrkExit),
            14 => Ok(EventType::SyscallIoUringSetupEnter),
            15 => Ok(EventType::SyscallIoUringSetupExit),
            16 => Ok(EventType::SyscallIoUringEnterEnter),
            17 => Ok(EventType::SyscallIoUringEnterExit),
            18 => Ok(EventType::SyscallIoUringRegisterEnter),
            19 => Ok(EventType::SyscallIoUringRegisterExit),
            20 => Ok(EventType::CpuSample),
            21 => Ok(EventType::SyscallFsyncEnter),
            22 => Ok(EventType::SyscallFsyncExit),
            23 => Ok(EventType::SyscallFdatasyncEnter),
            24 => Ok(EventType::SyscallFdatasyncExit),
            25 => Ok(EventType::IoUringComplete),
            v => Err(v),
        }
    }
}

/// Common header for all events
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct EventHeader {
    pub timestamp_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    /// User-space stack id from bpf_get_stackid(BPF_F_USER_STACK), or -1.
    pub stack_id: i32,
    /// Kernel-space stack id from bpf_get_stackid(0), or -1.
    pub kernel_stack_id: i32,
    pub stack_kind: u8,
    pub event_type: u8,
    pub cpu: u8,
    pub _padding: [u8; 5],
}

pub const STACK_KIND_NONE: u8 = 0;
pub const STACK_KIND_USER: u8 = 1;
pub const STACK_KIND_KERNEL: u8 = 2;
pub const STACK_KIND_BOTH: u8 = STACK_KIND_USER | STACK_KIND_KERNEL;

/// Maximum number of frame-pointer-derived user frames emitted in each cpu sample event.
pub const MAX_CPU_SAMPLE_FRAMES: usize = 127;

// CPU sampler stats indices (per-CPU array slot 0).
pub const CPU_SAMPLE_STATS_LEN: usize = 7;
pub const CPU_SAMPLE_STAT_CALLBACK_TOTAL: usize = 0;
pub const CPU_SAMPLE_STAT_FILTERED_NOT_TRACED: usize = 1;
pub const CPU_SAMPLE_STAT_EMITTED: usize = 2;
pub const CPU_SAMPLE_STAT_RINGBUF_DROPPED: usize = 3;
pub const CPU_SAMPLE_STAT_USER_STACK: usize = 4;
pub const CPU_SAMPLE_STAT_KERNEL_STACK: usize = 5;
pub const CPU_SAMPLE_STAT_NO_STACK: usize = 6;

/// CPU sample event carrying explicit user-space return addresses from frame-pointer walking.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct CpuSampleEvent {
    pub header: EventHeader,
    pub frame_count: u16,
    pub _padding: [u8; 6],
    pub frames: [u64; MAX_CPU_SAMPLE_FRAMES],
}

/// Context switch event
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SchedSwitchEvent {
    pub header: EventHeader,
    pub prev_pid: u32,
    pub prev_tgid: u32,
    pub next_pid: u32,
    pub next_tgid: u32,
    pub prev_state: i64,
}

/// Process fork event
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessForkEvent {
    pub header: EventHeader,
    pub parent_pid: u32,
    pub child_pid: u32,
}

/// Process exit event
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ProcessExitEvent {
    pub header: EventHeader,
    pub exit_code: i32,
    pub _padding: u32,
}

/// Page fault event
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PageFaultEvent {
    pub header: EventHeader,
    pub address: u64,
    pub error_code: u64,
}

/// Syscall enter event (for read/write)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SyscallEnterEvent {
    pub header: EventHeader,
    pub fd: i64,
    pub count: u64,
}

/// Syscall exit event (for read/write)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct SyscallExitEvent {
    pub header: EventHeader,
    pub ret: i64,
}

/// io_uring completion event — emitted when a CQE is posted.
/// Latency = header.timestamp_ns - submit_ts_ns.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct IoUringCompleteEvent {
    pub header: EventHeader,
    /// Timestamp (ktime_get_ns) when the SQE was submitted via io_uring_submit_req.
    pub submit_ts_ns: u64,
    /// io_uring opcode (IORING_OP_*).
    pub opcode: u8,
    pub _padding: [u8; 3],
    /// CQE result — bytes transferred for read/write, or negative errno.
    pub res: i32,
}

// Constants for event sizes
pub const SCHED_SWITCH_EVENT_SIZE: usize = core::mem::size_of::<SchedSwitchEvent>();
pub const PROCESS_FORK_EVENT_SIZE: usize = core::mem::size_of::<ProcessForkEvent>();
pub const PROCESS_EXIT_EVENT_SIZE: usize = core::mem::size_of::<ProcessExitEvent>();
pub const PAGE_FAULT_EVENT_SIZE: usize = core::mem::size_of::<PageFaultEvent>();
pub const SYSCALL_ENTER_EVENT_SIZE: usize = core::mem::size_of::<SyscallEnterEvent>();
pub const SYSCALL_EXIT_EVENT_SIZE: usize = core::mem::size_of::<SyscallExitEvent>();
pub const IO_URING_COMPLETE_EVENT_SIZE: usize = core::mem::size_of::<IoUringCompleteEvent>();
pub const CPU_SAMPLE_EVENT_SIZE: usize = core::mem::size_of::<CpuSampleEvent>();

// Ring buffer size
pub const RING_BUF_SIZE: u32 = 64 * 1024 * 1024;

// Maximum number of tracked PIDs
pub const MAX_TRACKED_PIDS: u32 = 8192;

// Maximum number of in-flight io_uring requests tracked for latency
pub const MAX_IO_URING_INFLIGHT: u32 = 16384;

#[cfg(feature = "viewer-api")]
pub mod viewer_api {
    use serde::{Deserialize, Serialize};
    use std::collections::HashMap;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct HistogramBucket {
        pub bucket_start_ns: u64,
        pub bucket_end_ns: u64,
        pub count: usize,
        pub counts_by_type: HashMap<String, usize>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct HistogramResponse {
        pub buckets: Vec<HistogramBucket>,
        pub total_in_range: usize,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
    pub struct EventTypeCounts {
        pub counts: HashMap<String, usize>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
    pub struct LatencySummary {
        pub count: usize,
        pub avg_ns: u64,
        pub p50_ns: u64,
        pub p95_ns: u64,
        pub max_ns: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
    pub struct SyscallLatencyStats {
        pub read: LatencySummary,
        pub write: LatencySummary,
        pub io_uring: LatencySummary,
        pub mmap_alloc_bytes: u64,
        pub munmap_free_bytes: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
    pub struct TraceSummary {
        pub total_events: usize,
        pub event_types: Vec<String>,
        pub unique_pids: Vec<u32>,
        pub min_ts_ns: u64,
        pub max_ts_ns: u64,
        pub cpu_sample_frequency_hz: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct ProcessLifetime {
        pub pid: u32,
        pub process_name: Option<String>,
        pub parent_pid: Option<u32>,
        pub start_ns: u64,
        pub end_ns: Option<u64>,
        pub exit_code: Option<i32>,
        pub was_forked: bool,
        pub did_exit: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct ProcessLifetimesResponse {
        pub processes: Vec<ProcessLifetime>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct EventMarker {
        pub ts_ns: u64,
        pub event_type: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct ProcessEventsResponse {
        pub events_by_pid: HashMap<u32, Vec<EventMarker>>,
        pub cpu_sample_counts_by_pid: HashMap<u32, Vec<u16>>,
        pub cpu_sample_bucket_count: usize,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
    pub struct EventFlamegraphResponse {
        pub event_type: String,
        pub total_samples: usize,
        pub svg: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct LatencyBucket {
        pub min_ns: u64,
        pub max_ns: u64,
        pub count: u64,
        pub label: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct SizeBucket {
        pub min_bytes: u64,
        pub max_bytes: u64,
        pub count: u64,
        pub label: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct IoTypeStats {
        pub operation: String,
        pub total_ops: u64,
        pub total_bytes: u64,
        pub avg_latency_ns: u64,
        pub p50_ns: u64,
        pub p95_ns: u64,
        pub p99_ns: u64,
        pub max_ns: u64,
        pub latency_histogram: Vec<LatencyBucket>,
        pub size_histogram: Vec<SizeBucket>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct IoStatistics {
        pub by_operation: Vec<IoTypeStats>,
        pub size_histogram: Vec<SizeBucket>,
        pub total_ops: u64,
        pub total_bytes: u64,
        pub time_range_ns: (u64, u64),
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct CumulativeMemoryPoint {
        pub ts_ns: u64,
        pub cumulative_bytes: i64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct MemoryStatistics {
        pub by_operation: Vec<IoTypeStats>,
        pub size_histogram: Vec<SizeBucket>,
        pub total_alloc_ops: u64,
        pub total_alloc_bytes: u64,
        pub total_free_ops: u64,
        pub total_free_bytes: u64,
        pub cumulative_usage: Vec<CumulativeMemoryPoint>,
        pub time_range_ns: (u64, u64),
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct EventDetail {
        pub ts_ns: u64,
        pub event_type: String,
        pub pid: u32,
        pub stack_trace: Option<Vec<String>>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct EventListResponse {
        pub events: Vec<EventDetail>,
        pub total_in_range: usize,
    }
}
