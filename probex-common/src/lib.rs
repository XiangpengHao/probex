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
        pub end_ns: u64,
        pub exit: Option<i32>,
        pub was_forked: bool,
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

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub enum ProbeSchemaSource {
        TraceFsFormat,
        KernelBtf,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub enum ProbeSchemaKind {
        Tracepoint,
        Fentry,
        Fexit,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ProbeSchemaArg {
        pub name: String,
        pub arg_type: String,
        pub is_supported: bool,
        pub unsupported_reason: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ProbeSchemaField {
        pub declaration: String,
        pub name: String,
        pub field_type: String,
        pub offset: u32,
        pub size: u32,
        pub is_signed: bool,
        pub is_common: bool,
        pub is_supported: bool,
        pub unsupported_reason: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct ProbeSchema {
        pub display_name: String,
        pub provider: String,
        pub target: String,
        pub probe: String,
        pub symbol: Option<String>,
        pub kind: ProbeSchemaKind,
        pub source: ProbeSchemaSource,
        pub return_type: Option<String>,
        pub return_supported: bool,
        pub return_unsupported_reason: Option<String>,
        pub args: Vec<ProbeSchemaArg>,
        pub fields: Vec<ProbeSchemaField>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub enum CustomProbeFieldRef {
        Field { name: String },
        Arg { name: String },
        Return,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub enum CustomProbeFilterOp {
        Eq,
        Ne,
        Gt,
        Ge,
        Lt,
        Le,
        Contains,
        StartsWith,
        EndsWith,
        IsNull,
        IsNotNull,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CustomProbeFilter {
        pub field: CustomProbeFieldRef,
        pub op: CustomProbeFilterOp,
        pub value: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CustomProbeSpec {
        pub probe_display_name: String,
        pub record_fields: Vec<CustomProbeFieldRef>,
        pub record_stack_trace: bool,
        pub filters: Vec<CustomProbeFilter>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub enum CustomPayloadTypeKind {
        U64,
        I64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CustomPayloadFieldSchema {
        pub field_id: u16,
        pub name: String,
        pub type_kind: CustomPayloadTypeKind,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CustomPayloadSchema {
        pub schema_id: u32,
        pub probe_display_name: String,
        pub event_type: String,
        pub fields: Vec<CustomPayloadFieldSchema>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
    pub struct ProbeSchemasResponse {
        pub probes: Vec<ProbeSchema>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
    pub struct ProbeSchemasPageResponse {
        pub probes: Vec<ProbeSchema>,
        pub total: usize,
        pub offset: usize,
        pub limit: usize,
        pub has_more: bool,
        pub is_loading: bool,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct StartTraceRequest {
        pub program: String,
        pub args: Vec<String>,
        pub output_parquet: String,
        pub sample_freq_hz: u64,
        pub custom_probes: Vec<CustomProbeSpec>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct LoadTraceRequest {
        pub parquet_path: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub enum TraceRunStatus {
        Idle,
        Running {
            run_id: u64,
            command: Vec<String>,
            output_parquet: String,
            started_at_unix_ms: u64,
        },
        Finished {
            run_id: u64,
            command: Vec<String>,
            output_parquet: String,
            started_at_unix_ms: u64,
            finished_at_unix_ms: u64,
            exit_code: i32,
            success: bool,
            error: Option<String>,
        },
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TraceRunStatusResponse {
        pub sequence: u64,
        pub status: TraceRunStatus,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub enum TraceDebugStepStatus {
        Pending,
        Running,
        Success,
        Failed,
        Skipped,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TraceDebugStep {
        pub step: String,
        pub status: TraceDebugStepStatus,
        pub detail: Option<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct TraceDebugInfo {
        pub generated_rust_code: String,
        pub steps: Vec<TraceDebugStep>,
        pub last_error: Option<String>,
        pub updated_at_unix_ms: u64,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CustomEventDebugField {
        pub field_id: u16,
        pub name: String,
        pub type_kind: CustomPayloadTypeKind,
        pub value_u64: u64,
        pub value_i64: Option<i64>,
        pub display_value: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CustomEventDebugRow {
        pub ts_ns: u64,
        pub event_type: String,
        pub pid: u32,
        pub tgid: u32,
        pub process_name: Option<String>,
        pub schema_id: u32,
        pub fields: Vec<CustomEventDebugField>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CustomEventField {
        pub field_id: u16,
        pub name: String,
        pub type_kind: CustomPayloadTypeKind,
        pub value_u64: u64,
        pub value_i64: Option<i64>,
        pub display_value: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
    pub struct CustomEventPayload {
        pub schema_id: u32,
        pub fields: Vec<CustomEventField>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
    pub struct CustomEventsDebugResponse {
        pub events: Vec<CustomEventDebugRow>,
        pub shown: usize,
        pub limit: usize,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct IoTypeStats {
        pub operation: String,
        pub total_ops: u64,
        pub total_bytes: u64,
        pub avg_latency_ns: u64,
        /// Representative events for percentiles
        pub p50_event: Option<EventDetail>,
        pub p95_event: Option<EventDetail>,
        pub p99_event: Option<EventDetail>,
        pub max_event: Option<EventDetail>,
        /// Sorted raw latency values in nanoseconds.
        pub latencies_ns: Vec<u64>,
        /// Sorted raw size values in bytes.
        pub sizes_bytes: Vec<u64>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct IoStatistics {
        pub by_operation: Vec<IoTypeStats>,
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
        pub latency_ns: Option<u64>,
        pub event_type: String,
        pub pid: u32,
        pub stack_trace: Option<Vec<String>>,
        pub custom_payload: Option<CustomEventPayload>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    pub struct EventListResponse {
        pub events: Vec<EventDetail>,
        pub total_in_range: usize,
    }
}
