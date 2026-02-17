use probex_common::{STACK_KIND_BOTH, STACK_KIND_KERNEL, STACK_KIND_USER};

/// Flattened event structure for Parquet output.
/// All event types share common fields, with type-specific fields being optional.
#[derive(Default)]
pub struct Event {
    pub event_type: &'static str,
    pub ts_ns: u64,
    pub pid: u32,
    pub tgid: u32,
    pub process_name: Option<String>,
    /// User-space stack id.
    pub stack_id: Option<i32>,
    /// Kernel-space stack id.
    pub kernel_stack_id: Option<i32>,
    pub stack_kind: Option<&'static str>,
    pub stack_frames: Option<String>,
    pub stack_trace: Option<String>,
    pub cpu: u8,
    // SchedSwitch fields
    pub prev_pid: Option<u32>,
    pub next_pid: Option<u32>,
    pub prev_state: Option<i64>,
    // ProcessFork fields
    pub parent_pid: Option<u32>,
    pub child_pid: Option<u32>,
    // ProcessExit fields
    pub exit_code: Option<i32>,
    // PageFault fields
    pub address: Option<u64>,
    pub error_code: Option<u64>,
    // Syscall fields
    pub fd: Option<i64>,
    pub count: Option<u64>,
    pub ret: Option<i64>,
    // io_uring completion fields
    pub submit_ts_ns: Option<u64>,
    pub io_uring_opcode: Option<u8>,
    pub io_uring_res: Option<i32>,
}

pub fn stack_kind_from_header(stack_kind: u8) -> Option<&'static str> {
    match stack_kind {
        STACK_KIND_USER => Some("user"),
        STACK_KIND_KERNEL => Some("kernel"),
        STACK_KIND_BOTH => Some("both"),
        _ => None,
    }
}
