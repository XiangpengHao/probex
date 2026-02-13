#![no_std]

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

// Constants for event sizes
pub const SCHED_SWITCH_EVENT_SIZE: usize = core::mem::size_of::<SchedSwitchEvent>();
pub const PROCESS_FORK_EVENT_SIZE: usize = core::mem::size_of::<ProcessForkEvent>();
pub const PROCESS_EXIT_EVENT_SIZE: usize = core::mem::size_of::<ProcessExitEvent>();
pub const PAGE_FAULT_EVENT_SIZE: usize = core::mem::size_of::<PageFaultEvent>();
pub const SYSCALL_ENTER_EVENT_SIZE: usize = core::mem::size_of::<SyscallEnterEvent>();
pub const SYSCALL_EXIT_EVENT_SIZE: usize = core::mem::size_of::<SyscallExitEvent>();
pub const CPU_SAMPLE_EVENT_SIZE: usize = core::mem::size_of::<CpuSampleEvent>();

// Ring buffer size
pub const RING_BUF_SIZE: u32 = 64 * 1024 * 1024;

// Maximum number of tracked PIDs
pub const MAX_TRACKED_PIDS: u32 = 8192;
