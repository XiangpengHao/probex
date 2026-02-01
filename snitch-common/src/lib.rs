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
    pub event_type: u8,
    pub cpu: u8,
    pub _padding: [u8; 2],
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

// Ring buffer size (2MB)
pub const RING_BUF_SIZE: u32 = 2 * 1024 * 1024;

// Maximum number of tracked PIDs
pub const MAX_TRACKED_PIDS: u32 = 8192;
