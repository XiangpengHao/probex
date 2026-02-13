#![no_std]
#![no_main]

use aya_ebpf::{
    EbpfContext,
    bindings::{BPF_F_USER_STACK, BPF_RB_FORCE_WAKEUP, bpf_perf_event_data},
    helpers::{bpf_get_smp_processor_id, bpf_ktime_get_ns, bpf_probe_read_user},
    macros::{map, perf_event, tracepoint},
    maps::{HashMap, PerCpuArray, RingBuf, StackTrace},
    programs::{PerfEventContext, TracePointContext},
};
use snitch_common::{
    CPU_SAMPLE_STAT_CALLBACK_TOTAL, CPU_SAMPLE_STAT_EMITTED, CPU_SAMPLE_STAT_FILTERED_NOT_TRACED,
    CPU_SAMPLE_STAT_NO_STACK, CPU_SAMPLE_STAT_RINGBUF_DROPPED, CPU_SAMPLE_STAT_USER_STACK,
    CPU_SAMPLE_STATS_LEN, CpuSampleEvent, EventHeader, EventType, MAX_CPU_SAMPLE_FRAMES,
    MAX_TRACKED_PIDS, PageFaultEvent, ProcessExitEvent, ProcessForkEvent, RING_BUF_SIZE,
    STACK_KIND_KERNEL, STACK_KIND_NONE, STACK_KIND_USER, SchedSwitchEvent, SyscallEnterEvent,
    SyscallExitEvent,
};

/// Ring buffer for sending events to userspace
#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(RING_BUF_SIZE, 0);

/// Stack trace storage used by bpf_get_stackid.
#[map]
static STACK_TRACES: StackTrace = StackTrace::with_max_entries(16384, 0);

/// HashMap to track which PIDs we're tracing
#[map]
static TRACED_PIDS: HashMap<u32, u8> = HashMap::with_max_entries(MAX_TRACKED_PIDS, 0);

/// Per-CPU counters for cpu sampling diagnostics.
#[map]
static CPU_SAMPLE_STATS: PerCpuArray<[u64; CPU_SAMPLE_STATS_LEN]> =
    PerCpuArray::with_max_entries(1, 0);

/// Check if a PID is being traced
#[inline(always)]
fn is_traced(pid: u32) -> bool {
    unsafe { TRACED_PIDS.get(&pid).is_some() }
}

#[inline(always)]
fn bump_cpu_sample_stat(index: usize) {
    if let Some(ptr) = CPU_SAMPLE_STATS.get_ptr_mut(0) {
        unsafe {
            (*ptr)[index] = (*ptr)[index].wrapping_add(1);
        }
    }
}

#[inline(always)]
fn capture_stack_ids<C: EbpfContext>(ctx: &C) -> (i32, i32, u8) {
    let user_stack_id = unsafe { STACK_TRACES.get_stackid::<C>(ctx, BPF_F_USER_STACK as u64) }
        .map(|stack_id| stack_id as i32)
        .unwrap_or(-1);
    let kernel_stack_id = unsafe { STACK_TRACES.get_stackid::<C>(ctx, 0) }
        .map(|stack_id| stack_id as i32)
        .unwrap_or(-1);

    let mut stack_kind = STACK_KIND_NONE;
    if user_stack_id >= 0 {
        stack_kind |= STACK_KIND_USER;
    }
    if kernel_stack_id >= 0 {
        stack_kind |= STACK_KIND_KERNEL;
    }

    (user_stack_id, kernel_stack_id, stack_kind)
}

/// Create an event header with stack capture from bpf_get_stackid.
#[inline(always)]
fn make_header<C: EbpfContext>(ctx: &C, event_type: EventType) -> EventHeader {
    let (stack_id, kernel_stack_id, stack_kind) = capture_stack_ids(ctx);
    EventHeader {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid: ctx.pid(),
        tgid: ctx.tgid(),
        stack_id,
        kernel_stack_id,
        stack_kind,
        event_type: event_type as u8,
        cpu: unsafe { bpf_get_smp_processor_id() } as u8,
        _padding: [0; 5],
    }
}

/// Create an event header without stack capture.
#[inline(always)]
fn make_header_without_stack<C: EbpfContext>(ctx: &C, event_type: EventType) -> EventHeader {
    EventHeader {
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        pid: ctx.pid(),
        tgid: ctx.tgid(),
        stack_id: -1,
        kernel_stack_id: -1,
        stack_kind: STACK_KIND_NONE,
        event_type: event_type as u8,
        cpu: unsafe { bpf_get_smp_processor_id() } as u8,
        _padding: [0; 5],
    }
}

#[inline(always)]
fn is_plausible_user_instruction_ip(ip: u64) -> bool {
    ip >= 0x1000 && ip < (1u64 << 63) && ip != u64::MAX
}

#[inline(always)]
fn is_plausible_user_stack_ptr(ptr: u64) -> bool {
    ptr >= 0x1000 && ptr < (1u64 << 63) && (ptr & 0x7) == 0
}

#[inline(always)]
fn capture_user_frames_fp(
    ctx: &PerfEventContext,
    frames: &mut [u64; MAX_CPU_SAMPLE_FRAMES],
) -> u16 {
    let regs = unsafe { &(*(ctx.as_ptr() as *const bpf_perf_event_data)).regs };

    let mut depth = 0usize;
    let first_ip = regs.rip as u64;
    if is_plausible_user_instruction_ip(first_ip) {
        frames[depth] = first_ip;
        depth += 1;
    }

    let mut frame_ptr = regs.rbp as u64;
    let mut prev_frame_ptr = 0u64;

    for _ in 1..MAX_CPU_SAMPLE_FRAMES {
        if depth >= MAX_CPU_SAMPLE_FRAMES
            || !is_plausible_user_stack_ptr(frame_ptr)
            || frame_ptr <= prev_frame_ptr
        {
            break;
        }

        let frame_ptr_addr = frame_ptr as *const u64;
        let next_frame_ptr = match unsafe { bpf_probe_read_user(frame_ptr_addr) } {
            Ok(value) => value,
            Err(_) => break,
        };
        let return_ip = match unsafe { bpf_probe_read_user(frame_ptr_addr.wrapping_add(1)) } {
            Ok(value) => value,
            Err(_) => break,
        };
        if !is_plausible_user_instruction_ip(return_ip) {
            break;
        }

        frames[depth] = return_ip;
        depth += 1;

        if !is_plausible_user_stack_ptr(next_frame_ptr)
            || next_frame_ptr <= frame_ptr
            || next_frame_ptr.saturating_sub(frame_ptr) > (1 << 20)
        {
            break;
        }
        prev_frame_ptr = frame_ptr;
        frame_ptr = next_frame_ptr;
    }

    depth as u16
}

#[perf_event]
pub fn cpu_sample(ctx: PerfEventContext) -> u32 {
    match try_cpu_sample(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_cpu_sample(ctx: &PerfEventContext) -> Result<u32, i64> {
    bump_cpu_sample_stat(CPU_SAMPLE_STAT_CALLBACK_TOTAL);

    if !is_traced(ctx.tgid()) {
        bump_cpu_sample_stat(CPU_SAMPLE_STAT_FILTERED_NOT_TRACED);
        return Ok(0);
    }

    if let Some(mut buf) = EVENTS.reserve::<CpuSampleEvent>(0) {
        let event_ptr = buf.as_mut_ptr();
        unsafe {
            *event_ptr = CpuSampleEvent {
                header: make_header_without_stack(ctx, EventType::CpuSample),
                frame_count: 0,
                _padding: [0; 6],
                frames: [0; MAX_CPU_SAMPLE_FRAMES],
            };
        }
        let frame_count = unsafe { capture_user_frames_fp(ctx, &mut (*event_ptr).frames) };
        unsafe {
            (*event_ptr).frame_count = frame_count;
            if frame_count > 0 {
                (*event_ptr).header.stack_kind = STACK_KIND_USER;
            }
        }

        bump_cpu_sample_stat(CPU_SAMPLE_STAT_EMITTED);
        if frame_count > 0 {
            bump_cpu_sample_stat(CPU_SAMPLE_STAT_USER_STACK);
        } else {
            bump_cpu_sample_stat(CPU_SAMPLE_STAT_NO_STACK);
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    } else {
        bump_cpu_sample_stat(CPU_SAMPLE_STAT_RINGBUF_DROPPED);
    }

    Ok(0)
}

/// sched_switch tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/sched/sched_switch/format:
/// - prev_comm[16]: offset 8
/// - prev_pid: offset 24
/// - prev_prio: offset 28
/// - prev_state: offset 32
/// - next_comm[16]: offset 40
/// - next_pid: offset 56
/// - next_prio: offset 60
#[tracepoint]
pub fn sched_switch(ctx: TracePointContext) -> u32 {
    match try_sched_switch(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sched_switch(ctx: &TracePointContext) -> Result<u32, i64> {
    // Read prev_pid at offset 24
    let prev_pid: u32 = unsafe { ctx.read_at(24)? };
    // Read prev_state at offset 32
    let prev_state: i64 = unsafe { ctx.read_at(32)? };
    // Read next_pid at offset 56
    let next_pid: u32 = unsafe { ctx.read_at(56)? };

    // Only emit event if either prev or next PID is being traced
    if !is_traced(prev_pid) && !is_traced(next_pid) {
        return Ok(0);
    }

    // Reserve space in ring buffer for the event
    if let Some(mut buf) = EVENTS.reserve::<SchedSwitchEvent>(0) {
        let mut header = make_header(ctx, EventType::SchedSwitch);
        header.pid = if is_traced(prev_pid) {
            prev_pid
        } else {
            next_pid
        };
        let event = SchedSwitchEvent {
            header,
            prev_pid,
            prev_tgid: 0, // Not available in tracepoint
            next_pid,
            next_tgid: 0, // Not available in tracepoint
            prev_state,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sched_process_fork tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/sched/sched_process_fork/format:
/// - parent_comm[16]: offset 8
/// - parent_pid: offset 24
/// - child_comm[16]: offset 28
/// - child_pid: offset 44
#[tracepoint]
pub fn sched_process_fork(ctx: TracePointContext) -> u32 {
    match try_sched_process_fork(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sched_process_fork(ctx: &TracePointContext) -> Result<u32, i64> {
    // Read parent_pid at offset 24
    let parent_pid: u32 = unsafe { ctx.read_at(24)? };
    // Read child_pid at offset 44
    let child_pid: u32 = unsafe { ctx.read_at(44)? };

    // Only track if parent is being traced
    if !is_traced(parent_pid) {
        return Ok(0);
    }

    // Add child to traced PIDs
    let _ = TRACED_PIDS.insert(&child_pid, &1, 0);

    // Emit fork event
    if let Some(mut buf) = EVENTS.reserve::<ProcessForkEvent>(0) {
        let event = ProcessForkEvent {
            header: make_header(ctx, EventType::ProcessFork),
            parent_pid,
            child_pid,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sched_process_exit tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/sched/sched_process_exit/format:
/// - comm[16]: offset 8
/// - pid: offset 24
/// - prio: offset 28
#[tracepoint]
pub fn sched_process_exit(ctx: TracePointContext) -> u32 {
    match try_sched_process_exit(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sched_process_exit(ctx: &TracePointContext) -> Result<u32, i64> {
    let pid = ctx.pid();

    // Only emit if this PID is being traced
    if !is_traced(pid) {
        return Ok(0);
    }

    // Emit exit event
    if let Some(mut buf) = EVENTS.reserve::<ProcessExitEvent>(0) {
        let event = ProcessExitEvent {
            header: make_header(ctx, EventType::ProcessExit),
            exit_code: 0, // Exit code not directly available in tracepoint
            _padding: 0,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    // Remove PID from traced set
    let _ = TRACED_PIDS.remove(&pid);

    Ok(0)
}

/// page_fault_user tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/exceptions/page_fault_user/format:
/// - address: offset 8
/// - ip: offset 16
/// - error_code: offset 24
#[tracepoint]
pub fn page_fault_user(ctx: TracePointContext) -> u32 {
    match try_page_fault_user(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_page_fault_user(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();

    // Only emit if this process is being traced
    if !is_traced(tgid) {
        return Ok(0);
    }

    // Read address at offset 8
    let address: u64 = unsafe { ctx.read_at(8)? };
    // Read error_code at offset 24
    let error_code: u64 = unsafe { ctx.read_at(24)? };

    // Emit page fault event
    if let Some(mut buf) = EVENTS.reserve::<PageFaultEvent>(0) {
        let event = PageFaultEvent {
            header: make_header(ctx, EventType::PageFault),
            address,
            error_code,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_enter_read tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_enter_read/format:
/// - __syscall_nr: offset 8
/// - fd: offset 16
/// - buf: offset 24
/// - count: offset 32
#[tracepoint]
pub fn sys_enter_read(ctx: TracePointContext) -> u32 {
    match try_sys_enter_read(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_read(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();

    if !is_traced(tgid) {
        return Ok(0);
    }

    // Read fd at offset 16
    let fd: i64 = unsafe { ctx.read_at(16)? };
    // Read count at offset 32
    let count: u64 = unsafe { ctx.read_at(32)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallEnterEvent>(0) {
        let event = SyscallEnterEvent {
            header: make_header(ctx, EventType::SyscallReadEnter),
            fd,
            count,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_exit_read tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_exit_read/format:
/// - __syscall_nr: offset 8
/// - ret: offset 16
#[tracepoint]
pub fn sys_exit_read(ctx: TracePointContext) -> u32 {
    match try_sys_exit_read(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_exit_read(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();

    if !is_traced(tgid) {
        return Ok(0);
    }

    // Read ret at offset 16
    let ret: i64 = unsafe { ctx.read_at(16)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallExitEvent>(0) {
        let event = SyscallExitEvent {
            header: make_header(ctx, EventType::SyscallReadExit),
            ret,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_enter_write tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_enter_write/format:
/// - __syscall_nr: offset 8
/// - fd: offset 16
/// - buf: offset 24
/// - count: offset 32
#[tracepoint]
pub fn sys_enter_write(ctx: TracePointContext) -> u32 {
    match try_sys_enter_write(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_write(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();

    if !is_traced(tgid) {
        return Ok(0);
    }

    // Read fd at offset 16
    let fd: i64 = unsafe { ctx.read_at(16)? };
    // Read count at offset 32
    let count: u64 = unsafe { ctx.read_at(32)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallEnterEvent>(0) {
        let event = SyscallEnterEvent {
            header: make_header(ctx, EventType::SyscallWriteEnter),
            fd,
            count,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_exit_write tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_exit_write/format:
/// - __syscall_nr: offset 8
/// - ret: offset 16
#[tracepoint]
pub fn sys_exit_write(ctx: TracePointContext) -> u32 {
    match try_sys_exit_write(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_exit_write(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();

    if !is_traced(tgid) {
        return Ok(0);
    }

    // Read ret at offset 16
    let ret: i64 = unsafe { ctx.read_at(16)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallExitEvent>(0) {
        let event = SyscallExitEvent {
            header: make_header(ctx, EventType::SyscallWriteExit),
            ret,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_enter_mmap tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_enter_mmap/format:
/// - __syscall_nr: offset 8
/// - addr: offset 16
/// - len: offset 24
#[tracepoint]
pub fn sys_enter_mmap(ctx: TracePointContext) -> u32 {
    match try_sys_enter_mmap(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_mmap(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();
    if !is_traced(tgid) {
        return Ok(0);
    }

    let addr: u64 = unsafe { ctx.read_at(16)? };
    let len: u64 = unsafe { ctx.read_at(24)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallEnterEvent>(0) {
        let event = SyscallEnterEvent {
            header: make_header(ctx, EventType::SyscallMmapEnter),
            fd: addr as i64,
            count: len,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_exit_mmap tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_exit_mmap/format:
/// - __syscall_nr: offset 8
/// - ret: offset 16
#[tracepoint]
pub fn sys_exit_mmap(ctx: TracePointContext) -> u32 {
    match try_sys_exit_mmap(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_exit_mmap(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();
    if !is_traced(tgid) {
        return Ok(0);
    }

    let ret: i64 = unsafe { ctx.read_at(16)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallExitEvent>(0) {
        let event = SyscallExitEvent {
            header: make_header(ctx, EventType::SyscallMmapExit),
            ret,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_enter_munmap tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_enter_munmap/format:
/// - __syscall_nr: offset 8
/// - addr: offset 16
/// - len: offset 24
#[tracepoint]
pub fn sys_enter_munmap(ctx: TracePointContext) -> u32 {
    match try_sys_enter_munmap(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_munmap(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();
    if !is_traced(tgid) {
        return Ok(0);
    }

    let addr: u64 = unsafe { ctx.read_at(16)? };
    let len: u64 = unsafe { ctx.read_at(24)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallEnterEvent>(0) {
        let event = SyscallEnterEvent {
            header: make_header(ctx, EventType::SyscallMunmapEnter),
            fd: addr as i64,
            count: len,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_exit_munmap tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_exit_munmap/format:
/// - __syscall_nr: offset 8
/// - ret: offset 16
#[tracepoint]
pub fn sys_exit_munmap(ctx: TracePointContext) -> u32 {
    match try_sys_exit_munmap(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_exit_munmap(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();
    if !is_traced(tgid) {
        return Ok(0);
    }

    let ret: i64 = unsafe { ctx.read_at(16)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallExitEvent>(0) {
        let event = SyscallExitEvent {
            header: make_header(ctx, EventType::SyscallMunmapExit),
            ret,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_enter_brk tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_enter_brk/format:
/// - __syscall_nr: offset 8
/// - brk: offset 16
#[tracepoint]
pub fn sys_enter_brk(ctx: TracePointContext) -> u32 {
    match try_sys_enter_brk(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_brk(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();
    if !is_traced(tgid) {
        return Ok(0);
    }

    let brk: u64 = unsafe { ctx.read_at(16)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallEnterEvent>(0) {
        let event = SyscallEnterEvent {
            header: make_header(ctx, EventType::SyscallBrkEnter),
            fd: brk as i64,
            count: 0,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_exit_brk tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_exit_brk/format:
/// - __syscall_nr: offset 8
/// - ret: offset 16
#[tracepoint]
pub fn sys_exit_brk(ctx: TracePointContext) -> u32 {
    match try_sys_exit_brk(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_exit_brk(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();
    if !is_traced(tgid) {
        return Ok(0);
    }

    let ret: i64 = unsafe { ctx.read_at(16)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallExitEvent>(0) {
        let event = SyscallExitEvent {
            header: make_header(ctx, EventType::SyscallBrkExit),
            ret,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_enter_io_uring_setup tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_enter_io_uring_setup/format:
/// - __syscall_nr: offset 8
/// - entries: offset 16
/// - p: offset 24
#[tracepoint]
pub fn sys_enter_io_uring_setup(ctx: TracePointContext) -> u32 {
    match try_sys_enter_io_uring_setup(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_io_uring_setup(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();
    if !is_traced(tgid) {
        return Ok(0);
    }

    let entries: u64 = unsafe { ctx.read_at(16)? };
    let params_ptr: u64 = unsafe { ctx.read_at(24)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallEnterEvent>(0) {
        let event = SyscallEnterEvent {
            header: make_header(ctx, EventType::SyscallIoUringSetupEnter),
            fd: entries as i64,
            count: params_ptr,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_exit_io_uring_setup tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_exit_io_uring_setup/format:
/// - __syscall_nr: offset 8
/// - ret: offset 16
#[tracepoint]
pub fn sys_exit_io_uring_setup(ctx: TracePointContext) -> u32 {
    match try_sys_exit_io_uring_setup(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_exit_io_uring_setup(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();
    if !is_traced(tgid) {
        return Ok(0);
    }

    let ret: i64 = unsafe { ctx.read_at(16)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallExitEvent>(0) {
        let event = SyscallExitEvent {
            header: make_header(ctx, EventType::SyscallIoUringSetupExit),
            ret,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_enter_io_uring_enter tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_enter_io_uring_enter/format:
/// - __syscall_nr: offset 8
/// - fd: offset 16
/// - to_submit: offset 24
#[tracepoint]
pub fn sys_enter_io_uring_enter(ctx: TracePointContext) -> u32 {
    match try_sys_enter_io_uring_enter(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_io_uring_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();
    if !is_traced(tgid) {
        return Ok(0);
    }

    let fd: i64 = unsafe { ctx.read_at(16)? };
    let to_submit: u64 = unsafe { ctx.read_at(24)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallEnterEvent>(0) {
        let event = SyscallEnterEvent {
            header: make_header(ctx, EventType::SyscallIoUringEnterEnter),
            fd,
            count: to_submit,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_exit_io_uring_enter tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_exit_io_uring_enter/format:
/// - __syscall_nr: offset 8
/// - ret: offset 16
#[tracepoint]
pub fn sys_exit_io_uring_enter(ctx: TracePointContext) -> u32 {
    match try_sys_exit_io_uring_enter(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_exit_io_uring_enter(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();
    if !is_traced(tgid) {
        return Ok(0);
    }

    let ret: i64 = unsafe { ctx.read_at(16)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallExitEvent>(0) {
        let event = SyscallExitEvent {
            header: make_header(ctx, EventType::SyscallIoUringEnterExit),
            ret,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_enter_io_uring_register tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_enter_io_uring_register/format:
/// - __syscall_nr: offset 8
/// - fd: offset 16
/// - opcode: offset 24
#[tracepoint]
pub fn sys_enter_io_uring_register(ctx: TracePointContext) -> u32 {
    match try_sys_enter_io_uring_register(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_enter_io_uring_register(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();
    if !is_traced(tgid) {
        return Ok(0);
    }

    let fd: i64 = unsafe { ctx.read_at(16)? };
    let opcode: u64 = unsafe { ctx.read_at(24)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallEnterEvent>(0) {
        let event = SyscallEnterEvent {
            header: make_header(ctx, EventType::SyscallIoUringRegisterEnter),
            fd,
            count: opcode,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

/// sys_exit_io_uring_register tracepoint handler
/// Tracepoint format from /sys/kernel/tracing/events/syscalls/sys_exit_io_uring_register/format:
/// - __syscall_nr: offset 8
/// - ret: offset 16
#[tracepoint]
pub fn sys_exit_io_uring_register(ctx: TracePointContext) -> u32 {
    match try_sys_exit_io_uring_register(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

fn try_sys_exit_io_uring_register(ctx: &TracePointContext) -> Result<u32, i64> {
    let tgid = ctx.tgid();
    if !is_traced(tgid) {
        return Ok(0);
    }

    let ret: i64 = unsafe { ctx.read_at(16)? };

    if let Some(mut buf) = EVENTS.reserve::<SyscallExitEvent>(0) {
        let event = SyscallExitEvent {
            header: make_header(ctx, EventType::SyscallIoUringRegisterExit),
            ret,
        };
        unsafe {
            (*buf.as_mut_ptr()) = event;
        }
        buf.submit(BPF_RB_FORCE_WAKEUP as u64);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
