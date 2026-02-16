use crate::event::{stack_kind_from_header, Event};
use crate::stacks::format_stack_frames_hex;
use anyhow::{anyhow, Result};
use probex_common::{
    CpuSampleEvent, EventHeader, EventType, IoUringCompleteEvent, PageFaultEvent, ProcessExitEvent,
    ProcessForkEvent, SchedSwitchEvent, SyscallEnterEvent, SyscallExitEvent, MAX_CPU_SAMPLE_FRAMES,
};

pub fn read_unaligned_from_bytes<T: Copy>(data: &[u8]) -> Option<T> {
    if data.len() < std::mem::size_of::<T>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const T) })
}

pub fn event_base(event_type: &'static str, header: EventHeader) -> Event {
    Event {
        event_type,
        ts_ns: header.timestamp_ns,
        pid: header.pid,
        tgid: header.tgid,
        stack_id: (header.stack_id >= 0).then_some(header.stack_id),
        kernel_stack_id: (header.kernel_stack_id >= 0).then_some(header.kernel_stack_id),
        stack_kind: stack_kind_from_header(header.stack_kind),
        cpu: header.cpu,
        ..Default::default()
    }
}

/// Parse event from ring buffer data into a flattened Event struct
pub fn parse_event(data: &[u8]) -> Result<Event> {
    let header = read_unaligned_from_bytes::<EventHeader>(data).ok_or_else(|| {
        anyhow!(
            "event payload too short for EventHeader: {} bytes",
            data.len()
        )
    })?;
    let event_type = EventType::try_from(header.event_type)
        .map_err(|value| anyhow!("unknown event_type discriminant: {value}"))?;

    match event_type {
        EventType::SchedSwitch => {
            let event = read_unaligned_from_bytes::<SchedSwitchEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SchedSwitchEvent"))?;
            Ok(Event {
                prev_pid: Some(event.prev_pid),
                next_pid: Some(event.next_pid),
                prev_state: Some(event.prev_state),
                ..event_base("sched_switch", event.header)
            })
        }
        EventType::ProcessFork => {
            let event = read_unaligned_from_bytes::<ProcessForkEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for ProcessForkEvent"))?;
            Ok(Event {
                parent_pid: Some(event.parent_pid),
                child_pid: Some(event.child_pid),
                ..event_base("process_fork", event.header)
            })
        }
        EventType::ProcessExit => {
            let event = read_unaligned_from_bytes::<ProcessExitEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for ProcessExitEvent"))?;
            Ok(Event {
                exit_code: Some(event.exit_code),
                ..event_base("process_exit", event.header)
            })
        }
        EventType::PageFault => {
            let event = read_unaligned_from_bytes::<PageFaultEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for PageFaultEvent"))?;
            Ok(Event {
                address: Some(event.address),
                error_code: Some(event.error_code),
                ..event_base("page_fault", event.header)
            })
        }
        EventType::SyscallReadEnter => {
            let event = read_unaligned_from_bytes::<SyscallEnterEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallEnterEvent"))?;
            Ok(Event {
                fd: Some(event.fd),
                count: Some(event.count),
                ..event_base("syscall_read_enter", event.header)
            })
        }
        EventType::SyscallReadExit => {
            let event = read_unaligned_from_bytes::<SyscallExitEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallExitEvent"))?;
            Ok(Event {
                ret: Some(event.ret),
                ..event_base("syscall_read_exit", event.header)
            })
        }
        EventType::SyscallWriteEnter => {
            let event = read_unaligned_from_bytes::<SyscallEnterEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallEnterEvent"))?;
            Ok(Event {
                fd: Some(event.fd),
                count: Some(event.count),
                ..event_base("syscall_write_enter", event.header)
            })
        }
        EventType::SyscallWriteExit => {
            let event = read_unaligned_from_bytes::<SyscallExitEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallExitEvent"))?;
            Ok(Event {
                ret: Some(event.ret),
                ..event_base("syscall_write_exit", event.header)
            })
        }
        EventType::SyscallMmapEnter => {
            let event = read_unaligned_from_bytes::<SyscallEnterEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallEnterEvent"))?;
            Ok(Event {
                address: Some(event.fd as u64),
                count: Some(event.count),
                ..event_base("syscall_mmap_enter", event.header)
            })
        }
        EventType::SyscallMmapExit => {
            let event = read_unaligned_from_bytes::<SyscallExitEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallExitEvent"))?;
            Ok(Event {
                ret: Some(event.ret),
                ..event_base("syscall_mmap_exit", event.header)
            })
        }
        EventType::SyscallMunmapEnter => {
            let event = read_unaligned_from_bytes::<SyscallEnterEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallEnterEvent"))?;
            Ok(Event {
                address: Some(event.fd as u64),
                count: Some(event.count),
                ..event_base("syscall_munmap_enter", event.header)
            })
        }
        EventType::SyscallMunmapExit => {
            let event = read_unaligned_from_bytes::<SyscallExitEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallExitEvent"))?;
            Ok(Event {
                ret: Some(event.ret),
                ..event_base("syscall_munmap_exit", event.header)
            })
        }
        EventType::SyscallBrkEnter => {
            let event = read_unaligned_from_bytes::<SyscallEnterEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallEnterEvent"))?;
            Ok(Event {
                address: Some(event.fd as u64),
                ..event_base("syscall_brk_enter", event.header)
            })
        }
        EventType::SyscallBrkExit => {
            let event = read_unaligned_from_bytes::<SyscallExitEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallExitEvent"))?;
            Ok(Event {
                ret: Some(event.ret),
                ..event_base("syscall_brk_exit", event.header)
            })
        }
        EventType::SyscallIoUringSetupEnter => {
            let event = read_unaligned_from_bytes::<SyscallEnterEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallEnterEvent"))?;
            Ok(Event {
                fd: Some(event.fd),
                count: Some(event.count),
                ..event_base("syscall_io_uring_setup_enter", event.header)
            })
        }
        EventType::SyscallIoUringSetupExit => {
            let event = read_unaligned_from_bytes::<SyscallExitEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallExitEvent"))?;
            Ok(Event {
                ret: Some(event.ret),
                ..event_base("syscall_io_uring_setup_exit", event.header)
            })
        }
        EventType::SyscallIoUringEnterEnter => {
            let event = read_unaligned_from_bytes::<SyscallEnterEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallEnterEvent"))?;
            Ok(Event {
                fd: Some(event.fd),
                count: Some(event.count),
                ..event_base("syscall_io_uring_enter_enter", event.header)
            })
        }
        EventType::SyscallIoUringEnterExit => {
            let event = read_unaligned_from_bytes::<SyscallExitEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallExitEvent"))?;
            Ok(Event {
                ret: Some(event.ret),
                ..event_base("syscall_io_uring_enter_exit", event.header)
            })
        }
        EventType::SyscallIoUringRegisterEnter => {
            let event = read_unaligned_from_bytes::<SyscallEnterEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallEnterEvent"))?;
            Ok(Event {
                fd: Some(event.fd),
                count: Some(event.count),
                ..event_base("syscall_io_uring_register_enter", event.header)
            })
        }
        EventType::SyscallIoUringRegisterExit => {
            let event = read_unaligned_from_bytes::<SyscallExitEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallExitEvent"))?;
            Ok(Event {
                ret: Some(event.ret),
                ..event_base("syscall_io_uring_register_exit", event.header)
            })
        }
        EventType::CpuSample => {
            let event = read_unaligned_from_bytes::<CpuSampleEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for CpuSampleEvent"))?;
            let frame_count = usize::from(event.frame_count).min(MAX_CPU_SAMPLE_FRAMES);
            // Frame-pointer walk captures frames from leaf to root.
            // Flamegraph folding expects root to leaf.
            let mut frames: Vec<u64> = event.frames[..frame_count].to_vec();
            frames.reverse();

            let mut out = event_base("cpu_sample", event.header);
            if let Some(stack_frames) = format_stack_frames_hex(&frames) {
                out.stack_frames = Some(stack_frames.clone());
                out.stack_trace = Some(format!("[user];{stack_frames}"));
            } else {
                out.stack_kind = None;
            }
            Ok(out)
        }
        EventType::SyscallFsyncEnter => {
            let event = read_unaligned_from_bytes::<SyscallEnterEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallEnterEvent"))?;
            Ok(Event {
                fd: Some(event.fd),
                ..event_base("syscall_fsync_enter", event.header)
            })
        }
        EventType::SyscallFsyncExit => {
            let event = read_unaligned_from_bytes::<SyscallExitEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallExitEvent"))?;
            Ok(Event {
                ret: Some(event.ret),
                ..event_base("syscall_fsync_exit", event.header)
            })
        }
        EventType::SyscallFdatasyncEnter => {
            let event = read_unaligned_from_bytes::<SyscallEnterEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallEnterEvent"))?;
            Ok(Event {
                fd: Some(event.fd),
                ..event_base("syscall_fdatasync_enter", event.header)
            })
        }
        EventType::SyscallFdatasyncExit => {
            let event = read_unaligned_from_bytes::<SyscallExitEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for SyscallExitEvent"))?;
            Ok(Event {
                ret: Some(event.ret),
                ..event_base("syscall_fdatasync_exit", event.header)
            })
        }
        EventType::IoUringComplete => {
            let event = read_unaligned_from_bytes::<IoUringCompleteEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for IoUringCompleteEvent"))?;
            Ok(Event {
                submit_ts_ns: Some(event.submit_ts_ns),
                io_uring_opcode: Some(event.opcode),
                io_uring_res: Some(event.res),
                ..event_base("io_uring_complete", event.header)
            })
        }
    }
}
