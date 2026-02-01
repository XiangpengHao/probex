//! # Snitch - eBPF Process Tracing Tool
//!
//! ## Flow Overview
//!
//! ```text
//! 1. STARTUP
//!    snitch -- sleep 1
//!         │
//!         ▼
//!    ┌─────────────────────────────────────┐
//!    │  Load eBPF bytecode into kernel     │
//!    │  (embedded at compile time)         │
//!    └─────────────────────────────────────┘
//!         │
//!         ▼
//! 2. SPAWN TARGET PROCESS
//!    ┌─────────────────────────────────────┐
//!    │  fork() child with pre_exec hook    │
//!    │  that calls raise(SIGSTOP)          │
//!    │  Child stops before exec()          │
//!    └─────────────────────────────────────┘
//!         │
//!         ▼
//! 3. SETUP TRACING
//!    ┌─────────────────────────────────────┐
//!    │  Insert child PID into TRACED_PIDS  │
//!    │  HashMap in kernel                  │
//!    └─────────────────────────────────────┘
//!         │
//!         ▼
//!    ┌─────────────────────────────────────┐
//!    │  Attach tracepoint handlers:        │
//!    │  - sched:sched_switch               │
//!    │  - sched:sched_process_fork         │
//!    │  - sched:sched_process_exit         │
//!    │  - exceptions:page_fault_user       │
//!    │  - syscalls:sys_enter/exit_read     │
//!    │  - syscalls:sys_enter/exit_write    │
//!    └─────────────────────────────────────┘
//!         │
//!         ▼
//!    ┌─────────────────────────────────────┐
//!    │  Send SIGCONT to resume child       │
//!    │  Child now exec()s target program   │
//!    └─────────────────────────────────────┘
//!         │
//!         ▼
//! 4. EVENT LOOP
//!    ┌──────────────────────────────────────────────────────────┐
//!    │  KERNEL (eBPF)              │   USERSPACE (snitch)       │
//!    │                             │                            │
//!    │  Tracepoint fires ──────────┼──► Ring buffer poll        │
//!    │       │                     │         │                  │
//!    │       ▼                     │         ▼                  │
//!    │  Check TRACED_PIDS map      │    Parse event struct      │
//!    │       │                     │         │                  │
//!    │       ▼                     │         ▼                  │
//!    │  If PID tracked:            │    Serialize to JSON       │
//!    │  Write event to ring buffer │         │                  │
//!    │                             │         ▼                  │
//!    │  (Fork events also add      │    Write to output         │
//!    │   child PID to map)         │    (file or stdout)        │
//!    └──────────────────────────────────────────────────────────┘
//!         │
//!         ▼
//! 5. TERMINATION
//!    ┌─────────────────────────────────────┐
//!    │  On process_exit for target PID     │
//!    │  or Ctrl-C: exit event loop         │
//!    └─────────────────────────────────────┘
//! ```
//!
//! ## Key Components
//!
//! - **TRACED_PIDS**: HashMap<u32, u8> in kernel - tracks which PIDs to trace
//! - **EVENTS**: RingBuf (2MB) - kernel→userspace event transfer
//! - **SIGSTOP/SIGCONT**: Ensures probes attach before target executes
//!
//! ## Event Types
//!
//! | Event | Tracepoint | Data |
//! |-------|------------|------|
//! | sched_switch | sched:sched_switch | prev_pid, next_pid, prev_state |
//! | process_fork | sched:sched_process_fork | parent_pid, child_pid |
//! | process_exit | sched:sched_process_exit | exit_code |
//! | page_fault | exceptions:page_fault_user | address, error_code |
//! | syscall_read_enter | syscalls:sys_enter_read | fd, count |
//! | syscall_read_exit | syscalls:sys_exit_read | ret |
//! | syscall_write_enter | syscalls:sys_enter_write | fd, count |
//! | syscall_write_exit | syscalls:sys_exit_write | ret |

use std::ffi::CString;
use std::fs::File;
use std::io::{BufWriter, Write};

use anyhow::{Context as _, Result, anyhow};
use aya::maps::{HashMap, RingBuf};
use aya::programs::TracePoint;
use clap::Parser;
use log::{debug, info, warn};
use nix::sys::signal::{Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Pid, fork};
use serde::Serialize;
use snitch_common::{
    EventHeader, EventType, PageFaultEvent, ProcessExitEvent, ProcessForkEvent,
    SchedSwitchEvent, SyscallEnterEvent, SyscallExitEvent,
};
use tokio::io::unix::AsyncFd;
use tokio::signal;

#[derive(Parser, Debug)]
#[command(name = "snitch")]
#[command(about = "eBPF process tracing tool")]
#[command(version)]
struct Args {
    /// Output file for JSON lines (default: stdout)
    #[arg(short, long)]
    output: Option<String>,

    /// Command to run
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

/// JSON output event types
#[derive(Serialize)]
#[serde(tag = "type")]
#[serde(rename_all = "snake_case")]
enum JsonEvent {
    SchedSwitch {
        ts_ns: u64,
        pid: u32,
        cpu: u8,
        prev_pid: u32,
        next_pid: u32,
        prev_state: i64,
    },
    ProcessFork {
        ts_ns: u64,
        pid: u32,
        cpu: u8,
        parent_pid: u32,
        child_pid: u32,
    },
    ProcessExit {
        ts_ns: u64,
        pid: u32,
        cpu: u8,
        exit_code: i32,
    },
    PageFault {
        ts_ns: u64,
        pid: u32,
        cpu: u8,
        address: u64,
        error_code: u64,
    },
    SyscallReadEnter {
        ts_ns: u64,
        pid: u32,
        cpu: u8,
        fd: i64,
        count: u64,
    },
    SyscallReadExit {
        ts_ns: u64,
        pid: u32,
        cpu: u8,
        ret: i64,
    },
    SyscallWriteEnter {
        ts_ns: u64,
        pid: u32,
        cpu: u8,
        fd: i64,
        count: u64,
    },
    SyscallWriteExit {
        ts_ns: u64,
        pid: u32,
        cpu: u8,
        ret: i64,
    },
}

/// Parse event from ring buffer data
fn parse_event(data: &[u8]) -> Option<JsonEvent> {
    if data.len() < std::mem::size_of::<EventHeader>() {
        return None;
    }

    // Read the header to determine event type
    let header: &EventHeader = unsafe { &*(data.as_ptr() as *const EventHeader) };
    let event_type = EventType::try_from(header.event_type).ok()?;

    match event_type {
        EventType::SchedSwitch => {
            if data.len() < std::mem::size_of::<SchedSwitchEvent>() {
                return None;
            }
            let event: &SchedSwitchEvent = unsafe { &*(data.as_ptr() as *const SchedSwitchEvent) };
            Some(JsonEvent::SchedSwitch {
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                prev_pid: event.prev_pid,
                next_pid: event.next_pid,
                prev_state: event.prev_state,
            })
        }
        EventType::ProcessFork => {
            if data.len() < std::mem::size_of::<ProcessForkEvent>() {
                return None;
            }
            let event: &ProcessForkEvent = unsafe { &*(data.as_ptr() as *const ProcessForkEvent) };
            Some(JsonEvent::ProcessFork {
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                parent_pid: event.parent_pid,
                child_pid: event.child_pid,
            })
        }
        EventType::ProcessExit => {
            if data.len() < std::mem::size_of::<ProcessExitEvent>() {
                return None;
            }
            let event: &ProcessExitEvent = unsafe { &*(data.as_ptr() as *const ProcessExitEvent) };
            Some(JsonEvent::ProcessExit {
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                exit_code: event.exit_code,
            })
        }
        EventType::PageFault => {
            if data.len() < std::mem::size_of::<PageFaultEvent>() {
                return None;
            }
            let event: &PageFaultEvent = unsafe { &*(data.as_ptr() as *const PageFaultEvent) };
            Some(JsonEvent::PageFault {
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                address: event.address,
                error_code: event.error_code,
            })
        }
        EventType::SyscallReadEnter => {
            if data.len() < std::mem::size_of::<SyscallEnterEvent>() {
                return None;
            }
            let event: &SyscallEnterEvent = unsafe { &*(data.as_ptr() as *const SyscallEnterEvent) };
            Some(JsonEvent::SyscallReadEnter {
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                fd: event.fd,
                count: event.count,
            })
        }
        EventType::SyscallReadExit => {
            if data.len() < std::mem::size_of::<SyscallExitEvent>() {
                return None;
            }
            let event: &SyscallExitEvent = unsafe { &*(data.as_ptr() as *const SyscallExitEvent) };
            Some(JsonEvent::SyscallReadExit {
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                ret: event.ret,
            })
        }
        EventType::SyscallWriteEnter => {
            if data.len() < std::mem::size_of::<SyscallEnterEvent>() {
                return None;
            }
            let event: &SyscallEnterEvent = unsafe { &*(data.as_ptr() as *const SyscallEnterEvent) };
            Some(JsonEvent::SyscallWriteEnter {
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                fd: event.fd,
                count: event.count,
            })
        }
        EventType::SyscallWriteExit => {
            if data.len() < std::mem::size_of::<SyscallExitEvent>() {
                return None;
            }
            let event: &SyscallExitEvent = unsafe { &*(data.as_ptr() as *const SyscallExitEvent) };
            Some(JsonEvent::SyscallWriteExit {
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                ret: event.ret,
            })
        }
    }
}

/// Attach a tracepoint program
fn attach_tracepoint(
    ebpf: &mut aya::Ebpf,
    program_name: &str,
    category: &str,
    name: &str,
) -> Result<()> {
    let program: &mut TracePoint = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program {} not found", program_name))?
        .try_into()?;
    program.load()?;
    program
        .attach(category, name)
        .with_context(|| format!("failed to attach {}:{}", category, name))?;
    info!("Attached tracepoint {}:{}", category, name);
    Ok(())
}

fn spawn_child(program: &str, args: &[String]) -> Result<Pid> {
    let mut cstrings = Vec::with_capacity(args.len() + 1);
    cstrings.push(CString::new(program).with_context(|| {
        format!("failed to spawn {program}: program contains NUL")
    })?);
    for arg in args {
        cstrings.push(CString::new(arg.as_str()).with_context(|| {
            format!("failed to spawn {program}: argument contains NUL")
        })?);
    }
    let mut argv: Vec<*const libc::c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    match unsafe { fork()? } {
        ForkResult::Parent { child } => Ok(child),
        ForkResult::Child => unsafe {
            libc::raise(libc::SIGSTOP);
            libc::execvp(argv[0], argv.as_ptr());
            libc::_exit(127);
        },
    }
}

fn wait_for_child_stop(pid: Pid) -> Result<()> {
    match waitpid(pid, Some(WaitPidFlag::WUNTRACED)) {
        Ok(WaitStatus::Stopped(_, _)) => Ok(()),
        Ok(WaitStatus::Exited(_, status)) => {
            Err(anyhow!("child exited early with status {status}"))
        }
        Ok(WaitStatus::Signaled(_, signal, _)) => {
            Err(anyhow!("child exited early with signal {signal}"))
        }
        Ok(status) => Err(anyhow!(
            "unexpected wait status while waiting for stop: {status:?}"
        )),
        Err(err) => Err(anyhow!("waitpid failed while waiting for stop: {err}")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();

    if args.command.is_empty() {
        return Err(anyhow!("No command specified"));
    }

    // Bump the memlock rlimit
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load eBPF program
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/snitch"
    )))?;

    // Initialize eBPF logger (optional)
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // Spawn child process with SIGSTOP
    let program = &args.command[0];
    let program_args = &args.command[1..];

    let child_pid = spawn_child(program, program_args)?;
    let child_pid_u32 = child_pid.as_raw() as u32;
    info!("Spawned child process with PID {}", child_pid);

    wait_for_child_stop(child_pid)?;

    let mut child_wait = tokio::task::spawn_blocking(move || waitpid(child_pid, None));

    // Insert child PID into TRACED_PIDS map
    {
        let mut traced_pids: HashMap<_, u32, u8> =
            HashMap::try_from(ebpf.map_mut("TRACED_PIDS").unwrap())?;
        traced_pids.insert(child_pid_u32, 1, 0)?;
        info!("Added PID {} to traced PIDs", child_pid_u32);
    }

    // Attach all tracepoints
    attach_tracepoint(&mut ebpf, "sched_switch", "sched", "sched_switch")?;
    attach_tracepoint(&mut ebpf, "sched_process_fork", "sched", "sched_process_fork")?;
    attach_tracepoint(&mut ebpf, "sched_process_exit", "sched", "sched_process_exit")?;
    attach_tracepoint(&mut ebpf, "page_fault_user", "exceptions", "page_fault_user")?;
    attach_tracepoint(&mut ebpf, "sys_enter_read", "syscalls", "sys_enter_read")?;
    attach_tracepoint(&mut ebpf, "sys_exit_read", "syscalls", "sys_exit_read")?;
    attach_tracepoint(&mut ebpf, "sys_enter_write", "syscalls", "sys_enter_write")?;
    attach_tracepoint(&mut ebpf, "sys_exit_write", "syscalls", "sys_exit_write")?;

    // Resume child process
    kill(child_pid, Signal::SIGCONT)
        .with_context(|| format!("failed to resume child process {}", child_pid))?;
    info!("Resumed child process {}", child_pid);

    // Open output file or use stdout
    let mut output: Box<dyn Write + Send> = match &args.output {
        Some(path) => {
            let file = File::create(path)
                .with_context(|| format!("failed to create output file {}", path))?;
            Box::new(BufWriter::new(file))
        }
        None => Box::new(BufWriter::new(std::io::stdout())),
    };

    // Get ring buffer
    let ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut async_ring_buf = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let mut child_wait_done = false;

    // Event loop
    info!("Starting event loop...");

    loop {
        tokio::select! {
            result = &mut child_wait => {
                child_wait_done = true;
                match result {
                    Ok(Ok(WaitStatus::Exited(_, _))) | Ok(Ok(WaitStatus::Signaled(_, _, _))) => {}
                    Ok(Ok(_)) => {}
                    Ok(Err(err)) => warn!("failed to wait on child process {}: {err}", child_pid),
                    Err(err) => warn!("wait task failed for child process {}: {err}", child_pid),
                }

                // Drain any remaining events
                while let Some(item) = async_ring_buf.get_mut().next() {
                    if let Some(event) = parse_event(&item) {
                        let json = serde_json::to_string(&event)?;
                        writeln!(output, "{}", json)?;
                    }
                }
                info!("Child process {} exited", child_pid);
                break;
            }
            // Check for Ctrl-C
            _ = signal::ctrl_c() => {
                info!("Received Ctrl-C, exiting...");
                // Kill child process if still running
                if !child_wait.is_finished() {
                    let _ = kill(child_pid, Signal::SIGTERM);
                }
                break;
            }

            // Poll ring buffer for events
            result = async_ring_buf.readable_mut() => {
                let mut guard = result?;

                // Process all available events
                while let Some(item) = guard.get_inner_mut().next() {
                    if let Some(event) = parse_event(&item) {
                        // Write JSON line
                        let json = serde_json::to_string(&event)?;
                        writeln!(output, "{}", json)?;
                    }
                }

                // Flush output
                output.flush()?;

                guard.clear_ready();
            }
        }
    }

    if !child_wait_done {
        let _ = child_wait.await;
    }

    // Final flush
    output.flush()?;
    info!("Done.");

    Ok(())
}
