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
//!    │  If PID tracked:            │    Buffer events in batch  │
//!    │  Write event to ring buffer │         │                  │
//!    │                             │         ▼                  │
//!    │  (Fork events also add      │    Write batch to Parquet  │
//!    │   child PID to map)         │    when batch is full      │
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
//! | syscall_mmap_enter | syscalls:sys_enter_mmap | address, count(len) |
//! | syscall_mmap_exit | syscalls:sys_exit_mmap | ret |
//! | syscall_munmap_enter | syscalls:sys_enter_munmap | address, count(len) |
//! | syscall_munmap_exit | syscalls:sys_exit_munmap | ret |
//! | syscall_brk_enter | syscalls:sys_enter_brk | address |
//! | syscall_brk_exit | syscalls:sys_exit_brk | ret |

use std::{
    ffi::CString,
    fs::File,
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context as _, Result, anyhow};
use arrow::{
    array::{
        ArrayRef, Int32Builder, Int64Builder, StringBuilder, UInt8Builder, UInt32Builder,
        UInt64Builder,
    },
    datatypes::{DataType, Field, Schema},
    record_batch::RecordBatch,
};
use aya::{
    maps::{HashMap, RingBuf},
    programs::TracePoint,
};
use clap::Parser;
use log::{debug, info, warn};
use nix::{
    sys::{
        signal::{Signal, kill},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{ForkResult, Pid, fork},
};
use parquet::{arrow::ArrowWriter, basic::Compression, file::properties::WriterProperties};
use snitch_common::{
    EventHeader, EventType, PageFaultEvent, ProcessExitEvent, ProcessForkEvent, SchedSwitchEvent,
    SyscallEnterEvent, SyscallExitEvent,
};
use tokio::{io::unix::AsyncFd, signal};

/// Batch size for Parquet writes (10,000 events per batch)
const BATCH_SIZE: usize = 10_000;

#[derive(Parser, Debug)]
#[command(name = "snitch")]
#[command(about = "eBPF process tracing tool")]
#[command(version)]
struct Args {
    /// Output parquet file (default: trace.parquet)
    #[arg(short, long, default_value = "trace.parquet")]
    output: String,

    /// Port for the viewer web interface
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Don't launch the viewer after tracing
    #[arg(long)]
    no_viewer: bool,

    /// Command to run
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

/// Flattened event structure for Parquet output.
/// All event types share common fields, with type-specific fields being optional.
#[derive(Default)]
struct Event {
    event_type: &'static str,
    ts_ns: u64,
    pid: u32,
    process_name: Option<String>,
    cpu: u8,
    // SchedSwitch fields
    prev_pid: Option<u32>,
    next_pid: Option<u32>,
    prev_state: Option<i64>,
    // ProcessFork fields
    parent_pid: Option<u32>,
    child_pid: Option<u32>,
    // ProcessExit fields
    exit_code: Option<i32>,
    // PageFault fields
    address: Option<u64>,
    error_code: Option<u64>,
    // Syscall fields
    fd: Option<i64>,
    count: Option<u64>,
    ret: Option<i64>,
}

/// Creates the Arrow schema for the unified event table
fn create_schema() -> Schema {
    Schema::new(vec![
        Field::new("event_type", DataType::Utf8, false),
        Field::new("ts_ns", DataType::UInt64, false),
        Field::new("pid", DataType::UInt32, false),
        Field::new("process_name", DataType::Utf8, true),
        Field::new("cpu", DataType::UInt8, false),
        // SchedSwitch fields (nullable)
        Field::new("prev_pid", DataType::UInt32, true),
        Field::new("next_pid", DataType::UInt32, true),
        Field::new("prev_state", DataType::Int64, true),
        // ProcessFork fields (nullable)
        Field::new("parent_pid", DataType::UInt32, true),
        Field::new("child_pid", DataType::UInt32, true),
        // ProcessExit fields (nullable)
        Field::new("exit_code", DataType::Int32, true),
        // PageFault fields (nullable)
        Field::new("address", DataType::UInt64, true),
        Field::new("error_code", DataType::UInt64, true),
        // Syscall fields (nullable)
        Field::new("fd", DataType::Int64, true),
        Field::new("count", DataType::UInt64, true),
        Field::new("ret", DataType::Int64, true),
    ])
}

/// Parquet batch writer that buffers events and writes them in batches
/// to minimize memory usage and improve write efficiency.
struct ParquetBatchWriter {
    writer: ArrowWriter<File>,
    schema: Arc<Schema>,
    batch: Vec<Event>,
    total_written: usize,
}

impl ParquetBatchWriter {
    /// Create a new ParquetBatchWriter that writes to the specified file
    fn new(path: &str) -> Result<Self> {
        let schema = Arc::new(create_schema());
        let file =
            File::create(path).with_context(|| format!("failed to create output file {}", path))?;

        let props = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .build();

        let writer = ArrowWriter::try_new(file, schema.clone(), Some(props))
            .with_context(|| "failed to create Parquet writer")?;

        Ok(Self {
            writer,
            schema,
            batch: Vec::with_capacity(BATCH_SIZE),
            total_written: 0,
        })
    }

    /// Push an event to the batch. Automatically flushes when batch is full.
    fn push(&mut self, event: Event) -> Result<()> {
        self.batch.push(event);
        if self.batch.len() >= BATCH_SIZE {
            self.flush_batch()?;
        }
        Ok(())
    }

    /// Flush the current batch to the Parquet file
    fn flush_batch(&mut self) -> Result<()> {
        if self.batch.is_empty() {
            return Ok(());
        }

        let batch_len = self.batch.len();

        // Build Arrow arrays from the batch
        let mut event_type_builder = StringBuilder::with_capacity(batch_len, batch_len * 20);
        let mut ts_ns_builder = UInt64Builder::with_capacity(batch_len);
        let mut pid_builder = UInt32Builder::with_capacity(batch_len);
        let mut process_name_builder = StringBuilder::with_capacity(batch_len, batch_len * 24);
        let mut cpu_builder = UInt8Builder::with_capacity(batch_len);
        let mut prev_pid_builder = UInt32Builder::with_capacity(batch_len);
        let mut next_pid_builder = UInt32Builder::with_capacity(batch_len);
        let mut prev_state_builder = Int64Builder::with_capacity(batch_len);
        let mut parent_pid_builder = UInt32Builder::with_capacity(batch_len);
        let mut child_pid_builder = UInt32Builder::with_capacity(batch_len);
        let mut exit_code_builder = Int32Builder::with_capacity(batch_len);
        let mut address_builder = UInt64Builder::with_capacity(batch_len);
        let mut error_code_builder = UInt64Builder::with_capacity(batch_len);
        let mut fd_builder = Int64Builder::with_capacity(batch_len);
        let mut count_builder = UInt64Builder::with_capacity(batch_len);
        let mut ret_builder = Int64Builder::with_capacity(batch_len);

        for event in self.batch.drain(..) {
            event_type_builder.append_value(event.event_type);
            ts_ns_builder.append_value(event.ts_ns);
            pid_builder.append_value(event.pid);
            process_name_builder.append_option(event.process_name.as_deref());
            cpu_builder.append_value(event.cpu);
            prev_pid_builder.append_option(event.prev_pid);
            next_pid_builder.append_option(event.next_pid);
            prev_state_builder.append_option(event.prev_state);
            parent_pid_builder.append_option(event.parent_pid);
            child_pid_builder.append_option(event.child_pid);
            exit_code_builder.append_option(event.exit_code);
            address_builder.append_option(event.address);
            error_code_builder.append_option(event.error_code);
            fd_builder.append_option(event.fd);
            count_builder.append_option(event.count);
            ret_builder.append_option(event.ret);
        }

        let columns: Vec<ArrayRef> = vec![
            Arc::new(event_type_builder.finish()),
            Arc::new(ts_ns_builder.finish()),
            Arc::new(pid_builder.finish()),
            Arc::new(process_name_builder.finish()),
            Arc::new(cpu_builder.finish()),
            Arc::new(prev_pid_builder.finish()),
            Arc::new(next_pid_builder.finish()),
            Arc::new(prev_state_builder.finish()),
            Arc::new(parent_pid_builder.finish()),
            Arc::new(child_pid_builder.finish()),
            Arc::new(exit_code_builder.finish()),
            Arc::new(address_builder.finish()),
            Arc::new(error_code_builder.finish()),
            Arc::new(fd_builder.finish()),
            Arc::new(count_builder.finish()),
            Arc::new(ret_builder.finish()),
        ];

        let record_batch = RecordBatch::try_new(self.schema.clone(), columns)
            .with_context(|| "failed to create record batch")?;

        self.writer
            .write(&record_batch)
            .with_context(|| "failed to write record batch")?;

        self.total_written += batch_len;
        debug!(
            "Flushed {} events to Parquet (total: {})",
            batch_len, self.total_written
        );

        Ok(())
    }

    /// Finish writing and close the file. Returns total events written.
    fn finish(mut self) -> Result<usize> {
        self.flush_batch()?;
        self.writer
            .close()
            .with_context(|| "failed to close Parquet writer")?;
        Ok(self.total_written)
    }
}

/// Parse event from ring buffer data into a flattened Event struct
fn parse_event(data: &[u8]) -> Option<Event> {
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
            Some(Event {
                event_type: "sched_switch",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                prev_pid: Some(event.prev_pid),
                next_pid: Some(event.next_pid),
                prev_state: Some(event.prev_state),
                ..Default::default()
            })
        }
        EventType::ProcessFork => {
            if data.len() < std::mem::size_of::<ProcessForkEvent>() {
                return None;
            }
            let event: &ProcessForkEvent = unsafe { &*(data.as_ptr() as *const ProcessForkEvent) };
            Some(Event {
                event_type: "process_fork",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                parent_pid: Some(event.parent_pid),
                child_pid: Some(event.child_pid),
                ..Default::default()
            })
        }
        EventType::ProcessExit => {
            if data.len() < std::mem::size_of::<ProcessExitEvent>() {
                return None;
            }
            let event: &ProcessExitEvent = unsafe { &*(data.as_ptr() as *const ProcessExitEvent) };
            Some(Event {
                event_type: "process_exit",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                exit_code: Some(event.exit_code),
                ..Default::default()
            })
        }
        EventType::PageFault => {
            if data.len() < std::mem::size_of::<PageFaultEvent>() {
                return None;
            }
            let event: &PageFaultEvent = unsafe { &*(data.as_ptr() as *const PageFaultEvent) };
            Some(Event {
                event_type: "page_fault",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                address: Some(event.address),
                error_code: Some(event.error_code),
                ..Default::default()
            })
        }
        EventType::SyscallReadEnter => {
            if data.len() < std::mem::size_of::<SyscallEnterEvent>() {
                return None;
            }
            let event: &SyscallEnterEvent =
                unsafe { &*(data.as_ptr() as *const SyscallEnterEvent) };
            Some(Event {
                event_type: "syscall_read_enter",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                fd: Some(event.fd),
                count: Some(event.count),
                ..Default::default()
            })
        }
        EventType::SyscallReadExit => {
            if data.len() < std::mem::size_of::<SyscallExitEvent>() {
                return None;
            }
            let event: &SyscallExitEvent = unsafe { &*(data.as_ptr() as *const SyscallExitEvent) };
            Some(Event {
                event_type: "syscall_read_exit",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                ret: Some(event.ret),
                ..Default::default()
            })
        }
        EventType::SyscallWriteEnter => {
            if data.len() < std::mem::size_of::<SyscallEnterEvent>() {
                return None;
            }
            let event: &SyscallEnterEvent =
                unsafe { &*(data.as_ptr() as *const SyscallEnterEvent) };
            Some(Event {
                event_type: "syscall_write_enter",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                fd: Some(event.fd),
                count: Some(event.count),
                ..Default::default()
            })
        }
        EventType::SyscallWriteExit => {
            if data.len() < std::mem::size_of::<SyscallExitEvent>() {
                return None;
            }
            let event: &SyscallExitEvent = unsafe { &*(data.as_ptr() as *const SyscallExitEvent) };
            Some(Event {
                event_type: "syscall_write_exit",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                ret: Some(event.ret),
                ..Default::default()
            })
        }
        EventType::SyscallMmapEnter => {
            if data.len() < std::mem::size_of::<SyscallEnterEvent>() {
                return None;
            }
            let event: &SyscallEnterEvent =
                unsafe { &*(data.as_ptr() as *const SyscallEnterEvent) };
            Some(Event {
                event_type: "syscall_mmap_enter",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                address: Some(event.fd as u64),
                count: Some(event.count),
                ..Default::default()
            })
        }
        EventType::SyscallMmapExit => {
            if data.len() < std::mem::size_of::<SyscallExitEvent>() {
                return None;
            }
            let event: &SyscallExitEvent = unsafe { &*(data.as_ptr() as *const SyscallExitEvent) };
            Some(Event {
                event_type: "syscall_mmap_exit",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                ret: Some(event.ret),
                ..Default::default()
            })
        }
        EventType::SyscallMunmapEnter => {
            if data.len() < std::mem::size_of::<SyscallEnterEvent>() {
                return None;
            }
            let event: &SyscallEnterEvent =
                unsafe { &*(data.as_ptr() as *const SyscallEnterEvent) };
            Some(Event {
                event_type: "syscall_munmap_enter",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                address: Some(event.fd as u64),
                count: Some(event.count),
                ..Default::default()
            })
        }
        EventType::SyscallMunmapExit => {
            if data.len() < std::mem::size_of::<SyscallExitEvent>() {
                return None;
            }
            let event: &SyscallExitEvent = unsafe { &*(data.as_ptr() as *const SyscallExitEvent) };
            Some(Event {
                event_type: "syscall_munmap_exit",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                ret: Some(event.ret),
                ..Default::default()
            })
        }
        EventType::SyscallBrkEnter => {
            if data.len() < std::mem::size_of::<SyscallEnterEvent>() {
                return None;
            }
            let event: &SyscallEnterEvent =
                unsafe { &*(data.as_ptr() as *const SyscallEnterEvent) };
            Some(Event {
                event_type: "syscall_brk_enter",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                address: Some(event.fd as u64),
                ..Default::default()
            })
        }
        EventType::SyscallBrkExit => {
            if data.len() < std::mem::size_of::<SyscallExitEvent>() {
                return None;
            }
            let event: &SyscallExitEvent = unsafe { &*(data.as_ptr() as *const SyscallExitEvent) };
            Some(Event {
                event_type: "syscall_brk_exit",
                ts_ns: event.header.timestamp_ns,
                pid: event.header.pid,
                cpu: event.header.cpu,
                ret: Some(event.ret),
                ..Default::default()
            })
        }
    }
}

fn read_process_name(pid: u32) -> Option<String> {
    let comm_path = format!("/proc/{pid}/comm");
    std::fs::read_to_string(comm_path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn enrich_process_name(
    event: &mut Event,
    pid_name_cache: &mut std::collections::HashMap<u32, Option<String>>,
) {
    let maybe_name = pid_name_cache
        .entry(event.pid)
        .or_insert_with(|| read_process_name(event.pid))
        .clone();
    event.process_name = maybe_name;
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
    cstrings.push(
        CString::new(program)
            .with_context(|| format!("failed to spawn {program}: program contains NUL"))?,
    );
    for arg in args {
        cstrings.push(
            CString::new(arg.as_str())
                .with_context(|| format!("failed to spawn {program}: argument contains NUL"))?,
        );
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
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

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
            let mut logger = AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
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
    attach_tracepoint(
        &mut ebpf,
        "sched_process_fork",
        "sched",
        "sched_process_fork",
    )?;
    attach_tracepoint(
        &mut ebpf,
        "sched_process_exit",
        "sched",
        "sched_process_exit",
    )?;
    attach_tracepoint(
        &mut ebpf,
        "page_fault_user",
        "exceptions",
        "page_fault_user",
    )?;
    attach_tracepoint(&mut ebpf, "sys_enter_read", "syscalls", "sys_enter_read")?;
    attach_tracepoint(&mut ebpf, "sys_exit_read", "syscalls", "sys_exit_read")?;
    attach_tracepoint(&mut ebpf, "sys_enter_write", "syscalls", "sys_enter_write")?;
    attach_tracepoint(&mut ebpf, "sys_exit_write", "syscalls", "sys_exit_write")?;
    attach_tracepoint(&mut ebpf, "sys_enter_mmap", "syscalls", "sys_enter_mmap")?;
    attach_tracepoint(&mut ebpf, "sys_exit_mmap", "syscalls", "sys_exit_mmap")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_munmap",
        "syscalls",
        "sys_enter_munmap",
    )?;
    attach_tracepoint(&mut ebpf, "sys_exit_munmap", "syscalls", "sys_exit_munmap")?;
    attach_tracepoint(&mut ebpf, "sys_enter_brk", "syscalls", "sys_enter_brk")?;
    attach_tracepoint(&mut ebpf, "sys_exit_brk", "syscalls", "sys_exit_brk")?;

    // Resume child process
    kill(child_pid, Signal::SIGCONT)
        .with_context(|| format!("failed to resume child process {}", child_pid))?;
    info!("Resumed child process {}", child_pid);

    // Create Parquet batch writer
    let mut writer = ParquetBatchWriter::new(&args.output)?;
    info!("Writing events to {}", args.output);

    // Get ring buffer
    let ring_buf = RingBuf::try_from(ebpf.map_mut("EVENTS").unwrap())?;
    let mut async_ring_buf = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let mut child_wait_done = false;
    let mut pid_name_cache: std::collections::HashMap<u32, Option<String>> =
        std::collections::HashMap::new();

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
                    if let Some(mut event) = parse_event(&item) {
                        enrich_process_name(&mut event, &mut pid_name_cache);
                        writer.push(event)?;
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
                    if let Some(mut event) = parse_event(&item) {
                        enrich_process_name(&mut event, &mut pid_name_cache);
                        writer.push(event)?;
                    }
                }

                guard.clear_ready();
            }
        }
    }

    if !child_wait_done {
        let _ = child_wait.await;
    }

    // Finish writing and close the Parquet file
    let total_events = writer.finish()?;
    info!("Done. Wrote {} events to {}", total_events, args.output);

    // Launch the viewer if we have events and --no-viewer wasn't specified
    if total_events > 0
        && !args.no_viewer
        && let Err(error) = launch_viewer(&args.output, args.port)
    {
        warn!("Skipping viewer launch: {error}");
    }

    Ok(())
}

/// Launch the snitch-viewer subprocess
fn launch_viewer(parquet_file: &str, port: u16) -> Result<()> {
    // Get absolute path to the parquet file
    let parquet_path = Path::new(parquet_file)
        .canonicalize()
        .with_context(|| format!("failed to resolve path: {}", parquet_file))?;

    // Resolve viewer binary from known locations or PATH.
    let viewer_path = resolve_viewer_binary()?;
    let viewer_dir = viewer_path
        .parent()
        .ok_or_else(|| anyhow!("failed to resolve viewer directory"))?;

    info!("Viewer path: {}", viewer_path.display());
    info!(
        "Launching viewer at http://0.0.0.0:{} for {}",
        port,
        parquet_path.display()
    );

    // Spawn the viewer process
    let mut cmd = std::process::Command::new(&viewer_path);
    cmd.arg("--file")
        .arg(&parquet_path)
        .arg("--port")
        .arg(port.to_string())
        .current_dir(viewer_dir)
        // `cargo run` sets CARGO_MANIFEST_DIR. If forwarded, Dioxus treats the app as unbundled
        // and emits absolute source paths for assets (breaking browser loading).
        .env_remove("CARGO_MANIFEST_DIR");

    // Run in foreground so user can Ctrl-C to stop
    let status = cmd
        .status()
        .with_context(|| format!("failed to run snitch-viewer: {:?}", viewer_path))?;

    if !status.success() {
        warn!("snitch-viewer exited with status: {}", status);
    }

    Ok(())
}

fn resolve_viewer_binary() -> Result<PathBuf> {
    if let Some(path) = find_existing_viewer_binary() {
        return Ok(path);
    }

    Err(anyhow!(
        "snitch-viewer not found (or missing fullstack web assets) in PATH/known locations; trace \
was saved, but viewer was not launched. Build it with: dx bundle --platform server --fullstack \
--release -p snitch-viewer"
    ))
}

fn find_existing_viewer_binary() -> Option<PathBuf> {
    let mut candidates = Vec::new();

    // Prefer Dioxus bundle outputs in the current workspace.
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(
            cwd.join("target")
                .join("dx")
                .join("snitch-viewer")
                .join("release")
                .join("web")
                .join("snitch-viewer"),
        );
        candidates.push(
            cwd.join("target")
                .join("dx")
                .join("snitch-viewer")
                .join("debug")
                .join("web")
                .join("snitch-viewer"),
        );
    }

    // Then check colocated binaries for packaged distributions.
    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
    {
        candidates.push(exe_dir.join("snitch-viewer"));
        candidates.push(exe_dir.join("web").join("snitch-viewer"));
        candidates.push(
            exe_dir
                .join("snitch-viewer")
                .join("web")
                .join("snitch-viewer"),
        );
    }

    for path in candidates {
        if path.is_file() && viewer_binary_is_runnable(&path) {
            return Some(path);
        }
    }

    which::which("snitch-viewer")
        .ok()
        .filter(|path| viewer_binary_is_runnable(path))
}

fn viewer_binary_is_runnable(path: &Path) -> bool {
    let Some(viewer_dir) = path.parent() else {
        return false;
    };

    let public_dir = viewer_dir.join("public");
    if !public_dir.is_dir() || !public_dir.join("index.html").is_file() {
        return false;
    }

    let mut has_js = false;
    let mut has_wasm = false;
    let mut stack = vec![public_dir];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }

            if let Some(ext) = path.extension().and_then(|ext| ext.to_str()) {
                match ext {
                    "js" => has_js = true,
                    "wasm" => has_wasm = true,
                    _ => {}
                }
            }

            if has_js && has_wasm {
                return true;
            }
        }
    }

    false
}
