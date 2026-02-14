//! # Probex - eBPF Process Tracing Tool
//!
//! ## Flow Overview
//!
//! ```text
//! 1. STARTUP
//!    probex -- sleep 1
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
//!    │  KERNEL (eBPF)              │   USERSPACE (probex)       │
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
//! | syscall_io_uring_setup_enter | syscalls:sys_enter_io_uring_setup | entries, params_ptr |
//! | syscall_io_uring_setup_exit | syscalls:sys_exit_io_uring_setup | ret |
//! | syscall_io_uring_enter_enter | syscalls:sys_enter_io_uring_enter | fd, to_submit |
//! | syscall_io_uring_enter_exit | syscalls:sys_exit_io_uring_enter | ret |
//! | syscall_io_uring_register_enter | syscalls:sys_enter_io_uring_register | fd, opcode |
//! | syscall_io_uring_register_exit | syscalls:sys_exit_io_uring_register | ret |
//! | cpu_sample | perf_event (cpu clock) | stack sample |

use std::{
    collections::{BTreeMap, HashSet},
    ffi::CString,
    fs::File,
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context as _, Result, anyhow};
use arrow::{
    array::{
        Array, ArrayRef, Int32Builder, Int64Builder, ListBuilder, StringArray, StringBuilder,
        StructBuilder, UInt8Builder, UInt32Array, UInt32Builder, UInt64Array, UInt64Builder,
    },
    datatypes::{DataType, Field, Fields, Schema},
    record_batch::{RecordBatch, RecordBatchReader},
};
use aya::{
    maps::{HashMap, MapData, PerCpuArray, RingBuf, StackTraceMap},
    programs::{
        TracePoint,
        perf_event::{PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy, perf_sw_ids},
    },
    util::kernel_symbols,
};
use clap::{ArgGroup, Parser};
use log::{debug, info, warn};
use nix::{
    sys::{
        signal::{Signal, kill},
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{ForkResult, Pid, fork},
};
use parquet::{
    arrow::{ArrowWriter, arrow_reader::ParquetRecordBatchReaderBuilder},
    basic::Compression,
    file::{metadata::KeyValue, properties::WriterProperties},
};
use probex_common::{
    CPU_SAMPLE_STAT_CALLBACK_TOTAL, CPU_SAMPLE_STAT_EMITTED, CPU_SAMPLE_STAT_FILTERED_NOT_TRACED,
    CPU_SAMPLE_STAT_KERNEL_STACK, CPU_SAMPLE_STAT_NO_STACK, CPU_SAMPLE_STAT_RINGBUF_DROPPED,
    CPU_SAMPLE_STAT_USER_STACK, CPU_SAMPLE_STATS_LEN, CpuSampleEvent, EventHeader, EventType,
    MAX_CPU_SAMPLE_FRAMES, PageFaultEvent, ProcessExitEvent, ProcessForkEvent, STACK_KIND_BOTH,
    STACK_KIND_KERNEL, STACK_KIND_USER, SchedSwitchEvent, SyscallEnterEvent, SyscallExitEvent,
};
use tokio::{io::unix::AsyncFd, signal};

mod viewer_backend;
mod viewer_probe_catalog;
mod viewer_server;
mod viewer_trace_runtime;

/// Batch size for Parquet writes (10,000 events per batch)
const BATCH_SIZE: usize = 10_000;
const PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY: &str = "probex.sample_freq_hz";

#[derive(Parser, Debug)]
#[command(name = "probex")]
#[command(about = "eBPF process tracing tool")]
#[command(version)]
#[command(group(
    ArgGroup::new("mode")
        .args(["view", "command"])
        .required(true)
))]
struct Args {
    /// Output parquet file (default: trace.parquet)
    #[arg(short, long, default_value = "trace.parquet")]
    output: String,

    /// Port for the viewer web interface
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Don't launch the viewer after tracing
    #[arg(long, conflicts_with = "view")]
    no_viewer: bool,

    /// View an existing parquet trace file without tracing a new command
    #[arg(long, value_name = "PARQUET", conflicts_with = "command")]
    view: Option<String>,

    /// Perf-style CPU clock sampling frequency (Hz)
    #[arg(long, value_name = "HZ", default_value_t = 999)]
    sample_freq: u64,

    /// Command to run
    #[arg(
        trailing_var_arg = true,
        allow_hyphen_values = true,
        required_unless_present = "view"
    )]
    command: Vec<String>,
}

/// Flattened event structure for Parquet output.
/// All event types share common fields, with type-specific fields being optional.
#[derive(Default)]
struct Event {
    event_type: &'static str,
    ts_ns: u64,
    pid: u32,
    tgid: u32,
    process_name: Option<String>,
    /// User-space stack id.
    stack_id: Option<i32>,
    /// Kernel-space stack id.
    kernel_stack_id: Option<i32>,
    stack_kind: Option<&'static str>,
    stack_frames: Option<String>,
    stack_trace: Option<String>,
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
    // Optional inline process map snapshot for this event's tgid.
    proc_maps_snapshot: Option<Vec<ProcMapInlineSegment>>,
}

#[derive(Clone, Debug)]
struct ProcMapInlineSegment {
    start_addr: u64,
    end_addr: u64,
    file_offset: u64,
    path: String,
}

fn proc_maps_snapshot_data_type() -> DataType {
    let segment_fields = Fields::from(vec![
        Field::new("start_addr", DataType::UInt64, false),
        Field::new("end_addr", DataType::UInt64, false),
        Field::new("file_offset", DataType::UInt64, false),
        Field::new("path", DataType::Utf8, false),
    ]);
    DataType::List(Arc::new(Field::new(
        "item",
        DataType::Struct(segment_fields),
        true,
    )))
}

/// Creates the Arrow schema for the unified event table
fn create_schema() -> Schema {
    Schema::new(vec![
        Field::new("event_type", DataType::Utf8, false),
        Field::new("ts_ns", DataType::UInt64, false),
        Field::new("pid", DataType::UInt32, false),
        Field::new("tgid", DataType::UInt32, false),
        Field::new("process_name", DataType::Utf8, true),
        Field::new("stack_id", DataType::Int32, true),
        Field::new("kernel_stack_id", DataType::Int32, true),
        Field::new("stack_kind", DataType::Utf8, true),
        Field::new("stack_frames", DataType::Utf8, true),
        Field::new("stack_trace", DataType::Utf8, true),
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
        Field::new("proc_maps_snapshot", proc_maps_snapshot_data_type(), true),
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
    fn new(path: &str, sample_freq_hz: u64) -> Result<Self> {
        let schema = Arc::new(create_schema());
        let file =
            File::create(path).with_context(|| format!("failed to create output file {}", path))?;

        let key_value_metadata = vec![KeyValue::new(
            PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY.to_string(),
            sample_freq_hz.to_string(),
        )];
        let props = WriterProperties::builder()
            .set_compression(Compression::SNAPPY)
            .set_key_value_metadata(Some(key_value_metadata))
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
        let mut tgid_builder = UInt32Builder::with_capacity(batch_len);
        let mut process_name_builder = StringBuilder::with_capacity(batch_len, batch_len * 24);
        let mut stack_id_builder = Int32Builder::with_capacity(batch_len);
        let mut kernel_stack_id_builder = Int32Builder::with_capacity(batch_len);
        let mut stack_kind_builder = StringBuilder::with_capacity(batch_len, batch_len * 8);
        let mut stack_frames_builder = StringBuilder::with_capacity(batch_len, batch_len * 64);
        let mut stack_trace_builder = StringBuilder::with_capacity(batch_len, batch_len * 48);
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
        let proc_map_item_fields = vec![
            Field::new("start_addr", DataType::UInt64, false),
            Field::new("end_addr", DataType::UInt64, false),
            Field::new("file_offset", DataType::UInt64, false),
            Field::new("path", DataType::Utf8, false),
        ];
        let proc_map_item_builder = StructBuilder::new(
            proc_map_item_fields,
            vec![
                Box::new(UInt64Builder::new()),
                Box::new(UInt64Builder::new()),
                Box::new(UInt64Builder::new()),
                Box::new(StringBuilder::new()),
            ],
        );
        let mut proc_maps_snapshot_builder = ListBuilder::new(proc_map_item_builder);

        for event in self.batch.drain(..) {
            event_type_builder.append_value(event.event_type);
            ts_ns_builder.append_value(event.ts_ns);
            pid_builder.append_value(event.pid);
            tgid_builder.append_value(event.tgid);
            process_name_builder.append_option(event.process_name.as_deref());
            stack_id_builder.append_option(event.stack_id);
            kernel_stack_id_builder.append_option(event.kernel_stack_id);
            stack_kind_builder.append_option(event.stack_kind);
            stack_frames_builder.append_option(event.stack_frames.as_deref());
            stack_trace_builder.append_option(event.stack_trace.as_deref());
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
            if let Some(segments) = event.proc_maps_snapshot {
                for segment in segments {
                    proc_maps_snapshot_builder
                        .values()
                        .field_builder::<UInt64Builder>(0)
                        .expect("proc_maps_snapshot.start_addr builder type should match")
                        .append_value(segment.start_addr);
                    proc_maps_snapshot_builder
                        .values()
                        .field_builder::<UInt64Builder>(1)
                        .expect("proc_maps_snapshot.end_addr builder type should match")
                        .append_value(segment.end_addr);
                    proc_maps_snapshot_builder
                        .values()
                        .field_builder::<UInt64Builder>(2)
                        .expect("proc_maps_snapshot.file_offset builder type should match")
                        .append_value(segment.file_offset);
                    proc_maps_snapshot_builder
                        .values()
                        .field_builder::<StringBuilder>(3)
                        .expect("proc_maps_snapshot.path builder type should match")
                        .append_value(segment.path);
                    proc_maps_snapshot_builder.values().append(true);
                }
                proc_maps_snapshot_builder.append(true);
            } else {
                proc_maps_snapshot_builder.append(false);
            }
        }

        let columns: Vec<ArrayRef> = vec![
            Arc::new(event_type_builder.finish()),
            Arc::new(ts_ns_builder.finish()),
            Arc::new(pid_builder.finish()),
            Arc::new(tgid_builder.finish()),
            Arc::new(process_name_builder.finish()),
            Arc::new(stack_id_builder.finish()),
            Arc::new(kernel_stack_id_builder.finish()),
            Arc::new(stack_kind_builder.finish()),
            Arc::new(stack_frames_builder.finish()),
            Arc::new(stack_trace_builder.finish()),
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
            Arc::new(proc_maps_snapshot_builder.finish()),
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

fn stack_kind_from_header(stack_kind: u8) -> Option<&'static str> {
    match stack_kind {
        STACK_KIND_USER => Some("user"),
        STACK_KIND_KERNEL => Some("kernel"),
        STACK_KIND_BOTH => Some("both"),
        _ => None,
    }
}

fn event_base(event_type: &'static str, header: EventHeader) -> Event {
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

fn read_unaligned_from_bytes<T: Copy>(data: &[u8]) -> Option<T> {
    if data.len() < std::mem::size_of::<T>() {
        return None;
    }
    Some(unsafe { std::ptr::read_unaligned(data.as_ptr() as *const T) })
}

/// Parse event from ring buffer data into a flattened Event struct
fn parse_event(data: &[u8]) -> Result<Event> {
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

const STACK_FRAME_LIMIT: usize = 256;

fn format_kernel_ip(ip: u64, symbols: Option<&BTreeMap<u64, String>>) -> String {
    if let Some(symbols) = symbols
        && let Some((addr, name)) = symbols.range(..=ip).next_back()
    {
        let offset = ip.saturating_sub(*addr);
        return if offset == 0 {
            name.clone()
        } else {
            format!("{name}+0x{offset:x}")
        };
    }
    format!("0x{ip:x}")
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProcMapEntry {
    start: u64,
    end: u64,
    offset: u64,
    path: PathBuf,
}

#[derive(Default)]
struct MaterializedStack {
    stack_frames: Option<String>,
    stack_trace: Option<String>,
}

type StackCacheKey = (Option<i32>, Option<i32>, Option<&'static str>);
type StackTraceCache = std::collections::HashMap<StackCacheKey, MaterializedStack>;

type ProcMapsSnapshotIndex =
    std::collections::HashMap<u32, std::collections::BTreeMap<u64, Arc<Vec<ProcMapInlineSegment>>>>;

#[derive(Default)]
struct ProcMapsSnapshotCollector {
    snapshots: ProcMapsSnapshotIndex,
    total_rows: usize,
}

impl ProcMapsSnapshotCollector {
    fn capture(&mut self, tgid: u32, captured_ts_ns: u64, maps: &[ProcMapEntry]) {
        let segments = maps
            .iter()
            .map(|entry| ProcMapInlineSegment {
                start_addr: entry.start,
                end_addr: entry.end,
                file_offset: entry.offset,
                path: entry.path.to_string_lossy().to_string(),
            })
            .collect::<Vec<_>>();
        self.total_rows += segments.len();
        self.snapshots
            .entry(tgid)
            .or_default()
            .insert(captured_ts_ns, Arc::new(segments));
    }

    fn total_rows(&self) -> usize {
        self.total_rows
    }

    fn snapshot_index(&self) -> &ProcMapsSnapshotIndex {
        &self.snapshots
    }
}

fn read_proc_maps(pid: u32) -> Vec<ProcMapEntry> {
    let path = format!("/proc/{pid}/maps");
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    contents.lines().filter_map(parse_proc_map_line).collect()
}

fn parse_proc_map_line(line: &str) -> Option<ProcMapEntry> {
    let mut parts = line.split_whitespace();
    let range = parts.next()?;
    let _perms = parts.next()?;
    let offset_hex = parts.next()?;
    let _dev = parts.next()?;
    let _inode = parts.next()?;
    let raw_path = parts.next()?;

    if raw_path.starts_with('[') {
        return None;
    }

    let path = raw_path
        .strip_suffix("(deleted)")
        .map(str::trim_end)
        .unwrap_or(raw_path);
    if !path.starts_with('/') {
        return None;
    }

    let (start_hex, end_hex) = range.split_once('-')?;
    let start = u64::from_str_radix(start_hex, 16).ok()?;
    let end = u64::from_str_radix(end_hex, 16).ok()?;
    let offset = u64::from_str_radix(offset_hex, 16).ok()?;

    Some(ProcMapEntry {
        start,
        end,
        offset,
        path: PathBuf::from(path),
    })
}

fn maybe_capture_proc_maps_snapshot(
    tgid: u32,
    captured_ts_ns: u64,
    force_snapshot: bool,
    snapshot_cache: &mut std::collections::HashMap<u32, Vec<ProcMapEntry>>,
    snapshot_collector: &mut ProcMapsSnapshotCollector,
) {
    if tgid == 0 {
        return;
    }
    let maps = read_proc_maps(tgid);
    if maps.is_empty() {
        return;
    }

    let changed = snapshot_cache.get(&tgid) != Some(&maps);
    if !force_snapshot && !changed {
        return;
    }

    snapshot_collector.capture(tgid, captured_ts_ns, &maps);
    snapshot_cache.insert(tgid, maps);
}

fn row_requires_inline_proc_maps(stack_kind: Option<&str>, stack_frames: Option<&str>) -> bool {
    matches!(stack_kind, Some("user") | Some("both"))
        && stack_frames.is_some_and(|frames| !frames.is_empty())
}

fn find_inline_segments_for_event(
    snapshot_index: &ProcMapsSnapshotIndex,
    tgid: u32,
    ts_ns: u64,
) -> Option<&[ProcMapInlineSegment]> {
    let snapshots = snapshot_index.get(&tgid)?;
    let (_captured_ts_ns, segments) = snapshots.range(..=ts_ns).next_back()?;
    Some(segments.as_slice())
}

fn embed_proc_maps_snapshots_into_events_parquet(
    events_output_path: &str,
    snapshot_index: &ProcMapsSnapshotIndex,
    sample_freq_hz: u64,
) -> Result<usize> {
    let file = File::open(events_output_path)
        .with_context(|| format!("failed to open events file {}", events_output_path))?;
    let reader_builder = ParquetRecordBatchReaderBuilder::try_new(file)
        .with_context(|| format!("failed to create reader for {}", events_output_path))?;
    let mut reader = reader_builder
        .with_batch_size(BATCH_SIZE)
        .build()
        .with_context(|| format!("failed to build reader for {}", events_output_path))?;

    let schema = reader.schema();
    let proc_maps_snapshot_idx = schema
        .index_of("proc_maps_snapshot")
        .with_context(|| "events schema missing proc_maps_snapshot column")?;
    let tgid_idx = schema
        .index_of("tgid")
        .with_context(|| "events schema missing tgid column")?;
    let ts_ns_idx = schema
        .index_of("ts_ns")
        .with_context(|| "events schema missing ts_ns column")?;
    let stack_kind_idx = schema
        .index_of("stack_kind")
        .with_context(|| "events schema missing stack_kind column")?;
    let stack_frames_idx = schema
        .index_of("stack_frames")
        .with_context(|| "events schema missing stack_frames column")?;

    let tmp_output_path = format!("{events_output_path}.postprocess.tmp");
    let output_file = File::create(&tmp_output_path)
        .with_context(|| format!("failed to create temp output {}", tmp_output_path))?;
    let key_value_metadata = vec![KeyValue::new(
        PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY.to_string(),
        sample_freq_hz.to_string(),
    )];
    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .set_key_value_metadata(Some(key_value_metadata))
        .build();
    let mut writer = ArrowWriter::try_new(output_file, schema.clone(), Some(props))
        .with_context(|| "failed to create post-process parquet writer")?;

    let mut rows_with_snapshot = 0usize;
    for batch in &mut reader {
        let batch = batch.with_context(|| "failed to read events batch")?;

        let tgid_array = batch
            .column(tgid_idx)
            .as_any()
            .downcast_ref::<UInt32Array>()
            .ok_or_else(|| anyhow!("events column tgid has unexpected type"))?;
        let ts_ns_array = batch
            .column(ts_ns_idx)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or_else(|| anyhow!("events column ts_ns has unexpected type"))?;
        let stack_kind_array = batch
            .column(stack_kind_idx)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| anyhow!("events column stack_kind has unexpected type"))?;
        let stack_frames_array = batch
            .column(stack_frames_idx)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| anyhow!("events column stack_frames has unexpected type"))?;

        let proc_map_item_fields = vec![
            Field::new("start_addr", DataType::UInt64, false),
            Field::new("end_addr", DataType::UInt64, false),
            Field::new("file_offset", DataType::UInt64, false),
            Field::new("path", DataType::Utf8, false),
        ];
        let proc_map_item_builder = StructBuilder::new(
            proc_map_item_fields,
            vec![
                Box::new(UInt64Builder::new()),
                Box::new(UInt64Builder::new()),
                Box::new(UInt64Builder::new()),
                Box::new(StringBuilder::new()),
            ],
        );
        let mut proc_maps_snapshot_builder = ListBuilder::new(proc_map_item_builder);

        for row_idx in 0..batch.num_rows() {
            let stack_kind = if stack_kind_array.is_null(row_idx) {
                None
            } else {
                Some(stack_kind_array.value(row_idx))
            };
            let stack_frames = if stack_frames_array.is_null(row_idx) {
                None
            } else {
                Some(stack_frames_array.value(row_idx))
            };
            if !row_requires_inline_proc_maps(stack_kind, stack_frames) {
                proc_maps_snapshot_builder.append(false);
                continue;
            }

            let tgid = tgid_array.value(row_idx);
            if tgid == 0 {
                proc_maps_snapshot_builder.append(false);
                continue;
            }

            let ts_ns = ts_ns_array.value(row_idx);
            let Some(segments) = find_inline_segments_for_event(snapshot_index, tgid, ts_ns) else {
                proc_maps_snapshot_builder.append(false);
                continue;
            };
            if segments.is_empty() {
                proc_maps_snapshot_builder.append(false);
                continue;
            }

            rows_with_snapshot += 1;
            for segment in segments {
                proc_maps_snapshot_builder
                    .values()
                    .field_builder::<UInt64Builder>(0)
                    .expect("proc_maps_snapshot.start_addr builder type should match")
                    .append_value(segment.start_addr);
                proc_maps_snapshot_builder
                    .values()
                    .field_builder::<UInt64Builder>(1)
                    .expect("proc_maps_snapshot.end_addr builder type should match")
                    .append_value(segment.end_addr);
                proc_maps_snapshot_builder
                    .values()
                    .field_builder::<UInt64Builder>(2)
                    .expect("proc_maps_snapshot.file_offset builder type should match")
                    .append_value(segment.file_offset);
                proc_maps_snapshot_builder
                    .values()
                    .field_builder::<StringBuilder>(3)
                    .expect("proc_maps_snapshot.path builder type should match")
                    .append_value(segment.path.as_str());
                proc_maps_snapshot_builder.values().append(true);
            }
            proc_maps_snapshot_builder.append(true);
        }

        let mut columns = batch.columns().to_vec();
        columns[proc_maps_snapshot_idx] = Arc::new(proc_maps_snapshot_builder.finish());
        let rewritten_batch = RecordBatch::try_new(schema.clone(), columns)
            .with_context(|| "failed to construct rewritten events batch")?;
        writer
            .write(&rewritten_batch)
            .with_context(|| "failed to write rewritten events batch")?;
    }

    writer
        .close()
        .with_context(|| "failed to close rewritten events writer")?;
    std::fs::rename(&tmp_output_path, events_output_path).with_context(|| {
        format!(
            "failed to replace {} with post-processed output {}",
            events_output_path, tmp_output_path
        )
    })?;

    Ok(rows_with_snapshot)
}

fn format_stack_frames_hex(frames: &[u64]) -> Option<String> {
    if frames.is_empty() {
        return None;
    }
    Some(
        frames
            .iter()
            .map(|ip| format!("0x{ip:x}"))
            .collect::<Vec<_>>()
            .join(";"),
    )
}

fn is_plausible_user_instruction_ip(ip: u64) -> bool {
    // User-space instruction pointers should never be tiny sentinel values
    // and should stay in the user half of virtual address space.
    (0x1000..(1u64 << 63)).contains(&ip)
}

fn read_stack_frames(
    stack_id: u32,
    is_user_stack: bool,
    stack_traces: &StackTraceMap<MapData>,
) -> Vec<u64> {
    let Ok(stack) = stack_traces.get(&stack_id, 0) else {
        return Vec::new();
    };

    let mut frames: Vec<u64> = stack
        .frames()
        .iter()
        .take(STACK_FRAME_LIMIT)
        .map(|frame| frame.ip)
        .collect();
    if is_user_stack {
        // Aya exposes raw frames as produced by bpf_get_stackid(). Filtering out
        // impossible user IPs here avoids polluting flamegraph roots with junk
        // values when user-space unwinding is partial.
        frames.retain(|ip| is_plausible_user_instruction_ip(*ip));
    }
    frames.reverse();
    frames
}

fn format_kernel_stack_trace(
    frames: &[u64],
    symbols: Option<&BTreeMap<u64, String>>,
) -> Option<String> {
    if frames.is_empty() {
        return None;
    }
    let mut parts = Vec::with_capacity(frames.len() + 1);
    parts.push("[kernel]".to_string());
    parts.extend(frames.iter().map(|ip| format_kernel_ip(*ip, symbols)));
    Some(parts.join(";"))
}

fn materialize_stacks(
    user_stack_id: Option<i32>,
    kernel_stack_id: Option<i32>,
    stack_kind: Option<&'static str>,
    stack_traces: &StackTraceMap<MapData>,
    kernel_syms: Option<&BTreeMap<u64, String>>,
) -> MaterializedStack {
    let user_frames = user_stack_id
        .map(|stack_id| {
            read_stack_frames(
                u32::try_from(stack_id).expect("stack_id should always be non-negative"),
                true,
                stack_traces,
            )
        })
        .unwrap_or_default();
    let kernel_frames = kernel_stack_id
        .map(|stack_id| {
            read_stack_frames(
                u32::try_from(stack_id).expect("kernel_stack_id should always be non-negative"),
                false,
                stack_traces,
            )
        })
        .unwrap_or_default();

    match stack_kind {
        Some("user") => {
            let stack_frames = format_stack_frames_hex(&user_frames);
            let stack_trace = stack_frames
                .as_ref()
                .map(|frames| format!("[user];{frames}"));
            MaterializedStack {
                stack_frames,
                stack_trace,
            }
        }
        Some("kernel") => MaterializedStack {
            stack_frames: format_stack_frames_hex(&kernel_frames),
            stack_trace: format_kernel_stack_trace(&kernel_frames, kernel_syms),
        },
        Some("both") => MaterializedStack {
            // Keep user frames in hex for later userspace symbolization in viewer.
            stack_frames: format_stack_frames_hex(&user_frames),
            // Keep kernel chain pre-symbolized to avoid per-request kernel lookups.
            stack_trace: format_kernel_stack_trace(&kernel_frames, kernel_syms),
        },
        _ => {
            let stack_frames = format_stack_frames_hex(&user_frames);
            MaterializedStack {
                stack_trace: stack_frames.clone(),
                stack_frames,
            }
        }
    }
}

fn enrich_stack_data(
    event: &mut Event,
    stack_traces: &StackTraceMap<MapData>,
    kernel_syms: Option<&BTreeMap<u64, String>>,
    stack_cache: &mut StackTraceCache,
) {
    if event.stack_id.is_none() && event.kernel_stack_id.is_none() {
        return;
    }
    let key = (event.stack_id, event.kernel_stack_id, event.stack_kind);
    if let Some(cached) = stack_cache.get(&key) {
        event.stack_frames = cached.stack_frames.clone();
        event.stack_trace = cached.stack_trace.clone();
        return;
    }

    let materialized = materialize_stacks(
        event.stack_id,
        event.kernel_stack_id,
        event.stack_kind,
        stack_traces,
        kernel_syms,
    );
    event.stack_frames = materialized.stack_frames.clone();
    event.stack_trace = materialized.stack_trace.clone();
    stack_cache.insert(key, materialized);
}

fn should_refresh_maps_for_event(event_type: &str) -> bool {
    matches!(
        event_type,
        "syscall_mmap_enter" | "syscall_munmap_enter" | "syscall_brk_enter" | "process_fork"
    )
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

fn attach_cpu_sampler(ebpf: &mut aya::Ebpf, target_pid: u32, frequency_hz: u64) -> Result<()> {
    if frequency_hz == 0 {
        return Err(anyhow!("--sample-freq must be greater than 0"));
    }

    let program: &mut PerfEvent = ebpf
        .program_mut("cpu_sample")
        .ok_or_else(|| anyhow!("program cpu_sample not found"))?
        .try_into()?;
    program.load()?;

    program.attach(
        PerfTypeId::Software,
        perf_sw_ids::PERF_COUNT_SW_CPU_CLOCK as u64,
        PerfEventScope::OneProcessAnyCpu { pid: target_pid },
        SamplePolicy::Frequency(frequency_hz),
        true,
    )?;

    info!(
        "Attached CPU sampler at {} Hz for pid {} (inherit=true)",
        frequency_hz, target_pid
    );
    Ok(())
}

fn read_cpu_sample_stats(
    stats_map: &PerCpuArray<MapData, [u64; CPU_SAMPLE_STATS_LEN]>,
) -> Result<[u64; CPU_SAMPLE_STATS_LEN]> {
    let per_cpu = stats_map
        .get(&0, 0)
        .context("failed to read CPU_SAMPLE_STATS[0]")?;
    let mut totals = [0u64; CPU_SAMPLE_STATS_LEN];
    for cpu_stats in per_cpu.iter() {
        for (idx, value) in cpu_stats.iter().enumerate() {
            totals[idx] = totals[idx].saturating_add(*value);
        }
    }
    Ok(totals)
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

#[derive(Clone, Debug)]
pub(crate) struct TraceCommandConfig {
    pub output: String,
    pub sample_freq_hz: u64,
    pub program: String,
    pub args: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct TraceCommandOutcome {
    pub total_events: usize,
    pub output_path: String,
}

pub(crate) async fn run_trace_command(
    config: TraceCommandConfig,
    mut stop_signal: Option<tokio::sync::watch::Receiver<bool>>,
    allow_ctrl_c: bool,
) -> Result<TraceCommandOutcome> {
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
        "/probex"
    )))?;

    // Initialize eBPF logger (optional)
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // Spawn child process with SIGSTOP
    let child_pid = spawn_child(&config.program, &config.args)?;
    let child_pid_u32 = child_pid.as_raw() as u32;
    info!("Spawned child process with PID {}", child_pid);

    wait_for_child_stop(child_pid)?;

    let mut child_wait = tokio::task::spawn_blocking(move || waitpid(child_pid, None));

    // Insert child PID into TRACED_PIDS map
    {
        let mut traced_pids: HashMap<_, u32, u8> = HashMap::try_from(
            ebpf.map_mut("TRACED_PIDS")
                .ok_or_else(|| anyhow!("map TRACED_PIDS not found"))?,
        )?;
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
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_io_uring_setup",
        "syscalls",
        "sys_enter_io_uring_setup",
    )?;
    attach_tracepoint(
        &mut ebpf,
        "sys_exit_io_uring_setup",
        "syscalls",
        "sys_exit_io_uring_setup",
    )?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_io_uring_enter",
        "syscalls",
        "sys_enter_io_uring_enter",
    )?;
    attach_tracepoint(
        &mut ebpf,
        "sys_exit_io_uring_enter",
        "syscalls",
        "sys_exit_io_uring_enter",
    )?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_io_uring_register",
        "syscalls",
        "sys_enter_io_uring_register",
    )?;
    attach_tracepoint(
        &mut ebpf,
        "sys_exit_io_uring_register",
        "syscalls",
        "sys_exit_io_uring_register",
    )?;
    let target_pid = u32::try_from(child_pid.as_raw())
        .context("child pid is negative and cannot be used for perf scope")?;
    attach_cpu_sampler(&mut ebpf, target_pid, config.sample_freq_hz)?;

    // Resume child process
    kill(child_pid, Signal::SIGCONT)
        .with_context(|| format!("failed to resume child process {}", child_pid))?;
    info!("Resumed child process {}", child_pid);

    // Create Parquet batch writer
    let mut writer = ParquetBatchWriter::new(&config.output, config.sample_freq_hz)?;
    info!("Writing events to {}", config.output);
    let mut snapshot_collector = ProcMapsSnapshotCollector::default();

    // Stack trace map for resolving stack ids into raw frame addresses.
    let stack_traces: StackTraceMap<_> = StackTraceMap::try_from(
        ebpf.take_map("STACK_TRACES")
            .ok_or_else(|| anyhow!("map STACK_TRACES not found"))?,
    )?;
    let cpu_sample_stats: PerCpuArray<_, [u64; CPU_SAMPLE_STATS_LEN]> = PerCpuArray::try_from(
        ebpf.take_map("CPU_SAMPLE_STATS")
            .ok_or_else(|| anyhow!("map CPU_SAMPLE_STATS not found"))?,
    )?;
    let kernel_syms = kernel_symbols().ok();
    if kernel_syms.is_none() {
        warn!("kernel symbols unavailable; kernel stack frames will be shown as raw addresses");
    }

    // Get ring buffer
    let ring_buf = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow!("map EVENTS not found"))?,
    )?;
    let mut async_ring_buf = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;

    let mut child_wait_done = false;
    let mut pid_name_cache: std::collections::HashMap<u32, Option<String>> =
        std::collections::HashMap::new();
    let mut stack_trace_cache: StackTraceCache = std::collections::HashMap::new();
    let mut proc_map_snapshot_cache: std::collections::HashMap<u32, Vec<ProcMapEntry>> =
        std::collections::HashMap::new();
    let mut seen_tgids: HashSet<u32> = HashSet::new();

    let mut handle_event = |event: &mut Event| -> Result<()> {
        enrich_process_name(event, &mut pid_name_cache);
        enrich_stack_data(
            event,
            &stack_traces,
            kernel_syms.as_ref(),
            &mut stack_trace_cache,
        );

        if event.tgid > 0 {
            let is_first_seen = seen_tgids.insert(event.tgid);
            let should_refresh = is_first_seen || should_refresh_maps_for_event(event.event_type);
            if should_refresh {
                maybe_capture_proc_maps_snapshot(
                    event.tgid,
                    event.ts_ns,
                    should_refresh,
                    &mut proc_map_snapshot_cache,
                    &mut snapshot_collector,
                );
            }
        }

        if event.event_type == "process_fork"
            && let Some(child_pid) = event.child_pid
        {
            maybe_capture_proc_maps_snapshot(
                child_pid,
                event.ts_ns,
                true,
                &mut proc_map_snapshot_cache,
                &mut snapshot_collector,
            );
            seen_tgids.insert(child_pid);
        }

        writer.push(std::mem::take(event))
    };

    // Event loop
    info!("Starting event loop...");

    loop {
        if stop_signal.as_ref().is_some_and(|sig| *sig.borrow()) {
            info!("Received stop request, exiting trace loop...");
            if !child_wait.is_finished() {
                let _ = kill(child_pid, Signal::SIGTERM);
            }
            break;
        }

        let stop_changed = async {
            if let Some(signal) = stop_signal.as_mut() {
                let _ = signal.changed().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        let ctrl_c = async {
            if allow_ctrl_c {
                let _ = signal::ctrl_c().await;
            } else {
                std::future::pending::<()>().await;
            }
        };
        tokio::pin!(stop_changed);
        tokio::pin!(ctrl_c);

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
                    let mut event = parse_event(&item)
                        .with_context(|| "failed to parse ring buffer event while draining")?;
                    handle_event(&mut event)?;
                }
                info!("Child process {} exited", child_pid);
                break;
            }
            _ = &mut stop_changed => {
                info!("Received stop request, exiting...");
                if !child_wait.is_finished() {
                    let _ = kill(child_pid, Signal::SIGTERM);
                }
                break;
            }
            _ = &mut ctrl_c => {
                info!("Received Ctrl-C, exiting...");
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
                    let mut event =
                        parse_event(&item).with_context(|| "failed to parse ring buffer event")?;
                    handle_event(&mut event)?;
                }

                guard.clear_ready();
            }
        }
    }

    if !child_wait_done {
        let _ = child_wait.await;
    }

    match read_cpu_sample_stats(&cpu_sample_stats) {
        Ok(stats) => {
            let callback_total = stats[CPU_SAMPLE_STAT_CALLBACK_TOTAL];
            let filtered = stats[CPU_SAMPLE_STAT_FILTERED_NOT_TRACED];
            let emitted = stats[CPU_SAMPLE_STAT_EMITTED];
            let dropped = stats[CPU_SAMPLE_STAT_RINGBUF_DROPPED];
            let accepted = callback_total.saturating_sub(filtered);
            let drop_pct = if accepted == 0 {
                0.0
            } else {
                (dropped as f64) * 100.0 / (accepted as f64)
            };
            info!(
                "CPU sampler stats: callbacks={}, filtered_not_traced={}, accepted={}, emitted={}, dropped_ringbuf={} ({:.2}%), user_stack={}, kernel_stack={}, no_stack={}",
                callback_total,
                filtered,
                accepted,
                emitted,
                dropped,
                drop_pct,
                stats[CPU_SAMPLE_STAT_USER_STACK],
                stats[CPU_SAMPLE_STAT_KERNEL_STACK],
                stats[CPU_SAMPLE_STAT_NO_STACK],
            );
            if dropped > 0 {
                warn!(
                    "Detected {} cpu_sample drops due to ringbuf reservation failure (traced samples only)",
                    dropped
                );
            }
        }
        Err(error) => warn!("Failed to read CPU sampler stats: {error}"),
    }

    // Finish writing and close the Parquet file
    let total_events = writer.finish()?;
    let total_maps = snapshot_collector.total_rows();
    let mut embedded_snapshot_rows = 0usize;

    if total_events > 0 && total_maps > 0 {
        embedded_snapshot_rows = embed_proc_maps_snapshots_into_events_parquet(
            &config.output,
            snapshot_collector.snapshot_index(),
            config.sample_freq_hz,
        )?;
        info!(
            "Post-processing complete: embedded proc map snapshots into {} event rows",
            embedded_snapshot_rows
        );
    }

    info!("Done. Wrote {} events to {}", total_events, config.output);
    if total_maps > 0 {
        info!(
            "Captured {} proc map rows and embedded {} snapshots into {}",
            total_maps, embedded_snapshot_rows, config.output
        );
    }

    Ok(TraceCommandOutcome {
        total_events,
        output_path: config.output,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    if let Some(parquet_file) = args.view.as_deref() {
        return viewer_server::launch(parquet_file, args.port).await;
    }
    let (program, program_args) = args
        .command
        .split_first()
        .ok_or_else(|| anyhow!("clap invariant violated: missing command in trace mode"))?;
    let outcome = run_trace_command(
        TraceCommandConfig {
            output: args.output.clone(),
            sample_freq_hz: args.sample_freq,
            program: program.clone(),
            args: program_args.to_vec(),
        },
        None,
        true,
    )
    .await?;

    // Launch the viewer if we have events and --no-viewer wasn't specified
    if outcome.total_events > 0 && !args.no_viewer {
        viewer_server::launch(&outcome.output_path, args.port).await?;
    }

    Ok(())
}
