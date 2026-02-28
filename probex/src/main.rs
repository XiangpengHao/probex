//! # Probex - eBPF Process Tracing Tool
//!
//! (Flow diagram omitted for brevity - see README)

use crate::custom_codegen::{
    CompiledCustomPlan, CompiledCustomProbeKind, CustomProbeRuntimeEvent,
    build_generated_ebpf_binary, compile_custom_probe_plan, generate_custom_probe_source,
    generate_custom_probe_source_preview,
};
use anyhow::{Context as _, Result, anyhow};
use arrow::{
    array::{
        Array, ArrayRef, Int32Builder, Int64Builder, ListBuilder, StringArray, StringBuilder,
        StringViewArray, StringViewBuilder, UInt8Builder, UInt32Array, UInt32Builder, UInt64Array,
        UInt64Builder,
    },
    datatypes::{DataType, Field, Schema},
    record_batch::{RecordBatch, RecordBatchReader},
};
use aya::{
    Btf,
    maps::{HashMap as AyaHashMap, Map, MapData, PerCpuArray, RingBuf, StackTraceMap},
    programs::{
        FEntry, FExit, TracePoint,
        perf_event::{PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy, perf_sw_ids},
    },
    util::kernel_symbols,
};
use clap::Parser;
use log::{debug, info};
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
    IoUringCompleteEvent, MAX_CPU_SAMPLE_FRAMES, PageFaultEvent, ProcessExitEvent,
    ProcessForkEvent, STACK_KIND_BOTH, STACK_KIND_KERNEL, STACK_KIND_USER, SchedSwitchEvent,
    SyscallEnterEvent, SyscallExitEvent,
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    env,
    ffi::CString,
    fs::File,
    os::fd::{AsFd as _, AsRawFd as _, FromRawFd as _, OwnedFd},
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::{io::unix::AsyncFd, signal};
use wholesym::{LookupAddress, SymbolManager, SymbolManagerConfig};

mod custom_codegen;
mod privileged_daemon;
mod trace_privilege;
mod tracepoint_format;
mod unix_fd;
mod viewer_backend;
mod viewer_privileged_daemon_client;
mod viewer_probe_catalog;
mod viewer_server;
mod viewer_trace_runtime;

/// Batch size for Parquet writes (10,000 events per batch)
const BATCH_SIZE: usize = 10_000;
const PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY: &str = "probex.sample_freq_hz";
const PARQUET_METADATA_STACK_TRACE_FORMAT_KEY: &str = "probex.stack_trace_format";
const PARQUET_METADATA_CUSTOM_PAYLOAD_SCHEMAS_KEY: &str = "probex.custom_payload_schemas_v1";
const STACK_TRACE_FORMAT_SYMBOLIZED_V1: &str = "symbolized_v1";

#[derive(Parser, Debug)]
#[command(name = "probex")]
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
    #[arg(long, conflicts_with = "view")]
    no_viewer: bool,

    /// View an existing parquet trace file without tracing a new command
    #[arg(long, value_name = "PARQUET", conflicts_with = "command")]
    view: Option<String>,

    /// Perf-style CPU clock sampling frequency (Hz)
    #[arg(long, value_name = "HZ", default_value_t = 999)]
    sample_freq: u64,

    /// Command to run
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<String>,

    /// Internal mode: run privileged daemon on a local Unix socket.
    #[arg(long, hide = true)]
    privileged_daemon: bool,

    /// Socket path used by privileged daemon mode.
    #[arg(long, hide = true, default_value = "/tmp/probex-privileged.sock")]
    privileged_daemon_socket: String,

    /// Owner uid allowed to use privileged daemon socket.
    #[arg(long, hide = true)]
    privileged_daemon_owner_uid: Option<u32>,

    /// Start the privileged daemon upfront (prompts for auth immediately).
    #[arg(long)]
    start_privileged_daemon: bool,
}

/// Flattened event structure for Parquet output.
/// All event types share common fields, with type-specific fields being optional.
#[derive(Clone, Default)]
struct Event {
    event_type: String,
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
    // Dynamic custom payload fields
    custom_schema_id: Option<u32>,
    custom_payload_json: Option<String>,
}

#[derive(Clone, Debug)]
struct ProcMapInlineSegment {
    start_addr: u64,
    end_addr: u64,
    file_offset: u64,
    path: String,
}

/// Creates the Arrow schema for the temporary event table before stack finalization.
fn create_intermediate_schema() -> Schema {
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
        // Dynamic custom payload columns (nullable)
        Field::new("custom_schema_id", DataType::UInt32, true),
        Field::new("custom_payload_json", DataType::Utf8, true),
    ])
}

/// Creates the final Arrow schema for persisted traces.
fn create_final_schema() -> Schema {
    Schema::new(vec![
        Field::new("event_type", DataType::Utf8, false),
        Field::new("ts_ns", DataType::UInt64, false),
        Field::new("pid", DataType::UInt32, false),
        Field::new("tgid", DataType::UInt32, false),
        Field::new("process_name", DataType::Utf8, true),
        Field::new("stack_id", DataType::Int32, true),
        Field::new("kernel_stack_id", DataType::Int32, true),
        Field::new("stack_kind", DataType::Utf8, true),
        Field::new(
            "stack_trace",
            DataType::List(Arc::new(Field::new("item", DataType::Utf8View, true))),
            true,
        ),
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
        // Dynamic custom payload columns (nullable)
        Field::new("custom_schema_id", DataType::UInt32, true),
        Field::new("custom_payload_json", DataType::Utf8, true),
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
    fn new(path: &str, sample_freq_hz: u64, custom_payload_schemas_json: &str) -> Result<Self> {
        let schema = Arc::new(create_intermediate_schema());
        let file = create_output_file(path)?;

        let key_value_metadata = vec![
            KeyValue::new(
                PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY.to_string(),
                sample_freq_hz.to_string(),
            ),
            KeyValue::new(
                PARQUET_METADATA_CUSTOM_PAYLOAD_SCHEMAS_KEY.to_string(),
                custom_payload_schemas_json.to_string(),
            ),
        ];
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
        let mut custom_schema_id_builder = UInt32Builder::with_capacity(batch_len);
        let mut custom_payload_json_builder =
            StringBuilder::with_capacity(batch_len, batch_len * 64);

        for event in self.batch.drain(..) {
            event_type_builder.append_value(&event.event_type);
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
            custom_schema_id_builder.append_option(event.custom_schema_id);
            custom_payload_json_builder.append_option(event.custom_payload_json.as_deref());
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
            Arc::new(custom_schema_id_builder.finish()),
            Arc::new(custom_payload_json_builder.finish()),
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

fn create_output_file(path: &str) -> Result<File> {
    match File::create(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            let output = Path::new(path);
            if !output.exists() {
                return Err(anyhow!("failed to create output file {}: {}", path, error));
            }
            std::fs::remove_file(output).with_context(|| {
                format!(
                    "failed to replace existing output file {} after permission denied",
                    path
                )
            })?;
            File::create(output).with_context(|| format!("failed to recreate output file {}", path))
        }
        Err(error) => Err(anyhow!("failed to create output file {}: {}", path, error)),
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
        event_type: event_type.to_string(),
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
        EventType::IoUringComplete => {
            let event = read_unaligned_from_bytes::<IoUringCompleteEvent>(data)
                .ok_or_else(|| anyhow!("payload too short for IoUringCompleteEvent"))?;
            Ok(Event {
                fd: Some(i64::from(event.opcode)),
                count: Some(event.submit_ts_ns),
                ret: Some(i64::from(event.res)),
                ..event_base("io_uring_complete", event.header)
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
    }
}

fn parse_custom_runtime_event(data: &[u8], plan: &CompiledCustomPlan) -> Result<Option<Event>> {
    let raw = read_unaligned_from_bytes::<CustomProbeRuntimeEvent>(data)
        .ok_or_else(|| anyhow!("custom runtime payload too short"))?;
    let Some(probe) = plan.by_probe_id.get(&raw.probe_id) else {
        return Ok(None);
    };

    #[derive(Serialize)]
    struct CustomPayloadValueJson {
        field_id: u16,
        name: String,
        type_kind: &'static str,
        value_u64: u64,
        value_i64: Option<i64>,
    }

    let mut field_by_id = BTreeMap::new();
    for field in &probe.recorded_fields {
        field_by_id.insert(field.field_id, field);
    }

    let value_count = usize::from(raw.value_count);
    if value_count > raw.values.len() {
        return Err(anyhow!(
            "custom runtime payload declared {} values but max is {}",
            value_count,
            raw.values.len()
        ));
    }
    let mut payload_values = Vec::with_capacity(value_count);
    for idx in 0..value_count {
        let value = raw.values[idx];
        let field = field_by_id.get(&value.field_id).ok_or_else(|| {
            anyhow!(
                "custom runtime payload references unknown field_id {} for probe '{}'",
                value.field_id,
                probe.probe_display_name
            )
        })?;
        let value_i64 = field.signed.then_some(value.value as i64);
        payload_values.push(CustomPayloadValueJson {
            field_id: value.field_id,
            name: field.name.clone(),
            type_kind: if field.signed { "i64" } else { "u64" },
            value_u64: value.value,
            value_i64,
        });
    }
    let custom_payload_json = if payload_values.is_empty() {
        None
    } else {
        Some(
            serde_json::to_string(&payload_values)
                .with_context(|| "failed to encode custom payload values as json")?,
        )
    };

    let event = Event {
        event_type: probe.custom_event_type.clone(),
        ts_ns: raw.header.timestamp_ns,
        pid: raw.header.pid,
        tgid: raw.header.tgid,
        stack_id: (raw.header.stack_id >= 0).then_some(raw.header.stack_id),
        kernel_stack_id: (raw.header.kernel_stack_id >= 0).then_some(raw.header.kernel_stack_id),
        stack_kind: stack_kind_from_header(raw.header.stack_kind),
        cpu: raw.header.cpu,
        custom_schema_id: Some(probe.probe_id),
        custom_payload_json,
        ..Default::default()
    };
    Ok(Some(event))
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

fn find_inline_segments_for_event(
    snapshot_index: &ProcMapsSnapshotIndex,
    tgid: u32,
    ts_ns: u64,
) -> Option<&[ProcMapInlineSegment]> {
    let snapshots = snapshot_index.get(&tgid)?;
    let (_captured_ts_ns, segments) = snapshots.range(..=ts_ns).next_back()?;
    Some(segments.as_slice())
}

fn extract_option_utf8_from_column<'a>(
    column: &'a dyn Array,
    row: usize,
    column_name: &str,
) -> Result<Option<&'a str>> {
    if let Some(arr) = column.as_any().downcast_ref::<StringArray>() {
        return Ok((!arr.is_null(row)).then(|| arr.value(row)));
    }
    if let Some(arr) = column.as_any().downcast_ref::<StringViewArray>() {
        return Ok((!arr.is_null(row)).then(|| arr.value(row)));
    }
    Err(anyhow!("events column {column_name} has unexpected type"))
}

fn mapped_frame_fallback_label(path: &str, file_offset: u64) -> String {
    format!("{path}+0x{file_offset:x}")
}

fn sanitize_stack_trace_label(label: &str) -> String {
    let cleaned = label
        .replace(';', ":")
        .replace(['\n', '\r'], " ")
        .trim()
        .to_string();
    if cleaned.is_empty() {
        "[unknown]".to_string()
    } else {
        cleaned
    }
}

fn labels_to_stack_trace(labels: Vec<String>) -> Option<String> {
    let cleaned = labels
        .into_iter()
        .map(|label| sanitize_stack_trace_label(&label))
        .filter(|label| !label.is_empty())
        .collect::<Vec<_>>();
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned.join(";"))
    }
}

fn parse_stack_trace_labels(stack_trace: &str) -> Vec<String> {
    stack_trace
        .split(';')
        .filter(|label| !label.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_kernel_labels_from_stack_trace(stack_trace: &str) -> Vec<String> {
    let mut labels = Vec::new();
    let mut in_kernel_section = false;
    for frame in stack_trace.split(';').filter(|frame| !frame.is_empty()) {
        if frame == "[kernel]" {
            in_kernel_section = true;
            labels.push(frame.to_string());
            continue;
        }
        if in_kernel_section {
            labels.push(frame.to_string());
        }
    }
    labels
}

fn parse_stack_frames_hex(stack_frames: &str) -> Result<Vec<u64>> {
    let mut frames = Vec::new();
    for token in stack_frames.split(';') {
        let trimmed = token.trim();
        if trimmed.is_empty() {
            continue;
        }
        let hex = trimmed
            .strip_prefix("0x")
            .or_else(|| trimmed.strip_prefix("0X"))
            .unwrap_or(trimmed);
        let ip = u64::from_str_radix(hex, 16)
            .with_context(|| format!("invalid stack frame address '{trimmed}'"))?;
        frames.push(ip);
    }
    Ok(frames)
}

fn find_segment_for_ip(
    segments: &[ProcMapInlineSegment],
    ip: u64,
) -> Option<&ProcMapInlineSegment> {
    segments
        .iter()
        .find(|segment| ip >= segment.start_addr && ip < segment.end_addr)
}

fn symbol_labels_from_address_info(address_info: wholesym::AddressInfo) -> Option<Vec<String>> {
    if let Some(frames) = &address_info.frames {
        let mut labels: Vec<String> = frames
            .iter()
            .filter_map(|frame| {
                frame
                    .function
                    .as_ref()
                    .filter(|function| !function.is_empty())
                    .cloned()
            })
            .collect();
        if !labels.is_empty() {
            labels.reverse();
            return Some(labels);
        }
    }

    if address_info.symbol.name.is_empty() || address_info.symbol.name == "??" {
        None
    } else {
        Some(vec![address_info.symbol.name])
    }
}

struct ExportUserSymbolizer {
    symbol_manager: SymbolManager,
    symbol_cache: std::collections::HashMap<(String, u64), Option<Vec<String>>>,
    symbol_map_cache: std::collections::HashMap<String, Option<wholesym::SymbolMap>>,
}

impl ExportUserSymbolizer {
    fn new() -> Self {
        Self {
            symbol_manager: SymbolManager::with_config(SymbolManagerConfig::default()),
            symbol_cache: std::collections::HashMap::new(),
            symbol_map_cache: std::collections::HashMap::new(),
        }
    }

    fn runtime_file_offset(runtime_ip: u64, map_start: u64, map_file_offset: u64) -> u64 {
        runtime_ip
            .saturating_sub(map_start)
            .saturating_add(map_file_offset)
    }

    async fn ensure_symbol_map_loaded(&mut self, path: &str) {
        if self.symbol_map_cache.contains_key(path) {
            return;
        }
        let symbol_map = self
            .symbol_manager
            .load_symbol_map_for_binary_at_path(Path::new(path), None)
            .await
            .ok();
        self.symbol_map_cache.insert(path.to_string(), symbol_map);
    }

    async fn symbolize_addrs_batch(&mut self, path: &str, addrs: &[u64]) {
        if addrs.is_empty() {
            return;
        }

        let path_key = path.to_string();
        let mut unresolved = Vec::new();
        let mut seen = HashSet::new();
        for addr in addrs {
            if !seen.insert(*addr) {
                continue;
            }
            let cache_key = (path_key.clone(), *addr);
            if self.symbol_cache.contains_key(&cache_key) {
                continue;
            }
            unresolved.push(*addr);
        }

        if unresolved.is_empty() {
            return;
        }

        self.ensure_symbol_map_loaded(path).await;

        let Some(symbol_map) = self
            .symbol_map_cache
            .get(&path_key)
            .and_then(|m| m.as_ref())
        else {
            for addr in unresolved {
                self.symbol_cache.insert((path_key.clone(), addr), None);
            }
            return;
        };

        for addr in unresolved {
            let symbol = symbol_map
                .lookup(LookupAddress::FileOffset(addr))
                .await
                .and_then(symbol_labels_from_address_info);
            self.symbol_cache.insert((path_key.clone(), addr), symbol);
        }
    }

    fn lookup_symbol_labels(&self, path: &str, addr: u64) -> Option<Vec<String>> {
        self.symbol_cache
            .get(&(path.to_string(), addr))
            .cloned()
            .flatten()
    }
}

#[derive(Default)]
struct UserFrameRewriteStats {
    mapped_fallback_frames: usize,
    raw_fallback_frames: usize,
}

#[derive(Default)]
struct StackTraceFinalizationStats {
    rewritten_rows: usize,
    symbolized_user_rows: usize,
    symbolized_mixed_rows: usize,
    mapped_fallback_frames: usize,
    raw_fallback_frames: usize,
}

async fn symbolize_user_frames_for_export(
    frames: &[u64],
    inline_snapshot: Option<&[ProcMapInlineSegment]>,
    symbolizer: &mut ExportUserSymbolizer,
) -> (Vec<String>, UserFrameRewriteStats) {
    let mut labels = Vec::with_capacity(frames.len() + 1);
    labels.push("[user]".to_string());

    let Some(segments) = inline_snapshot else {
        labels.extend(frames.iter().map(|ip| format!("0x{ip:x}")));
        return (
            labels,
            UserFrameRewriteStats {
                raw_fallback_frames: frames.len(),
                ..Default::default()
            },
        );
    };

    if segments.is_empty() {
        labels.extend(frames.iter().map(|ip| format!("0x{ip:x}")));
        return (
            labels,
            UserFrameRewriteStats {
                raw_fallback_frames: frames.len(),
                ..Default::default()
            },
        );
    }

    let mapped_segments: Vec<Option<&ProcMapInlineSegment>> = frames
        .iter()
        .map(|ip| find_segment_for_ip(segments, *ip))
        .collect();

    let mut frame_symbol_keys: Vec<Option<(String, u64)>> = Vec::with_capacity(frames.len());
    let mut unresolved_by_path: std::collections::HashMap<String, Vec<u64>> =
        std::collections::HashMap::new();

    for (ip, maybe_segment) in frames.iter().zip(mapped_segments.iter()) {
        if let Some(segment) = maybe_segment {
            let file_offset = ExportUserSymbolizer::runtime_file_offset(
                *ip,
                segment.start_addr,
                segment.file_offset,
            );
            frame_symbol_keys.push(Some((segment.path.clone(), file_offset)));
            unresolved_by_path
                .entry(segment.path.clone())
                .or_default()
                .push(file_offset);
        } else {
            frame_symbol_keys.push(None);
        }
    }

    for (path, addrs) in unresolved_by_path {
        symbolizer.symbolize_addrs_batch(&path, &addrs).await;
    }

    let mut stats = UserFrameRewriteStats::default();
    for (ip, maybe_key) in frames.iter().zip(frame_symbol_keys.into_iter()) {
        if let Some((path, addr)) = maybe_key {
            if let Some(symbols) = symbolizer.lookup_symbol_labels(&path, addr) {
                labels.extend(symbols);
            } else {
                stats.mapped_fallback_frames += 1;
                labels.push(mapped_frame_fallback_label(&path, addr));
            }
        } else {
            stats.raw_fallback_frames += 1;
            labels.push(format!("0x{ip:x}"));
        }
    }
    (labels, stats)
}

async fn symbolize_stack_traces_into_events_parquet(
    events_output_path: &str,
    snapshot_index: &ProcMapsSnapshotIndex,
    sample_freq_hz: u64,
    custom_payload_schemas_json: &str,
) -> Result<StackTraceFinalizationStats> {
    let file = File::open(events_output_path)
        .with_context(|| format!("failed to open events file {}", events_output_path))?;
    let reader_builder = ParquetRecordBatchReaderBuilder::try_new(file)
        .with_context(|| format!("failed to create reader for {}", events_output_path))?;
    let mut reader = reader_builder
        .with_batch_size(BATCH_SIZE)
        .build()
        .with_context(|| format!("failed to build reader for {}", events_output_path))?;

    let source_schema = reader.schema();
    let tgid_idx = source_schema
        .index_of("tgid")
        .with_context(|| "events schema missing tgid column")?;
    let ts_ns_idx = source_schema
        .index_of("ts_ns")
        .with_context(|| "events schema missing ts_ns column")?;
    let stack_kind_idx = source_schema
        .index_of("stack_kind")
        .with_context(|| "events schema missing stack_kind column")?;
    let stack_frames_idx = source_schema
        .index_of("stack_frames")
        .with_context(|| "events schema missing stack_frames column")?;
    let stack_trace_idx = source_schema
        .index_of("stack_trace")
        .with_context(|| "events schema missing stack_trace column")?;

    let tmp_output_path = format!("{events_output_path}.postprocess.tmp");
    let output_file = File::create(&tmp_output_path)
        .with_context(|| format!("failed to create temp output {}", tmp_output_path))?;
    let key_value_metadata = vec![
        KeyValue::new(
            PARQUET_METADATA_SAMPLE_FREQ_HZ_KEY.to_string(),
            sample_freq_hz.to_string(),
        ),
        KeyValue::new(
            PARQUET_METADATA_STACK_TRACE_FORMAT_KEY.to_string(),
            STACK_TRACE_FORMAT_SYMBOLIZED_V1.to_string(),
        ),
        KeyValue::new(
            PARQUET_METADATA_CUSTOM_PAYLOAD_SCHEMAS_KEY.to_string(),
            custom_payload_schemas_json.to_string(),
        ),
    ];
    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .set_key_value_metadata(Some(key_value_metadata))
        .build();
    let final_schema = Arc::new(create_final_schema());
    let mut writer = ArrowWriter::try_new(output_file, final_schema.clone(), Some(props))
        .with_context(|| "failed to create post-process parquet writer")?;

    let mut symbolizer = ExportUserSymbolizer::new();
    let mut stats = StackTraceFinalizationStats::default();

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
        let stack_kind_column = batch.column(stack_kind_idx).as_ref();
        let stack_frames_column = batch.column(stack_frames_idx).as_ref();
        let stack_trace_column = batch.column(stack_trace_idx).as_ref();
        let mut stack_trace_builder = ListBuilder::new(StringViewBuilder::new());

        for row_idx in 0..batch.num_rows() {
            stats.rewritten_rows += 1;
            let stack_kind =
                extract_option_utf8_from_column(stack_kind_column, row_idx, "stack_kind")?;
            let stack_frames =
                extract_option_utf8_from_column(stack_frames_column, row_idx, "stack_frames")?;
            let current_stack_trace =
                extract_option_utf8_from_column(stack_trace_column, row_idx, "stack_trace")?;
            let tgid = tgid_array.value(row_idx);
            let ts_ns = ts_ns_array.value(row_idx);
            let rewritten_stack_trace = match (stack_kind, stack_frames) {
                (Some("user"), Some(frames_hex)) if !frames_hex.is_empty() => {
                    let frames = parse_stack_frames_hex(frames_hex)?;
                    if frames.is_empty() {
                        labels_to_stack_trace(
                            current_stack_trace
                                .map(parse_stack_trace_labels)
                                .unwrap_or_default(),
                        )
                    } else {
                        let snapshot = if tgid == 0 {
                            None
                        } else {
                            find_inline_segments_for_event(snapshot_index, tgid, ts_ns)
                        };
                        let (labels, row_stats) =
                            symbolize_user_frames_for_export(&frames, snapshot, &mut symbolizer)
                                .await;
                        stats.symbolized_user_rows += 1;
                        stats.mapped_fallback_frames += row_stats.mapped_fallback_frames;
                        stats.raw_fallback_frames += row_stats.raw_fallback_frames;
                        labels_to_stack_trace(labels)
                    }
                }
                (Some("both"), Some(frames_hex)) if !frames_hex.is_empty() => {
                    let frames = parse_stack_frames_hex(frames_hex)?;
                    if frames.is_empty() {
                        labels_to_stack_trace(
                            current_stack_trace
                                .map(parse_stack_trace_labels)
                                .unwrap_or_default(),
                        )
                    } else {
                        let snapshot = if tgid == 0 {
                            None
                        } else {
                            find_inline_segments_for_event(snapshot_index, tgid, ts_ns)
                        };
                        let (mut labels, row_stats) =
                            symbolize_user_frames_for_export(&frames, snapshot, &mut symbolizer)
                                .await;
                        if let Some(trace) = current_stack_trace {
                            labels.extend(parse_kernel_labels_from_stack_trace(trace));
                        }
                        stats.symbolized_mixed_rows += 1;
                        stats.mapped_fallback_frames += row_stats.mapped_fallback_frames;
                        stats.raw_fallback_frames += row_stats.raw_fallback_frames;
                        labels_to_stack_trace(labels)
                    }
                }
                _ => labels_to_stack_trace(
                    current_stack_trace
                        .map(parse_stack_trace_labels)
                        .unwrap_or_default(),
                ),
            };
            if let Some(rewritten_stack_trace) = rewritten_stack_trace {
                let labels = parse_stack_trace_labels(&rewritten_stack_trace);
                if labels.is_empty() {
                    stack_trace_builder.append(false);
                } else {
                    for label in labels {
                        stack_trace_builder.values().append_value(label);
                    }
                    stack_trace_builder.append(true);
                }
            } else {
                stack_trace_builder.append(false);
            }
        }

        let rewritten_stack_trace_column: ArrayRef = Arc::new(stack_trace_builder.finish());
        let mut final_columns = Vec::with_capacity(final_schema.fields().len());
        for field in final_schema.fields() {
            if field.name() == "stack_trace" {
                final_columns.push(rewritten_stack_trace_column.clone());
                continue;
            }
            let source_idx = source_schema
                .index_of(field.name())
                .with_context(|| format!("events schema missing {} column", field.name()))?;
            final_columns.push(batch.column(source_idx).clone());
        }

        let rewritten_batch = RecordBatch::try_new(final_schema.clone(), final_columns)
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

    Ok(stats)
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
    debug!("Attached tracepoint {}:{}", category, name);
    Ok(())
}

fn attach_fentry(
    ebpf: &mut aya::Ebpf,
    btf: &Btf,
    program_name: &str,
    function: &str,
) -> Result<()> {
    let program: &mut FEntry = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program {} not found", program_name))?
        .try_into()?;
    program.load(function, btf)?;
    program.attach()?;
    debug!("Attached fentry {}", function);
    Ok(())
}

fn attach_fexit(ebpf: &mut aya::Ebpf, btf: &Btf, program_name: &str, function: &str) -> Result<()> {
    let program: &mut FExit = ebpf
        .program_mut(program_name)
        .ok_or_else(|| anyhow!("program {} not found", program_name))?
        .try_into()?;
    program.load(function, btf)?;
    program.attach()?;
    debug!("Attached fexit {}", function);
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

    debug!(
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

#[derive(Clone, Copy, Debug)]
struct PrivilegeDropTarget {
    uid: libc::uid_t,
    gid: libc::gid_t,
}

fn parse_env_id(name: &str) -> Result<Option<u32>> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u32>()
            .map(Some)
            .with_context(|| format!("invalid {name} value '{value}'")),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(anyhow!("failed to read {name}: {err}")),
    }
}

fn resolve_privilege_drop_target() -> Result<Option<PrivilegeDropTarget>> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(None);
    }

    let sudo_uid = parse_env_id("SUDO_UID")?;
    let sudo_gid = parse_env_id("SUDO_GID")?;
    match (sudo_uid, sudo_gid) {
        (Some(uid), Some(gid)) => Ok(Some(PrivilegeDropTarget { uid, gid })),
        (None, None) => {
            debug!(
                "running as root without SUDO_UID/SUDO_GID; staying root for runtime and output files"
            );
            Ok(None)
        }
        _ => Err(anyhow!(
            "running as root but SUDO_UID/SUDO_GID are inconsistent; both must be set to drop privileges"
        )),
    }
}

fn drop_process_privileges(target: PrivilegeDropTarget) -> Result<()> {
    let ret = unsafe { libc::setgroups(0, std::ptr::null()) };
    if ret != 0 {
        return Err(anyhow!(
            "setgroups(0, NULL) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let ret = unsafe { libc::setgid(target.gid) };
    if ret != 0 {
        return Err(anyhow!(
            "setgid({}) failed: {}",
            target.gid,
            std::io::Error::last_os_error()
        ));
    }

    let ret = unsafe { libc::setuid(target.uid) };
    if ret != 0 {
        return Err(anyhow!(
            "setuid({}) failed: {}",
            target.uid,
            std::io::Error::last_os_error()
        ));
    }

    let uid_matches = unsafe { libc::geteuid() == target.uid };
    let gid_matches = unsafe { libc::getegid() == target.gid };
    if !uid_matches || !gid_matches {
        return Err(anyhow!(
            "privilege drop verification failed: euid={}, egid={}, expected uid={}, gid={}",
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            target.uid,
            target.gid
        ));
    }

    Ok(())
}

pub(crate) fn spawn_child(
    program: &str,
    args: &[String],
    privilege_drop: Option<PrivilegeDropTarget>,
) -> Result<Pid> {
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
            if let Some(target) = privilege_drop
                && let Err(error) = drop_process_privileges(target)
            {
                eprintln!("failed to drop child privileges before exec: {error}");
                libc::_exit(126);
            }
            libc::raise(libc::SIGSTOP);
            libc::execvp(argv[0], argv.as_ptr());
            libc::_exit(127);
        },
    }
}

pub(crate) fn wait_for_child_stop(pid: Pid) -> Result<()> {
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
    pub custom_probes: Vec<probex_common::viewer_api::CustomProbeSpec>,
    pub prebuilt_generated_ebpf_path: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct TraceCommandOutcome {
    pub total_events: usize,
    pub output_path: String,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct TraceMapFdBundle {
    pub events_fd: i32,
    pub stack_traces_fd: i32,
    pub cpu_sample_stats_fd: i32,
    pub custom_events_fd: Option<i32>,
}

pub(crate) struct PreparedTraceSession {
    ebpf: aya::Ebpf,
    child_pid: Pid,
    child_wait: tokio::task::JoinHandle<Result<WaitStatus, nix::Error>>,
    custom_probe_plan: CompiledCustomPlan,
    custom_mode: bool,
    custom_payload_schemas_json: String,
    privilege_drop_target: Option<PrivilegeDropTarget>,
}

pub(crate) struct PreparedAttachSession {
    pub ebpf: aya::Ebpf,
    pub custom_mode: bool,
}

fn map_data_ref(map: &Map) -> &MapData {
    match map {
        Map::Array(v) => v,
        Map::BloomFilter(v) => v,
        Map::CpuMap(v) => v,
        Map::DevMap(v) => v,
        Map::DevMapHash(v) => v,
        Map::HashMap(v) => v,
        Map::LpmTrie(v) => v,
        Map::LruHashMap(v) => v,
        Map::PerCpuArray(v) => v,
        Map::PerCpuHashMap(v) => v,
        Map::PerCpuLruHashMap(v) => v,
        Map::PerfEventArray(v) => v,
        Map::ProgramArray(v) => v,
        Map::Queue(v) => v,
        Map::RingBuf(v) => v,
        Map::SockHash(v) => v,
        Map::SockMap(v) => v,
        Map::Stack(v) => v,
        Map::StackTraceMap(v) => v,
        Map::Unsupported(v) => v,
        Map::XskMap(v) => v,
    }
}

fn map_raw_fd(ebpf: &mut aya::Ebpf, map_name: &str) -> Result<i32> {
    let map = ebpf
        .map_mut(map_name)
        .ok_or_else(|| anyhow!("map {map_name} not found"))?;
    Ok(map_data_ref(map).fd().as_fd().as_raw_fd())
}

pub(crate) fn trace_map_fds_from_parts(
    ebpf: &mut aya::Ebpf,
    custom_mode: bool,
) -> Result<TraceMapFdBundle> {
    Ok(TraceMapFdBundle {
        events_fd: map_raw_fd(ebpf, "EVENTS").with_context(|| "failed to resolve EVENTS map fd")?,
        stack_traces_fd: map_raw_fd(ebpf, "STACK_TRACES")
            .with_context(|| "failed to resolve STACK_TRACES map fd")?,
        cpu_sample_stats_fd: map_raw_fd(ebpf, "CPU_SAMPLE_STATS")
            .with_context(|| "failed to resolve CPU_SAMPLE_STATS map fd")?,
        custom_events_fd: if custom_mode {
            Some(
                map_raw_fd(ebpf, "CUSTOM_EVENTS")
                    .with_context(|| "failed to resolve CUSTOM_EVENTS map fd")?,
            )
        } else {
            None
        },
    })
}

fn ring_buf_from_fd(fd: i32) -> Result<RingBuf<MapData>> {
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let map_data = MapData::from_fd(owned)?;
    RingBuf::try_from(Map::RingBuf(map_data)).with_context(|| "failed to create ringbuf from fd")
}

fn stack_trace_map_from_fd(fd: i32) -> Result<StackTraceMap<MapData>> {
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let map_data = MapData::from_fd(owned)?;
    StackTraceMap::try_from(Map::StackTraceMap(map_data))
        .with_context(|| "failed to create stack trace map from fd")
}

fn cpu_sample_stats_from_fd(fd: i32) -> Result<PerCpuArray<MapData, [u64; CPU_SAMPLE_STATS_LEN]>> {
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let map_data = MapData::from_fd(owned)?;
    PerCpuArray::try_from(Map::PerCpuArray(map_data))
        .with_context(|| "failed to create cpu sample stats map from fd")
}

pub(crate) async fn consume_trace_from_map_fds(
    config: TraceCommandConfig,
    custom_probe_plan: CompiledCustomPlan,
    custom_payload_schemas_json: String,
    map_fds: TraceMapFdBundle,
    mut stop_signal: Option<tokio::sync::watch::Receiver<bool>>,
    mut finished_signal: tokio::sync::watch::Receiver<bool>,
) -> Result<TraceCommandOutcome> {
    let custom_mode = !custom_probe_plan.by_probe_id.is_empty();
    let mut writer = ParquetBatchWriter::new(
        &config.output,
        config.sample_freq_hz,
        &custom_payload_schemas_json,
    )?;
    info!("Writing events to {}", config.output);
    let mut snapshot_collector = ProcMapsSnapshotCollector::default();

    let stack_traces = stack_trace_map_from_fd(map_fds.stack_traces_fd)?;
    let cpu_sample_stats = cpu_sample_stats_from_fd(map_fds.cpu_sample_stats_fd)?;
    let kernel_syms = kernel_symbols().ok();
    if kernel_syms.is_none() {
        debug!("kernel symbols unavailable; kernel stack frames will be shown as raw addresses");
    }

    let ring_buf = ring_buf_from_fd(map_fds.events_fd)?;
    let mut async_ring_buf = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;
    let mut custom_async_ring_buf = if let Some(custom_fd) = map_fds.custom_events_fd {
        let custom_ring_buf =
            ring_buf_from_fd(custom_fd).with_context(|| "step=open_custom_events_map_fd failed")?;
        Some(AsyncFd::with_interest(
            custom_ring_buf,
            tokio::io::Interest::READABLE,
        )?)
    } else {
        None
    };

    let mut pid_name_cache: HashMap<u32, Option<String>> = HashMap::new();
    let mut stack_trace_cache: StackTraceCache = HashMap::new();
    let mut proc_map_snapshot_cache: HashMap<u32, Vec<ProcMapEntry>> = HashMap::new();
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
            let should_refresh =
                is_first_seen || should_refresh_maps_for_event(event.event_type.as_str());
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

    loop {
        if stop_signal.as_ref().is_some_and(|sig| *sig.borrow()) {
            return Err(anyhow!("trace stopped by request"));
        }
        if *finished_signal.borrow() {
            while let Some(item) = async_ring_buf.get_mut().next() {
                let mut event = parse_event(&item)
                    .with_context(|| "failed to parse ring buffer event while draining")?;
                handle_event(&mut event)?;
            }
            if let Some(custom_ring) = custom_async_ring_buf.as_mut() {
                while let Some(item) = custom_ring.get_mut().next() {
                    if let Some(mut custom_event) =
                        parse_custom_runtime_event(&item, &custom_probe_plan)?
                    {
                        handle_event(&mut custom_event)?;
                    }
                }
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
        tokio::pin!(stop_changed);

        tokio::select! {
            _ = finished_signal.changed() => {}
            _ = &mut stop_changed => {
                return Err(anyhow!("trace stopped by request"));
            }
            result = async_ring_buf.readable_mut() => {
                let mut guard = result?;
                while let Some(item) = guard.get_inner_mut().next() {
                    let mut event =
                        parse_event(&item).with_context(|| "failed to parse ring buffer event")?;
                    handle_event(&mut event)?;
                }
                if custom_mode
                    && let Some(custom_ring) = custom_async_ring_buf.as_mut()
                {
                    while let Some(item) = custom_ring.get_mut().next() {
                        if let Some(mut custom_event) =
                            parse_custom_runtime_event(&item, &custom_probe_plan)?
                        {
                            handle_event(&mut custom_event)?;
                        }
                    }
                }
                guard.clear_ready();
            }
        }
    }

    match read_cpu_sample_stats(&cpu_sample_stats) {
        Ok(stats) => {
            let total = stats[CPU_SAMPLE_STAT_CALLBACK_TOTAL];
            let filtered = stats[CPU_SAMPLE_STAT_FILTERED_NOT_TRACED];
            let emitted = stats[CPU_SAMPLE_STAT_EMITTED];
            let dropped = stats[CPU_SAMPLE_STAT_RINGBUF_DROPPED];
            let user_stack = stats[CPU_SAMPLE_STAT_USER_STACK];
            let kernel_stack = stats[CPU_SAMPLE_STAT_KERNEL_STACK];
            let no_stack = stats[CPU_SAMPLE_STAT_NO_STACK];
            let drop_pct = if emitted + dropped > 0 {
                (dropped as f64) * 100.0 / ((emitted + dropped) as f64)
            } else {
                0.0
            };
            info!(
                "CPU samples: {} total, {} filtered, {} emitted, {} dropped ({:.1}% loss) | stacks: {} user, {} kernel, {} none",
                total, filtered, emitted, dropped, drop_pct, user_stack, kernel_stack, no_stack
            );
        }
        Err(error) => debug!("Failed to read CPU sampler stats: {error}"),
    }

    let total_events = writer.finish()?;
    let total_maps = snapshot_collector.total_rows();

    debug!("Symbolizing stack traces (this may take a few seconds)...");
    let finalization_stats = symbolize_stack_traces_into_events_parquet(
        &config.output,
        snapshot_collector.snapshot_index(),
        config.sample_freq_hz,
        &custom_payload_schemas_json,
    )
    .await?;
    info!(
        "Post-processing complete: rows={}, symbolized_user_rows={}, symbolized_mixed_rows={}, mapped_fallback_frames={}, raw_fallback_frames={}",
        finalization_stats.rewritten_rows,
        finalization_stats.symbolized_user_rows,
        finalization_stats.symbolized_mixed_rows,
        finalization_stats.mapped_fallback_frames,
        finalization_stats.raw_fallback_frames,
    );

    info!("Wrote {} events to {}", total_events, config.output);
    debug!("Captured {} proc map rows while tracing", total_maps);

    Ok(TraceCommandOutcome {
        total_events,
        output_path: config.output,
    })
}

async fn resolve_custom_probe_schemas(
    specs: &[probex_common::viewer_api::CustomProbeSpec],
) -> Result<std::collections::HashMap<String, probex_common::viewer_api::ProbeSchema>> {
    let mut resolved = std::collections::HashMap::with_capacity(specs.len());
    for spec in specs {
        let schema =
            viewer_probe_catalog::query_probe_schema_detail(spec.probe_display_name.clone())
                .await
                .map_err(|error| {
                    anyhow!(
                        "failed to resolve custom probe '{}': {error}",
                        spec.probe_display_name
                    )
                })?;
        resolved.insert(spec.probe_display_name.clone(), schema);
    }
    Ok(resolved)
}

pub(crate) async fn prepare_trace_session(
    config: &TraceCommandConfig,
) -> Result<PreparedTraceSession> {
    let resolved_custom_probe_schemas =
        resolve_custom_probe_schemas(&config.custom_probes)
            .await
            .with_context(|| "step=resolve_custom_probe_schemas failed")?;
    let custom_probe_plan =
        compile_custom_probe_plan(&config.custom_probes, &resolved_custom_probe_schemas)
            .with_context(|| "step=compile_custom_probe_plan failed")?;
    let custom_payload_schemas_json = custom_probe_plan
        .payload_schemas_json()
        .with_context(|| "step=encode_custom_payload_schemas failed")?;
    if !custom_probe_plan.by_probe_id.is_empty() {
        info!(
            "Custom probes enabled: {} generated probe(s), {} custom probe spec(s)",
            custom_probe_plan.by_probe_id.len(),
            config.custom_probes.len()
        );
    }
    let custom_mode = !custom_probe_plan.by_probe_id.is_empty();
    let privilege_drop_target = resolve_privilege_drop_target()?;
    // Bump the memlock rlimit
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load eBPF program (embedded by default, generated when custom probes are present).
    let mut ebpf = if custom_mode {
        let generated_binary =
            if let Some(prebuilt_path) = config.prebuilt_generated_ebpf_path.as_ref() {
                std::fs::read(prebuilt_path).with_context(|| {
                    format!("step=load_prebuilt_generated_ebpf failed: {prebuilt_path}")
                })?
            } else {
                let generated_source = generate_custom_probe_source(&custom_probe_plan)
                    .with_context(|| "step=generate_rust_code failed")?;
                tokio::task::spawn_blocking(move || build_generated_ebpf_binary(&generated_source))
                    .await
                    .with_context(|| "step=build_generated_ebpf failed: task join error")?
                    .with_context(|| "step=build_generated_ebpf failed")?
            };
        aya::Ebpf::load(&generated_binary).with_context(|| "step=load_ebpf failed")?
    } else {
        aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/probex"
        )))
        .with_context(|| "step=load_ebpf failed")?
    };

    // Initialize eBPF logger (optional)
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        debug!("failed to initialize eBPF logger: {e}");
    }

    // Spawn child process with SIGSTOP
    let child_pid = spawn_child(&config.program, &config.args, privilege_drop_target)
        .with_context(|| "step=spawn_child failed")?;
    let child_pid_u32 = child_pid.as_raw() as u32;
    info!("Spawned child process with PID {}", child_pid);

    wait_for_child_stop(child_pid).with_context(|| "step=wait_child_stop failed")?;

    let child_wait = tokio::task::spawn_blocking(move || waitpid(child_pid, None));

    // Insert child PID into TRACED_PIDS map
    {
        let mut traced_pids: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(
            ebpf.map_mut("TRACED_PIDS")
                .ok_or_else(|| anyhow!("map TRACED_PIDS not found"))?,
        )
        .with_context(|| "step=open_traced_pids_map failed")?;
        traced_pids
            .insert(child_pid_u32, 1, 0)
            .with_context(|| "step=insert_traced_pid failed")?;
        info!("Added PID {} to traced PIDs", child_pid_u32);
    }

    // Attach all built-in tracepoints
    attach_tracepoint(&mut ebpf, "sched_switch", "sched", "sched_switch")
        .with_context(|| "step=attach_tracepoint failed: sched_switch")?;
    attach_tracepoint(
        &mut ebpf,
        "sched_process_fork",
        "sched",
        "sched_process_fork",
    )
    .with_context(|| "step=attach_tracepoint failed: sched_process_fork")?;
    attach_tracepoint(
        &mut ebpf,
        "sched_process_exit",
        "sched",
        "sched_process_exit",
    )
    .with_context(|| "step=attach_tracepoint failed: sched_process_exit")?;
    attach_tracepoint(
        &mut ebpf,
        "page_fault_user",
        "exceptions",
        "page_fault_user",
    )
    .with_context(|| "step=attach_tracepoint failed: page_fault_user")?;
    attach_tracepoint(&mut ebpf, "sys_enter_read", "syscalls", "sys_enter_read")
        .with_context(|| "step=attach_tracepoint failed: sys_enter_read")?;
    attach_tracepoint(&mut ebpf, "sys_exit_read", "syscalls", "sys_exit_read")
        .with_context(|| "step=attach_tracepoint failed: sys_exit_read")?;
    attach_tracepoint(&mut ebpf, "sys_enter_write", "syscalls", "sys_enter_write")
        .with_context(|| "step=attach_tracepoint failed: sys_enter_write")?;
    attach_tracepoint(&mut ebpf, "sys_exit_write", "syscalls", "sys_exit_write")
        .with_context(|| "step=attach_tracepoint failed: sys_exit_write")?;
    attach_tracepoint(&mut ebpf, "sys_enter_mmap", "syscalls", "sys_enter_mmap")
        .with_context(|| "step=attach_tracepoint failed: sys_enter_mmap")?;
    attach_tracepoint(&mut ebpf, "sys_exit_mmap", "syscalls", "sys_exit_mmap")
        .with_context(|| "step=attach_tracepoint failed: sys_exit_mmap")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_munmap",
        "syscalls",
        "sys_enter_munmap",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_enter_munmap")?;
    attach_tracepoint(&mut ebpf, "sys_exit_munmap", "syscalls", "sys_exit_munmap")
        .with_context(|| "step=attach_tracepoint failed: sys_exit_munmap")?;
    attach_tracepoint(&mut ebpf, "sys_enter_brk", "syscalls", "sys_enter_brk")
        .with_context(|| "step=attach_tracepoint failed: sys_enter_brk")?;
    attach_tracepoint(&mut ebpf, "sys_exit_brk", "syscalls", "sys_exit_brk")
        .with_context(|| "step=attach_tracepoint failed: sys_exit_brk")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_io_uring_setup",
        "syscalls",
        "sys_enter_io_uring_setup",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_enter_io_uring_setup")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_exit_io_uring_setup",
        "syscalls",
        "sys_exit_io_uring_setup",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_exit_io_uring_setup")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_io_uring_enter",
        "syscalls",
        "sys_enter_io_uring_enter",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_enter_io_uring_enter")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_exit_io_uring_enter",
        "syscalls",
        "sys_exit_io_uring_enter",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_exit_io_uring_enter")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_io_uring_register",
        "syscalls",
        "sys_enter_io_uring_register",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_enter_io_uring_register")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_exit_io_uring_register",
        "syscalls",
        "sys_exit_io_uring_register",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_exit_io_uring_register")?;
    attach_tracepoint(&mut ebpf, "sys_enter_fsync", "syscalls", "sys_enter_fsync")
        .with_context(|| "step=attach_tracepoint failed: sys_enter_fsync")?;
    attach_tracepoint(&mut ebpf, "sys_exit_fsync", "syscalls", "sys_exit_fsync")
        .with_context(|| "step=attach_tracepoint failed: sys_exit_fsync")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_fdatasync",
        "syscalls",
        "sys_enter_fdatasync",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_enter_fdatasync")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_exit_fdatasync",
        "syscalls",
        "sys_exit_fdatasync",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_exit_fdatasync")?;

    attach_tracepoint(
        &mut ebpf,
        "io_uring_submit_req",
        "io_uring",
        "io_uring_submit_req",
    )
    .with_context(|| "step=attach_tracepoint failed: io_uring_submit_req")?;
    attach_tracepoint(
        &mut ebpf,
        "io_uring_complete",
        "io_uring",
        "io_uring_complete",
    )
    .with_context(|| "step=attach_tracepoint failed: io_uring_complete")?;

    if custom_mode {
        let mut probes = custom_probe_plan
            .by_probe_id
            .values()
            .cloned()
            .collect::<Vec<_>>();
        probes.sort_by_key(|probe| probe.probe_id);
        let mut kernel_btf = None;
        for probe in probes {
            match probe.kind {
                CompiledCustomProbeKind::Tracepoint => {
                    attach_tracepoint(
                        &mut ebpf,
                        probe.program_name.as_str(),
                        probe.category.as_str(),
                        probe.probe_name.as_str(),
                    )
                    .with_context(|| {
                        format!("step=attach_tracepoint failed: {}", probe.program_name)
                    })?;
                }
                CompiledCustomProbeKind::Fentry => {
                    if kernel_btf.is_none() {
                        kernel_btf = Some(Btf::from_sys_fs().with_context(
                            || "step=load_kernel_btf failed for fentry/fexit custom probes",
                        )?);
                    }
                    let btf = kernel_btf
                        .as_ref()
                        .expect("kernel_btf should be initialized before fentry attach");
                    attach_fentry(
                        &mut ebpf,
                        btf,
                        probe.program_name.as_str(),
                        probe.probe_name.as_str(),
                    )
                    .with_context(|| {
                        format!("step=attach_fentry failed: {}", probe.program_name)
                    })?;
                }
                CompiledCustomProbeKind::Fexit => {
                    if kernel_btf.is_none() {
                        kernel_btf = Some(Btf::from_sys_fs().with_context(
                            || "step=load_kernel_btf failed for fentry/fexit custom probes",
                        )?);
                    }
                    let btf = kernel_btf
                        .as_ref()
                        .expect("kernel_btf should be initialized before fexit attach");
                    attach_fexit(
                        &mut ebpf,
                        btf,
                        probe.program_name.as_str(),
                        probe.probe_name.as_str(),
                    )
                    .with_context(|| format!("step=attach_fexit failed: {}", probe.program_name))?;
                }
            }
        }
    }
    let target_pid = u32::try_from(child_pid.as_raw())
        .context("child pid is negative and cannot be used for perf scope")?;
    attach_cpu_sampler(&mut ebpf, target_pid, config.sample_freq_hz)?;

    Ok(PreparedTraceSession {
        ebpf,
        child_pid,
        child_wait,
        custom_probe_plan,
        custom_mode,
        custom_payload_schemas_json,
        privilege_drop_target,
    })
}

pub(crate) async fn prepare_trace_session_for_existing_pid(
    target_pid: u32,
    sample_freq_hz: u64,
    custom_probes: &[probex_common::viewer_api::CustomProbeSpec],
    prebuilt_generated_ebpf_path: Option<String>,
) -> Result<PreparedAttachSession> {
    let resolved_custom_probe_schemas = resolve_custom_probe_schemas(custom_probes)
        .await
        .with_context(|| "step=resolve_custom_probe_schemas failed")?;
    let custom_probe_plan =
        compile_custom_probe_plan(custom_probes, &resolved_custom_probe_schemas)
            .with_context(|| "step=compile_custom_probe_plan failed")?;
    let custom_mode = !custom_probe_plan.by_probe_id.is_empty();
    if custom_mode {
        info!(
            "Custom probes enabled: {} generated probe(s), {} custom probe spec(s)",
            custom_probe_plan.by_probe_id.len(),
            custom_probes.len()
        );
    }

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = if custom_mode {
        let generated_binary = if let Some(prebuilt_path) = prebuilt_generated_ebpf_path.as_ref() {
            std::fs::read(prebuilt_path).with_context(|| {
                format!("step=load_prebuilt_generated_ebpf failed: {prebuilt_path}")
            })?
        } else {
            let generated_source = generate_custom_probe_source(&custom_probe_plan)
                .with_context(|| "step=generate_rust_code failed")?;
            tokio::task::spawn_blocking(move || build_generated_ebpf_binary(&generated_source))
                .await
                .with_context(|| "step=build_generated_ebpf failed: task join error")?
                .with_context(|| "step=build_generated_ebpf failed")?
        };
        aya::Ebpf::load(&generated_binary).with_context(|| "step=load_ebpf failed")?
    } else {
        aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/probex"
        )))
        .with_context(|| "step=load_ebpf failed")?
    };

    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        debug!("failed to initialize eBPF logger: {e}");
    }

    {
        let mut traced_pids: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(
            ebpf.map_mut("TRACED_PIDS")
                .ok_or_else(|| anyhow!("map TRACED_PIDS not found"))?,
        )
        .with_context(|| "step=open_traced_pids_map failed")?;
        traced_pids
            .insert(target_pid, 1, 0)
            .with_context(|| "step=insert_traced_pid failed")?;
    }

    attach_tracepoint(&mut ebpf, "sched_switch", "sched", "sched_switch")
        .with_context(|| "step=attach_tracepoint failed: sched_switch")?;
    attach_tracepoint(
        &mut ebpf,
        "sched_process_fork",
        "sched",
        "sched_process_fork",
    )
    .with_context(|| "step=attach_tracepoint failed: sched_process_fork")?;
    attach_tracepoint(
        &mut ebpf,
        "sched_process_exit",
        "sched",
        "sched_process_exit",
    )
    .with_context(|| "step=attach_tracepoint failed: sched_process_exit")?;
    attach_tracepoint(
        &mut ebpf,
        "page_fault_user",
        "exceptions",
        "page_fault_user",
    )
    .with_context(|| "step=attach_tracepoint failed: page_fault_user")?;
    attach_tracepoint(&mut ebpf, "sys_enter_read", "syscalls", "sys_enter_read")
        .with_context(|| "step=attach_tracepoint failed: sys_enter_read")?;
    attach_tracepoint(&mut ebpf, "sys_exit_read", "syscalls", "sys_exit_read")
        .with_context(|| "step=attach_tracepoint failed: sys_exit_read")?;
    attach_tracepoint(&mut ebpf, "sys_enter_write", "syscalls", "sys_enter_write")
        .with_context(|| "step=attach_tracepoint failed: sys_enter_write")?;
    attach_tracepoint(&mut ebpf, "sys_exit_write", "syscalls", "sys_exit_write")
        .with_context(|| "step=attach_tracepoint failed: sys_exit_write")?;
    attach_tracepoint(&mut ebpf, "sys_enter_mmap", "syscalls", "sys_enter_mmap")
        .with_context(|| "step=attach_tracepoint failed: sys_enter_mmap")?;
    attach_tracepoint(&mut ebpf, "sys_exit_mmap", "syscalls", "sys_exit_mmap")
        .with_context(|| "step=attach_tracepoint failed: sys_exit_mmap")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_munmap",
        "syscalls",
        "sys_enter_munmap",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_enter_munmap")?;
    attach_tracepoint(&mut ebpf, "sys_exit_munmap", "syscalls", "sys_exit_munmap")
        .with_context(|| "step=attach_tracepoint failed: sys_exit_munmap")?;
    attach_tracepoint(&mut ebpf, "sys_enter_brk", "syscalls", "sys_enter_brk")
        .with_context(|| "step=attach_tracepoint failed: sys_enter_brk")?;
    attach_tracepoint(&mut ebpf, "sys_exit_brk", "syscalls", "sys_exit_brk")
        .with_context(|| "step=attach_tracepoint failed: sys_exit_brk")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_io_uring_setup",
        "syscalls",
        "sys_enter_io_uring_setup",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_enter_io_uring_setup")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_exit_io_uring_setup",
        "syscalls",
        "sys_exit_io_uring_setup",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_exit_io_uring_setup")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_io_uring_enter",
        "syscalls",
        "sys_enter_io_uring_enter",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_enter_io_uring_enter")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_exit_io_uring_enter",
        "syscalls",
        "sys_exit_io_uring_enter",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_exit_io_uring_enter")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_io_uring_register",
        "syscalls",
        "sys_enter_io_uring_register",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_enter_io_uring_register")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_exit_io_uring_register",
        "syscalls",
        "sys_exit_io_uring_register",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_exit_io_uring_register")?;
    attach_tracepoint(&mut ebpf, "sys_enter_fsync", "syscalls", "sys_enter_fsync")
        .with_context(|| "step=attach_tracepoint failed: sys_enter_fsync")?;
    attach_tracepoint(&mut ebpf, "sys_exit_fsync", "syscalls", "sys_exit_fsync")
        .with_context(|| "step=attach_tracepoint failed: sys_exit_fsync")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_fdatasync",
        "syscalls",
        "sys_enter_fdatasync",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_enter_fdatasync")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_exit_fdatasync",
        "syscalls",
        "sys_exit_fdatasync",
    )
    .with_context(|| "step=attach_tracepoint failed: sys_exit_fdatasync")?;
    attach_tracepoint(
        &mut ebpf,
        "io_uring_submit_req",
        "io_uring",
        "io_uring_submit_req",
    )
    .with_context(|| "step=attach_tracepoint failed: io_uring_submit_req")?;
    attach_tracepoint(
        &mut ebpf,
        "io_uring_complete",
        "io_uring",
        "io_uring_complete",
    )
    .with_context(|| "step=attach_tracepoint failed: io_uring_complete")?;

    if custom_mode {
        let mut probes = custom_probe_plan
            .by_probe_id
            .values()
            .cloned()
            .collect::<Vec<_>>();
        probes.sort_by_key(|probe| probe.probe_id);
        let mut kernel_btf = None;
        for probe in probes {
            match probe.kind {
                CompiledCustomProbeKind::Tracepoint => {
                    attach_tracepoint(
                        &mut ebpf,
                        probe.program_name.as_str(),
                        probe.category.as_str(),
                        probe.probe_name.as_str(),
                    )
                    .with_context(|| {
                        format!("step=attach_tracepoint failed: {}", probe.program_name)
                    })?;
                }
                CompiledCustomProbeKind::Fentry => {
                    if kernel_btf.is_none() {
                        kernel_btf = Some(Btf::from_sys_fs().with_context(
                            || "step=load_kernel_btf failed for fentry/fexit custom probes",
                        )?);
                    }
                    let btf = kernel_btf
                        .as_ref()
                        .expect("kernel_btf should be initialized before fentry attach");
                    attach_fentry(
                        &mut ebpf,
                        btf,
                        probe.program_name.as_str(),
                        probe.probe_name.as_str(),
                    )
                    .with_context(|| {
                        format!("step=attach_fentry failed: {}", probe.program_name)
                    })?;
                }
                CompiledCustomProbeKind::Fexit => {
                    if kernel_btf.is_none() {
                        kernel_btf = Some(Btf::from_sys_fs().with_context(
                            || "step=load_kernel_btf failed for fentry/fexit custom probes",
                        )?);
                    }
                    let btf = kernel_btf
                        .as_ref()
                        .expect("kernel_btf should be initialized before fexit attach");
                    attach_fexit(
                        &mut ebpf,
                        btf,
                        probe.program_name.as_str(),
                        probe.probe_name.as_str(),
                    )
                    .with_context(|| format!("step=attach_fexit failed: {}", probe.program_name))?;
                }
            }
        }
    }

    attach_cpu_sampler(&mut ebpf, target_pid, sample_freq_hz)?;

    Ok(PreparedAttachSession { ebpf, custom_mode })
}

pub(crate) async fn consume_trace_session(
    config: TraceCommandConfig,
    mut session: PreparedTraceSession,
    mut stop_signal: Option<tokio::sync::watch::Receiver<bool>>,
    allow_ctrl_c: bool,
) -> Result<TraceCommandOutcome> {
    let PreparedTraceSession {
        ebpf,
        child_pid,
        child_wait,
        custom_probe_plan,
        custom_mode,
        custom_payload_schemas_json,
        privilege_drop_target,
    } = &mut session;

    if allow_ctrl_c && let Some(target) = privilege_drop_target {
        drop_process_privileges(*target).context("failed to drop runtime privileges")?;
        debug!(
            "Dropped privileges to uid={}, gid={} after eBPF setup",
            target.uid, target.gid
        );
    } else if !allow_ctrl_c && privilege_drop_target.is_some() {
        debug!("Skipping runtime privilege drop for viewer-managed trace session");
    }

    // Resume child process
    kill(*child_pid, Signal::SIGCONT)
        .with_context(|| format!("failed to resume child process {}", child_pid))?;
    debug!("Resumed child process {}", child_pid);

    // Create Parquet batch writer
    let mut writer = ParquetBatchWriter::new(
        &config.output,
        config.sample_freq_hz,
        custom_payload_schemas_json,
    )?;
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
        debug!("kernel symbols unavailable; kernel stack frames will be shown as raw addresses");
    }

    // Get ring buffer
    let ring_buf = RingBuf::try_from(
        ebpf.take_map("EVENTS")
            .ok_or_else(|| anyhow!("map EVENTS not found"))?,
    )?;
    let mut async_ring_buf = AsyncFd::with_interest(ring_buf, tokio::io::Interest::READABLE)?;
    let mut custom_async_ring_buf = if *custom_mode {
        let custom_ring_buf = RingBuf::try_from(
            ebpf.take_map("CUSTOM_EVENTS")
                .ok_or_else(|| anyhow!("map CUSTOM_EVENTS not found"))?,
        )
        .with_context(|| "step=open_custom_events_map failed")?;
        Some(AsyncFd::with_interest(
            custom_ring_buf,
            tokio::io::Interest::READABLE,
        )?)
    } else {
        None
    };

    let mut child_wait_done = false;
    let mut pid_name_cache: HashMap<u32, Option<String>> = HashMap::new();
    let mut stack_trace_cache: StackTraceCache = HashMap::new();
    let mut proc_map_snapshot_cache: HashMap<u32, Vec<ProcMapEntry>> = HashMap::new();
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
            let should_refresh =
                is_first_seen || should_refresh_maps_for_event(event.event_type.as_str());
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

    loop {
        if stop_signal.as_ref().is_some_and(|sig| *sig.borrow()) {
            info!("Received stop request, exiting trace loop...");
            if !child_wait.is_finished() {
                let _ = kill(*child_pid, Signal::SIGTERM);
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
            result = &mut *child_wait => {
                child_wait_done = true;
                match result {
                    Ok(Ok(WaitStatus::Exited(_, _))) | Ok(Ok(WaitStatus::Signaled(_, _, _))) => {}
                    Ok(Ok(_)) => {}
                    Ok(Err(err)) => debug!("failed to wait on child process {}: {err}", child_pid),
                    Err(err) => debug!("wait task failed for child process {}: {err}", child_pid),
                }

                // Drain any remaining events
                while let Some(item) = async_ring_buf.get_mut().next() {
                    let mut event = parse_event(&item)
                        .with_context(|| "failed to parse ring buffer event while draining")?;
                    handle_event(&mut event)?;
                }
                if let Some(custom_ring) = custom_async_ring_buf.as_mut() {
                    while let Some(item) = custom_ring.get_mut().next() {
                        if let Some(mut custom_event) =
                            parse_custom_runtime_event(&item, custom_probe_plan)?
                        {
                            handle_event(&mut custom_event)?;
                        }
                    }
                }
                info!("Child process {} exited", child_pid);
                break;
            }
            _ = &mut stop_changed => {
                info!("Received stop request, exiting...");
                if !child_wait.is_finished() {
                    let _ = kill(*child_pid, Signal::SIGTERM);
                }
                break;
            }
            _ = &mut ctrl_c => {
                info!("Received Ctrl-C, exiting...");
                if !child_wait.is_finished() {
                    let _ = kill(*child_pid, Signal::SIGTERM);
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
                if let Some(custom_ring) = custom_async_ring_buf.as_mut() {
                    while let Some(item) = custom_ring.get_mut().next() {
                        if let Some(mut custom_event) =
                            parse_custom_runtime_event(&item, custom_probe_plan)?
                        {
                            handle_event(&mut custom_event)?;
                        }
                    }
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
            let total = stats[CPU_SAMPLE_STAT_CALLBACK_TOTAL];
            let filtered = stats[CPU_SAMPLE_STAT_FILTERED_NOT_TRACED];
            let emitted = stats[CPU_SAMPLE_STAT_EMITTED];
            let dropped = stats[CPU_SAMPLE_STAT_RINGBUF_DROPPED];
            let user_stack = stats[CPU_SAMPLE_STAT_USER_STACK];
            let kernel_stack = stats[CPU_SAMPLE_STAT_KERNEL_STACK];
            let no_stack = stats[CPU_SAMPLE_STAT_NO_STACK];
            let drop_pct = if emitted + dropped > 0 {
                (dropped as f64) * 100.0 / ((emitted + dropped) as f64)
            } else {
                0.0
            };
            info!(
                "CPU samples: {} total, {} filtered, {} emitted, {} dropped ({:.1}% loss) | stacks: {} user, {} kernel, {} none",
                total, filtered, emitted, dropped, drop_pct, user_stack, kernel_stack, no_stack
            );
        }
        Err(error) => debug!("Failed to read CPU sampler stats: {error}"),
    }

    // Finish writing and close the Parquet file
    let total_events = writer.finish()?;
    let total_maps = snapshot_collector.total_rows();

    debug!("Symbolizing stack traces (this may take a few seconds)...");
    let finalization_stats = symbolize_stack_traces_into_events_parquet(
        &config.output,
        snapshot_collector.snapshot_index(),
        config.sample_freq_hz,
        custom_payload_schemas_json,
    )
    .await?;
    info!(
        "Post-processing complete: rows={}, symbolized_user_rows={}, symbolized_mixed_rows={}, mapped_fallback_frames={}, raw_fallback_frames={}",
        finalization_stats.rewritten_rows,
        finalization_stats.symbolized_user_rows,
        finalization_stats.symbolized_mixed_rows,
        finalization_stats.mapped_fallback_frames,
        finalization_stats.raw_fallback_frames,
    );

    info!("Wrote {} events to {}", total_events, config.output);
    debug!("Captured {} proc map rows while tracing", total_maps);

    Ok(TraceCommandOutcome {
        total_events,
        output_path: config.output,
    })
}

pub(crate) async fn run_trace_command(
    config: TraceCommandConfig,
    stop_signal: Option<tokio::sync::watch::Receiver<bool>>,
    allow_ctrl_c: bool,
) -> Result<TraceCommandOutcome> {
    let session = prepare_trace_session(&config).await?;
    consume_trace_session(config, session, stop_signal, allow_ctrl_c).await
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    if args.privileged_daemon {
        let owner_uid = args
            .privileged_daemon_owner_uid
            .ok_or_else(|| anyhow!("--privileged-daemon requires --privileged-daemon-owner-uid"))?;
        let mut token_buf = String::new();
        std::io::stdin()
            .read_line(&mut token_buf)
            .with_context(|| "failed to read privileged daemon token from stdin")?;
        let session_token = token_buf.trim().to_string();
        if session_token.is_empty() {
            return Err(anyhow!(
                "privileged daemon requires non-empty token on stdin"
            ));
        }
        return privileged_daemon::run(
            std::path::Path::new(&args.privileged_daemon_socket),
            owner_uid,
            session_token,
        )
        .await;
    }
    if args.start_privileged_daemon {
        viewer_privileged_daemon_client::start_privileged_daemon()
            .await
            .with_context(|| "failed to start privileged daemon")?;
    }
    if let Some(parquet_file) = args.view.as_deref() {
        return viewer_server::launch(parquet_file, args.port).await;
    }
    if args.command.is_empty() {
        if env::var("DISPLAY").is_err() && env::var("WAYLAND_DISPLAY").is_err() {
            info!("No GUI detected; starting privileged daemon proactively");
            viewer_privileged_daemon_client::start_privileged_daemon()
                .await
                .with_context(|| "failed to start privileged daemon (headless heuristic)")?;
        }
        return viewer_server::launch_empty(args.port).await;
    }
    let (program, program_args) = args
        .command
        .split_first()
        .ok_or_else(|| anyhow!("clap invariant violated: missing command in trace mode"))?;
    let config = TraceCommandConfig {
        output: args.output.clone(),
        sample_freq_hz: args.sample_freq,
        program: program.clone(),
        args: program_args.to_vec(),
        custom_probes: Vec::new(),
        prebuilt_generated_ebpf_path: None,
    };
    let outcome = trace_privilege::run_trace_with_privilege_fallback(config, None, true).await?;

    // Launch the viewer if we have events and --no-viewer wasn't specified
    if outcome.total_events > 0 && !args.no_viewer {
        viewer_server::launch(&outcome.output_path, args.port).await?;
    }

    Ok(())
}
