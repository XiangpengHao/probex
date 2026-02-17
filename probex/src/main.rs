//! # Probex - eBPF Process Tracing Tool
//!
//! (Flow diagram omitted for brevity - see README)

use anyhow::{Context as _, Result, anyhow};
use aya::{
    maps::{HashMap as AyaHashMap, PerCpuArray, RingBuf, StackTraceMap},
    util::kernel_symbols,
};
use clap::Parser;
use log::{debug, info};
use nix::sys::{
    signal::{Signal, kill},
    wait::{WaitStatus, waitpid},
};
use probex_common::{
    CPU_SAMPLE_STAT_CALLBACK_TOTAL, CPU_SAMPLE_STAT_EMITTED, CPU_SAMPLE_STAT_FILTERED_NOT_TRACED,
    CPU_SAMPLE_STAT_KERNEL_STACK, CPU_SAMPLE_STAT_NO_STACK, CPU_SAMPLE_STAT_RINGBUF_DROPPED,
    CPU_SAMPLE_STAT_USER_STACK, CPU_SAMPLE_STATS_LEN,
};
use std::collections::{HashMap, HashSet};
use tokio::{io::unix::AsyncFd, signal};

mod args;
mod ebpf;
mod event;
mod parsing;
mod process;
mod schema;
mod stacks;
mod viewer_backend;
mod viewer_server;
mod writer;

use args::Args;
use ebpf::{attach_cpu_sampler, attach_tracepoint, read_cpu_sample_stats};
use event::Event;
use parsing::parse_event;
use process::{
    drop_process_privileges, resolve_privilege_drop_target, spawn_child, wait_for_child_stop,
};
use stacks::{
    ProcMapEntry, ProcMapsSnapshotCollector, StackTraceCache, enrich_process_name,
    enrich_stack_data, maybe_capture_proc_maps_snapshot, should_refresh_maps_for_event,
    symbolize_stack_traces_into_events_parquet,
};
use writer::ParquetBatchWriter;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let privilege_drop_target = resolve_privilege_drop_target()?;

    if let Some(parquet_file) = args.view.as_deref() {
        return viewer_server::launch(parquet_file, args.port).await;
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
        "/probex"
    )))?;

    // Initialize eBPF logger (optional)
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        debug!("failed to initialize eBPF logger: {e}");
    }

    // Spawn child process with SIGSTOP
    let (program, program_args) = args
        .command
        .split_first()
        .ok_or_else(|| anyhow!("clap invariant violated: missing command in trace mode"))?;

    let child_pid = spawn_child(program, program_args, privilege_drop_target)?;
    let child_pid_u32 = child_pid.as_raw() as u32;
    info!("Spawned child process with PID {}", child_pid);

    wait_for_child_stop(child_pid)?;

    let mut child_wait = tokio::task::spawn_blocking(move || waitpid(child_pid, None));

    // Insert child PID into TRACED_PIDS map
    {
        let mut traced_pids: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(
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
    attach_tracepoint(&mut ebpf, "sys_enter_fsync", "syscalls", "sys_enter_fsync")?;
    attach_tracepoint(&mut ebpf, "sys_exit_fsync", "syscalls", "sys_exit_fsync")?;
    attach_tracepoint(
        &mut ebpf,
        "sys_enter_fdatasync",
        "syscalls",
        "sys_enter_fdatasync",
    )?;
    attach_tracepoint(
        &mut ebpf,
        "sys_exit_fdatasync",
        "syscalls",
        "sys_exit_fdatasync",
    )?;
    attach_tracepoint(
        &mut ebpf,
        "io_uring_submit_req",
        "io_uring",
        "io_uring_submit_req",
    )?;
    attach_tracepoint(
        &mut ebpf,
        "io_uring_complete",
        "io_uring",
        "io_uring_complete",
    )?;
    let target_pid = u32::try_from(child_pid.as_raw())
        .context("child pid is negative and cannot be used for perf scope")?;
    attach_cpu_sampler(&mut ebpf, target_pid, args.sample_freq)?;

    if let Some(target) = privilege_drop_target {
        drop_process_privileges(target).context("failed to drop runtime privileges")?;
        debug!(
            "Dropped privileges to uid={}, gid={} after eBPF setup",
            target.uid, target.gid
        );
    }

    // Resume child process
    kill(child_pid, Signal::SIGCONT)
        .with_context(|| format!("failed to resume child process {}", child_pid))?;
    debug!("Resumed child process {}", child_pid);

    let output_file = args.output.clone().unwrap_or_else(|| {
        let now = chrono::Local::now();
        format!("probex-{}.parquet", now.format("%Y%m%d-%H%M%S"))
    });

    // Create Parquet batch writer
    let mut writer = ParquetBatchWriter::new(&output_file, args.sample_freq)?;
    debug!("Writing events to {}", output_file);
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

    loop {
        tokio::select! {
            result = &mut child_wait => {
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

    info!("Symbolizing stack traces (this may take a few seconds)...");
    let finalization_stats = symbolize_stack_traces_into_events_parquet(
        &output_file,
        snapshot_collector.snapshot_index(),
        args.sample_freq,
    )
    .await?;
    debug!(
        "Post-processing complete: rows={}, symbolized_user_rows={}, symbolized_mixed_rows={}, mapped_fallback_frames={}, raw_fallback_frames={}",
        finalization_stats.rewritten_rows,
        finalization_stats.symbolized_user_rows,
        finalization_stats.symbolized_mixed_rows,
        finalization_stats.mapped_fallback_frames,
        finalization_stats.raw_fallback_frames,
    );

    info!("Wrote {} events to {}", total_events, output_file);
    debug!("Captured {} proc map rows while tracing", total_maps);

    // Launch the viewer if we have events and --no-viewer wasn't specified
    if total_events > 0 && !args.no_viewer {
        viewer_server::launch(&output_file, args.port).await?;
    }

    Ok(())
}
