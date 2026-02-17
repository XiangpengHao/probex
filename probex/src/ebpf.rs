use anyhow::{Context as _, Result, anyhow};
use aya::{
    maps::{MapData, PerCpuArray},
    programs::{
        TracePoint,
        perf_event::{PerfEvent, PerfEventScope, PerfTypeId, SamplePolicy, perf_sw_ids},
    },
};
use log::debug;
use probex_common::CPU_SAMPLE_STATS_LEN;

/// Attach a tracepoint program
pub fn attach_tracepoint(
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

pub fn attach_cpu_sampler(ebpf: &mut aya::Ebpf, target_pid: u32, frequency_hz: u64) -> Result<()> {
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

pub fn read_cpu_sample_stats(
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
