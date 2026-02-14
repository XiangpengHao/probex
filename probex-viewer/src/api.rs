use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type ApiResult<T> = Result<T, String>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistogramBucket {
    pub bucket_start_ns: u64,
    pub bucket_end_ns: u64,
    pub count: usize,
    pub counts_by_type: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HistogramResponse {
    pub buckets: Vec<HistogramBucket>,
    pub total_in_range: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct EventTypeCounts {
    pub counts: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct LatencySummary {
    pub count: usize,
    pub avg_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub max_ns: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct SyscallLatencyStats {
    pub read: LatencySummary,
    pub write: LatencySummary,
    pub mmap_alloc_bytes: u64,
    pub munmap_free_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TraceSummary {
    pub total_events: usize,
    pub event_types: Vec<String>,
    pub unique_pids: Vec<u32>,
    pub min_ts_ns: u64,
    pub max_ts_ns: u64,
    pub cpu_sample_frequency_hz: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessLifetime {
    pub pid: u32,
    pub process_name: Option<String>,
    pub parent_pid: Option<u32>,
    pub start_ns: u64,
    pub end_ns: Option<u64>,
    pub exit_code: Option<i32>,
    pub was_forked: bool,
    pub did_exit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessLifetimesResponse {
    pub processes: Vec<ProcessLifetime>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EventMarker {
    pub ts_ns: u64,
    pub event_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessEventsResponse {
    pub events_by_pid: HashMap<u32, Vec<EventMarker>>,
    pub cpu_sample_counts_by_pid: HashMap<u32, Vec<u16>>,
    pub cpu_sample_bucket_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct EventFlamegraphResponse {
    pub event_type: String,
    pub total_samples: usize,
    pub svg: Option<String>,
}

async fn get_json<T>(path: &str, query: &[(&str, String)]) -> ApiResult<T>
where
    T: serde::de::DeserializeOwned,
{
    use gloo_net::http::Request;

    let mut url = path.to_string();
    if !query.is_empty() {
        url.push('?');
        for (idx, (key, value)) in query.iter().enumerate() {
            if idx > 0 {
                url.push('&');
            }
            url.push_str(key);
            url.push('=');
            url.push_str(value);
        }
    }

    let response = Request::get(&url)
        .send()
        .await
        .map_err(|error| error.to_string())?;

    if !response.ok() {
        let status = response.status();
        let text = response
            .text()
            .await
            .map_err(|error| format!("HTTP {status}: failed to read response body: {error}"))?;
        return Err(format!("HTTP {status}: {text}"));
    }

    response
        .json::<T>()
        .await
        .map_err(|error| error.to_string())
}

pub async fn get_summary() -> ApiResult<TraceSummary> {
    get_json("/api/summary", &[]).await
}

pub async fn get_histogram(
    start_ns: u64,
    end_ns: u64,
    num_buckets: usize,
) -> ApiResult<HistogramResponse> {
    get_json(
        "/api/histogram",
        &[
            ("start_ns", start_ns.to_string()),
            ("end_ns", end_ns.to_string()),
            ("num_buckets", num_buckets.to_string()),
        ],
    )
    .await
}

pub async fn get_event_type_counts(
    start_ns: Option<u64>,
    end_ns: Option<u64>,
) -> ApiResult<EventTypeCounts> {
    let mut query = Vec::new();
    if let Some(start_ns) = start_ns {
        query.push(("start_ns", start_ns.to_string()));
    }
    if let Some(end_ns) = end_ns {
        query.push(("end_ns", end_ns.to_string()));
    }
    get_json("/api/event_type_counts", &query).await
}

pub async fn get_pid_event_type_counts(
    pid: u32,
    start_ns: Option<u64>,
    end_ns: Option<u64>,
) -> ApiResult<EventTypeCounts> {
    let mut query = vec![("pid", pid.to_string())];
    if let Some(start_ns) = start_ns {
        query.push(("start_ns", start_ns.to_string()));
    }
    if let Some(end_ns) = end_ns {
        query.push(("end_ns", end_ns.to_string()));
    }
    get_json("/api/pid_event_type_counts", &query).await
}

pub async fn get_syscall_latency_stats(
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
) -> ApiResult<SyscallLatencyStats> {
    let mut query = vec![
        ("start_ns", start_ns.to_string()),
        ("end_ns", end_ns.to_string()),
    ];
    if let Some(pid) = pid {
        query.push(("pid", pid.to_string()));
    }
    get_json("/api/syscall_latency_stats", &query).await
}

pub async fn get_process_lifetimes() -> ApiResult<ProcessLifetimesResponse> {
    get_json("/api/process_lifetimes", &[]).await
}

pub async fn get_process_events(
    start_ns: u64,
    end_ns: u64,
    max_events_per_pid: usize,
) -> ApiResult<ProcessEventsResponse> {
    get_json(
        "/api/process_events",
        &[
            ("start_ns", start_ns.to_string()),
            ("end_ns", end_ns.to_string()),
            ("max_events_per_pid", max_events_per_pid.to_string()),
        ],
    )
    .await
}

pub async fn get_event_flamegraph(
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
    event_type: String,
    max_stacks: usize,
) -> ApiResult<EventFlamegraphResponse> {
    let mut query = vec![
        ("start_ns", start_ns.to_string()),
        ("end_ns", end_ns.to_string()),
        ("event_type", event_type),
        ("max_stacks", max_stacks.to_string()),
    ];
    if let Some(pid) = pid {
        query.push(("pid", pid.to_string()));
    }
    get_json("/api/event_flamegraph", &query).await
}
