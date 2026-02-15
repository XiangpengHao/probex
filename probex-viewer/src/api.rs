pub use probex_common::viewer_api::{
    CumulativeMemoryPoint, EventFlamegraphResponse, EventListResponse, EventMarker,
    EventTypeCounts, HistogramResponse, IoStatistics, IoTypeStats, MemoryStatistics,
    ProcessEventsResponse, ProcessLifetime, ProcessLifetimesResponse, SizeBucket,
    SyscallLatencyStats, TraceSummary,
};

pub type ApiResult<T> = Result<T, String>;

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

pub async fn get_event_list(
    start_ns: u64,
    end_ns: u64,
    pid: u32,
    limit: usize,
    offset: usize,
    event_types: &[String],
) -> ApiResult<EventListResponse> {
    let mut query = vec![
        ("start_ns", start_ns.to_string()),
        ("end_ns", end_ns.to_string()),
        ("pid", pid.to_string()),
        ("limit", limit.to_string()),
        ("offset", offset.to_string()),
    ];
    if !event_types.is_empty() {
        query.push(("event_types", event_types.join(",")));
    }
    get_json("/api/event_list", &query).await
}

pub async fn get_io_statistics(
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
) -> ApiResult<IoStatistics> {
    let mut query = vec![
        ("start_ns", start_ns.to_string()),
        ("end_ns", end_ns.to_string()),
    ];
    if let Some(pid) = pid {
        query.push(("pid", pid.to_string()));
    }
    get_json("/api/io_statistics", &query).await
}

pub async fn get_memory_statistics(
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
) -> ApiResult<MemoryStatistics> {
    let mut query = vec![
        ("start_ns", start_ns.to_string()),
        ("end_ns", end_ns.to_string()),
    ];
    if let Some(pid) = pid {
        query.push(("pid", pid.to_string()));
    }
    get_json("/api/memory_statistics", &query).await
}
