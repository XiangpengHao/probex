pub use probex_common::viewer_api::{
    CustomEventsDebugResponse, CustomProbeFieldRef, CustomProbeFilter, CustomProbeFilterOp,
    CustomProbeSpec, EventFlamegraphResponse, EventMarker, EventTypeCounts, HistogramResponse,
    ProbeSchema, ProbeSchemaKind, ProbeSchemasPageResponse, ProcessEventsResponse, ProcessLifetime,
    ProcessLifetimesResponse, StartTraceRequest, SyscallLatencyStats, TraceDebugInfo,
    TraceDebugStepStatus, TraceRunStatus, TraceRunStatusResponse, TraceSummary,
    EventListResponse, IoStatistics, IoTypeStats, SizeBucket,
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
            url.push_str(&percent_encode_component(value));
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

async fn post_json<B, T>(path: &str, body: &B) -> ApiResult<T>
where
    B: serde::Serialize + ?Sized,
    T: serde::de::DeserializeOwned,
{
    use gloo_net::http::Request;

    let response = Request::post(path)
        .header("content-type", "application/json")
        .json(body)
        .map_err(|error| error.to_string())?
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

fn percent_encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        let unreserved = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~');
        if unreserved {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push_str(&format!("{:02X}", b));
        }
    }
    out
}

pub async fn get_summary() -> ApiResult<TraceSummary> {
    get_json("/api/summary", &[]).await
}

pub async fn get_probe_schemas_page(
    search: Option<String>,
    category: Option<String>,
    kinds: Option<String>,
    source: Option<String>,
    offset: usize,
    limit: usize,
) -> ApiResult<ProbeSchemasPageResponse> {
    let mut query = vec![("offset", offset.to_string()), ("limit", limit.to_string())];
    if let Some(search) = search {
        query.push(("search", search));
    }
    if let Some(category) = category {
        query.push(("category", category));
    }
    if let Some(kinds) = kinds {
        query.push(("kinds", kinds));
    }
    if let Some(source) = source {
        query.push(("source", source));
    }
    get_json("/api/probe_schemas_page", &query).await
}

pub async fn get_probe_schema_detail(display_name: String) -> ApiResult<ProbeSchema> {
    get_json(
        "/api/probe_schema_detail",
        &[("display_name", display_name)],
    )
    .await
}

pub async fn get_trace_run_status(
    last_sequence: Option<u64>,
    wait_ms: Option<u64>,
) -> ApiResult<TraceRunStatusResponse> {
    let mut query = Vec::new();
    if let Some(last_sequence) = last_sequence {
        query.push(("last_sequence", last_sequence.to_string()));
    }
    if let Some(wait_ms) = wait_ms {
        query.push(("wait_ms", wait_ms.to_string()));
    }
    get_json("/api/trace/status", &query).await
}

pub async fn get_trace_debug_info() -> ApiResult<TraceDebugInfo> {
    get_json("/api/trace/debug", &[]).await
}

pub async fn get_custom_events_debug() -> ApiResult<CustomEventsDebugResponse> {
    get_json("/api/custom_events_debug", &[]).await
}

pub async fn start_trace_run(request: StartTraceRequest) -> ApiResult<TraceRunStatusResponse> {
    post_json("/api/trace/start", &request).await
}

pub async fn stop_trace_run() -> ApiResult<TraceRunStatusResponse> {
    post_json::<_, TraceRunStatusResponse>("/api/trace/stop", &()).await
}

pub async fn load_trace_file(parquet_path: String) -> ApiResult<TraceSummary> {
    post_json(
        "/api/trace/load",
        &probex_common::viewer_api::LoadTraceRequest { parquet_path },
    )
    .await
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
) -> ApiResult<EventListResponse> {
    get_json(
        "/api/event_list",
        &[
            ("start_ns", start_ns.to_string()),
            ("end_ns", end_ns.to_string()),
            ("pid", pid.to_string()),
            ("limit", limit.to_string()),
            ("offset", offset.to_string()),
        ],
    )
    .await
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
