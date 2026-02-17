use std::path::Path;

use anyhow::{Context as _, Result, anyhow};
use axum::{
    Json, Router,
    extract::Query,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use probex_common::viewer_api::{LoadTraceRequest, StartTraceRequest};
use rust_embed::Embed;
use serde::Deserialize;

use crate::{viewer_backend, viewer_trace_runtime};

const INDEX_HTML: &str = "index.html";

#[derive(Embed)]
#[folder = "assets/viewer/"]
struct ViewerAssets;

#[derive(Debug, Deserialize)]
struct HistogramQuery {
    start_ns: u64,
    end_ns: u64,
    num_buckets: usize,
}

#[derive(Debug, Deserialize)]
struct EventTypeCountsQuery {
    start_ns: Option<u64>,
    end_ns: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct PidEventTypeCountsQuery {
    pid: u32,
    start_ns: Option<u64>,
    end_ns: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct SyscallLatencyQuery {
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct ProcessEventsQuery {
    start_ns: u64,
    end_ns: u64,
    max_events_per_pid: usize,
}

#[derive(Debug, Deserialize)]
struct EventFlamegraphQuery {
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
    event_type: String,
    max_stacks: usize,
}

#[derive(Debug, Deserialize)]
struct ProbeSchemasPageQuery {
    search: Option<String>,
    category: Option<String>,
    provider: Option<String>,
    kinds: Option<String>,
    source: Option<String>,
    offset: Option<usize>,
    limit: Option<usize>,
    include_fields: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct ProbeSchemaDetailQuery {
    display_name: String,
}

#[derive(Debug, Deserialize)]
struct TraceStatusQuery {
    last_sequence: Option<u64>,
    wait_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct IoStatisticsQuery {
    start_ns: u64,
    end_ns: u64,
    pid: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct EventListQuery {
    start_ns: u64,
    end_ns: u64,
    pid: u32,
    limit: usize,
    offset: usize,
    #[serde(default)]
    event_types: Option<String>,
}

pub async fn launch(parquet_file: &str, port: u16) -> Result<()> {
    let parquet_path = Path::new(parquet_file)
        .canonicalize()
        .with_context(|| format!("failed to resolve path: {}", parquet_file))?;
    viewer_backend::initialize(parquet_path.clone())
        .await
        .map_err(|error| anyhow!("failed to initialize viewer backend: {error}"))?;
    viewer_trace_runtime::initialize()
        .map_err(|error| anyhow!("failed to initialize trace runtime: {error}"))?;
    if ViewerAssets::get(INDEX_HTML).is_none() {
        return Err(anyhow!(
            "embedded viewer assets missing index.html; rebuild probex with bundled frontend assets"
        ));
    }

    let bind_addr = format!("0.0.0.0:{port}");
    let launch_urls = viewer_launch_urls(port);
    let primary_url = launch_urls
        .first()
        .cloned()
        .expect("viewer launch urls should always include localhost");
    let alt_urls = launch_urls.iter().skip(1).cloned().collect::<Vec<String>>();
    if alt_urls.is_empty() {
        log::info!("Launching viewer at {primary_url}");
    } else {
        log::info!("Launching viewer at {primary_url}, {}", alt_urls.join(", "));
    }

    let api_router = Router::new()
        .route("/api/summary", get(get_summary))
        .route("/api/probe_schemas", get(get_probe_schemas))
        .route("/api/probe_schemas_page", get(get_probe_schemas_page))
        .route("/api/probe_schema_detail", get(get_probe_schema_detail))
        .route("/api/trace/status", get(get_trace_status))
        .route("/api/trace/debug", get(get_trace_debug))
        .route("/api/trace/start", post(post_trace_start))
        .route("/api/trace/stop", post(post_trace_stop))
        .route("/api/trace/load", post(post_trace_load))
        .route("/api/histogram", get(get_histogram))
        .route("/api/event_type_counts", get(get_event_type_counts))
        .route("/api/pid_event_type_counts", get(get_pid_event_type_counts))
        .route("/api/syscall_latency_stats", get(get_syscall_latency_stats))
        .route("/api/process_lifetimes", get(get_process_lifetimes))
        .route("/api/process_events", get(get_process_events))
        .route("/api/event_flamegraph", get(get_event_flamegraph))
        .route("/api/custom_events_debug", get(get_custom_events_debug))
        .route("/api/io_statistics", get(get_io_statistics))
        .route("/api/memory_statistics", get(get_memory_statistics))
        .route("/api/event_list", get(get_event_list));

    let app = api_router.fallback(get(static_handler));

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .with_context(|| "viewer server exited unexpectedly")?;

    Ok(())
}

async fn get_summary() -> Response {
    into_json_response(viewer_backend::query_summary().await)
}

async fn get_probe_schemas() -> Response {
    into_json_response(viewer_backend::query_probe_schemas().await)
}

async fn get_probe_schemas_page(Query(query): Query<ProbeSchemasPageQuery>) -> Response {
    let kinds = match query.kinds {
        Some(value) => {
            let mut parsed = Vec::new();
            for raw in value.split(',') {
                let raw = raw.trim();
                if raw.is_empty() {
                    continue;
                }
                match parse_probe_kind(raw) {
                    Ok(kind) => parsed.push(kind),
                    Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
                }
            }
            if parsed.is_empty() {
                None
            } else {
                Some(parsed)
            }
        }
        None => None,
    };
    let source = match query.source {
        Some(value) => match parse_probe_source(&value) {
            Ok(source) => Some(source),
            Err(error) => return (StatusCode::BAD_REQUEST, error).into_response(),
        },
        None => None,
    };

    into_json_response(
        viewer_backend::query_probe_schemas_page(viewer_backend::ProbeSchemasQuery {
            search: query.search,
            category: query.category,
            provider: query.provider,
            kinds,
            source,
            offset: query.offset.unwrap_or(0),
            limit: query.limit.unwrap_or(100),
            include_fields: query.include_fields.unwrap_or(false),
        })
        .await,
    )
}

async fn get_probe_schema_detail(Query(query): Query<ProbeSchemaDetailQuery>) -> Response {
    into_json_response(viewer_backend::query_probe_schema_detail(query.display_name).await)
}

async fn get_trace_status(Query(query): Query<TraceStatusQuery>) -> Response {
    into_json_response(viewer_trace_runtime::status_wait(query.last_sequence, query.wait_ms).await)
}

async fn get_trace_debug() -> Response {
    into_json_response(viewer_trace_runtime::debug_info().await)
}

async fn post_trace_start(Json(request): Json<StartTraceRequest>) -> Response {
    into_json_response(viewer_trace_runtime::start(request).await)
}

async fn post_trace_stop() -> Response {
    into_json_response(viewer_trace_runtime::stop().await)
}

async fn post_trace_load(Json(request): Json<LoadTraceRequest>) -> Response {
    let parquet_path = match Path::new(request.parquet_path.as_str()).canonicalize() {
        Ok(path) => path,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "failed to resolve parquet path '{}': {}",
                    request.parquet_path, error
                ),
            )
                .into_response();
        }
    };
    if let Err(error) = viewer_trace_runtime::load_trace(parquet_path.as_path()).await {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to load parquet trace: {}", error),
        )
            .into_response();
    }
    into_json_response(viewer_backend::query_summary().await)
}

fn parse_probe_kind(value: &str) -> Result<viewer_backend::ProbeSchemaKind, String> {
    match value {
        "tracepoint" => Ok(viewer_backend::ProbeSchemaKind::Tracepoint),
        "fentry" => Ok(viewer_backend::ProbeSchemaKind::Fentry),
        "fexit" => Ok(viewer_backend::ProbeSchemaKind::Fexit),
        _ => Err(format!("invalid kind '{}'", value)),
    }
}

fn parse_probe_source(value: &str) -> Result<viewer_backend::ProbeSchemaSource, String> {
    match value {
        "tracefs" => Ok(viewer_backend::ProbeSchemaSource::TraceFsFormat),
        "btf" => Ok(viewer_backend::ProbeSchemaSource::KernelBtf),
        _ => Err(format!("invalid source '{}'", value)),
    }
}

async fn get_histogram(Query(query): Query<HistogramQuery>) -> Response {
    into_json_response(
        viewer_backend::query_histogram(query.start_ns, query.end_ns, query.num_buckets).await,
    )
}

async fn get_event_type_counts(Query(query): Query<EventTypeCountsQuery>) -> Response {
    into_json_response(viewer_backend::query_event_type_counts(query.start_ns, query.end_ns).await)
}

async fn get_pid_event_type_counts(Query(query): Query<PidEventTypeCountsQuery>) -> Response {
    into_json_response(
        viewer_backend::query_pid_event_type_counts(query.pid, query.start_ns, query.end_ns).await,
    )
}

async fn get_syscall_latency_stats(Query(query): Query<SyscallLatencyQuery>) -> Response {
    into_json_response(
        viewer_backend::query_syscall_latency_stats(query.start_ns, query.end_ns, query.pid).await,
    )
}

async fn get_process_lifetimes() -> Response {
    into_json_response(viewer_backend::query_process_lifetimes().await)
}

async fn get_process_events(Query(query): Query<ProcessEventsQuery>) -> Response {
    into_json_response(
        viewer_backend::query_process_events(
            query.start_ns,
            query.end_ns,
            query.max_events_per_pid,
        )
        .await,
    )
}

async fn get_event_flamegraph(Query(query): Query<EventFlamegraphQuery>) -> Response {
    into_json_response(
        viewer_backend::query_event_flamegraph(
            query.start_ns,
            query.end_ns,
            query.pid,
            query.event_type,
            query.max_stacks,
        )
        .await,
    )
}

async fn get_custom_events_debug() -> Response {
    into_json_response(viewer_backend::query_custom_events_debug().await)
}

async fn get_io_statistics(Query(query): Query<IoStatisticsQuery>) -> Response {
    into_json_response(
        viewer_backend::query_io_statistics(query.start_ns, query.end_ns, query.pid).await,
    )
}

async fn get_memory_statistics(Query(query): Query<IoStatisticsQuery>) -> Response {
    into_json_response(
        viewer_backend::query_memory_statistics(query.start_ns, query.end_ns, query.pid).await,
    )
}

async fn get_event_list(Query(query): Query<EventListQuery>) -> Response {
    let event_types: Vec<String> = query
        .event_types
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| s.split(',').map(|t| t.to_string()).collect())
        .unwrap_or_default();
    into_json_response(
        viewer_backend::query_event_list(
            query.start_ns,
            query.end_ns,
            query.pid,
            query.limit,
            query.offset,
            &event_types,
        )
        .await,
    )
}

fn into_json_response<T>(result: Result<T, Box<dyn std::error::Error + Send + Sync>>) -> Response
where
    T: serde::Serialize,
{
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("query failed: {}", error),
        )
            .into_response(),
    }
}

async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    if path.is_empty() || path == INDEX_HTML {
        return index_html_response();
    }

    if let Some(response) = embedded_asset_response(path) {
        return response;
    }

    // Keep API misses as real 404s; treat non-file routes as SPA paths.
    if path.starts_with("api/") || path.contains('.') {
        return (StatusCode::NOT_FOUND, "404 Not Found").into_response();
    }

    index_html_response()
}

fn index_html_response() -> Response {
    embedded_asset_response(INDEX_HTML).expect("embedded viewer assets must include index.html")
}

fn embedded_asset_response(path: &str) -> Option<Response> {
    ViewerAssets::get(path).map(|asset| {
        (
            [(header::CONTENT_TYPE, asset.metadata.mimetype())],
            asset.data,
        )
            .into_response()
    })
}

fn viewer_launch_urls(port: u16) -> Vec<String> {
    fn push_unique(urls: &mut Vec<String>, url: String) {
        if !urls.iter().any(|existing| existing == &url) {
            urls.push(url);
        }
    }

    let mut urls = Vec::new();
    push_unique(&mut urls, format!("http://localhost:{port}"));

    if let Some(hostname) = detect_hostname() {
        push_unique(&mut urls, format!("http://{hostname}:{port}"));
    }

    urls
}

fn detect_hostname() -> Option<String> {
    fn normalize_hostname(value: &str) -> Option<String> {
        let trimmed = value.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return None;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower == "localhost" || lower == "localhost.localdomain" {
            return None;
        }
        Some(trimmed.to_string())
    }

    if let Ok(value) = std::env::var("HOSTNAME")
        && let Some(hostname) = normalize_hostname(&value)
    {
        return Some(hostname);
    }

    if let Ok(value) = std::env::var("COMPUTERNAME")
        && let Some(hostname) = normalize_hostname(&value)
    {
        return Some(hostname);
    }

    if let Ok(contents) = std::fs::read_to_string("/etc/hostname")
        && let Some(hostname) = normalize_hostname(&contents)
    {
        return Some(hostname);
    }

    None
}
