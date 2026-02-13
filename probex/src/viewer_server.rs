use std::path::Path;

use anyhow::{Context as _, Result, anyhow};
use axum::{
    Json, Router,
    extract::Query,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
    routing::get,
};
use rust_embed::Embed;
use serde::Deserialize;

use crate::viewer_backend;

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

pub async fn launch(parquet_file: &str, port: u16) -> Result<()> {
    let parquet_path = Path::new(parquet_file)
        .canonicalize()
        .with_context(|| format!("failed to resolve path: {}", parquet_file))?;

    viewer_backend::initialize(parquet_path.clone())
        .await
        .map_err(|error| anyhow!("failed to initialize viewer backend: {error}"))?;

    let bind_addr = format!("0.0.0.0:{port}");
    let launch_urls = viewer_launch_urls(port);
    let primary_url = launch_urls
        .first()
        .cloned()
        .unwrap_or_else(|| format!("http://localhost:{port}"));
    let alt_urls = launch_urls.iter().skip(1).cloned().collect::<Vec<String>>();
    if alt_urls.is_empty() {
        log::info!("Launching viewer at {primary_url}");
    } else {
        log::info!("Launching viewer at {primary_url}, {}", alt_urls.join(", "));
    }

    let api_router = Router::new()
        .route("/api/summary", get(get_summary))
        .route("/api/histogram", get(get_histogram))
        .route("/api/event_type_counts", get(get_event_type_counts))
        .route("/api/pid_event_type_counts", get(get_pid_event_type_counts))
        .route("/api/syscall_latency_stats", get(get_syscall_latency_stats))
        .route("/api/process_lifetimes", get(get_process_lifetimes))
        .route("/api/process_events", get(get_process_events))
        .route("/api/event_flamegraph", get(get_event_flamegraph));

    let app = api_router.fallback(get(static_handler));

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;

    spawn_browser_open(primary_url.clone());

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(async {
            if tokio::signal::ctrl_c().await.is_ok() {
                log::info!("Received Ctrl-C, shutting down viewer server");
            }
        })
        .await
        .with_context(|| "viewer server exited unexpectedly")?;

    Ok(())
}

async fn get_summary() -> Response {
    into_json_response(viewer_backend::query_summary().await)
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
    match embedded_asset_response(INDEX_HTML) {
        Some(response) => response,
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            "viewer assets are not embedded. Build frontend first with `dx bundle --release --platform web -p probex-viewer`, then rebuild probex.",
        )
            .into_response(),
    }
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

fn spawn_browser_open(url: String) {
    tokio::spawn(async move {
        // Allow the listener to start accepting before opening the browser.
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        if let Err(error) = open_url_in_default_browser(&url) {
            log::debug!("Unable to open browser at {url}: {error}");
        }
    });
}

fn open_url_in_default_browser(url: &str) -> std::io::Result<()> {
    std::process::Command::new("xdg-open")
        .arg(url)
        .spawn()
        .map(|_| ())
}
