use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, anyhow};
use axum::{
    Json, Router,
    extract::Query,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
};
use serde::Deserialize;
use tower_http::services::{ServeDir, ServeFile};

use crate::viewer_backend;

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

    let public_dir = resolve_viewer_public_dir()?;
    let bind_addr = format!("0.0.0.0:{port}");
    log::info!(
        "Launching integrated viewer server at http://{} for {}",
        bind_addr,
        parquet_path.display()
    );

    let api_router = Router::new()
        .route("/api/summary", get(get_summary))
        .route("/api/histogram", get(get_histogram))
        .route("/api/event_type_counts", get(get_event_type_counts))
        .route("/api/pid_event_type_counts", get(get_pid_event_type_counts))
        .route("/api/syscall_latency_stats", get(get_syscall_latency_stats))
        .route("/api/process_lifetimes", get(get_process_lifetimes))
        .route("/api/process_events", get(get_process_events))
        .route("/api/event_flamegraph", get(get_event_flamegraph));

    let index_file = public_dir.join("index.html");
    let static_service = ServeDir::new(public_dir).not_found_service(ServeFile::new(index_file));

    let app = api_router.fallback_service(static_service);

    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .with_context(|| format!("failed to bind {bind_addr}"))?;

    axum::serve(listener, app.into_make_service())
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

fn resolve_viewer_public_dir() -> Result<PathBuf> {
    if let Ok(path) = std::env::var("SNITCH_VIEWER_PUBLIC_DIR") {
        let candidate = PathBuf::from(path);
        if viewer_public_dir_is_valid(&candidate) {
            return Ok(candidate);
        }
    }

    let mut candidates = Vec::new();

    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(
            cwd.join("target")
                .join("dx")
                .join("snitch-viewer")
                .join("release")
                .join("web")
                .join("public"),
        );
        candidates.push(
            cwd.join("target")
                .join("dx")
                .join("snitch-viewer")
                .join("debug")
                .join("web")
                .join("public"),
        );
    }

    if let Ok(exe) = std::env::current_exe()
        && let Some(exe_dir) = exe.parent()
    {
        candidates.push(exe_dir.join("public"));
        candidates.push(exe_dir.join("web").join("public"));
    }

    for candidate in candidates {
        if viewer_public_dir_is_valid(&candidate) {
            return Ok(candidate);
        }
    }

    Err(anyhow!(
        "snitch-viewer web assets not found. Build them with: dx bundle --release --platform web -p snitch-viewer"
    ))
}

fn viewer_public_dir_is_valid(path: &Path) -> bool {
    path.is_dir() && path.join("index.html").is_file()
}
