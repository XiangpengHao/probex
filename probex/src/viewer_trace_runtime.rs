use crate::{TraceCommandConfig, run_trace_command, viewer_backend};
use probex_common::viewer_api::{StartTraceRequest, TraceRunStatus, TraceRunStatusResponse};
use std::io::{Error as IoError, ErrorKind};
use std::path::Path;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, watch};

use anyhow::Result as AnyhowResult;

type RuntimeResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

static RUNTIME_STATE: OnceLock<Mutex<TraceRuntimeState>> = OnceLock::new();

struct ActiveTraceRun {
    run_id: u64,
    command: Vec<String>,
    output_parquet: String,
    started_at_unix_ms: u64,
    stop_tx: watch::Sender<bool>,
    task: tokio::task::JoinHandle<AnyhowResult<crate::TraceCommandOutcome>>,
}

#[derive(Debug, Clone)]
struct FinishedTraceRun {
    run_id: u64,
    command: Vec<String>,
    output_parquet: String,
    started_at_unix_ms: u64,
    finished_at_unix_ms: u64,
    exit_code: i32,
    success: bool,
    error: Option<String>,
}

#[derive(Default)]
struct TraceRuntimeState {
    next_run_id: u64,
    sequence: u64,
    active: Option<ActiveTraceRun>,
    finished: Option<FinishedTraceRun>,
}

fn state() -> &'static Mutex<TraceRuntimeState> {
    RUNTIME_STATE.get_or_init(|| Mutex::new(TraceRuntimeState::default()))
}

fn now_unix_ms() -> RuntimeResult<u64> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| IoError::other(format!("system clock before unix epoch: {error}")))?;
    Ok(now.as_millis() as u64)
}

fn to_status(
    active: Option<&ActiveTraceRun>,
    finished: Option<&FinishedTraceRun>,
) -> TraceRunStatus {
    if let Some(active) = active {
        return TraceRunStatus::Running {
            run_id: active.run_id,
            command: active.command.clone(),
            output_parquet: active.output_parquet.clone(),
            started_at_unix_ms: active.started_at_unix_ms,
        };
    }
    if let Some(finished) = finished {
        return TraceRunStatus::Finished {
            run_id: finished.run_id,
            command: finished.command.clone(),
            output_parquet: finished.output_parquet.clone(),
            started_at_unix_ms: finished.started_at_unix_ms,
            finished_at_unix_ms: finished.finished_at_unix_ms,
            exit_code: finished.exit_code,
            success: finished.success,
            error: finished.error.clone(),
        };
    }
    TraceRunStatus::Idle
}

fn to_status_response(state: &TraceRuntimeState) -> TraceRunStatusResponse {
    TraceRunStatusResponse {
        sequence: state.sequence,
        status: to_status(state.active.as_ref(), state.finished.as_ref()),
    }
}

fn mark_state_changed(state: &mut TraceRuntimeState) {
    state.sequence = state.sequence.saturating_add(1);
}

async fn refresh_active_run(state: &mut TraceRuntimeState) -> RuntimeResult<()> {
    let is_finished = state
        .active
        .as_ref()
        .is_some_and(|active| active.task.is_finished());
    if !is_finished {
        return Ok(());
    }

    let active = state
        .active
        .take()
        .ok_or_else(|| IoError::other("active trace run missing while refreshing"))?;
    let finished_at_unix_ms = now_unix_ms()?;

    let finished = match active.task.await {
        Ok(Ok(outcome)) => FinishedTraceRun {
            run_id: active.run_id,
            command: active.command,
            output_parquet: outcome.output_path,
            started_at_unix_ms: active.started_at_unix_ms,
            finished_at_unix_ms,
            exit_code: 0,
            success: true,
            error: None,
        },
        Ok(Err(error)) => FinishedTraceRun {
            run_id: active.run_id,
            command: active.command,
            output_parquet: active.output_parquet,
            started_at_unix_ms: active.started_at_unix_ms,
            finished_at_unix_ms,
            exit_code: 1,
            success: false,
            error: Some(error.to_string()),
        },
        Err(error) => FinishedTraceRun {
            run_id: active.run_id,
            command: active.command,
            output_parquet: active.output_parquet,
            started_at_unix_ms: active.started_at_unix_ms,
            finished_at_unix_ms,
            exit_code: 1,
            success: false,
            error: Some(format!("trace task failed: {error}")),
        },
    };

    state.finished = Some(finished);
    mark_state_changed(state);
    Ok(())
}

pub fn initialize() -> RuntimeResult<()> {
    let _ = state();
    Ok(())
}

pub async fn status_wait(
    last_sequence: Option<u64>,
    wait_ms: Option<u64>,
) -> RuntimeResult<TraceRunStatusResponse> {
    let max_wait_ms = wait_ms.unwrap_or(0).min(10_000);
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(max_wait_ms);

    loop {
        {
            let mut state = state().lock().await;
            refresh_active_run(&mut state).await?;
            let response = to_status_response(&state);
            if last_sequence.is_none_or(|seq| seq != response.sequence) {
                return Ok(response);
            }
            if max_wait_ms == 0 || std::time::Instant::now() >= deadline {
                return Ok(response);
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

pub async fn start(request: StartTraceRequest) -> RuntimeResult<TraceRunStatusResponse> {
    if request.program.trim().is_empty() {
        return Err(IoError::new(ErrorKind::InvalidInput, "program must not be empty").into());
    }
    if request.output_parquet.trim().is_empty() {
        return Err(
            IoError::new(ErrorKind::InvalidInput, "output_parquet must not be empty").into(),
        );
    }
    if request.sample_freq_hz == 0 {
        return Err(IoError::new(ErrorKind::InvalidInput, "sample_freq_hz must be > 0").into());
    }

    let mut state = state().lock().await;
    refresh_active_run(&mut state).await?;
    if state.active.is_some() {
        return Err(IoError::new(
            ErrorKind::AlreadyExists,
            "a trace run is already in progress",
        )
        .into());
    }

    let run_id = state.next_run_id;
    state.next_run_id = state.next_run_id.saturating_add(1);
    let started_at_unix_ms = now_unix_ms()?;

    let mut traced_command = Vec::with_capacity(request.args.len() + 1);
    traced_command.push(request.program.clone());
    traced_command.extend(request.args.clone());

    let (stop_tx, stop_rx) = watch::channel(false);
    let config = TraceCommandConfig {
        output: request.output_parquet.clone(),
        sample_freq_hz: request.sample_freq_hz,
        program: request.program,
        args: request.args,
    };
    let task = tokio::spawn(async move { run_trace_command(config, Some(stop_rx), false).await });

    state.finished = None;
    state.active = Some(ActiveTraceRun {
        run_id,
        command: traced_command,
        output_parquet: request.output_parquet,
        started_at_unix_ms,
        stop_tx,
        task,
    });
    mark_state_changed(&mut state);
    Ok(to_status_response(&state))
}

pub async fn stop() -> RuntimeResult<TraceRunStatusResponse> {
    let mut state = state().lock().await;
    refresh_active_run(&mut state).await?;
    let Some(active) = state.active.as_ref() else {
        return Ok(to_status_response(&state));
    };
    let _ = active.stop_tx.send(true);
    mark_state_changed(&mut state);
    Ok(to_status_response(&state))
}

pub async fn load_trace(parquet_path: &Path) -> RuntimeResult<()> {
    viewer_backend::load_trace_file(parquet_path.to_path_buf()).await
}
