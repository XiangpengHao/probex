use crate::{
    PreparedAttachSession, TraceMapFdBundle, prepare_trace_session_for_existing_pid,
    trace_map_fds_from_parts,
};
use anyhow::{Context as _, Result, anyhow};
use nix::{
    sys::{signal::Signal, signal::kill},
    unistd::Pid,
};
use probex_common::viewer_api::{
    PrivilegedDaemonEnvelope, PrivilegedDaemonRequest, PrivilegedDaemonResponse,
    PrivilegedProbeSchemasQuery, PrivilegedTraceMapFdsResponse, TraceRunStatus,
    TraceRunStatusResponse,
};
use std::os::fd::AsRawFd as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

struct ActiveRun {
    run_id: u64,
    target_pid: u32,
    command: Vec<String>,
    output_parquet: String,
    started_at_unix_ms: u64,
    _session: PreparedAttachSession,
    map_fds: TraceMapFdBundle,
    has_custom_events: bool,
}

struct DaemonState {
    next_run_id: u64,
    sequence: u64,
    active: Option<ActiveRun>,
}

impl DaemonState {
    fn new() -> Self {
        Self {
            next_run_id: 0,
            sequence: 0,
            active: None,
        }
    }
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_millis() as u64)
        .unwrap_or(0)
}

fn status_response(state: &DaemonState) -> TraceRunStatusResponse {
    let status = if let Some(active) = state.active.as_ref() {
        TraceRunStatus::Running {
            run_id: active.run_id,
            command: active.command.clone(),
            output_parquet: active.output_parquet.clone(),
            started_at_unix_ms: active.started_at_unix_ms,
        }
    } else {
        TraceRunStatus::Idle
    };
    TraceRunStatusResponse {
        sequence: state.sequence,
        status,
    }
}

async fn refresh(state: &mut DaemonState) -> Result<()> {
    let _ = state;
    Ok(())
}

fn to_probe_schemas_query(
    query: PrivilegedProbeSchemasQuery,
) -> crate::viewer_probe_catalog::ProbeSchemasQuery {
    crate::viewer_probe_catalog::ProbeSchemasQuery {
        search: query.search,
        category: query.category,
        provider: query.provider,
        kinds: query.kinds,
        source: query.source,
        offset: query.offset,
        limit: query.limit,
        include_fields: query.include_fields,
    }
}

async fn handle_request(
    state: Arc<Mutex<DaemonState>>,
    request: PrivilegedDaemonRequest,
) -> PrivilegedDaemonResponse {
    match request {
        PrivilegedDaemonRequest::AttachTrace {
            target_pid,
            command,
            output_parquet,
            sample_freq_hz,
            custom_probes,
            prebuilt_generated_ebpf_path,
        } => {
            let mut guard = state.lock().await;
            if let Err(error) = refresh(&mut guard).await {
                return PrivilegedDaemonResponse {
                    ok: false,
                    status: Some(status_response(&guard)),
                    probe_schemas_page: None,
                    probe_schema_detail: None,
                    error: Some(format!("failed to refresh daemon state: {error:#}")),
                };
            }
            if guard.active.is_some() {
                return PrivilegedDaemonResponse {
                    ok: false,
                    status: Some(status_response(&guard)),
                    probe_schemas_page: None,
                    probe_schema_detail: None,
                    error: Some("a privileged trace is already running".to_string()),
                };
            }
            let run_id = guard.next_run_id;
            guard.next_run_id = guard.next_run_id.saturating_add(1);
            let started_at_unix_ms = now_unix_ms();
            if let Some(path) = prebuilt_generated_ebpf_path.as_deref() {
                let candidate = std::path::Path::new(path);
                if !candidate.is_absolute() {
                    return PrivilegedDaemonResponse {
                        ok: false,
                        status: Some(status_response(&guard)),
                        probe_schemas_page: None,
                        probe_schema_detail: None,
                        error: Some(format!(
                            "prebuilt_generated_ebpf_path must be absolute, got {}",
                            path
                        )),
                    };
                }
                if !candidate.is_file() {
                    return PrivilegedDaemonResponse {
                        ok: false,
                        status: Some(status_response(&guard)),
                        probe_schemas_page: None,
                        probe_schema_detail: None,
                        error: Some(format!(
                            "prebuilt_generated_ebpf_path does not exist or is not a file: {}",
                            path
                        )),
                    };
                }
            }
            let mut prepared = match prepare_trace_session_for_existing_pid(
                target_pid,
                sample_freq_hz,
                &custom_probes,
                prebuilt_generated_ebpf_path,
            )
            .await
            {
                Ok(session) => session,
                Err(error) => {
                    return PrivilegedDaemonResponse {
                        ok: false,
                        status: Some(status_response(&guard)),
                        probe_schemas_page: None,
                        probe_schema_detail: None,
                        error: Some(format!(
                            "failed to prepare trace session in privileged daemon: {error:#}"
                        )),
                    };
                }
            };
            let map_fds = match trace_map_fds_from_parts(&mut prepared.ebpf, prepared.custom_mode) {
                Ok(fds) => fds,
                Err(error) => {
                    return PrivilegedDaemonResponse {
                        ok: false,
                        status: Some(status_response(&guard)),
                        probe_schemas_page: None,
                        probe_schema_detail: None,
                        error: Some(format!(
                            "failed to extract trace map fds in privileged daemon: {error:#}"
                        )),
                    };
                }
            };
            let has_custom_events = map_fds.custom_events_fd.is_some();
            guard.active = Some(ActiveRun {
                run_id,
                target_pid,
                command,
                output_parquet,
                started_at_unix_ms,
                _session: prepared,
                map_fds,
                has_custom_events,
            });
            guard.sequence = guard.sequence.saturating_add(1);
            PrivilegedDaemonResponse {
                ok: true,
                status: Some(status_response(&guard)),
                probe_schemas_page: None,
                probe_schema_detail: None,
                error: None,
            }
        }
        PrivilegedDaemonRequest::TakeTraceMapFds => {
            let mut guard = state.lock().await;
            if let Err(error) = refresh(&mut guard).await {
                return PrivilegedDaemonResponse {
                    ok: false,
                    status: Some(status_response(&guard)),
                    probe_schemas_page: None,
                    probe_schema_detail: None,
                    error: Some(format!("failed to refresh daemon state: {error:#}")),
                };
            }
            PrivilegedDaemonResponse {
                ok: false,
                status: Some(status_response(&guard)),
                probe_schemas_page: None,
                probe_schema_detail: None,
                error: Some("TakeTraceMapFds must be handled via fd-transfer endpoint".to_string()),
            }
        }
        PrivilegedDaemonRequest::StopTrace => {
            let mut guard = state.lock().await;
            if let Err(error) = refresh(&mut guard).await {
                return PrivilegedDaemonResponse {
                    ok: false,
                    status: Some(status_response(&guard)),
                    probe_schemas_page: None,
                    probe_schema_detail: None,
                    error: Some(format!("failed to refresh daemon state: {error:#}")),
                };
            }
            if let Some(active) = guard.active.as_ref() {
                let pid = Pid::from_raw(active.target_pid as i32);
                let _ = kill(pid, Signal::SIGTERM);
                guard.sequence = guard.sequence.saturating_add(1);
            }
            guard.active = None;
            PrivilegedDaemonResponse {
                ok: true,
                status: Some(status_response(&guard)),
                probe_schemas_page: None,
                probe_schema_detail: None,
                error: None,
            }
        }
        PrivilegedDaemonRequest::Status => {
            let mut guard = state.lock().await;
            if let Err(error) = refresh(&mut guard).await {
                return PrivilegedDaemonResponse {
                    ok: false,
                    status: Some(status_response(&guard)),
                    probe_schemas_page: None,
                    probe_schema_detail: None,
                    error: Some(format!("failed to refresh daemon state: {error:#}")),
                };
            }
            PrivilegedDaemonResponse {
                ok: true,
                status: Some(status_response(&guard)),
                probe_schemas_page: None,
                probe_schema_detail: None,
                error: None,
            }
        }
        PrivilegedDaemonRequest::QueryProbeSchemasPage { query } => {
            match crate::viewer_probe_catalog::query_probe_schemas_page(to_probe_schemas_query(
                query,
            ))
            .await
            {
                Ok(page) => PrivilegedDaemonResponse {
                    ok: true,
                    status: None,
                    probe_schemas_page: Some(page),
                    probe_schema_detail: None,
                    error: None,
                },
                Err(error) => PrivilegedDaemonResponse {
                    ok: false,
                    status: None,
                    probe_schemas_page: None,
                    probe_schema_detail: None,
                    error: Some(format!(
                        "privileged daemon failed to query probe schemas page: {error}"
                    )),
                },
            }
        }
        PrivilegedDaemonRequest::QueryProbeSchemaDetail { display_name } => {
            match crate::viewer_probe_catalog::query_probe_schema_detail(display_name).await {
                Ok(schema) => PrivilegedDaemonResponse {
                    ok: true,
                    status: None,
                    probe_schemas_page: None,
                    probe_schema_detail: Some(schema),
                    error: None,
                },
                Err(error) => PrivilegedDaemonResponse {
                    ok: false,
                    status: None,
                    probe_schemas_page: None,
                    probe_schema_detail: None,
                    error: Some(format!(
                        "privileged daemon failed to query probe schema detail: {error}"
                    )),
                },
            }
        }
    }
}

async fn handle_conn(
    state: Arc<Mutex<DaemonState>>,
    mut stream: UnixStream,
    owner_uid: u32,
    expected_session_token: Arc<String>,
) -> Result<()> {
    let peer = stream
        .peer_cred()
        .with_context(|| "failed to read peer credentials for daemon connection")?;
    if peer.uid() != owner_uid {
        return Err(anyhow!(
            "unauthorized daemon client uid={} (expected uid={})",
            peer.uid(),
            owner_uid
        ));
    }
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .with_context(|| "failed to read daemon request")?;
    if buf.is_empty() {
        return Ok(());
    }
    let envelope: PrivilegedDaemonEnvelope =
        serde_json::from_slice(&buf).with_context(|| "failed to parse daemon request envelope")?;
    if envelope.session_token != *expected_session_token {
        return Err(anyhow!("unauthorized daemon client: invalid session token"));
    }
    let request = envelope.request;
    if matches!(request, PrivilegedDaemonRequest::TakeTraceMapFds) {
        let mut guard = state.lock().await;
        if let Err(error) = refresh(&mut guard).await {
            let response = PrivilegedTraceMapFdsResponse {
                ok: false,
                run_id: None,
                has_custom_events: false,
                error: Some(format!("failed to refresh daemon state: {error:#}")),
            };
            let payload = serde_json::to_vec(&response)
                .with_context(|| "failed to serialize daemon fd-transfer response")?;
            crate::unix_fd::send_with_fds(stream.as_raw_fd(), &payload, &[])?;
            return Ok(());
        }
        let (response, fds): (PrivilegedTraceMapFdsResponse, Vec<i32>) =
            if let Some(active) = guard.active.as_ref() {
                let mut fds = vec![
                    active.map_fds.events_fd,
                    active.map_fds.stack_traces_fd,
                    active.map_fds.cpu_sample_stats_fd,
                ];
                if let Some(custom) = active.map_fds.custom_events_fd {
                    fds.push(custom);
                }
                (
                    PrivilegedTraceMapFdsResponse {
                        ok: true,
                        run_id: Some(active.run_id),
                        has_custom_events: active.has_custom_events,
                        error: None,
                    },
                    fds,
                )
            } else {
                (
                    PrivilegedTraceMapFdsResponse {
                        ok: false,
                        run_id: None,
                        has_custom_events: false,
                        error: Some("no active privileged trace run".to_string()),
                    },
                    Vec::new(),
                )
            };
        let payload = serde_json::to_vec(&response)
            .with_context(|| "failed to serialize daemon fd-transfer response")?;
        crate::unix_fd::send_with_fds(stream.as_raw_fd(), &payload, &fds)?;
        return Ok(());
    }
    let response = handle_request(state, request).await;
    let payload =
        serde_json::to_vec(&response).with_context(|| "failed to serialize daemon response")?;
    stream
        .write_all(&payload)
        .await
        .with_context(|| "failed to write daemon response")?;
    stream
        .flush()
        .await
        .with_context(|| "failed to flush daemon response")?;
    Ok(())
}

pub(crate) async fn run(socket_path: &Path, owner_uid: u32, session_token: String) -> Result<()> {
    if socket_path.exists() {
        std::fs::remove_file(socket_path)
            .with_context(|| format!("failed to remove stale daemon socket {:?}", socket_path))?;
    }
    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("failed to bind daemon socket {:?}", socket_path))?;
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;

        let socket_cstr = CString::new(socket_path.as_os_str().as_bytes())
            .with_context(|| "failed to encode daemon socket path for chown")?;
        let chown_ret = unsafe { libc::chown(socket_cstr.as_ptr(), owner_uid, u32::MAX) };
        if chown_ret != 0 {
            return Err(anyhow!(
                "failed to chown daemon socket to uid {}: {}",
                owner_uid,
                std::io::Error::last_os_error()
            ));
        }
        let mut perms = std::fs::metadata(socket_path)
            .with_context(|| "failed to stat daemon socket")?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(socket_path, perms)
            .with_context(|| "failed to set daemon socket permissions")?;
    }

    let state = Arc::new(Mutex::new(DaemonState::new()));
    let expected_session_token = Arc::new(session_token);
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .with_context(|| "daemon accept failed")?;
        let state = Arc::clone(&state);
        let owner_uid = owner_uid;
        let expected_session_token = Arc::clone(&expected_session_token);
        tokio::spawn(async move {
            if let Err(error) = handle_conn(state, stream, owner_uid, expected_session_token).await
            {
                log::error!("privileged daemon connection error: {error:#}");
            }
        });
    }
}
