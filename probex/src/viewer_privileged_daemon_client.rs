use crate::{
    TraceCommandConfig, TraceCommandOutcome, TraceMapFdBundle, consume_trace_from_map_fds,
    custom_codegen, trace_privilege,
};
use anyhow::{Context as _, Result, anyhow};
use nix::sys::{
    signal::{Signal, kill},
    wait::waitpid,
};
use probex_common::viewer_api::{
    PrivilegedDaemonEnvelope, PrivilegedDaemonRequest, PrivilegedDaemonResponse,
    PrivilegedProbeSchemasQuery, PrivilegedTraceMapFdsResponse, ProbeSchema,
    ProbeSchemasPageResponse,
};
use std::env;
use std::io::Read as _;
use std::os::fd::AsRawFd as _;
use std::path::PathBuf;
use std::sync::OnceLock;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::process::ChildStdin;
use tokio::process::Command;
use tokio::sync::{Mutex, OnceCell, watch};

static DAEMON_START_LOCK: OnceCell<Mutex<()>> = OnceCell::const_new();
static DAEMON_SESSION_TOKEN: OnceLock<String> = OnceLock::new();

fn daemon_socket_path() -> PathBuf {
    let uid = unsafe { libc::geteuid() };
    PathBuf::from(format!("/tmp/probex-privileged-{uid}.sock"))
}

fn daemon_session_token() -> Result<&'static str> {
    if let Some(token) = DAEMON_SESSION_TOKEN.get() {
        return Ok(token.as_str());
    }
    let mut bytes = [0u8; 32];
    let mut file = std::fs::File::open("/dev/urandom")
        .with_context(|| "failed to open /dev/urandom for daemon session token")?;
    file.read_exact(&mut bytes)
        .with_context(|| "failed to read daemon session token bytes from /dev/urandom")?;
    let token = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let _ = DAEMON_SESSION_TOKEN.set(token);
    Ok(DAEMON_SESSION_TOKEN
        .get()
        .expect("daemon session token set")
        .as_str())
}

async fn resolve_custom_probe_schemas(
    specs: &[probex_common::viewer_api::CustomProbeSpec],
) -> Result<std::collections::HashMap<String, probex_common::viewer_api::ProbeSchema>> {
    let mut resolved = std::collections::HashMap::with_capacity(specs.len());
    for spec in specs {
        let schema =
            crate::viewer_backend::query_probe_schema_detail(spec.probe_display_name.clone())
                .await
                .map_err(|error| {
                    anyhow!(
                        "failed to resolve custom probe '{}': {error}",
                        spec.probe_display_name
                    )
                })?;
        resolved.insert(spec.probe_display_name.clone(), schema);
    }
    Ok(resolved)
}

async fn maybe_build_prebuilt_generated_ebpf(
    config: &TraceCommandConfig,
) -> Result<Option<String>> {
    if config.custom_probes.is_empty() {
        return Ok(None);
    }
    let schemas = resolve_custom_probe_schemas(&config.custom_probes).await?;
    let plan = custom_codegen::compile_custom_probe_plan(&config.custom_probes, &schemas)
        .with_context(|| "failed to compile custom probe plan for daemon prebuild")?;
    let source = custom_codegen::generate_custom_probe_source(&plan)
        .with_context(|| "failed to generate custom probe source for daemon prebuild")?;
    let built_path = tokio::task::spawn_blocking(move || {
        custom_codegen::build_generated_ebpf_binary_path(&source)
    })
    .await
    .with_context(|| "failed to join custom probe prebuild task")?
    .with_context(|| "failed to build generated eBPF object for daemon prebuild")?;
    Ok(Some(built_path.to_string_lossy().to_string()))
}

async fn compile_custom_probe_runtime_plan(
    config: &TraceCommandConfig,
) -> Result<(crate::custom_codegen::CompiledCustomPlan, String)> {
    let schemas = resolve_custom_probe_schemas(&config.custom_probes).await?;
    let plan = custom_codegen::compile_custom_probe_plan(&config.custom_probes, &schemas)
        .with_context(|| "failed to compile custom probe plan for runtime decode")?;
    let payload_schemas_json = plan
        .payload_schemas_json()
        .with_context(|| "failed to encode custom payload schemas for runtime decode")?;
    Ok((plan, payload_schemas_json))
}

fn parse_trace_map_fd_bundle(
    response: &PrivilegedTraceMapFdsResponse,
    fds: &[i32],
) -> Result<TraceMapFdBundle> {
    if !response.ok {
        return Err(anyhow!(
            "{}",
            response.error.clone().unwrap_or_else(|| {
                "privileged daemon rejected trace map fd request".to_string()
            })
        ));
    }
    let expected = if response.has_custom_events { 4 } else { 3 };
    if fds.len() != expected {
        return Err(anyhow!(
            "privileged daemon returned unexpected map fd count: got {}, expected {}",
            fds.len(),
            expected
        ));
    }
    let events_fd = fds[0];
    let stack_traces_fd = fds[1];
    let cpu_sample_stats_fd = fds[2];
    let custom_events_fd = if response.has_custom_events {
        Some(fds[3])
    } else {
        None
    };
    Ok(TraceMapFdBundle {
        events_fd,
        stack_traces_fd,
        cpu_sample_stats_fd,
        custom_events_fd,
    })
}

async fn send_request(request: PrivilegedDaemonRequest) -> Result<PrivilegedDaemonResponse> {
    let socket = daemon_socket_path();
    let mut stream = UnixStream::connect(&socket)
        .await
        .with_context(|| format!("failed to connect privileged daemon socket {:?}", socket))?;
    let payload = serde_json::to_vec(&PrivilegedDaemonEnvelope {
        session_token: daemon_session_token()?.to_string(),
        request,
    })
    .with_context(|| "failed to encode daemon request")?;
    stream
        .write_all(&payload)
        .await
        .with_context(|| "failed to write daemon request")?;
    stream
        .shutdown()
        .await
        .with_context(|| "failed to shutdown daemon request stream")?;
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .with_context(|| "failed to read daemon response")?;
    if buf.is_empty() {
        return Err(anyhow!("privileged daemon returned empty response"));
    }
    let response: PrivilegedDaemonResponse =
        serde_json::from_slice(&buf).with_context(|| "failed to parse daemon response")?;
    Ok(response)
}

async fn spawn_daemon_with(
    command: &str,
    exe: &std::path::Path,
    socket: &PathBuf,
    session_token: &str,
) -> Result<tokio::process::Child> {
    let mut child = Command::new(command)
        .arg(exe)
        .arg("--privileged-daemon")
        .arg("--privileged-daemon-socket")
        .arg(socket.as_os_str())
        .arg("--privileged-daemon-owner-uid")
        .arg(format!("{}", unsafe { libc::geteuid() }))
        .stdin(std::process::Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "failed to spawn privileged daemon via {} (is it installed and authorized?). {}",
                command,
                trace_privilege::privilege_hint()
            )
        })?;
    let mut stdin: ChildStdin = child
        .stdin
        .take()
        .ok_or_else(|| anyhow!("failed to open privileged daemon stdin for token transfer"))?;
    stdin
        .write_all(format!("{session_token}\n").as_bytes())
        .await
        .with_context(|| "failed to write privileged daemon session token")?;
    drop(stdin);
    Ok(child)
}

async fn ensure_daemon_running() -> Result<()> {
    if send_request(PrivilegedDaemonRequest::Status).await.is_ok() {
        return Ok(());
    }
    let lock = DAEMON_START_LOCK
        .get_or_init(|| async { Mutex::new(()) })
        .await;
    let _guard = lock.lock().await;
    if send_request(PrivilegedDaemonRequest::Status).await.is_ok() {
        return Ok(());
    }

    let socket = daemon_socket_path();
    let exe = env::current_exe().with_context(|| "failed to resolve current executable path")?;
    let session_token = daemon_session_token()?.to_string();

    let mut child = spawn_daemon_with("pkexec", &exe, &socket, &session_token).await?;
    let mut attempted_sudo = false;

    loop {
        // Wait for daemon socket readiness. Keep helper process running in background.
        for _ in 0..300u32 {
            if send_request(PrivilegedDaemonRequest::Status).await.is_ok() {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            if let Some(status) = child
                .try_wait()
                .with_context(|| "failed waiting privileged helper process")?
                && !status.success()
            {
                break;
            }
        }

        if attempted_sudo {
            break;
        }
        attempted_sudo = true;
        log::warn!("pkexec did not succeed; trying sudo as a fallback");
        child = spawn_daemon_with("sudo", &exe, &socket, &session_token).await?;
    }

    Err(anyhow!(
        "privileged daemon did not become ready; ensure pkexec or sudo auth succeeded. {}",
        trace_privilege::privilege_hint()
    ))
}

pub(crate) async fn start_privileged_daemon() -> Result<()> {
    ensure_daemon_running().await
}

pub(crate) async fn run_trace_via_daemon(
    config: TraceCommandConfig,
    mut stop_signal: Option<watch::Receiver<bool>>,
) -> Result<TraceCommandOutcome> {
    ensure_daemon_running().await?;
    let runtime_config = config.clone();
    let (runtime_custom_probe_plan, runtime_payload_schemas_json) =
        compile_custom_probe_runtime_plan(&runtime_config).await?;
    let prebuilt_generated_ebpf_path = maybe_build_prebuilt_generated_ebpf(&config).await?;
    let child_pid = crate::spawn_child(&config.program, &config.args, None)
        .with_context(|| "step=spawn_child failed in unprivileged backend")?;
    crate::wait_for_child_stop(child_pid)
        .with_context(|| "step=wait_child_stop failed in unprivileged backend")?;
    let child_wait = tokio::task::spawn_blocking(move || waitpid(child_pid, None));
    let mut command = Vec::with_capacity(config.args.len() + 1);
    command.push(config.program.clone());
    command.extend(config.args.clone());

    let target_pid = u32::try_from(child_pid.as_raw())
        .with_context(|| format!("child pid must be non-negative, got {}", child_pid.as_raw()))?;
    let start_resp = send_request(PrivilegedDaemonRequest::AttachTrace {
        target_pid,
        command,
        output_parquet: config.output.clone(),
        sample_freq_hz: config.sample_freq_hz,
        custom_probes: config.custom_probes.clone(),
        prebuilt_generated_ebpf_path,
    })
    .await?;
    if !start_resp.ok {
        return Err(anyhow!(
            "{}",
            start_resp
                .error
                .unwrap_or_else(|| "privileged daemon rejected start request".to_string())
        ));
    }
    let (fd_response, fds) = take_trace_map_fds_via_daemon().await?;
    let map_fds = match parse_trace_map_fd_bundle(&fd_response, &fds) {
        Ok(bundle) => bundle,
        Err(error) => {
            for fd in fds {
                let _ = unsafe { libc::close(fd) };
            }
            return Err(error);
        }
    };

    kill(child_pid, Signal::SIGCONT)
        .with_context(|| format!("failed to resume child process {}", child_pid))?;

    let (finished_tx, finished_rx) = watch::channel(false);
    let child_wait_task = tokio::spawn(async move {
        let _ = child_wait.await;
        let _ = finished_tx.send(true);
    });

    let consume_result = consume_trace_from_map_fds(
        runtime_config,
        runtime_custom_probe_plan,
        runtime_payload_schemas_json,
        map_fds,
        stop_signal.take(),
        finished_rx,
    )
    .await;

    let consume_outcome = if let Err(error) = consume_result {
        if error.to_string().contains("trace stopped by request") {
            let _ = kill(child_pid, Signal::SIGTERM);
            let _ = send_request(PrivilegedDaemonRequest::StopTrace).await;
        }
        let _ = child_wait_task.await;
        return Err(error);
    } else {
        consume_result.expect("consume result checked above")
    };

    let _ = child_wait_task.await;
    let _ = send_request(PrivilegedDaemonRequest::StopTrace).await;
    Ok(consume_outcome)
}

pub(crate) async fn query_probe_schemas_page_via_daemon(
    query: PrivilegedProbeSchemasQuery,
) -> Result<ProbeSchemasPageResponse> {
    ensure_daemon_running().await?;
    let response = send_request(PrivilegedDaemonRequest::QueryProbeSchemasPage { query }).await?;
    if !response.ok {
        return Err(anyhow!(
            "{}",
            response
                .error
                .unwrap_or_else(|| "privileged daemon probe schemas page query failed".to_string())
        ));
    }
    response
        .probe_schemas_page
        .ok_or_else(|| anyhow!("privileged daemon response missing probe_schemas_page"))
}

pub(crate) async fn query_probe_schema_detail_via_daemon(
    display_name: String,
) -> Result<ProbeSchema> {
    ensure_daemon_running().await?;
    let response =
        send_request(PrivilegedDaemonRequest::QueryProbeSchemaDetail { display_name }).await?;
    if !response.ok {
        return Err(anyhow!(
            "{}",
            response
                .error
                .unwrap_or_else(|| "privileged daemon probe schema detail query failed".to_string())
        ));
    }
    response
        .probe_schema_detail
        .ok_or_else(|| anyhow!("privileged daemon response missing probe_schema_detail"))
}

pub(crate) async fn take_trace_map_fds_via_daemon()
-> Result<(PrivilegedTraceMapFdsResponse, Vec<i32>)> {
    ensure_daemon_running().await?;
    let socket = daemon_socket_path();
    let payload = serde_json::to_vec(&PrivilegedDaemonEnvelope {
        session_token: daemon_session_token()?.to_string(),
        request: PrivilegedDaemonRequest::TakeTraceMapFds,
    })
    .with_context(|| "failed to encode daemon request")?;
    let socket_clone = socket.clone();
    tokio::task::spawn_blocking(
        move || -> Result<(PrivilegedTraceMapFdsResponse, Vec<i32>)> {
            use std::io::{Read as _, Write as _};
            use std::os::unix::net::UnixStream as StdUnixStream;

            let mut stream = StdUnixStream::connect(&socket_clone).with_context(|| {
                format!(
                    "failed to connect privileged daemon socket {:?}",
                    socket_clone
                )
            })?;
            stream
                .write_all(&payload)
                .with_context(|| "failed to write daemon request")?;
            stream
                .shutdown(std::net::Shutdown::Write)
                .with_context(|| "failed to shutdown daemon request stream")?;

            let mut buf = vec![0u8; 16 * 1024];
            let (bytes, fds) = crate::unix_fd::recv_with_fds(stream.as_raw_fd(), &mut buf, 8)
                .with_context(|| "failed to receive daemon fd-transfer response")?;
            if bytes == 0 {
                return Err(anyhow!("privileged daemon returned empty response"));
            }
            let response: PrivilegedTraceMapFdsResponse = serde_json::from_slice(&buf[..bytes])
                .with_context(|| "failed to parse daemon fd-transfer response")?;
            // Drain potential remaining data to avoid abrupt close on some transports.
            let mut sink = Vec::new();
            let _ = stream.read_to_end(&mut sink);
            Ok((response, fds))
        },
    )
    .await
    .with_context(|| "failed to join daemon fd-transfer task")?
}
