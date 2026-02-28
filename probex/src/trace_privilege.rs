use crate::{
    TraceCommandConfig, TraceCommandOutcome, run_trace_command, viewer_privileged_daemon_client,
};
use anyhow::{Context as _, Result};
use tokio::sync::watch;

pub(crate) fn looks_like_permission_error(error_text: &str) -> bool {
    let lower = error_text.to_ascii_lowercase();
    lower.contains("permission denied")
        || lower.contains("operation not permitted")
        || lower.contains("eperm")
        || lower.contains("eacces")
}

pub(crate) fn privilege_hint() -> &'static str {
    "Hint: install/configure polkit + pkexec for privileged fallback, or run tracing with sudo (e.g. `sudo probex -- <cmd>`)."
}

pub(crate) async fn run_trace_with_privilege_fallback(
    config: TraceCommandConfig,
    stop_signal: Option<watch::Receiver<bool>>,
    allow_ctrl_c: bool,
) -> Result<TraceCommandOutcome> {
    let direct_stop = stop_signal.as_ref().cloned();
    match run_trace_command(config.clone(), direct_stop, allow_ctrl_c).await {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            let error_text = format!("{error:#}");
            if !looks_like_permission_error(&error_text) {
                return Err(error);
            }
            log::warn!(
                "Direct tracing failed with permission error; trying privileged daemon fallback: {}",
                error_text
            );
            viewer_privileged_daemon_client::run_trace_via_daemon(config, stop_signal)
                .await
                .with_context(|| {
                    format!(
                        "direct tracing failed with permission error: {error_text}; privileged daemon fallback failed. {}",
                        privilege_hint()
                    )
                })
        }
    }
}
