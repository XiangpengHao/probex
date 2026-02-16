use anyhow::{Context as _, Result, anyhow};
use log::debug;
use nix::{
    sys::{
        wait::{WaitPidFlag, WaitStatus, waitpid},
    },
    unistd::{ForkResult, Pid, fork},
};
use std::{env, ffi::CString};

#[derive(Clone, Copy, Debug)]
pub struct PrivilegeDropTarget {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

fn parse_env_id(name: &str) -> Result<Option<u32>> {
    match env::var(name) {
        Ok(value) => value
            .parse::<u32>()
            .map(Some)
            .with_context(|| format!("invalid {name} value '{value}'")),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(anyhow!("failed to read {name}: {err}")),
    }
}

pub fn resolve_privilege_drop_target() -> Result<Option<PrivilegeDropTarget>> {
    if unsafe { libc::geteuid() } != 0 {
        return Ok(None);
    }

    let sudo_uid = parse_env_id("SUDO_UID")?;
    let sudo_gid = parse_env_id("SUDO_GID")?;
    match (sudo_uid, sudo_gid) {
        (Some(uid), Some(gid)) => Ok(Some(PrivilegeDropTarget { uid, gid })),
        (None, None) => {
            debug!(
                "running as root without SUDO_UID/SUDO_GID; staying root for runtime and output files"
            );
            Ok(None)
        }
        _ => Err(anyhow!(
            "running as root but SUDO_UID/SUDO_GID are inconsistent; both must be set to drop privileges"
        )),
    }
}

pub fn drop_process_privileges(target: PrivilegeDropTarget) -> Result<()> {
    let ret = unsafe { libc::setgroups(0, std::ptr::null()) };
    if ret != 0 {
        return Err(anyhow!(
            "setgroups(0, NULL) failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    let ret = unsafe { libc::setgid(target.gid) };
    if ret != 0 {
        return Err(anyhow!(
            "setgid({}) failed: {}",
            target.gid,
            std::io::Error::last_os_error()
        ));
    }

    let ret = unsafe { libc::setuid(target.uid) };
    if ret != 0 {
        return Err(anyhow!(
            "setuid({}) failed: {}",
            target.uid,
            std::io::Error::last_os_error()
        ));
    }

    let uid_matches = unsafe { libc::geteuid() == target.uid };
    let gid_matches = unsafe { libc::getegid() == target.gid };
    if !uid_matches || !gid_matches {
        return Err(anyhow!(
            "privilege drop verification failed: euid={}, egid={}, expected uid={}, gid={}",
            unsafe { libc::geteuid() },
            unsafe { libc::getegid() },
            target.uid,
            target.gid
        ));
    }

    Ok(())
}

pub fn spawn_child(
    program: &str,
    args: &[String],
    privilege_drop: Option<PrivilegeDropTarget>,
) -> Result<Pid> {
    let mut cstrings = Vec::with_capacity(args.len() + 1);
    cstrings.push(
        CString::new(program)
            .with_context(|| format!("failed to spawn {program}: program contains NUL"))?,
    );
    for arg in args {
        cstrings.push(
            CString::new(arg.as_str())
                .with_context(|| format!("failed to spawn {program}: argument contains NUL"))?,
        );
    }
    let mut argv: Vec<*const libc::c_char> = cstrings.iter().map(|s| s.as_ptr()).collect();
    argv.push(std::ptr::null());

    match unsafe { fork()? } {
        ForkResult::Parent { child } => Ok(child),
        ForkResult::Child => unsafe {
            if let Some(target) = privilege_drop
                && let Err(error) = drop_process_privileges(target)
            {
                eprintln!("failed to drop child privileges before exec: {error}");
                libc::_exit(126);
            }
            libc::raise(libc::SIGSTOP);
            libc::execvp(argv[0], argv.as_ptr());
            libc::_exit(127);
        },
    }
}

pub fn wait_for_child_stop(pid: Pid) -> Result<()> {
    match waitpid(pid, Some(WaitPidFlag::WUNTRACED)) {
        Ok(WaitStatus::Stopped(_, _)) => Ok(()),
        Ok(WaitStatus::Exited(_, status)) => {
            Err(anyhow!("child exited early with status {status}"))
        }
        Ok(WaitStatus::Signaled(_, signal, _)) => {
            Err(anyhow!("child exited early with signal {signal}"))
        }
        Ok(status) => Err(anyhow!(
            "unexpected wait status while waiting for stop: {status:?}"
        )),
        Err(err) => Err(anyhow!("waitpid failed while waiting for stop: {err}")),
    }
}
