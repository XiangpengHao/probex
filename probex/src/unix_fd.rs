use anyhow::{Result, anyhow};
use nix::cmsg_space;
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::RawFd;

pub(crate) fn send_with_fds(socket_fd: RawFd, payload: &[u8], fds: &[RawFd]) -> Result<()> {
    let iov = [IoSlice::new(payload)];
    let sent = if fds.is_empty() {
        sendmsg::<()>(socket_fd, &iov, &[], MsgFlags::empty(), None)?
    } else {
        let cmsg = [ControlMessage::ScmRights(fds)];
        sendmsg::<()>(socket_fd, &iov, &cmsg, MsgFlags::empty(), None)?
    };
    if sent != payload.len() {
        return Err(anyhow!(
            "short send on unix socket: sent {} bytes, expected {} bytes",
            sent,
            payload.len()
        ));
    }
    Ok(())
}

pub(crate) fn recv_with_fds(
    socket_fd: RawFd,
    payload_buf: &mut [u8],
    max_fds: usize,
) -> Result<(usize, Vec<RawFd>)> {
    let mut iov = [IoSliceMut::new(payload_buf)];
    let mut cmsgspace = cmsg_space!([RawFd; 16]);
    let msg = recvmsg::<()>(socket_fd, &mut iov, Some(&mut cmsgspace), MsgFlags::empty())?;
    if msg.bytes == 0 {
        return Err(anyhow!("empty unix socket message"));
    }
    let mut fds = Vec::new();
    if let Ok(iter) = msg.cmsgs() {
        for cmsg in iter {
            if let ControlMessageOwned::ScmRights(rights) = cmsg {
                fds.extend(rights);
            }
        }
    }
    if fds.len() > max_fds {
        return Err(anyhow!(
            "received too many fds over unix socket: got {}, expected at most {}",
            fds.len(),
            max_fds
        ));
    }
    Ok((msg.bytes, fds))
}
