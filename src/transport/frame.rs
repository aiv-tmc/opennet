//! Raw length-prefixed framing shared by the plaintext greeting
//! exchange and the encrypted data path. This module only moves bytes
//! reliably over a non-blocking tokio socket; confidentiality and
//! integrity live in `super` and `handshake`.

use anyhow::{bail, Result};
use bytes::Bytes;
use std::io::IoSlice;
use tokio::net::TcpStream;

use super::MAX_FRAME;

/// Read exactly `buf.len()` bytes. `Ok(false)` signals a clean EOF
/// before the first byte; an EOF mid-buffer is an error.
async fn read_exact(stream: &TcpStream, buf: &mut [u8]) -> Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        stream.readable().await?;
        match stream.try_read(&mut buf[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                bail!("connection closed mid-frame");
            }
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(true)
}

/// Read one raw frame: a big-endian `u32` length capped at `MAX_FRAME`
/// followed by exactly that many payload bytes. `Ok(None)` on a clean
/// EOF with an empty read buffer.
pub(super) async fn read_frame(stream: &TcpStream) -> Result<Option<Bytes>> {
    let mut len = [0u8; 4];
    if !read_exact(stream, &mut len).await? {
        return Ok(None);
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_FRAME {
        bail!("frame length {len} exceeds the {}-byte cap", MAX_FRAME);
    }
    let mut data = vec![0u8; len];
    if !read_exact(stream, &mut data).await? {
        bail!("connection closed mid-frame");
    }
    Ok(Some(Bytes::from(data)))
}

/// Write one raw frame: the big-endian length header and the payload
/// are issued as a single vectored write on the fast path. The socket
/// is non-blocking: readiness is awaited, the vectored write is
/// attempted, and `WouldBlock` spins back to readiness; a short write
/// continues from the exact byte offset that was reached.
pub(super) async fn write_frame_raw(stream: &TcpStream, data: &[u8]) -> Result<()> {
    if data.len() > MAX_FRAME {
        bail!(
            "frame length {} exceeds the {}-byte cap",
            data.len(),
            MAX_FRAME
        );
    }
    let len = (data.len() as u32).to_be_bytes();
    let total = 4 + data.len();
    let mut written = 0usize;
    while written < total {
        stream.writable().await?;
        let pieces: &[IoSlice] = if written < 4 {
            &[IoSlice::new(&len[written..]), IoSlice::new(data)]
        } else {
            &[IoSlice::new(&data[written - 4..])]
        };
        match stream.try_write_vectored(pieces) {
            Ok(0) => bail!("socket closed during frame write"),
            Ok(n) => written += n,
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

/// Force-close a socket: the shutdown syscall is issued directly on
/// the raw descriptor, so both directions are closed and the peer's
/// reader wakes with EOF, even though tokio's non-blocking `TcpStream`
/// exposes no shutdown method of its own.
pub(super) async fn close_stream(stream: &TcpStream) {
    #[cfg(unix)]
    unsafe {
        use std::os::fd::AsRawFd;
        libc::shutdown(stream.as_raw_fd(), libc::SHUT_RDWR);
    }
    #[cfg(not(unix))]
    let _ = stream;
}
