//! Runner bridge: the local plumbing between one shard process and the
//! network.
//!
//! The worker spawns the manifest's runner command with the shard
//! environment exported; the runner connects to the worker's local
//! listener and speaks a minimal length-prefixed frame protocol:
//!
//! ```text
//! worker -> runner : [u32 len][payload]            pipeline input
//! runner -> worker : [u32 len][u8 tag][payload]    one of:
//!     tag 1: forward `payload` to the next shard (ShardFwd)
//!     tag 2: deliver `payload` to the coordinator (ShardOut)
//!     tag 3: report readiness (ShardReady)
//!     tag 4: report completion (SwarmDone)
//! ```
//!
//! Any program implementing these frames can serve as a shard runner, from
//! a small LLM-inference wrapper to a generic map-reduce worker. The
//! bridge owns the child process: on shutdown, plan end or runner exit it
//! kills the whole process group, reaps the child, cleans the working
//! directory and deregisters the shard.

use crate::daemon::send_msg;
use crate::daemon::Ctx;
use crate::message::Message;
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot};

/// Frame header size on the local runner socket.
const HEADER: usize = 4;
/// Deadline for one runner-side frame before the shard is considered dead.
const FRAME_TIMEOUT: Duration = Duration::from_secs(300);

/// Relay frames between the runner socket, the network and the local
/// inbound queue until shutdown, runner exit or completion, then kill the
/// runner process group, reap the child, remove the working directory and
/// deregister the shard.
#[allow(clippy::too_many_arguments)]
pub async fn bridge(
    ctx: Arc<Ctx>,
    plan_id: String,
    shard_index: u32,
    mut socket: TcpStream,
    mut inbound: mpsc::UnboundedReceiver<Vec<u8>>,
    mut shutdown: oneshot::Receiver<()>,
    pid: i32,
    mut child: Child,
    next_addr: String,
    coord_addr: String,
) {
    let mut seq = 1u64;
    loop {
        tokio::select! {
            // Plan end or consent revocation: stop relaying.
            _ = &mut shutdown => break,
            // A pipeline payload arrived from the network; hand it to the
            // runner as a plain length-prefixed frame.
            payload = inbound.recv() => {
                let Some(payload) = payload else { break };
                if let Err(err) = write_frame(&mut socket, 0, &payload).await {
                    eprintln!("[swarm] runner socket write failed: {err:#}");
                    break;
                }
            }
            // One frame from the runner.
            frame = read_frame(&mut socket) => {
                let (tag, payload) = match frame {
                    Ok(frame) => frame,
                    Err(err) => {
                        eprintln!("[swarm] runner socket closed: {err:#}");
                        break;
                    }
                };
                match tag {
                    1 => {
                        // Forward the payload along the pipeline; without a
                        // next shard the program contract is violated.
                        if next_addr.is_empty() {
                            eprintln!(
                                "[swarm] shard {shard_index} tried to forward past the last shard"
                            );
                            continue;
                        }
                        let _ = send_msg(
                            &ctx,
                            &next_addr,
                            &Message::ShardFwd {
                                plan_id: plan_id.clone(),
                                seq,
                                src: shard_index,
                                dst: shard_index + 1,
                                payload,
                            },
                        )
                        .await;
                        seq += 1;
                    }
                    2 => {
                        let _ = send_msg(
                            &ctx,
                            &coord_addr,
                            &Message::ShardOut {
                                plan_id: plan_id.clone(),
                                seq,
                                payload,
                            },
                        )
                        .await;
                        seq += 1;
                    }
                    3 => {
                        let _ = send_msg(
                            &ctx,
                            &coord_addr,
                            &Message::ShardReady {
                                plan_id: plan_id.clone(),
                                shard_index,
                            },
                        )
                        .await;
                    }
                    4 => {
                        let _ = send_msg(
                            &ctx,
                            &coord_addr,
                            &Message::SwarmDone {
                                plan_id: plan_id.clone(),
                                reason: "shard complete".to_string(),
                            },
                        )
                        .await;
                        break;
                    }
                    other => eprintln!("[swarm] runner sent unknown tag {other}"),
                }
            }
        }
    }
    // SAFETY: the pid belongs to the process group created for the runner
    // by the shard worker; the daemon lives in a different group.
    unsafe { libc::killpg(pid, libc::SIGKILL) };
    let _ = child.wait().await;
    let workdir = std::env::temp_dir().join(format!(
        "opennet-swarm-{}-{shard_index}",
        &plan_id[..plan_id.len().min(16)]
    ));
    let _ = tokio::fs::remove_dir_all(&workdir).await;
    ctx.swarm_procs
        .lock()
        .await
        .remove(&format!("{plan_id}:{shard_index}"));
}

/// Read one `[u32 len][u8 tag][payload]` frame from the runner socket
/// under the per-frame deadline.
async fn read_frame(socket: &mut TcpStream) -> Result<(u8, Vec<u8>)> {
    let raw = tokio::time::timeout(FRAME_TIMEOUT, read_raw(socket)).await??;
    let Some((&tag, payload)) = raw.split_first() else {
        anyhow::bail!("empty runner frame");
    };
    Ok((tag, payload.to_vec()))
}

/// Write one `[u32 len][u8 tag][payload]` frame to the runner socket.
async fn write_frame(socket: &mut TcpStream, tag: u8, payload: &[u8]) -> Result<()> {
    let mut buf = Vec::with_capacity(payload.len() + 1 + HEADER);
    buf.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    buf.push(tag);
    buf.extend_from_slice(payload);
    socket.write_all(&buf).await?;
    Ok(())
}

/// Read one length-prefixed byte blob from the runner socket.
async fn read_raw(socket: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; HEADER];
    socket.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > 64 * 1024 * 1024 {
        anyhow::bail!("runner frame of invalid size {len}");
    }
    let mut data = vec![0u8; len];
    socket.read_exact(&mut data).await?;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrip_over_a_local_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut stream = TcpStream::connect(addr).await.unwrap();
            write_frame(&mut stream, 3, b"ready").await.unwrap();
            let (tag, payload) = read_frame(&mut stream).await.unwrap();
            assert_eq!(tag, 0);
            assert_eq!(payload, b"input".to_vec());
        });
        let (mut server, _) = listener.accept().await.unwrap();
        let (tag, payload) = read_frame(&mut server).await.unwrap();
        assert_eq!(tag, 3);
        assert_eq!(payload, b"ready".to_vec());
        write_frame(&mut server, 0, b"input").await.unwrap();
        client.await.unwrap();
    }
}
