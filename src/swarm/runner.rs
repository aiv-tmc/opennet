//! The runner bridge: the worker side of the local runner protocol.
//!
//! The bridge owns the loopback socket between the daemon and one shard
//! runner process. It serves three flows until the runner exits, the
//! plan ends, or the socket breaks:
//!
//! * worker → runner: length-tagged frames (tag 0) drained from the
//!   shard's bounded inbound queue;
//! * runner → worker: tagged frames — tag 1 forwards an activation to
//!   the next shard host (an empty next address means the last shard,
//!   which must not forward), tag 2 delivers output to the coordinator,
//!   tag 3 reports readiness (once), tag 4 reports plan completion;
//! * shutdown: `finish_plan` fires the oneshot; the bridge kills the
//!   whole process group, reaps the child, removes the scratch
//!   directory and unregisters the bridge.
//!
//! Reads carry no inter-frame timeout: a shard may sit idle between
//! pipeline activations for the whole plan lifetime. Liveness is
//! bounded by the plan deadline on the coordinator side and by the
//! socket closing when the runner dies.

use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use crate::transport::MAX_FRAME;
use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Child;
use tokio::sync::{mpsc, oneshot};

/// Tag values of the runner → worker protocol.
const TAG_FWD: u8 = 1;
const TAG_OUT: u8 = 2;
const TAG_READY: u8 = 3;
const TAG_DONE: u8 = 4;

/// Serve one runner until completion or teardown, then clean up.
#[allow(clippy::too_many_arguments)]
pub async fn bridge(
    ctx: Arc<Ctx>,
    plan_id: String,
    shard_index: u32,
    mut socket: TcpStream,
    mut inbound: mpsc::Receiver<Vec<u8>>,
    mut shutdown: oneshot::Receiver<()>,
    pid: i32,
    mut child: Child,
    workdir: PathBuf,
    next_addr: String,
    coord_addr: String,
) {
    let mut ready_sent = false;
    let mut seq: u64 = 0;
    loop {
        tokio::select! {
            // Plan ended elsewhere: tear the runner down.
            _ = &mut shutdown => break,
            // Every inbound sender is gone (plan state dropped): the
            // queue will never receive pipeline frames again.
            frame = inbound.recv() => {
                let Some(payload) = frame else {
                    break;
                };
                if write_frame(&mut socket, 0, &payload).await.is_err() {
                    break;
                }
            }
            // One tagged frame from the runner. EOF and protocol errors
            // both end the loop; the cleanup below reaps the child.
            tagged = read_frame(&mut socket) => {
                let Some((tag, payload)) = tagged else {
                    break;
                };
                match tag {
                    TAG_FWD => {
                        if next_addr.is_empty() {
                            // The last shard has nowhere to forward; a
                            // tag-1 frame here is a contract violation
                            // by the runner, not a pipeline step.
                            eprintln!("[swarm] last shard tried to forward");
                            continue;
                        }
                        seq += 1;
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
                    }
                    TAG_OUT => {
                        seq += 1;
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
                    }
                    TAG_READY if !ready_sent => {
                        // Reported once; duplicates are ignored so a
                        // chatty runner cannot advance the coordinator's
                        // phase logic.
                        ready_sent = true;
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
                    TAG_DONE => {
                        let _ = send_msg(
                            &ctx,
                            &coord_addr,
                            &Message::SwarmDone {
                                plan_id: plan_id.clone(),
                                reason: "completed".to_string(),
                            },
                        )
                        .await;
                        break;
                    }
                    // Unknown tags are reserved for future extensions.
                    _ => {}
                }
            }
        }
    }
    // SAFETY: `pid` is the child's own process group id (created with
    // `process_group(0)`); the daemon lives in a different group and can
    // never signal itself.
    unsafe { libc::killpg(pid, libc::SIGKILL) };
    let _ = child.wait().await;
    let _ = std::fs::remove_dir_all(&workdir);
    ctx.swarm_procs
        .lock()
        .await
        .remove(&crate::swarm::proc_key(&plan_id, shard_index));
}

/// Write one worker → runner frame: u32 length (tag byte included), u8
/// tag, payload, in a single buffer so the loopback write stays atomic.
async fn write_frame(socket: &mut TcpStream, tag: u8, payload: &[u8]) -> Result<()> {
    let mut framed = Vec::with_capacity(5 + payload.len());
    framed.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    framed.push(tag);
    framed.extend_from_slice(payload);
    socket.write_all(&framed).await?;
    Ok(())
}

/// Read one runner → worker tagged frame: u32 length (tag byte included),
/// u8 tag, payload. Returns `None` on EOF or protocol violation; lengths
/// are capped at the wire frame limit so the local protocol never
/// exceeds what the transport accepts.
async fn read_frame(socket: &mut TcpStream) -> Option<(u8, Vec<u8>)> {
    let mut len_buf = [0u8; 4];
    socket.read_exact(&mut len_buf).await.ok()?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME {
        eprintln!("[swarm] runner frame length {len} outside 1..={MAX_FRAME}");
        return None;
    }
    let mut body = vec![0u8; len];
    socket.read_exact(&mut body).await.ok()?;
    let tag = body[0];
    Some((tag, body.split_off(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frame_roundtrip() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (mut server, _) = listener.accept().await.unwrap();
        write_frame(&mut client, 7, b"hello").await.unwrap();
        let (tag, payload) = read_frame(&mut server).await.unwrap();
        assert_eq!(tag, 7);
        assert_eq!(payload, b"hello");
    }
}
