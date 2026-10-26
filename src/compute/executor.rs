//! Provider-side executor: runs accepted commands safely and reports
//! completion so the scheduler frees the slot.
//!
//! Safety properties: every task runs in a fresh temporary directory with
//! a scrubbed environment (PATH and HOME only), inside its own process
//! group that is killed wholesale on timeout, and both output streams are
//! read with a hard cap so a flooding task cannot exhaust daemon memory.

use crate::compute::provider::{Cmd, Launch};
use crate::compute::TaskOutcome;
use crate::daemon::{send_msg, Ctx};
use crate::message::Message;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::mpsc;

/// Maximum captured output per stream, in bytes.
const OUTPUT_CAP: usize = 64 * 1024;
/// Execution environment handed to every task process.
const TASK_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// Executor loop: runs launched commands and reports `Cmd::Freed` after
/// each so the scheduler can refill the freed slot from the bid queue.
pub async fn run(ctx: Arc<Ctx>, mut rx: mpsc::Receiver<Launch>) {
    while let Some(launch) = rx.recv().await {
        execute(&ctx, launch).await;
        let _ = ctx.compute.send(Cmd::Freed).await;
    }
}

/// Run one command in a fresh working directory with a scrubbed environment
/// and a hard wall-clock limit, then credit the donated units, update
/// statistics and report the outcome to the consumer.
async fn execute(ctx: &Arc<Ctx>, launch: Launch) {
    let workdir = std::env::temp_dir().join(format!("opennet-task-{}", launch.task_id));
    let _ = tokio::fs::create_dir_all(&workdir).await;
    // The consumer-supplied limit is clamped to the locally configured
    // maximum so a manipulated assignment cannot extend the wall clock.
    let timeout_secs = launch
        .timeout_secs
        .clamp(1, ctx.config.network.task_timeout_secs.max(1));

    let mut child = match Command::new("sh")
        .arg("-c")
        .arg(&launch.command)
        .current_dir(&workdir)
        .env_clear()
        .env("PATH", TASK_PATH)
        .env("HOME", workdir.to_string_lossy().as_ref())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        // Give the task its own process group so the timeout path can kill
        // the whole tree, including grandchildren the shell may spawn.
        .process_group(0)
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            finish(
                ctx,
                &launch,
                &workdir,
                TaskOutcome {
                    exit_code: -1,
                    stdout: String::new(),
                    stderr: format!("failed to start task: {err}"),
                },
            )
            .await;
            return;
        }
    };
    // The child was just spawned, so its id is always available; it is
    // captured before waiting because the timeout and reap-failure paths
    // must address the process group by it.
    let pid = child.id().expect("freshly spawned child has no pid") as i32;
    let mut stdout_pipe = child.stdout.take().expect("stdout piped by spawn");
    let mut stderr_pipe = child.stderr.take().expect("stderr piped by spawn");
    let out_handle = tokio::spawn(async move { read_capped(&mut stdout_pipe).await });
    let err_handle = tokio::spawn(async move { read_capped(&mut stderr_pipe).await });

    let wall = Duration::from_secs(timeout_secs);
    let (exit_code, stderr) = match tokio::time::timeout(wall, child.wait()).await {
        Ok(Ok(status)) => (status.code().unwrap_or(-1), String::new()),
        Ok(Err(err)) => {
            // The wait syscall itself failed and the child state is
            // unknown: kill the whole process group to avoid leaking the
            // task, then reap it.
            unsafe { libc::killpg(pid, libc::SIGKILL) };
            let _ = child.wait().await;
            out_handle.abort();
            err_handle.abort();
            (-1, format!("failed to reap task: {err}"))
        }
        Err(_) => {
            // SAFETY: killpg with the child's own pid targets exactly the
            // process group created above; the daemon lives in a different
            // group and cannot signal itself or its siblings.
            unsafe { libc::killpg(pid, libc::SIGKILL) };
            // Reap the killed child so it cannot linger as a zombie.
            let _ = child.wait().await;
            (
                -2,
                format!("task exceeded its {timeout_secs}s limit and was killed"),
            )
        }
    };
    let stdout = out_handle.await.unwrap_or_default();
    let stderr = if stderr.is_empty() {
        to_text(err_handle.await.unwrap_or_default())
    } else {
        stderr
    };
    finish(
        ctx,
        &launch,
        &workdir,
        TaskOutcome {
            exit_code,
            stdout: to_text(stdout),
            stderr,
        },
    )
    .await;
}

/// Update statistics, credit the donated units to the local trust
/// coefficient, persist the state and deliver the outcome to the consumer.
async fn finish(ctx: &Arc<Ctx>, launch: &Launch, workdir: &std::path::Path, outcome: TaskOutcome) {
    let _ = tokio::fs::remove_dir_all(workdir).await;
    {
        let mut state = ctx.state.lock().await;
        if outcome.exit_code == 0 {
            state.tasks_completed += 1;
        } else {
            state.tasks_failed += 1;
        }
        // Donating compute to the network raises the trust coefficient.
        state.trust += launch.units;
        let _ = state.save();
    }
    let _ = send_msg(
        ctx,
        &launch.return_addr,
        &Message::TaskResult {
            task_id: launch.task_id.clone(),
            outcome,
        },
    )
    .await;
}

/// Read one output stream into memory capped at `OUTPUT_CAP` bytes; bytes
/// beyond the cap are drained and discarded so the task never blocks on a
/// full pipe and daemon memory stays bounded.
async fn read_capped(reader: &mut (impl AsyncReadExt + Unpin)) -> Vec<u8> {
    let mut buf = Vec::with_capacity(OUTPUT_CAP.min(4096));
    let mut chunk = [0u8; 4096];
    loop {
        match reader.read(&mut chunk).await {
            Ok(0) => break,
            Ok(read) => {
                if buf.len() < OUTPUT_CAP {
                    let take = read.min(OUTPUT_CAP - buf.len());
                    buf.extend_from_slice(&chunk[..take]);
                }
            }
            Err(_) => break,
        }
    }
    buf
}

/// Convert captured bytes to text, marking content that reached the cap.
fn to_text(bytes: Vec<u8>) -> String {
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    if text.len() >= OUTPUT_CAP {
        text.push_str("\n...[truncated]");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::Message;
    use crate::testutil::make_ctx;
    use crate::transport::Transport;
    use tokio::io::AsyncWriteExt;

    /// Build an executor context plus a standalone transport acting as the
    /// consumer side that receives the task outcome.
    async fn setup(tag: &str) -> (Arc<Ctx>, Transport) {
        let (ctx, _rx) = make_ctx(tag).await;
        let consumer_side = Transport::new(0).await.unwrap();
        (ctx, consumer_side)
    }

    fn launch(return_addr: &str, command: &str, timeout_secs: u64) -> Launch {
        // A unique task id gives every test its own working directory, so
        // parallel tests never remove each other's scratch directory.
        Launch {
            task_id: format!("t-test-{}", rand::random::<u32>()),
            return_addr: return_addr.to_string(),
            units: 5,
            command: command.to_string(),
            timeout_secs,
        }
    }

    async fn recv_outcome(consumer_side: &Transport) -> TaskOutcome {
        let (_src, data) = tokio::time::timeout(Duration::from_secs(10), consumer_side.recv())
            .await
            .expect("timed out waiting for TaskResult")
            .expect("transport closed");
        match Message::decode(&data) {
            Some(Message::TaskResult { outcome, .. }) => outcome,
            other => panic!("expected TaskResult, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn successful_task_credits_trust_and_reports_output() {
        let (ctx, consumer_side) = setup("ex-ok").await;
        execute(
            &ctx,
            launch(&consumer_side.local_id(), "echo hello-opennet", 30),
        )
        .await;
        assert_eq!(ctx.state.lock().await.trust, 105);
        assert_eq!(ctx.state.lock().await.tasks_completed, 1);
        let outcome = recv_outcome(&consumer_side).await;
        assert_eq!(outcome.exit_code, 0);
        assert!(
            outcome.stdout.contains("hello-opennet"),
            "unexpected stdout: {}",
            outcome.stdout
        );
    }

    #[tokio::test]
    async fn failing_task_counts_failure_and_captures_stderr() {
        let (ctx, consumer_side) = setup("ex-fail").await;
        execute(
            &ctx,
            launch(&consumer_side.local_id(), "echo oops >&2; exit 3", 30),
        )
        .await;
        assert_eq!(ctx.state.lock().await.tasks_failed, 1);
        let outcome = recv_outcome(&consumer_side).await;
        assert_eq!(outcome.exit_code, 3);
        assert!(outcome.stderr.contains("oops"), "unexpected stderr");
    }

    #[tokio::test]
    async fn timeout_kills_the_task_and_marks_it() {
        let (ctx, consumer_side) = setup("ex-timeout").await;
        let start = std::time::Instant::now();
        execute(&ctx, launch(&consumer_side.local_id(), "sleep 30", 1)).await;
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timeout path took too long"
        );
        let outcome = recv_outcome(&consumer_side).await;
        assert_eq!(outcome.exit_code, -2);
        assert!(outcome.stderr.contains("exceeded"), "unexpected stderr");
    }

    #[tokio::test]
    async fn capped_reader_bounds_memory_and_drains_the_rest() {
        let (mut mock, mut writer) = tokio::io::duplex(4096);
        let write = tokio::spawn(async move {
            for _ in 0..32 {
                writer.write_all(&[7u8; 4096]).await.unwrap();
            }
        });
        let data = read_capped(&mut mock).await;
        write.await.unwrap();
        assert_eq!(data.len(), OUTPUT_CAP);
        assert!(data.iter().all(|byte| *byte == 7));
    }

    #[tokio::test]
    async fn to_text_marks_truncated_content() {
        let big = vec![b'x'; OUTPUT_CAP];
        let text = to_text(big);
        assert!(text.ends_with("...[truncated]"));
        assert_eq!(to_text(b"abc".to_vec()), "abc");
    }
}
