//! Child supervision of the executor: waiting on the task process with
//! its wall-clock timeout, killing the whole process group on expiry,
//! and the capped output capture. Split from `executor.rs` so each
//! file stays focused; everything here is `pub(super)` plumbing.

/// Hard cap on captured output; beyond the cap the pipe keeps draining
/// (and discarding) so the child never blocks on a full pipe.
pub(super) const OUTPUT_CAP: usize = 64 * 1024;

use super::TaskOutcome;
use crate::compute::Launch;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

/// Supervise the child until exit or timeout. The wait future is
/// polled through `select!` against the timeout so the child handle
/// stays reachable on the timeout branch: the whole process group is
/// killed (on Unix, where the child leads its own group; elsewhere
/// the direct child is killed, which is all the platform offers), the
/// child is reaped, and the outcome reports the kill. Partial output
/// of a timed-out task is discarded: the bill is the full timeout
/// anyway.
pub(super) async fn run_command(
    child: &mut tokio::process::Child,
    #[cfg_attr(not(unix), allow(unused_variables))] pid: u32,
    launch: &Launch,
) -> std::result::Result<TaskOutcome, ()> {
    let mut stdout_pipe = child
        .stdout
        .take()
        .expect("stdout is piped by construction");
    let mut stderr_pipe = child
        .stderr
        .take()
        .expect("stderr is piped by construction");
    let wait = async {
        let (stdout, stderr, status) = tokio::join!(
            read_capped(&mut stdout_pipe, OUTPUT_CAP),
            read_capped(&mut stderr_pipe, OUTPUT_CAP),
            child.wait()
        );
        (stdout, stderr, status)
    };
    let outcome = tokio::select! {
        finished = wait => Ok(finished),
        _ = tokio::time::sleep(Duration::from_secs(launch.timeout_secs)) => Err(()),
    };
    match outcome {
        Ok((stdout, stderr, Ok(status))) => Ok(TaskOutcome {
            exit_code: status.code().unwrap_or(-1),
            stdout,
            stderr,
            billed_secs: 0,
        }),
        Ok((_stdout, _stderr, Err(err))) => {
            crate::log::warn(
                module_path!(),
                &format!("wait failed for {}: {err:#}", launch.task_id),
            );
            Err(())
        }
        Err(()) => {
            // The select dropped the `wait` future (releasing its
            // child borrow), so the child handle is usable here.
            #[cfg(unix)]
            // SAFETY: `pid` addresses the child's own process group
            // (created with `process_group(0)`), which the daemon is
            // not a member of.
            unsafe {
                libc::killpg(pid as i32, libc::SIGKILL);
            }
            #[cfg(not(unix))]
            let _ = child.start_kill();
            // Reap the killed child so it cannot linger as a zombie.
            let _ = child.wait().await;
            Ok(TaskOutcome {
                exit_code: -2,
                stdout: String::new(),
                stderr: "task timed out and was killed".to_string(),
                billed_secs: 0,
            })
        }
    }
}

/// Read one output pipe up to the cap; after the cap is reached the
/// pipe keeps being drained (and discarded) until end of file, so the
/// child never blocks on a full pipe even when it prints megabytes.
async fn read_capped(pipe: &mut (impl AsyncRead + Unpin), cap: usize) -> String {
    let mut text = String::new();
    let mut buf = [0u8; 4096];
    let mut budget = cap;
    loop {
        match pipe.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                if budget > 0 {
                    let take = budget.min(n);
                    text.push_str(&String::from_utf8_lossy(&buf[..take]));
                    budget -= take;
                }
            }
            Err(_) => break,
        }
    }
    text
}
