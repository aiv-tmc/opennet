//! Command dispatch for the control socket: parse one command line
//! and route it to the matching renderer or subsystem. The output
//! format is a contract: `src/control/tests.rs` pins it (genesis
//! trust 100, the `commands:` help list, the `no reputation data
//! recorded` line).

use super::{perf, render};
use crate::compute;
use crate::daemon::Ctx;
use crate::node::state::Mode;
use std::sync::Arc;

/// Execute one control command and render its response.
pub(super) async fn dispatch(ctx: &Arc<Ctx>, command: &str) -> String {
    let mut parts = command.split_whitespace();
    let Some(head) = parts.next() else {
        return render::help();
    };
    match (head, parts.next()) {
        ("status", None) => render::status(ctx).await,
        ("mode", None) => {
            let mode = ctx.state.lock().await.mode;
            format!("mode: {}\n", mode.as_str())
        }
        ("mode", Some(name)) => match Mode::parse(name) {
            Ok(mode) => {
                {
                    let mut state = ctx.state.lock().await;
                    state.mode = mode;
                    let _ = state.save();
                }
                format!("mode set to {}\n", mode.as_str())
            }
            Err(err) => format!("error: {err}\n"),
        },
        ("peers", None) => render::peers(ctx).await,
        ("limits", None) => render::limits(&ctx.config),
        ("compute", Some(peer_token)) => {
            // Leading options before the command text: `--gpus N`
            // requests GPU devices, `--ram-mb M` requests a memory cap,
            // `--verify N` runs the task on N peers and keeps the
            // majority output; the first non-option token starts the
            // command.
            let mut gpus = 0u32;
            let mut ram_mb = 0u64;
            let mut verify = 1u32;
            let mut rest: Vec<&str> = Vec::new();
            let mut args = parts.peekable();
            while let Some(arg) = args.next() {
                match arg {
                    "--gpus" => match args.next().and_then(|value| value.parse().ok()) {
                        Some(count) => gpus = count,
                        None => return "error: --gpus needs a device count\n".to_string(),
                    },
                    "--ram-mb" => match args.next().and_then(|value| value.parse().ok()) {
                        Some(megabytes) => ram_mb = megabytes,
                        None => return "error: --ram-mb needs a size\n".to_string(),
                    },
                    "--verify" => match args.next().and_then(|value| value.parse().ok()) {
                        Some(count) if count >= 1 => verify = count,
                        _ => return "error: --verify needs a count >= 1\n".to_string(),
                    },
                    other => {
                        rest.push(other);
                        rest.extend(args);
                        break;
                    }
                }
            }
            if rest.is_empty() {
                return "usage: compute <node_prefix|-> [--gpus N] [--ram-mb M] [--verify N] <command...>\n"
                    .to_string();
            }
            let command_text = rest.join(" ");
            let prefix = (peer_token != "-").then_some(peer_token);
            compute::client::compute(
                ctx,
                prefix,
                command_text,
                ctx.config.network.task_timeout_secs,
                ram_mb,
                gpus,
                verify,
            )
            .await
        }
        ("trust", None) => render::trust(ctx).await,
        ("reputation", None) => render::reputation(ctx).await,
        ("hwperf", None) => perf::hwperf(ctx).await,
        ("stress", None) => perf::stress(ctx).await,
        ("swarm", None) | ("swarm", Some("status")) => render::swarm_status(ctx).await,
        ("swarm", Some("enable")) => render::swarm_set(ctx, parts.next(), true).await,
        ("swarm", Some("disable")) => render::swarm_set(ctx, None, false).await,
        ("swarm", Some("run")) => {
            let (Some(program), Some(prompt_path)) = (parts.next(), parts.next()) else {
                return "error: usage: swarm run <program> <prompt-file>\n".to_string();
            };
            match crate::swarm::coordinator::run_program(ctx, program, prompt_path).await {
                Ok(output) => output,
                Err(err) => format!("error: {err:#}\n"),
            }
        }
        ("shutdown", None) => {
            let _ = ctx.shutdown.send(true);
            "shutting down\n".to_string()
        }
        _ => render::help(),
    }
}
