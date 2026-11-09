//! Hardware-performance commands of the control socket: the score
//! board viewer (`hwperf`) and the one-command guided stress test
//! (`stress`) that certifies the machine's ceilings on demand.

use crate::daemon::Ctx;
use std::sync::Arc;

/// Render the hardware score board: observed maxima per component, the
/// derived measured points and the unified total the node announces.
/// Unmeasured components show their static fallback so the operator
/// always sees which price is in effect and why.
pub(super) async fn hwperf(ctx: &Arc<Ctx>) -> String {
    let perf = ctx.hwperf.lock().await;
    let board = perf.board();
    let total = perf.total_points(&ctx.config, &ctx.config.limits);
    let measured = perf.points(
        &ctx.config.hwperf,
        ctx.config.gpu.effective_count(),
        ctx.config.gpu.points_per_gpu,
    );
    let render = |observed: u64, samples: u64, points: Option<u32>, unit: &str| {
        if observed == 0 {
            format!("not measured (static price applies)")
        } else {
            format!(
                "{observed} {unit} over {samples} sample(s) -> {} points",
                points.unwrap_or(0)
            )
        }
    };
    let gpu = if !board.gpu.seen {
        "not measured (static price applies)".to_string()
    } else {
        format!(
            "{}% peak utilisation -> {} points",
            board.gpu.util_max,
            measured.gpu.unwrap_or(0)
        )
    };
    format!(
        "hwperf: enabled={enabled}\n\
         cpu: {cpu}\n\
         ram: {ram}\n\
         gpu: {gpu}\n\
         announced points: {total}\n",
        enabled = ctx.config.hwperf.enabled,
        cpu = render(
            board.cpu.observed_max,
            board.cpu.samples,
            measured.cpu,
            "Mops/s"
        ),
        ram = render(
            board.ram.observed_max,
            board.ram.samples,
            measured.ram,
            "MiB/s"
        ),
    )
}

/// Run the guided stress test once and render its report. The rate
/// limit keeps the control socket from pinning the machine; the run
/// itself certifies every component it can drive and refreshes the
/// announced price.
pub(super) async fn stress(ctx: &Arc<Ctx>) -> String {
    if !ctx.config.hwperf.enabled {
        return "error: hwperf is disabled in the configuration\n".to_string();
    }
    {
        let perf = ctx.hwperf.lock().await;
        if !perf.stress_allowed() {
            return format!(
                "error: stress test ran less than {} seconds ago; retry later\n",
                crate::hwperf::STRESS_RATE_LIMIT.as_secs()
            );
        }
    }
    let report =
        crate::hwperf::stress::run(ctx.hwperf.clone(), &ctx.config, &ctx.config.limits).await;
    crate::hwperf::stress::render(&report)
}
