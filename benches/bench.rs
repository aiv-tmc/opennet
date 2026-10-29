//! Performance benchmarks for the hot paths of the node.
//!
//! Run with `cargo bench --bench bench`. Tuned for quick feedback:
//! 100 ms warmups, 500 ms measurement windows, 15 samples — the whole
//! suite finishes in well under a minute. Two rules keep the numbers
//! honest:
//!
//! * benchmarks never drain a shared resource across iterations (the
//!   settlement bench bills zero units so the trust coefficient stays
//!   sustainable for the whole run);
//! * allocation costs that are not part of the measured operation (string
//!   formatting for queue ids) are prepared outside the timed loop.
//!
//! Delete stale baselines (`rm -rf target/criterion`) before reading
//! `change:` lines — comparisons against baselines recorded under a
//! different config or machine load are meaningless.
//!
//! The suite measures:
//!
//! * wire message encoding and decoding (postcard roundtrips of the signed
//!   announcement, used as the template for every signed frame);
//! * ed25519 signing and verification of announcement payloads, which the
//!   heartbeat pays every round per peer;
//! * routing table operations at 1024 peers;
//! * trust accounting — reserve/release are in-memory by design, the
//!   settle benchmark measures the real persistence cost;
//! * the accepted-bid priority queue;
//! * a full loopback transport roundtrip with a pre-encoded frame.
//!
//! Results land in `target/criterion`; record a fresh baseline with
//! `cargo bench --bench bench -- --save-baseline main` after any code
//! change you intend to compare.

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use opennet::compute::queue::{BidQueue, QueuedBid};
use opennet::dht::Dht;
use opennet::message::Message;
use opennet::node::identity::Identity;
use opennet::node::state::{Mode, NodeState};
use opennet::transport::Transport;
use std::path::PathBuf;
use std::time::Duration;

/// Criterion configuration tuned for quick developer feedback.
fn fast_criterion() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(100))
        .measurement_time(Duration::from_millis(500))
        .sample_size(15)
}

/// Fresh scratch directory for one benchmark tag: pid plus a random
/// component, so a stale directory from an earlier run (maybe created by
/// another user) can never shadow the current measurement.
fn bench_dir(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "opennet-bench-{tag}-{}-{:08x}",
        std::process::id(),
        rand::random::<u32>()
    ))
}

/// Build a signed announcement like the heartbeat sends every round.
fn sample_ann(identity: &Identity) -> Message {
    let node_id = identity.node_id();
    let unix_ts = opennet::trust::now_unix();
    let signature = identity.sign(&Message::ann_signing_payload(
        &node_id, "peer", 100, 44, unix_ts,
    ));
    Message::Ann {
        node_id,
        mode: "peer".into(),
        trust: 100,
        points: 44,
        unix_ts,
        pubkey: identity.pubkey(),
        signature: signature.to_vec(),
    }
}

fn bench_message(c: &mut Criterion) {
    let identity = Identity::load_or_create(&bench_dir("id")).expect("identity");
    let ann = sample_ann(&identity);
    c.bench_function("message_ann_encode_decode", |b| {
        b.iter(|| {
            let bytes = black_box(&ann).encode();
            black_box(Message::decode(black_box(&bytes)));
        })
    });
    c.bench_function("message_assign_signing_payload", |b| {
        b.iter(|| {
            black_box(Message::assign_signing_payload(
                black_box("task-0123456789abcdef"),
                black_box("echo hello && uname -a"),
                black_box(300),
            ));
        })
    });
}

fn bench_signatures(c: &mut Criterion) {
    let identity = Identity::load_or_create(&bench_dir("sign")).expect("identity");
    let payload = Message::ann_signing_payload(&identity.node_id(), "peer", 100, 44, 1_700_000_000);
    c.bench_function("ed25519_sign_ann", |b| {
        b.iter(|| black_box(identity.sign(black_box(&payload))));
    });
    let signature = identity.sign(&payload);
    let pubkey = identity.pubkey();
    c.bench_function("ed25519_verify_ann", |b| {
        b.iter(|| {
            black_box(Identity::verify(
                black_box(&pubkey),
                black_box(&payload),
                black_box(&signature),
            ));
        })
    });
}

fn bench_dht(c: &mut Criterion) {
    let mut dht = Dht::new();
    for i in 0..1024u32 {
        let addr = format!("tcp:10.0.{}.{}:4000", i / 256, i % 256);
        dht.insert(&addr);
        dht.apply_ann(
            &addr,
            &format!("node-{i:08x}"),
            "peer",
            100,
            44,
            1_700_000_000,
        );
    }
    let mut group = c.benchmark_group("dht_1024_peers");
    group.bench_function("find_by_node_id_prefix", |b| {
        b.iter(|| black_box(dht.find_by_node_id(black_box("node-0000"))));
    });
    group.bench_function("all_peers_unsorted", |b| {
        b.iter(|| black_box(dht.all_peers()));
    });
    group.bench_function("all_peers_by_recency", |b| {
        b.iter(|| black_box(dht.all_peers_by_recency()));
    });
    group.bench_function("insert_and_apply_ann", |b| {
        b.iter(|| {
            let addr = "tcp:10.255.255.255:4999";
            dht.insert(black_box(addr));
            dht.apply_ann(
                black_box(addr),
                black_box("node-zzzz"),
                black_box("peer"),
                black_box(100),
                black_box(44),
                black_box(1_700_000_000),
            );
            black_box(());
        })
    });
    group.finish();
}

fn bench_state(c: &mut Criterion) {
    let dir = bench_dir("state");
    std::fs::create_dir_all(&dir).unwrap();
    let limits = opennet::config::Limits {
        cpu_percent: 50,
        ram_mb: 2048,
        max_tasks: 4,
    };
    let trust_cfg = opennet::config::TrustCfg {
        genesis_trust: 100,
        min_trust: 0,
        points_per_core: 10,
        points_per_gb: 2,
    };
    let mut state = NodeState::load(&dir, Mode::Peer, limits, &trust_cfg).expect("state");

    c.bench_function("state_reserve_release", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let task = format!("bench-{counter}");
            let _ = black_box(state.reserve(black_box(&task), black_box(5), black_box(0)));
            state.release(black_box(&task));
            black_box(());
        })
    });

    // Sanity gate before measuring: settlement MUST persist to disk. If
    // this fails, every measured number below is fiction.
    state.reserve("warmup", 5, 0).unwrap();
    state.settle("warmup", 0);
    assert!(
        dir.join("state.json").exists(),
        "settle must persist state.json"
    );

    // The persistence cost of one settlement (serde + temp write +
    // rename). Billing zero units keeps the trust coefficient constant
    // across iterations: billing real units would drain it within ~20
    // iterations and degrade the benchmark into measuring an early return.
    c.bench_function("state_settle", |b| {
        let mut counter = 0u64;
        b.iter(|| {
            counter += 1;
            let task = format!("bench-settle-{counter}");
            let _ = state.reserve(black_box(&task), black_box(5), black_box(0));
            black_box(state.settle(black_box(&task), black_box(0)));
        })
    });
}

fn bench_queue(c: &mut Criterion) {
    let mut queue = BidQueue::new();
    // Task ids are prepared once: the queue does not deduplicate, so a
    // fixed pool can be reused, and the measurement covers the priority
    // queue rather than String formatting.
    let ids: Vec<String> = (0..1000).map(|i| format!("t-{i}")).collect();
    c.bench_function("queue_push_pop_1000", |b| {
        b.iter(|| {
            for id in &ids {
                queue.push(black_box(QueuedBid {
                    task_id: id.clone(),
                    units: 7,
                    expires_unix: 9_999_999_999,
                }));
                black_box(());
            }
            while black_box(queue.pop_fresh(black_box(0))).is_some() {}
        })
    });
}

fn bench_transport(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let a = runtime
        .block_on(Transport::new(0, Duration::from_secs(60)))
        .unwrap();
    let b = runtime
        .block_on(Transport::new(0, Duration::from_secs(60)))
        .unwrap();
    let dest = b.local_id();
    // Encoding is benchmarked separately; here the wire bytes are fixed.
    let frame: bytes::Bytes = Message::TaskAccept {
        task_id: "bench".into(),
    }
    .encode()
    .into();
    let mut group = c.benchmark_group("transport_loopback");
    group.throughput(Throughput::Elements(1));
    group.bench_function("send_recv_roundtrip", |bencher| {
        bencher.to_async(&runtime).iter(|| async {
            let _ = black_box(a.send(black_box(&dest), black_box(frame.clone())).await);
            black_box(b.recv().await);
        });
    });
    group.finish();
}

criterion_group!(
    name = benches;
    config = fast_criterion();
    targets = bench_message,
    bench_signatures,
    bench_dht,
    bench_state,
    bench_queue,
    bench_transport
);
criterion_main!(benches);
