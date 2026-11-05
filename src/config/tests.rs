//! Unit tests for the configuration loader: defaults materialize,
//! section-level overrides keep the rest of the defaults, unknown keys
//! are rejected, and the generated default document round-trips.

use super::*;

#[test]
fn default_config_loads_from_an_empty_document() {
    let cfg: Config = toml::from_str("").expect("empty config");
    assert_eq!(cfg.mode, Mode::Peer);
    assert_eq!(cfg.limits.cpu_percent, 50);
    assert_eq!(cfg.gpu.count, 0);
    assert_eq!(cfg.trust.new_node_units_factor, 2);
    assert!(!cfg.network.wan);
    assert!(cfg.network.seeds.is_empty());
    assert_eq!(cfg.sandbox.pids_max, 512);
}

#[test]
fn wan_section_overrides_and_defaults() {
    let text = r#"
        [network]
        wan = true
        seeds = ["203.0.113.7:7000", "203.0.113.8:7000"]
    "#;
    let cfg: Config = toml::from_str(text).expect("wan config");
    assert!(cfg.network.wan);
    assert_eq!(cfg.network.seeds.len(), 2);
    // Omitted fields inside a present section keep their defaults.
    assert_eq!(cfg.network.port, 7000);
    assert_eq!(cfg.network.heartbeat_interval_secs, 30);
}

#[test]
fn unknown_keys_abort_the_parse() {
    let err = toml::from_str::<Config>("[limits]\ncpu_prcent = 50\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("cpu_prcent"), "unexpected error: {err}");
    let err = toml::from_str::<Config>("[netwrok]\nport = 7000\n")
        .unwrap_err()
        .to_string();
    assert!(err.contains("netwrok"), "unexpected error: {err}");
}

#[test]
fn partial_gpu_section_keeps_the_default_price() {
    let cfg: Config = toml::from_str("[gpu]\ncount = 1\n").expect("partial gpu");
    assert_eq!(cfg.gpu.count, 1);
    assert_eq!(cfg.gpu.points_per_gpu, 50);
    assert!(cfg.gpu.devices.is_empty());
}

#[test]
fn default_toml_roundtrips_through_the_loader() {
    let text = default_toml().expect("default toml");
    let cfg: Config = toml::from_str(&text).expect("roundtrip");
    assert_eq!(cfg, Config::default());
}

#[test]
fn mode_names_deserialize_lowercase() {
    #[derive(Deserialize)]
    struct Wrap {
        mode: Mode,
    }
    let wrap: Wrap = toml::from_str("mode = \"seed\"").unwrap();
    assert_eq!(wrap.mode, Mode::Seed);
    assert!(toml::from_str::<Wrap>("mode = \"bogus\"").is_err());
}
