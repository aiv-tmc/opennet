# NixOS module for the OpenNet daemon.
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.opennet;
  toml = pkgs.formats.toml { };

  # Defaults mirroring Config::default in src/config.rs; the user-supplied
  # `settings` are merged recursively on top.
  defaultSettings = {
    mode = "peer";
    limits = {
      cpu_percent = 50;
      ram_mb = 2048;
      max_tasks = 4;
    };
    trust = {
      genesis_trust = 100;
      min_trust = 0;
      points_per_core = 10;
      points_per_gb = 2;
    };
    network = {
      port = 0;
      multicast_addr = "239.255.0.1";
      multicast_port = 9999;
      hello_interval_secs = 5;
      heartbeat_interval_secs = 30;
      task_timeout_secs = 300;
      ann_max_age_secs = 120;
      ann_future_skew_secs = 120;
    };
    paths = {
      state_dir = cfg.stateDir;
      socket_path = "/run/opennet/control.sock";
    };
    swarm = {
      enabled = false;
      program = "";
      max_shard_ram_mb = 4096;
      max_shard_cpu_percent = 50;
      artifacts_dir = "${cfg.stateDir}/swarm";
    };
  };

  configFile = toml.generate "opennet.toml"
    (recursiveUpdate defaultSettings cfg.settings);
in
{
  options.services.opennet = {
    enable = mkEnableOption "the OpenNet peer-to-peer compute daemon";

    package = mkOption {
      type = types.package;
      default = pkgs.opennet;
      description = "The OpenNet package to run.";
    };

    stateDir = mkOption {
      type = types.path;
      default = "/var/lib/opennet";
      description = "Directory holding identity, state and the consent file.";
    };

    settings = mkOption {
      type = toml.type;
      default = { };
      description = ''
        Extra configuration merged over the built-in defaults and rendered
        to TOML, e.g. { swarm.enabled = true; swarm.program = "demo"; }.
      '';
    };
  };

  config = mkIf cfg.enable {
    users.users.opennet = {
      isSystemUser = true;
      group = "opennet";
      home = cfg.stateDir;
      description = "OpenNet P2P compute daemon";
    };
    users.groups.opennet = { };

    systemd.services.opennet = {
      description = "OpenNet P2P compute daemon";
      documentation = [ "https://github.com/aiv-tmc/opennet" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        Type = "notify";
        NotifyAccess = "main";
        ExecStart = "${cfg.package}/bin/opennetd --config ${configFile}";
        User = "opennet";
        Group = "opennet";
        StateDirectory = "opennet";
        RuntimeDirectory = "opennet";
        Delegate = true;
        Restart = "on-failure";
        RestartSec = 2;
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        ReadWritePaths = [ cfg.stateDir "/run/opennet" "/sys/fs/cgroup" ];
      };
    };
  };
}
