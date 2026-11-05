# NixOS module for the OpenNet daemon.
#
# The module is self-contained: it builds the package from the flake's
# own `package.nix` by default, so enabling `services.opennet` works on
# any system without importing the flake overlay. Importing
# `overlays.default` still replaces the package fleet-wide for users
# who prefer that workflow.
#
# The unit is `Type=notify`: opennetd delivers `READY=1` to the
# systemd notification socket once the transport is bound and every
# subsystem is running, and reports `STOPPING=1` before it drains
# tasks during shutdown, so systemd never restarts the service mid-save.
{ config, lib, pkgs, ... }:

with lib;

let
  cfg = config.services.opennet;
  toml = pkgs.formats.toml { };

  # Defaults mirroring Config::default in src/config.rs; the user-supplied
  # `settings` are merged recursively on top, and the fixed listen `port`
  # is injected last-but-one so an explicit `settings.network.port`
  # still wins while the firewall always tracks the effective value.
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
    (recursiveUpdate
      (recursiveUpdate defaultSettings { network.port = cfg.port; })
      cfg.settings);
in
{
  options.services.opennet = {
    enable = mkEnableOption "the OpenNet peer-to-peer compute daemon";

    package = mkOption {
      type = types.package;
      # Built from the flake's own expression: evaluation succeeds on
      # systems that never imported the overlay.
      default = pkgs.callPackage ../package.nix { };
      defaultText = literalExpression "pkgs.callPackage ../package.nix { }";
      description = "The OpenNet package to run.";
    };

    stateDir = mkOption {
      type = types.path;
      default = "/var/lib/opennet";
      description = "Directory holding identity, state and the consent file.";
    };

    port = mkOption {
      type = types.port;
      default = 7000;
      description = ''
        Fixed TCP port the daemon listens on for peer connections. A
        fixed default (rather than an ephemeral port) keeps host
        firewall rules meaningful and matches the documented container
        port. Override `settings.network.port` only if you also manage
        the firewall yourself.
      '';
    };

    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Open the daemon's TCP listen port in the host firewall. LAN
        discovery multicast (UDP 9999) is not touched by this option.
      '';
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

    networking.firewall.allowedTCPPorts = mkIf cfg.openFirewall [ cfg.port ];

    systemd.services.opennet = {
      description = "OpenNet P2P compute daemon";
      documentation = [ "https://github.com/aiv-tmc/opennet" ];
      wantedBy = [ "multi-user.target" ];
      after = [ "network.target" ];

      serviceConfig = {
        # opennetd notifies readiness itself (READY=1 after all
        # subsystems are up, STOPPING=1 before the drain), so the unit
        # never sits in activating and Restart= never fires mid-save.
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
