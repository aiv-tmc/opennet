# Nix package expression for the OpenNet daemon (opennetd) and the
# control CLI (opennetctl).
#
# The crate is built through `buildRustPackage` with the dependency
# resolution pinned by the committed `Cargo.lock` (`cargoLock.lockFile`)
# instead of a manually maintained fixed-output hash, so the build stays
# reproducible as dependencies evolve and no hash can silently drift out
# of sync with the manifest. After changing `[dependencies]` in
# `Cargo.toml`, refresh and commit the lockfile:
#
#     cargo generate-lockfile
#
# The init integration files for every supported service manager ship
# under `$out/share/opennet/` (systemd unit, sysusers/tmpfiles
# definitions, dinit/OpenRC/runit service files, s6-rc longrun
# definition), and the daemon's own default configuration is rendered at
# install time through `--print-default-config`.
{ lib, rustPlatform }:

rustPlatform.buildRustPackage rec {
  pname = "opennet";
  version = "1.0.0";

  # The whole repository is the source. Everything except the Cargo
  # build artifacts (`target/`) and Nix build results (`result`) is
  # included, so the lockfile, init files and sysusers/tmpfiles
  # definitions are all visible to the build and to `postInstall`.
  src = lib.cleanSourceWith {
    src = ../.;
    filter = path: _type:
      let base = baseNameOf path;
      in base != "target" && base != "result";
  };

  # Pin the dependency graph to the committed lockfile. Nix fetches
  # exactly the crates `Cargo.lock` names; no placeholder hash is ever
  # involved, so the build cannot fail with a hash mismatch.
  cargoLock = {
    lockFile = ../Cargo.lock;
  };

  # Run the crate's test suite (unit + loopback integration tests) as
  # the Nix check phase; the suite never touches system paths.
  doCheck = true;

  # Install the service-manager integration files alongside the
  # binaries. systemd/sysusers/tmpfiles land in their conventional
  # global locations; the dinit, OpenRC, runit and s6-rc definitions
  # live under share/ for distributions that wire them up manually.
  postInstall = ''
    install -Dm644 init/opennetd.service \
        $out/lib/systemd/system/opennetd.service
    install -Dm644 opennet.sysusers \
        $out/lib/sysusers.d/opennet.conf
    install -Dm644 opennet.tmpfiles \
        $out/lib/tmpfiles.d/opennet.conf

    install -d $out/share/opennet/init
    install -Dm644 init/opennetd.dinit \
        $out/share/opennet/init/opennetd.dinit
    install -Dm755 init/opennetd.openrc \
        $out/share/opennet/init/opennetd.openrc
    install -Dm755 init/opennetd.run \
        $out/share/opennet/init/opennetd.run

    install -d $out/share/opennet/s6-rc/opennetd
    install -Dm644 init/s6-rc/opennetd/type \
        $out/share/opennet/s6-rc/opennetd/type
    install -Dm755 init/s6-rc/opennetd/run \
        $out/share/opennet/s6-rc/opennetd/run

    $out/bin/opennetd --print-default-config > default-config.toml
    install -Dm644 default-config.toml \
        $out/etc/opennet/config.toml
  '';

  meta = with lib; {
    description = "Peer-to-peer network for distributed computing on a LAN";
    homepage = "https://github.com/aiv-tmc/opennet";
    license = licenses.mpl20;
    platforms = platforms.linux;
    mainProgram = "opennetd";
  };
}
