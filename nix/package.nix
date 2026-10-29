{ lib, rustPlatform }:

rustPlatform.buildRustPackage rec {
  pname = "opennet";
  version = "0.4.0";

  src = lib.cleanSource ../.;

  # First build with `cargoHash = lib.fakeHash;` — Nix aborts printing the
  # real hash ("got: sha256-..."); paste it here. See docs/packaging.md.
  cargoHash = lib.fakeHash;

  nativeBuildInputs = [ ];

  doCheck = true;

  postInstall = ''
    install -Dm644 init/opennetd.service $out/lib/systemd/system/opennetd.service
    install -Dm644 opennet.sysusers $out/lib/sysusers.d/opennet.conf
    install -Dm644 opennet.tmpfiles $out/lib/tmpfiles.d/opennet.conf
    $out/bin/opennetd --print-default-config > config.toml
    install -Dm644 config.toml $out/etc/opennet/config.toml
  '';

  meta = with lib; {
    description = "Peer-to-peer network for distributed computing on a LAN";
    homepage = "https://github.com/aiv-tmc/opennet";
    license = licenses.mpl20;
    platforms = platforms.linux;
    mainProgram = "opennetd";
  };
}
