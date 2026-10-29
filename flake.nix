{
  description = "OpenNet: peer-to-peer distributed computing on a LAN";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (system:
        let pkgs = import nixpkgs { inherit system; };
        in {
          default = pkgs.callPackage ./nix/package.nix { };
          opennet = pkgs.callPackage ./nix/package.nix { };
        });

      overlays.default = import ./nix/overlay.nix;

      nixosModules.default = import ./nix/module.nix;
      nixosModules.opennet = import ./nix/module.nix;
    };
}
