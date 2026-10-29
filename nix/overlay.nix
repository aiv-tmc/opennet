# Nixpkgs overlay exposing the OpenNet package as `pkgs.opennet`.
final: prev: {
  opennet = final.callPackage ./package.nix { };
}
