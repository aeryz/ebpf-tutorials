{
  description = "My ebpf related flake setup";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    eunomia-bpf.url = "github:eunomia-bpf/eunomia-bpf";
  };

  outputs = { self, nixpkgs, flake-utils, eunomia-bpf }:
      flake-utils.lib.eachSystem
      (with flake-utils.lib.system; [ x86_64-linux aarch64-linux ])
      (system: 
        let
          pkgs = import nixpkgs { inherit system; };
        in
    {
    devShells.default = pkgs.mkShell {
      packages = [
        eunomia-bpf.packages.x86_64-linux.ecli
      ];
    };

  });
}
