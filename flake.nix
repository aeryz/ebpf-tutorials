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
          eunomia-pkgs = eunomia-bpf.packages.${system};
          bpftool = pkgs.runCommand "bpftool" {} ''
            mkdir -p $out/bin
            cp ${eunomia-pkgs.bpftool}/src/bpftool $out/bin
          '';
        in
    {
    devShells.default = pkgs.mkShell {
      packages = with pkgs; [
        clang
      ] ++ [
        bpftool
      ] ++ (with eunomia-bpf.packages.${system}; [
        ecc
        ecli
      ]);

      shellHook = ''
        export NIX_CFLAGS_COMPILE="-fno-stack-protector"
      '';
    };

  });
}
