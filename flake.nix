{
  description = "My ebpf related flake setup";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    eunomia-bpf.url = "github:eunomia-bpf/eunomia-bpf";
    eunomia-bpf.inputs.nixpkgs.follows = "nixpkgs";
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
        
          vmlinux-headers = pkgs.fetchFromGitHub {
            owner = "eunomia-bpf";
            repo = "vmlinux";
            rev = "933f83becb45f5586ed5fd089e60d382aeefb409";
            hash = "sha256-CVEmKkzdFNLKCbcbeSIoM5QjYVLQglpz6gy7+ZFPgCY=";
          };

          eccNoHardening = pkgs.writeShellScriptBin "ecc" ''
            export NIX_HARDENING_ENABLE=
            export NIX_CFLAGS_COMPILE=
            export NIX_CFLAGS_COMPILE_FOR_TARGET=
            export NIX_LDFLAGS=
            exec ${eunomia-pkgs.ecc}/bin/ecc-rs "$@"
          '';

        in
    {
    devShells.default = pkgs.mkShell {
      packages = with pkgs; [
        clang
      ] ++ [
        bpftool
        eccNoHardening
      ] ++ (with eunomia-bpf.packages.${system}; [
        ecli
      ]);

      shellHook = ''
        export C_INCLUDE_PATH=$C_INCLUDE_PATH:${vmlinux-headers}:${pkgs.libbpf}/include
        export NIX_CFLAGS_COMPILE="-fno-stack-protector"
        export LIBCLANG_PATH=${pkgs.llvmPackages.libclang.lib}/lib
      '';
    };

  });
}
