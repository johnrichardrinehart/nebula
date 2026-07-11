{
  description = "Scalable overlay networking with hardware-bound identities";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, nixpkgs, ... }:
    let
      lib = nixpkgs.lib;
      goSources = lib.fileset.fileFilter (file: file.hasExt "go") ./.;
      goVendorHash = "sha256-qhEnYgHcvWdiQ9DsPbUoTGRst/ojzsuHhqacZcdmO8w=";
      packageSource = lib.fileset.toSource {
        root = ./.;
        fileset = lib.fileset.unions [
          goSources
          ./go.mod
          ./go.sum
        ];
      };
    in
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      imports = [ inputs.flake-parts.flakeModules.partitions ];

      partitionedAttrs = {
        checks = "dev";
        devShells = "dev";
        formatter = "dev";
      };

      partitions.dev = {
        extraInputsFlake = ./dev;
        module = import ./nix/flake/dev-partition.nix;
      };

      perSystem =
        { pkgs, ... }:
        {
          packages = rec {
            nebula = pkgs.buildGoModule {
              pname = "nebula";
              version = "unstable";
              src = packageSource;
              vendorHash = goVendorHash;

              subPackages = [
                "cmd/nebula"
                "cmd/nebula-cert"
                "cmd/nebula-keyring"
                "cmd/nebula-service"
              ];

              ldflags = [
                "-s"
                "-w"
              ];
              meta = {
                description = "Scalable overlay networking tool";
                homepage = "https://github.com/slackhq/nebula";
                license = lib.licenses.mit;
                mainProgram = "nebula";
              };
            };

            tpmclient-test = pkgs.buildGoModule {
              pname = "nebula-tpmclient-test";
              version = "unstable";
              src = packageSource;
              vendorHash = goVendorHash;
              buildPhase = ''
                runHook preBuild
                go test -c -o tpmclient.test ./tpmclient
                runHook postBuild
              '';
              installPhase = ''
                runHook preInstall
                install -Dm755 tpmclient.test $out/bin/tpmclient.test
                runHook postInstall
              '';
              doCheck = false;
            };

            default = nebula;
          };
        };
    };
}
