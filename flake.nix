{
  description = "Scalable overlay networking with hardware-bound identities";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
    nebula-upstream = {
      url = "github:slackhq/nebula/86733864fe7f13ad5664250af1c1726fe8275ab3";
      flake = false;
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

            nebula-upstream = pkgs.buildGoModule {
              pname = "nebula-upstream";
              version = "86733864";
              src = inputs.nebula-upstream;
              vendorHash = "sha256-RT3oE58+LevfJ+pZsu39XFKGuDfBRfdpx1ujWYVVOdU=";
              subPackages = [
                "cmd/nebula"
                "cmd/nebula-cert"
              ];
            };

            securekey-test = pkgs.buildGoModule {
              pname = "nebula-securekey-test";
              version = "unstable";
              src = packageSource;
              vendorHash = goVendorHash;
              buildPhase = ''
                runHook preBuild
                go test -c -o securekey.test ./securekey
                runHook postBuild
              '';
              installPhase = ''
                runHook preInstall
                install -Dm755 securekey.test $out/bin/securekey.test
                runHook postInstall
              '';
              doCheck = false;
            };

            handshake-test = pkgs.buildGoModule {
              pname = "nebula-handshake-test";
              version = "unstable";
              src = packageSource;
              vendorHash = goVendorHash;
              buildPhase = ''
                runHook preBuild
                go test -c -o handshake.test ./handshake
                runHook postBuild
              '';
              installPhase = ''
                runHook preInstall
                install -Dm755 handshake.test $out/bin/handshake.test
                runHook postInstall
              '';
              doCheck = false;
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
