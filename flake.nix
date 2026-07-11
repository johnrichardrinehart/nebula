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
              vendorHash = "sha256-RT3oE58+LevfJ+pZsu39XFKGuDfBRfdpx1ujWYVVOdU=";

              subPackages = [
                "cmd/nebula"
                "cmd/nebula-cert"
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
            default = nebula;
          };
        };
    };
}
