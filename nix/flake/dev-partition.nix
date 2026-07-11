{ inputs, ... }:
{
  imports = [
    inputs.git-hooks.flakeModule
    inputs.treefmt-nix.flakeModule
    ../git-hooks.nix
    ../treefmt.nix
  ];

  perSystem =
    {
      config,
      pkgs,
      self',
      ...
    }:
    {
      checks = {
        inherit (self'.packages) nebula;
        tpm-ecdh = import ../checks/tpm-ecdh.nix {
          inherit pkgs;
          tpmclientTest = self'.packages.tpmclient-test;
        };
      };

      devShells.default = pkgs.mkShell {
        inputsFrom = [ config.pre-commit.devShell ];
        packages = with pkgs; [
          go_1_25
          golangci-lint
          gopls
          gotools
          protobuf
          protoc-gen-go
          swtpm
          tpm2-tools
          keyutils
        ];
      };
    };
}
