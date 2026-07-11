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
          handshakeTest = self'.packages.handshake-test;
        };
        mixed-daemon = import ../checks/mixed-daemon.nix {
          inherit pkgs;
          nebula = self'.packages.nebula;
        };
        sealed-x25519 = import ../checks/sealed-x25519.nix {
          inherit pkgs;
          nebula = self'.packages.nebula;
          nebulaUpstream = self'.packages.nebula-upstream;
          securekeyTest = self'.packages.securekey-test;
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
