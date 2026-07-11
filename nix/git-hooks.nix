{ ... }:
{
  perSystem =
    { pkgs, ... }:
    {
      # Go's module cache is intentionally populated outside the sandbox.
      # The package derivation remains the hermetic test gate.
      pre-commit.check.enable = false;
      pre-commit.settings.hooks = {
        treefmt.enable = true;
        go-test = {
          enable = true;
          name = "go test";
          entry = "${pkgs.go_1_25}/bin/go test ./...";
          files = "\\.go$";
          pass_filenames = false;
        };
        golangci-lint = {
          enable = true;
          pass_filenames = false;
        };
      };
    };
}
