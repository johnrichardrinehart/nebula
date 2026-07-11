{ ... }:
{
  perSystem.treefmt = {
    projectRootFile = "flake.nix";
    programs = {
      gofmt.enable = true;
      nixfmt.enable = true;
    };
    settings.formatter.gofmt.includes = [ "*.go" ];
  };
}
