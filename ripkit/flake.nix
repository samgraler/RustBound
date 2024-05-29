{
  description = "A flake that provides a development shell with Python 3.11 and specific packages.";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs";

  outputs = { self, nixpkgs }: {
    devShells.default = import ./shell.nix { inherit nixpkgs; };
  };
}

