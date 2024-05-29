{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
  buildInputs = [
    pkgs.python311
    pkgs.python311Packages.typer
    pkgs.python311Packages.rich
    pkgs.python311Packages.numpy
    pkgs.python311Packages.matplotlib
    pkgs.python311Packages.lief
    pkgs.python311Packages.art
    pkgs.python311Packages.alive-progress
    pkgs.python311Packages.lief
    pkgs.python311Packages.polars
    pkgs.python311Packages.python-magic
    pkgs.python311Packages.pyelftools
    pkgs.python311Packages.pefile
    pkgs.python311Packages.capstone
    pkgs.python311Packages.pandas
    pkgs.python311Packages.scipy
    pkgs.cargo-cross
    pkgs.podman
  ];
}





