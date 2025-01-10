{
  description = "Cross compile enviroment on x86 machine for aarch64";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
  };

  outputs = {
    self,
    nixpkgs,
  }: {
    devShells.x86_64-linux.default = let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      crossPkgs = pkgs.pkgsCross.aarch64-multiplatform;
    in
      pkgs.mkShell {
        nativeBuildInputs = [
          crossPkgs.stdenv.cc
          crossPkgs.openssl
          crossPkgs.pkg-config
          crossPkgs.libcbor
          pkgs.cmake
        ];

        shellHook = ''
          echo "Entering aarch64 cross-compilation environment"

          # Set cross compiler paths
          export CC="${crossPkgs.stdenv.cc}/bin/aarch64-unknown-linux-gnu-gcc"
          export CXX="${crossPkgs.stdenv.cc}/bin/aarch64-unknown-linux-gnu-g++"

          echo "Cross compiler paths:"
          echo "CC=$CC"
          echo "CXX=$CXX"
          echo "Target architecture: $($CC -dumpmachine)"
        '';
      };
  };
}
