{
  description = "Dev shell for the RUKEM lattice estimator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-24.11";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system:
          f (import nixpkgs { inherit system; }));
    in
    {
      devShells = forAllSystems (pkgs:
        let
          pythonEnv = pkgs.python3.withPackages (ps: [
            ps.numpy
          ]);
          runRukem = pkgs.writeShellScriptBin "run-rukem" ''
            export PYTHONPATH="${pythonEnv}/${pkgs.python3.sitePackages}:''${PYTHONPATH:+$PYTHONPATH}"
            if [ -f "$PWD/rukem_params.py" ]; then
              exec sage -python "$PWD/rukem_params.py" "$@"
            fi

            if [ -f "$PWD/lattice_estimator/rukem_params.py" ]; then
              exec sage -python "$PWD/lattice_estimator/rukem_params.py" "$@"
            fi

            echo "run-rukem: could not find rukem_params.py from $PWD" >&2
            echo "Run from the lattice_estimator directory or the parent checkout." >&2
            exit 1
          '';
        in
        {
          default = pkgs.mkShell {
            buildInputs = [
              pkgs.sage
              pythonEnv
              runRukem
            ];

            shellHook = ''
              export PYTHONPATH="${pythonEnv}/${pkgs.python3.sitePackages}:''${PYTHONPATH:+$PYTHONPATH}"
              echo "Loaded SageMath + NumPy dev shell."
              echo "Run: sage -python rukem_params.py"
              echo "Or:  run-rukem"
            '';
          };
        });
    };
}
