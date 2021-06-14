let
  config   = { allowUnfree = true; };
  overlays = [
    (newPkgs: oldPkgs: rec {

      haskellPackages = oldPkgs.haskellPackages.override {
        overrides = haskellPackagesNew: _: {
          oidc-client = haskellPackagesNew.callCabal2nix "oidc-client" ./. { };
        };
      };

    })
  ];

  nixpkgs = import ./nix/21_05.nix;
  pkgs    = import nixpkgs { inherit config overlays; };

  oidc-client-shell = pkgs.haskellPackages.shellFor {
    withHoogle = false;
    packages = p: [
      p.oidc-client
    ];

    buildInputs = [
      pkgs.ghcid
    ];
  };

in

  { inherit (pkgs.haskellPackages) oidc-client;
    inherit oidc-client-shell;
  }
