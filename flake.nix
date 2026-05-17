{
  description = "Iota";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    ttp = {
      url = "git+https://git.methanium.net/Tensamin/TTP.git?rev=7e5d1953df8592a1feba0f390d205d0ef61a3119";
      flake = false;
    };
  };

  outputs = inputs@{ self, nixpkgs, flake-parts, rust-overlay, ttp, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem = { self', pkgs, system, ... }:
        let
          rustPkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          rustToolchain = rustPkgs.rust-bin.stable.latest.default.override {
            extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
          };
        in
        {
          packages = {
            default = self'.packages.iota;
            iota = pkgs.rustPlatform.buildRustPackage {
              pname = "iota";
              version = "0.1.0";
              src = ./.;
              cargoLock = {
                lockFile = ./Cargo.lock;
                allowBuiltinFetchGit = true;
              };
              nativeBuildInputs = with pkgs; [ cmake perl pkg-config ];
              buildInputs = with pkgs; [ openssl sqlite ];
              dontUseCmakeConfigure = true;
              preConfigure = ''
                if [ -d ../cargo-vendor-dir/ttp-core-0.1.0 ]; then
                  cp ${ttp}/ttp-codec.json ../cargo-vendor-dir/ttp-codec.json
                fi
              '';
              postInstall = ''
                mv $out/bin/iota-core $out/bin/iota
                for f in $out/bin/*; do
                  if [ "$(basename "$f")" != "iota" ]; then
                    rm "$f"
                  fi
                done
              '';
              passthru.dataDir = "/var/lib/iota";
            };
          };

          devShells.default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [ rustToolchain git cmake perl pkg-config ];
            buildInputs = with pkgs; [ openssl sqlite ];
          };
        };

      flake = {
        nixosModules.default = { config, pkgs, lib, ... }:
          let
            cfg = config.services.iota;
            defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.default or (throw "iota: no pre-built package for system ${pkgs.stdenv.hostPlatform.system}");

            configFile = if cfg.settingsFile != null then cfg.settingsFile else
              pkgs.writeText "iota-config.json" (builtins.toJSON cfg.settings);

            descriptionText = "Iota Service"
              + lib.optionalString cfg.useTmux " (attach TUI: tmux -S ${cfg.dataDir}/tmux.sock attach -t iota)";
          in
          {
            options.services.iota = {
              enable = lib.mkEnableOption "the Iota service";

              dataDir = lib.mkOption {
                type = lib.types.str;
                default = cfg.package.passthru.dataDir or "/var/lib/iota";
                defaultText = lib.literalExpression ''config.services.iota.package.passthru.dataDir or "/var/lib/iota"'';
                description = "Directory where Iota stores its data, config, and certificates.";
              };

              certFile = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "Path to the SSL certificate file (cert.pem).";
              };

              keyFile = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "Path to the SSL private key file (cert.key).";
              };

              environmentFiles = lib.mkOption {
                type = lib.types.listOf lib.types.path;
                default = [ ];
                description = "Environment files to load for the Iota service.";
              };

              openFirewall = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = "Whether to open the firewall for ports used by Iota.";
              };

              ttpBind = lib.mkOption {
                type = lib.types.str;
                default = "0.0.0.0";
                description = "IP address to bind the TTP/QUIC server to.";
              };

              bindAddress = lib.mkOption {
                type = lib.types.str;
                default = "0.0.0.0";
                description = "IP address to bind the HTTP server to.";
              };

              package = lib.mkOption {
                type = lib.types.package;
                default = defaultPackage;
                description = "The Iota package to use.";
              };

              useTmux = lib.mkOption {
                type = lib.types.bool;
                default = true;
                description = "Whether to run Iota inside a tmux session for shared TUI access.";
              };

              settings = lib.mkOption {
                type = lib.types.attrs;
                default = { };
                description = "Configuration attributes for Iota, written to config.json.";
              };

              settingsFile = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "Path to an existing config.json file to use instead of generating from settings.";
              };
            };

            config = lib.mkIf cfg.enable {
              users.users.iota = {
                isSystemUser = true;
                group = "iota";
                home = cfg.dataDir;
                createHome = true;
                description = "Iota service user";
              };

              users.groups.iota = { };

              systemd.services.iota = {
                description = descriptionText;
                wantedBy = [ "multi-user.target" ];
                after = [ "network.target" ];

                serviceConfig = {
                  Type = "simple";
                  User = "iota";
                  Group = "iota";
                  WorkingDirectory = cfg.dataDir;

                  ExecStart = if cfg.useTmux then
                    pkgs.writeShellScript "iota-start" ''
                      ${pkgs.tmux}/bin/tmux -S ${cfg.dataDir}/tmux.sock new-session -d -s iota '
                        ${cfg.package}/bin/iota 2>&1 | ${pkgs.coreutils}/bin/tee ${cfg.dataDir}/iota-output.log
                        EXIT_CODE=$?
                        echo ""
                        echo "============================================"
                        echo "Iota exited with code: $EXIT_CODE"
                        echo "Output saved to: ${cfg.dataDir}/iota-output.log"
                        echo "Press ENTER to close this session..."
                        read -r
                      '
                      while ${pkgs.tmux}/bin/tmux -S ${cfg.dataDir}/tmux.sock has-session -t iota 2>/dev/null; do
                        sleep 2
                      done
                    ''
                  else
                    "${cfg.package}/bin/iota";

                  ExecStartPre = [
                    ("+" + pkgs.writeShellScript "iota-setup" ''
                      mkdir -p ${cfg.dataDir}/certs

                      ${lib.optionalString (cfg.certFile != null) "ln -sf ${cfg.certFile} ${cfg.dataDir}/certs/cert.pem"}
                      ${lib.optionalString (cfg.keyFile != null) "ln -sf ${cfg.keyFile} ${cfg.dataDir}/certs/cert.key"}

                      install -m 644 ${configFile} ${cfg.dataDir}/config.json

                      chown -R iota:iota ${cfg.dataDir}

                      ${lib.optionalString cfg.useTmux ''
                        echo "Iota started under tmux. Attach with: tmux -S ${cfg.dataDir}/tmux.sock attach -t iota" >&2
                      ''}
                    '')
                  ];

                  Restart = "always";
                  RestartSec = "5s";

                  AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
                  CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];

                  ProtectSystem = "strict";
                  ProtectHome = true;
                  PrivateTmp = true;
                  NoNewPrivileges = true;
                  ReadWritePaths = [ cfg.dataDir ];
                  ProtectKernelTunables = true;
                  ProtectKernelModules = true;
                  ProtectControlGroups = true;
                  RestrictRealtime = true;
                  RestrictSUIDSGID = true;
                  LockPersonality = true;
                  MemoryDenyWriteExecute = true;
                  Environment = [
                    "TTP_BIND=${cfg.ttpBind}"
                    "BIND_ADDRESS=${cfg.bindAddress}"
                  ];
                } // lib.optionalAttrs (cfg.environmentFiles != [ ]) {
                  EnvironmentFile = cfg.environmentFiles;
                };
              };

              networking.firewall = lib.mkIf cfg.openFirewall {
                allowedTCPPorts = [ 1984 ];
                allowedUDPPorts = [ 1984 ];
              };
            };
          };
      };
    };
}
