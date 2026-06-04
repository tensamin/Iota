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
      url = "git+https://git.methanium.net/tensamin/ttp.git";
      flake = false;
    };
  };

  outputs = inputs @ {
    self,
    nixpkgs,
    flake-parts,
    rust-overlay,
    ttp,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      perSystem = {
        self',
        pkgs,
        system,
        ...
      }: let
        rustPkgs = import nixpkgs {
          inherit system;
          overlays = [(import rust-overlay)];
        };

        rustToolchain = rustPkgs.rust-bin.stable.latest.default.override {
          extensions = ["rust-src" "rust-analyzer" "clippy" "rustfmt"];
        };
      in {
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

            nativeBuildInputs = with pkgs; [
              cmake
              perl
              pkg-config
            ];

            buildInputs = with pkgs; [
              openssl
              sqlite
            ];

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
          nativeBuildInputs = with pkgs; [
            rustToolchain
            git
            cmake
            perl
            pkg-config
          ];

          buildInputs = with pkgs; [
            openssl
            sqlite
          ];
        };
      };

      flake = {
        nixosModules.default = {
          config,
          pkgs,
          lib,
          ...
        }: let
          cfg = config.services.iota;

          defaultPackage =
            self.packages.${pkgs.stdenv.hostPlatform.system}.default
            or (throw "iota: no pre-built package for system ${pkgs.stdenv.hostPlatform.system}");

          configFile =
            if cfg.settingsFile != null
            then cfg.settingsFile
            else pkgs.writeText "iota-config.json" (builtins.toJSON cfg.settings);

          descriptionText = "Tensamin Iota";

          tmuxSessionName = "iota";
          tmuxSocket = "${cfg.dataDir}/tmux.sock";

          setupScript = pkgs.writeShellScript "iota-setup" ''
            set -euo pipefail

            mkdir -p ${lib.escapeShellArg cfg.dataDir}/certs

            ${lib.optionalString (cfg.certFile != null) ''
              ln -sf ${lib.escapeShellArg cfg.certFile} ${lib.escapeShellArg cfg.dataDir}/certs/cert.pem
            ''}

            ${lib.optionalString (cfg.keyFile != null) ''
              ln -sf ${lib.escapeShellArg cfg.keyFile} ${lib.escapeShellArg cfg.dataDir}/certs/cert.key
            ''}

            install -m 644 ${lib.escapeShellArg configFile} ${lib.escapeShellArg cfg.dataDir}/config.json

            chown -R iota:iota ${lib.escapeShellArg cfg.dataDir}
          '';

          iotaSessionScript = pkgs.writeShellScript "iota-tmux-session" ''
            set -euo pipefail

            socket=${lib.escapeShellArg tmuxSocket}
            session=${lib.escapeShellArg tmuxSessionName}

            if ! ${pkgs.tmux}/bin/tmux -S "$socket" has-session -t "$session" 2>/dev/null; then
              ${pkgs.tmux}/bin/tmux -S "$socket" new-session \
                -d \
                -s "$session" \
                -c ${lib.escapeShellArg cfg.dataDir} \
                ${lib.escapeShellArg "${cfg.package}/bin/iota"}
            fi

            while ${pkgs.tmux}/bin/tmux -S "$socket" has-session -t "$session" 2>/dev/null; do
              sleep 5
            done

            exit 1
          '';

          ttydScript = pkgs.writeShellScript "iota-ttyd" ''
            set -euo pipefail

            exec ${pkgs.ttyd}/bin/ttyd \
              -W \
              -i ${lib.escapeShellArg cfg.web.bindAddress} \
              -p ${lib.escapeShellArg (toString cfg.web.port)} \
              ${pkgs.tmux}/bin/tmux \
              -S ${lib.escapeShellArg tmuxSocket} \
              attach-session \
              -t ${lib.escapeShellArg tmuxSessionName}
          '';
        in {
          options.services.iota = {
            enable = lib.mkEnableOption "Enable the Iota service.";

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
              default = [];
              description = "Environment files to load for the Iota service.";
            };

            openFirewall = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Whether to open the firewall for ports used by Iota.";
            };

            bindAddress = lib.mkOption {
              type = lib.types.str;
              default = "0.0.0.0";
              description = "IP address to bind the Iota HTTP and TTP/QUIC servers to.";
            };

            web = {
              bindAddress = lib.mkOption {
                type = lib.types.str;
                default = "0.0.0.0";
                description = "IP address to bind the ttyd terminal server to.";
              };

              port = lib.mkOption {
                type = lib.types.port;
                default = 7681;
                description = "Port to bind the ttyd terminal server to.";
              };
            };

            package = lib.mkOption {
              type = lib.types.package;
              default = defaultPackage;
              description = "The Iota package to use.";
            };

            settings = lib.mkOption {
              type = lib.types.attrs;
              default = {};
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
              shell = pkgs.bash;
            };

            users.groups.iota = {};

            systemd.services.iota-session = {
              description = "${descriptionText} tmux session";
              wantedBy = ["multi-user.target"];
              after = ["network.target"];

              serviceConfig =
                {
                  Type = "simple";
                  User = "iota";
                  Group = "iota";
                  WorkingDirectory = cfg.dataDir;

                  ExecStartPre = [
                    ("+" + setupScript)
                  ];

                  ExecStart = iotaSessionScript;

                  ExecStop = ''
                    ${pkgs.tmux}/bin/tmux -S ${lib.escapeShellArg tmuxSocket} kill-session -t ${lib.escapeShellArg tmuxSessionName}
                  '';

                  Restart = "always";
                  RestartSec = "5s";

                  AmbientCapabilities = ["CAP_NET_BIND_SERVICE"];
                  CapabilityBoundingSet = ["CAP_NET_BIND_SERVICE"];

                  ProtectSystem = "strict";
                  ProtectHome = true;
                  PrivateTmp = true;
                  NoNewPrivileges = true;
                  ReadWritePaths = [cfg.dataDir];
                  ProtectKernelTunables = true;
                  ProtectKernelModules = true;
                  ProtectControlGroups = true;
                  RestrictRealtime = true;
                  RestrictSUIDSGID = true;
                  LockPersonality = true;
                  MemoryDenyWriteExecute = true;
                  Environment = [
                    "TTP_BIND=${cfg.bindAddress}"
                    "BIND_ADDRESS=${cfg.bindAddress}"
                  ];
                }
                // lib.optionalAttrs (cfg.environmentFiles != []) {
                  EnvironmentFile = cfg.environmentFiles;
                };
            };

            systemd.services.iota = {
              description = descriptionText;
              wantedBy = ["multi-user.target"];
              requires = ["iota-session.service"];
              after = ["iota-session.service" "network.target"];

              serviceConfig = {
                Type = "simple";
                User = "iota";
                Group = "iota";
                WorkingDirectory = cfg.dataDir;

                ExecStart = ttydScript;

                Restart = "always";
                RestartSec = "5s";

                AmbientCapabilities = ["CAP_NET_BIND_SERVICE"];
                CapabilityBoundingSet = ["CAP_NET_BIND_SERVICE"];

                ProtectSystem = "strict";
                ProtectHome = true;
                PrivateTmp = true;
                NoNewPrivileges = true;
                ReadWritePaths = [cfg.dataDir];
                ProtectKernelTunables = true;
                ProtectKernelModules = true;
                ProtectControlGroups = true;
                RestrictRealtime = true;
                RestrictSUIDSGID = true;
                LockPersonality = true;
                MemoryDenyWriteExecute = true;
              };
            };

            networking.firewall = lib.mkIf cfg.openFirewall {
              allowedTCPPorts = [1984 cfg.web.port];
              allowedUDPPorts = [1984];
            };
          };
        };
      };
    };
}
