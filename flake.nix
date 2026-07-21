{
  description = "Iota";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs @ {
    self,
    nixpkgs,
    flake-parts,
    rust-overlay,
    ...
  }:
    flake-parts.lib.mkFlake {inherit inputs;} {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
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
        commonBuildInputs = with pkgs; [openssl sqlite];
        commonNativeBuildInputs = with pkgs; [cmake perl pkg-config];
      in {
        packages = {
          default = self'.packages.iota-daemon;

          iota-daemon = pkgs.rustPlatform.buildRustPackage {
            pname = "iota-daemon";
            version = "0.1.0";
            src = ./.;
            cargoBuildFlags = ["-p" "iota-daemon"];
            cargoLock = {
              lockFile = ./Cargo.lock;
              allowBuiltinFetchGit = true;
            };
            nativeBuildInputs = commonNativeBuildInputs;
            buildInputs = commonBuildInputs;
            dontUseCmakeConfigure = true;
            postInstall = ''
              for f in $out/bin/*; do
                if [ "$(basename "$f")" != "iota-daemon" ]; then
                  rm "$f"
                fi
              done
            '';
            passthru.dataDir = "/var/lib/iota";
          };

          iota-ui = pkgs.rustPlatform.buildRustPackage {
            pname = "iota-ui";
            version = "0.1.0";
            src = ./.;
            cargoBuildFlags = ["-p" "iota"];
            cargoLock = {
              lockFile = ./Cargo.lock;
              allowBuiltinFetchGit = true;
            };
            nativeBuildInputs = commonNativeBuildInputs;
            buildInputs = commonBuildInputs;
            dontUseCmakeConfigure = true;
            postInstall = ''
              for f in $out/bin/*; do
                if [ "$(basename "$f")" != "iota" ]; then
                  rm "$f"
                fi
              done
              # Rename to avoid confusion
              if [ -f "$out/bin/iota" ]; then
                mv "$out/bin/iota" "$out/bin/iota-ui"
              fi
            '';
          };
        };

        devShells.default = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [rustToolchain git cmake perl pkg-config];
          buildInputs = commonBuildInputs;
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
          defaultPackage = self.packages.${pkgs.stdenv.hostPlatform.system}.iota-daemon or (throw "iota: no pre-built package for system ${pkgs.stdenv.hostPlatform.system}");

          configFile =
            if cfg.settingsFile != null
            then cfg.settingsFile
            else pkgs.writeText "iota-config.json" (builtins.toJSON cfg.settings);

          descriptionText = "Tensamin Iota daemon";
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
              description = "IP address to bind the HTTP server to.";
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

            systemd.sockets.iota-daemon = {
              description = "${descriptionText} IPC socket";
              wantedBy = ["sockets.target"];
              socketConfig = {
                ListenStream = "/run/iota/iota.sock";
                SocketMode = "0660";
                SocketUser = "iota";
                SocketGroup = "iota";
                Backlog = 5;
                RemoveOnStop = "true";
              };
            };

            systemd.services.iota-daemon = {
              description = descriptionText;
              after = ["network.target"];
              requires = ["iota-daemon.socket"];

              serviceConfig =
                {
                  Type = "notify";
                  User = "iota";
                  Group = "iota";
                  WorkingDirectory = cfg.dataDir;

                  ExecStart = "${cfg.package}/bin/iota-daemon";

                  ExecStartPre = [
                    ("+"
                      + pkgs.writeShellScript "iota-setup" ''
                        mkdir -p ${cfg.dataDir}/certs

                        ${lib.optionalString (cfg.certFile != null) "ln -sf ${cfg.certFile} ${cfg.dataDir}/certs/cert.pem"}
                        ${lib.optionalString (cfg.keyFile != null) "ln -sf ${cfg.keyFile} ${cfg.dataDir}/certs/cert.key"}

                        install -m 644 ${configFile} ${cfg.dataDir}/config.json

                        chown -R iota:iota ${cfg.dataDir}
                      '')
                  ];

                  Restart = "on-failure";
                  RestartSec = "5s";
                  RuntimeDirectory = "iota";
                  RuntimeDirectoryMode = "0750";

                  # Exit code 75 = restart requested
                  RestartPreventExitStatus = "0";
                  RestartForceExitStatus = "75";

                  TimeoutStopSec = "10";
                  KillMode = "mixed";
                  KillSignal = "SIGTERM";

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
                    "BIND_ADDRESS=${cfg.bindAddress}"
                    "IOTA_SOCKET=/run/iota/iota.sock"
                  ];
                }
                // lib.optionalAttrs (cfg.environmentFiles != []) {
                  EnvironmentFile = cfg.environmentFiles;
                };
            };

            networking.firewall = lib.mkIf cfg.openFirewall {
              allowedTCPPorts = [1984];
              allowedUDPPorts = [1984];
            };
          };
        };
      };
    };
}
