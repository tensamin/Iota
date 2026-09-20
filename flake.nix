{
  description = "Iota";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    mtp-type-maps = {
      url = "git+https://git.methanium.net/tensamin/mtp-type-maps";
      flake = false;
    };
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-parts,
      rust-overlay,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];

      perSystem =
        {
          self',
          pkgs,
          system,
          ...
        }:
        let
          rustPkgs = import nixpkgs {
            inherit system;
            overlays = [ (import rust-overlay) ];
          };
          rustToolchain = rustPkgs.rust-bin.stable.latest.default.override {
            extensions = [
              "rust-src"
              "rust-analyzer"
              "clippy"
              "rustfmt"
            ];
          };
          commonBuildInputs = with pkgs; [
            openssl
            sqlite
          ];
          commonNativeBuildInputs = with pkgs; [
            cmake
            perl
            pkg-config
          ];
        in
        {
          packages = {
            default = pkgs.rustPlatform.buildRustPackage {
              pname = "iota";
              version = "0.1.0";
              src = ./.;
              cargoBuildFlags = [
                "-p"
                "iota"
                "-p"
                "iota-daemon"
                "-p"
                "iota-updater"
                "-p"
                "iota-installer"
              ];
              cargoLock = {
                lockFile = ./Cargo.lock;
                allowBuiltinFetchGit = true;
              };
              nativeBuildInputs = commonNativeBuildInputs;
              buildInputs = commonBuildInputs;
              dontUseCmakeConfigure = true;
              MTP_TYPE_MAPS = "${inputs.mtp-type-maps}/type-maps.yaml";
              passthru.dataDir = "/var/lib/iota";
            };

            iota-daemon = self'.packages.default.overrideAttrs (old: {
              pname = "iota-daemon";
              cargoBuildFlags = [
                "-p"
                "iota-daemon"
              ];
              postInstall = ''
                for f in $out/bin/*; do
                  if [ "$(basename "$f")" != "iota-daemon" ]; then
                    rm "$f"
                  fi
                done
              '';
            });

            iota-ui = self'.packages.default.overrideAttrs (old: {
              pname = "iota-ui";
              cargoBuildFlags = [
                "-p"
                "iota"
              ];
              postInstall = ''
                for f in $out/bin/*; do
                  if [ "$(basename "$f")" != "iota" ]; then
                    rm "$f"
                  fi
                done
                if [ -f "$out/bin/iota" ]; then
                  mv "$out/bin/iota" "$out/bin/iota-ui"
                fi
              '';
            });
          };

          devShells.default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              rustToolchain
              git
              cmake
              perl
              pkg-config
            ];
            buildInputs = commonBuildInputs;
          };
        };

      flake = {
        nixosModules.default =
          {
            config,
            pkgs,
            lib,
            ...
          }:
          let
            cfg = config.services.iota;
            defaultPackage =
              self.packages.${pkgs.stdenv.hostPlatform.system}.default
                or (throw "iota: no pre-built package for system ${pkgs.stdenv.hostPlatform.system}");

            configFormat = pkgs.formats.yaml { };
            effectiveSettings = lib.recursiveUpdate {
              port = cfg.port;
              web = {
                mode = "network";
                bind = cfg.bindAddress;
                port = cfg.port;
                required = true;
              }
              // lib.optionalAttrs (cfg.certFile != null) {
                certificate = "${cfg.stateDir}/tls/cert.pem";
                key = "${cfg.stateDir}/tls/key.pem";
              };
            } cfg.settings;
            configFile =
              if cfg.settingsFile != null then
                cfg.settingsFile
              else
                configFormat.generate "iota-config.yaml" effectiveSettings;

            descriptionText = "Tensamin Iota daemon";
          in
          {
            options.services.iota = {
              enable = lib.mkEnableOption "Enable the Iota service.";

              stateDir = lib.mkOption {
                type = lib.types.str;
                default = "/var/lib/iota";
                description = "Persistent mutable Iota state.";
              };
              cacheDir = lib.mkOption {
                type = lib.types.str;
                default = "/var/cache/iota";
              };
              runtimeDir = lib.mkOption {
                type = lib.types.str;
                default = "/run/iota";
              };
              logDir = lib.mkOption {
                type = lib.types.str;
                default = "/var/log/iota";
              };
              assetDir = lib.mkOption {
                type = lib.types.str;
                default = "${cfg.package}/share/iota/web";
              };

              certFile = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "Path to the SSL certificate file (cert.pem).";
              };

              keyFile = lib.mkOption {
                type = lib.types.nullOr lib.types.str;
                default = null;
                description = "Path to the SSL private key file (cert.key).";
              };

              environmentFiles = lib.mkOption {
                type = lib.types.listOf lib.types.str;
                default = [ ];
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

              port = lib.mkOption {
                type = lib.types.port;
                default = 1984;
                description = "TCP and UDP port for protocol-only Iota.";
              };

              omegaApiUrl = lib.mkOption {
                type = lib.types.str;
                default = "https://omega.tensamin.net";
                description = "Omega discovery API URL.";
              };

              package = lib.mkOption {
                type = lib.types.package;
                default = defaultPackage;
                description = "The Iota package to use.";
              };

              settings = lib.mkOption {
                type = lib.types.attrs;
                default = { };
                description = "Configuration attributes for Iota, written to YAML.";
              };

              settingsFile = lib.mkOption {
                type = lib.types.nullOr lib.types.path;
                default = null;
                description = "Path to an existing YAML file to use instead of generating from settings.";
              };
            };

            config = lib.mkIf cfg.enable {
              assertions = [
                {
                  assertion = (cfg.certFile == null) == (cfg.keyFile == null);
                  message = "services.iota: certFile and keyFile must be set together.";
                }
              ];

              users.users.iota = {
                isSystemUser = true;
                group = "iota";
                home = cfg.stateDir;
                createHome = true;
                description = "Iota service user";
                shell = pkgs.bash;
              };

              users.groups.iota = { };

              systemd.sockets.iota = {
                description = "${descriptionText} IPC socket";
                wantedBy = [ "sockets.target" ];
                socketConfig = {
                  ListenStream = "/run/iota/iota.sock";
                  SocketMode = "0660";
                  SocketUser = "iota";
                  SocketGroup = "iota";
                  DirectoryMode = "0750";
                  Backlog = 5;
                  RemoveOnStop = "true";
                  NonBlocking = true;
                };
              };

              systemd.services.iota = {
                description = descriptionText;
                wantedBy = [ "multi-user.target" ];
                after = [
                  "network.target"
                  "iota.socket"
                ];
                requires = [ "iota.socket" ];

                environment.OMEGA_API_URL = cfg.omegaApiUrl;

                serviceConfig = {
                  Type = "simple";
                  User = "iota";
                  Group = "iota";
                  ExecStart = "${cfg.package}/bin/iota-daemon";

                  Restart = "on-failure";
                  RestartSec = "5s";
                  RuntimeDirectory = "iota";
                  RuntimeDirectoryMode = "0750";
                  StateDirectory = "iota";
                  StateDirectoryMode = "0750";
                  CacheDirectory = "iota";
                  CacheDirectoryMode = "0750";
                  LogsDirectory = "iota";
                  LogsDirectoryMode = "0750";

                  # Exit code 75 = restart requested
                  RestartPreventExitStatus = "0";
                  RestartForceExitStatus = "75";

                  TimeoutStopSec = "10";
                  KillMode = "mixed";
                  KillSignal = "SIGTERM";

                  AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
                  CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];

                  ProtectSystem = "strict";
                  ProtectHome = true;
                  PrivateTmp = true;
                  NoNewPrivileges = true;
                  ReadWritePaths = [
                    cfg.stateDir
                    cfg.cacheDir
                    cfg.runtimeDir
                    cfg.logDir
                  ];
                  ReadOnlyPaths = [
                    configFile
                    cfg.assetDir
                  ];
                  ProtectKernelTunables = true;
                  ProtectKernelModules = true;
                  ProtectControlGroups = true;
                  RestrictRealtime = true;
                  RestrictSUIDSGID = true;
                  LockPersonality = true;
                  MemoryDenyWriteExecute = true;
                  Environment = [
                    "IOTA_SOCKET=/run/iota/iota.sock"
                    "IOTA_CONFIG_FILE=${configFile}"
                    "IOTA_STATE_DIR=${cfg.stateDir}"
                    "IOTA_CACHE_DIR=${cfg.cacheDir}"
                    "IOTA_RUNTIME_DIR=${cfg.runtimeDir}"
                    "IOTA_LOG_DIR=${cfg.logDir}"
                    "IOTA_ASSET_DIR=${cfg.assetDir}"
                    "IOTA_DEPLOYMENT_MODE=system_socket_activated"
                    "IOTA_SUPERVISOR=systemd"
                  ];
                }
                // lib.optionalAttrs (cfg.certFile != null) {
                  ExecStartPre = "+${pkgs.writeShellScript "iota-setup-tls" ''
                    install -d -m 0700 -o iota -g iota ${cfg.stateDir}/tls
                    install -m 0644 -o iota -g iota ${cfg.certFile} ${cfg.stateDir}/tls/cert.pem
                    install -m 0600 -o iota -g iota ${cfg.keyFile} ${cfg.stateDir}/tls/key.pem
                  ''}";
                }
                // lib.optionalAttrs (cfg.environmentFiles != [ ]) {
                  EnvironmentFile = cfg.environmentFiles;
                };
              };

              networking.firewall = lib.mkIf cfg.openFirewall {
                allowedTCPPorts = [ cfg.port ];
                allowedUDPPorts = [ cfg.port ];
              };
            };
          };
      };
    };
}
