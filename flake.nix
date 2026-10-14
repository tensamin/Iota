{
  description = "Iota packages and development shell";
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    type-maps = {
      url = "github:TensaminDev/MTP-Type-Maps/main";
      flake = false;
    };
  };
  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
      type-maps,
      ...
    }:
    let
      systems = nixpkgs.lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
      pkgsFor =
        system:
        import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      rustFor =
        pkgs:
        pkgs.rust-bin.stable.latest.default.override {
          extensions = [
            "rustfmt"
            "clippy"
          ];
          targets = [ "${pkgs.stdenv.hostPlatform.parsed.cpu.name}-unknown-linux-musl" ];
        };
    in
    {
      lib.mkPackage =
        {
          rustPlatform,
          pkgs,
          source,
          cargoDeps,
          typeMaps,
        }:
        rustPlatform.buildRustPackage {
          pname = "iota";
          version = "0.1.0";
          src = source;
          inherit cargoDeps;
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
          nativeBuildInputs = [
            pkgs.cmake
            pkgs.perl
            pkgs.pkg-config
          ];
          buildInputs = [
            pkgs.openssl
            pkgs.sqlite
          ];
          dontUseCmakeConfigure = true;
          MTP_TYPE_MAPS = "${typeMaps}/type-maps.yaml";
          doCheck = false;
          postInstall = ''
            mkdir -p "$out/share/iota"
            cp -r static/web "$out/share/iota/web"
          '';
          meta = {
            platforms = [
              "x86_64-linux"
              "aarch64-linux"
            ];
            mainProgram = "iota";
          };
        };
      lib.mkPortable =
        {
          pkgs,
          rustPlatform,
          rust,
          iota,
          typeMaps,
        }:
        let
          static = pkgs.pkgsStatic;
          target = static.stdenv.hostPlatform.rust;
          native = pkgs.stdenv.buildPlatform.rust;
        in
        rustPlatform.buildRustPackage {
          pname = "iota-portable";
          inherit (iota)
            version
            src
            cargoDeps
            cargoBuildFlags
            postInstall
            meta
            ;
          nativeBuildInputs = [
            pkgs.cmake
            pkgs.perl
            pkgs.pkg-config
            pkgs.binutils
            pkgs.removeReferencesTo
            static.stdenv.cc
          ];
          buildInputs = [
            static.openssl
            static.sqlite
            static.zlib
          ];
          OPENSSL_STATIC = "1";
          SQLITE3_STATIC = "1";
          env.PKG_CONFIG_ALLOW_CROSS = "1";
          buildPhase = ''
            runHook preBuild
            export CARGO_TARGET_${native.cargoEnvVarTarget}_LINKER=${pkgs.stdenv.cc}/bin/cc
            export CARGO_TARGET_${target.cargoEnvVarTarget}_LINKER=${static.stdenv.cc}/bin/${static.stdenv.cc.targetPrefix}cc
            export CC_${native.cargoEnvVarTarget}=${pkgs.stdenv.cc}/bin/cc
            export CC_${target.cargoEnvVarTarget}=${static.stdenv.cc}/bin/${static.stdenv.cc.targetPrefix}cc
            export CC_${
              builtins.replaceStrings [ "-" ] [ "_" ] target.rustcTarget
            }=${static.stdenv.cc}/bin/${static.stdenv.cc.targetPrefix}cc
            export CXX_${
              builtins.replaceStrings [ "-" ] [ "_" ] target.rustcTarget
            }=${static.stdenv.cc}/bin/${static.stdenv.cc.targetPrefix}c++
            unset NIX_CFLAGS_COMPILE NIX_LDFLAGS
            export CARGO_TARGET_${target.cargoEnvVarTarget}_RUSTFLAGS="-L native=${pkgs.lib.getLib static.zlib}/lib --remap-path-prefix=/nix/store=/usr/src"
            cargo build --locked --offline --release -j "$NIX_BUILD_CORES" \
              --target ${target.rustcTarget} ${pkgs.lib.escapeShellArgs iota.cargoBuildFlags}
            runHook postBuild
          '';
          installPhase = ''
            runHook preInstall
            mkdir -p "$out/bin"
            for binary in iota iota-daemon iota-updater iota-release iota-bundle; do
              cp "target/${target.rustcTarget}/release/$binary" "$out/bin/"
            done
            runHook postInstall
          '';
          dontUseCmakeConfigure = true;
          MTP_TYPE_MAPS = "${typeMaps}/type-maps.yaml";
          doCheck = false;
          postFixup = ''
            for binary in "$out"/bin/*; do
              remove-references-to -t ${rust} "$binary"
              if readelf -l "$binary" | grep -q INTERP || readelf -d "$binary" | grep -q NEEDED; then
                echo "Non-portable ELF: $binary" >&2
                exit 1
              fi
            done
          '';
          allowedReferences = [ "out" ];
        };
      lib.mkBundle =
        {
          pkgs,
          package,
          source,
          rawSource,
        }:
        pkgs.runCommand "iota-bundle" { } ''
          mkdir -p "$out/bin" "$out/share/iota"
          cp -r ${package}/bin/. "$out/bin/"
          cp -r ${rawSource}/systemd "$out/share/iota/"
          cp -r ${source}/scripts "$out/share/iota/"
          cp ${rawSource}/iota-updater/artifacts.tsv "$out/share/iota/"
          cp -r ${package}/share/iota/web "$out/share/iota/static-web"
          cp ${source}/iota-installer/bundle-files.txt "$out/share/iota/"
        '';
      lib.mkContainer =
        {
          pkgs,
          package,
          revision,
        }:
        pkgs.dockerTools.buildLayeredImage {
          name = "tensamin/iota";
          tag = revision;
          contents = [
            package
            pkgs.cacert
            pkgs.dockerTools.binSh
          ];
          fakeRootCommands = ''
            mkdir -p var/lib/iota/config var/lib/iota/runtime tmp
            chmod 1777 tmp
            chown -R 1000:1000 var/lib/iota
          '';
          enableFakechroot = true;
          config = {
            Entrypoint = [ "${package}/bin/iota-daemon" ];
            User = "1000:1000";
            WorkingDir = "/var/lib/iota";
            Volumes."/var/lib/iota" = { };
            ExposedPorts = {
              "1984/tcp" = { };
              "1984/udp" = { };
            };
            Env = [
              "HOME=/var/lib/iota"
              "IOTA_DATA_ROOT=/var/lib/iota"
              "IOTA_DEPLOYMENT_MODE=user_local"
              "IOTA_ASSET_DIR=${package}/share/iota/web"
              "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
            ];
          };
        };
      packages = systems (
        system:
        let
          pkgs = pkgsFor system;
          rust = rustFor pkgs;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = rust;
            rustc = rust;
          };
          source = pkgs.runCommand "iota-source" { } ''
            cp -r ${self} "$out"
            chmod -R u+w "$out"
            rm -rf "$out/mtp-type-maps"
            cp -r ${type-maps} "$out/mtp-type-maps"
          '';
        in
        {
          default = self.lib.mkPackage {
            inherit pkgs rustPlatform source;
            typeMaps = type-maps;
            cargoDeps = rustPlatform.fetchCargoVendor {
              pname = "iota";
              version = "0.1.0";
              src = source;
              hash = "sha256-YH/s5uFkkfqpDlxQ8Ci5NHMLZvJMQejP6qk+i24ZPFg=";
            };
          };
          cli = self.packages.${system}.default.overrideAttrs {
            pname = "iota-cli";
            cargoBuildFlags = [ "-p" "iota" ];
          };
          daemon = self.packages.${system}.default.overrideAttrs {
            pname = "iota-daemon";
            cargoBuildFlags = [ "-p" "iota-daemon" ];
            meta.mainProgram = "iota-daemon";
          };
          portable = self.lib.mkPortable {
            inherit pkgs rustPlatform rust;
            iota = self.packages.${system}.default;
            typeMaps = type-maps;
          };
          bundle = self.lib.mkBundle {
            inherit pkgs source;
            package = self.packages.${system}.default;
            rawSource = self;
          };
          container = self.lib.mkContainer {
            inherit pkgs;
            package = self.packages.${system}.portable;
            revision = self.shortRev or "local";
          };
        }
      );
      checks = systems (system: {
        inherit (self.packages.${system}) default;
      });
      devShells = systems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              (rustFor pkgs)
              pkgs.git
              pkgs.cmake
              pkgs.perl
              pkgs.pkg-config
            ];
            buildInputs = [
              pkgs.openssl
              pkgs.sqlite
            ];
            MTP_TYPE_MAPS = "${type-maps}/type-maps.yaml";
          };
        }
      );
    };
}
