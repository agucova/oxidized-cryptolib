{ pkgs, lib, ... }:

let
  # pjdfstest - POSIX filesystem test suite
  # https://github.com/pjd/pjdfstest
  pjdfstest = pkgs.stdenv.mkDerivation rec {
    pname = "pjdfstest";
    version = "0.1";

    src = pkgs.fetchFromGitHub {
      owner = "pjd";
      repo = "pjdfstest";
      rev = "03eb25706d8dbf3611c3f820b45b7a5e09a36c06";
      sha256 = "sha256-CUl9Hlz8Y/6mGTnm5CHNJOOJjda0sv7yPp1meoaJEN8=";
    };

    nativeBuildInputs = [ pkgs.autoreconfHook pkgs.perl ];

    # Tests need to run on an actual mounted filesystem
    doCheck = false;

    meta = with lib; {
      description = "POSIX filesystem test suite";
      homepage = "https://github.com/pjd/pjdfstest";
      license = licenses.bsd2;
      platforms = platforms.unix;
    };
  };

  # FSKitBridge - Bridge between macOS FSKit and Rust filesystem implementations
  # https://github.com/debox-network/FSKitBridge
  # Required for oxidized-fskit-legacy (FSKit-based vault mounting on macOS 15.4+)
  fskitbridge = pkgs.stdenv.mkDerivation rec {
    pname = "FSKitBridge";
    version = "0.1.0";

    src = pkgs.fetchurl {
      url = "https://github.com/debox-network/FSKitBridge/releases/download/v${version}/FSKitBridge-${version}.zip";
      sha256 = "sha256-u1z4Z/THPhD7M8t3nHNnYo62ozn83adFmT73JYb8vhE=";
    };

    nativeBuildInputs = [ pkgs.unzip ];

    unpackPhase = ''
      unzip $src
    '';

    installPhase = ''
      mkdir -p $out/Applications
      cp -Ra FSKitBridge.app $out/Applications/
    '';

    # macOS app bundles shouldn't be patched
    dontPatchShebangs = true;
    dontPatchELF = true;
    dontFixup = true;

    meta = with lib; {
      description = "FSKit bridge for Rust filesystem implementations on macOS 15.4+";
      homepage = "https://github.com/debox-network/FSKitBridge";
      license = licenses.mit;
      platforms = platforms.darwin;
    };
  };

  # fsstress - filesystem stress testing tool
  # Originally from SGI/XFS, ported via secfs.test
  fsstress = pkgs.stdenv.mkDerivation rec {
    pname = "fsstress";
    version = "1.0";

    src = pkgs.fetchFromGitHub {
      owner = "billziss-gh";
      repo = "secfs.test";
      rev = "edf5eb4a108bfb41073f765aef0cdd32bb3ee1ed";
      sha256 = "0gv8g44slbmf503mv4b8ndhrm3k2qhnpgrqdd0y2z7d2pxjj2lwh";
    };

    sourceRoot = "source/fsstress";

    buildPhase = ''
      $CC -Wall -DNO_XFS -D_LARGEFILE64_SOURCE -D_GNU_SOURCE fsstress.c -o fsstress
    '';

    installPhase = ''
      mkdir -p $out/bin
      cp fsstress $out/bin/
    '';

    meta = with lib; {
      description = "Filesystem stress testing tool from XFS/LTP";
      homepage = "https://github.com/billziss-gh/secfs.test";
      license = licenses.gpl2;
      platforms = platforms.linux;  # Linux-specific syscalls
    };
  };
  # Paths for FSKit Swift builds (requires Xcode toolchain for FSKit.framework)
  xcodeSwift = "/Applications/Xcode.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift";
  xcodeSdk = "/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk";
in
{
  languages.rust = {
    enable = true;
    channel = "nightly";
    components = [ "rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" "rust-src" "llvm-tools" ];
  };

  # Bun for Tailwind CSS in oxidized-gui
  languages.javascript.bun = {
    enable = true;
    install.enable = true;
  };

  packages = with pkgs; [
    cargo-edit
    cargo-outdated
    cargo-audit
    cargo-fuzz
    cargo-nextest
    dioxus-cli
    openssl
    pkg-config
  ]
  # Add pjdfstest and fsstress on Linux (requires FUSE which is native there)
  ++ lib.optionals stdenv.isLinux [
    pjdfstest
    fsstress
    fuse3
  ]
  # On macOS, add macfuse build dependencies (macfuse itself must be installed via brew)
  ++ lib.optionals stdenv.isDarwin [
    pjdfstest   # Can still build pjdfstest, just needs macFUSE at runtime
    protobuf    # Required for fskit-rs (FSKit filesystem support)
    fskitbridge # FSKitBridge.app for FSKit-based vault mounting (macOS 15.4+)
  ];

  env = {
    RUST_BACKTRACE = "1";
  } // lib.optionalAttrs pkgs.stdenv.isDarwin {
    PKG_CONFIG_PATH = "/usr/local/lib/pkgconfig";
  };

  enterShell = ''
    # Install cargo tools silently if missing
    command -v cargo-llvm-cov &> /dev/null || cargo install cargo-llvm-cov --quiet
    command -v fsx &> /dev/null || cargo install fsx --quiet
    command -v tokio-console &> /dev/null || cargo install tokio-console --locked --quiet

    # FSKitBridge installation for macOS 15.4+
    if [[ "$(uname)" == "Darwin" ]] && [[ -d "${fskitbridge}/Applications/FSKitBridge.app" ]]; then
      if [[ ! -d ~/Applications/FSKitBridge.app ]]; then
        mkdir -p ~/Applications
        cp -Ra "${fskitbridge}/Applications/FSKitBridge.app" ~/Applications/
        xattr -cr ~/Applications/FSKitBridge.app 2>/dev/null || true
      fi
    fi
  '';

  # FSKit Swift extension build scripts (macOS only)
  # These use Xcode's Swift toolchain because FSKit.framework requires the macOS SDK
  scripts = lib.optionalAttrs pkgs.stdenv.isDarwin {
    # Build just the Rust FFI static library
    fskit-build-rust.exec = ''
      echo "Building Rust FFI static library..."
      PKG_CONFIG_PATH=/usr/local/lib/pkgconfig cargo build -p oxidized-fskit-legacy-ffi --release
      echo "Static library built: target/release/liboxidized_fskit_ffi.a"
    '';

    # Sync generated Swift/C bindings to the Swift package
    fskit-sync-bindings.exec = ''
      set -e
      FFI_CRATE="crates/oxidized-fskit-legacy-ffi"
      GENERATED_DIR="$FFI_CRATE/generated"
      SWIFT_FFI="$FFI_CRATE/swift"
      SOURCES_DIR="$SWIFT_FFI/Sources/OxVaultFFI"
      INCLUDE_DIR="$SWIFT_FFI/include"

      if [[ ! -d "$GENERATED_DIR" ]]; then
        echo "Error: Generated directory not found. Run 'fskit-build-rust' first."
        exit 1
      fi

      mkdir -p "$SOURCES_DIR" "$INCLUDE_DIR"

      echo "Copying Swift sources..."
      # Add imports if not present
      if ! grep -q "import COxVaultFFI" "$GENERATED_DIR/SwiftBridgeCore.swift"; then
        echo -e "import Foundation\nimport COxVaultFFI\n$(tail -n +2 $GENERATED_DIR/SwiftBridgeCore.swift)" > "$SOURCES_DIR/SwiftBridgeCore.swift"
      else
        cp "$GENERATED_DIR/SwiftBridgeCore.swift" "$SOURCES_DIR/"
      fi

      if ! grep -q "import COxVaultFFI" "$GENERATED_DIR/oxidized-fskit-legacy-ffi/oxidized-fskit-legacy-ffi.swift"; then
        echo -e "import Foundation\nimport COxVaultFFI\n\n$(cat $GENERATED_DIR/oxidized-fskit-legacy-ffi/oxidized-fskit-legacy-ffi.swift)" > "$SOURCES_DIR/oxidized-fskit-legacy-ffi.swift"
      else
        cp "$GENERATED_DIR/oxidized-fskit-legacy-ffi/oxidized-fskit-legacy-ffi.swift" "$SOURCES_DIR/"
      fi

      echo "Copying C headers..."
      cp "$GENERATED_DIR/SwiftBridgeCore.h" "$INCLUDE_DIR/"
      cp "$GENERATED_DIR/oxidized-fskit-legacy-ffi/oxidized-fskit-legacy-ffi.h" "$INCLUDE_DIR/"

      cat > "$INCLUDE_DIR/module.modulemap" << 'EOF'
module COxVaultFFI {
    header "SwiftBridgeCore.h"
    header "oxidized-fskit-legacy-ffi.h"
    export *
}
EOF
      echo "Bindings synced to $SWIFT_FFI"
    '';

    # Build Swift packages (requires Xcode)
    fskit-build-swift.exec = ''
      set -e
      if [[ ! -x "${xcodeSwift}" ]]; then
        echo "Error: Xcode Swift not found at ${xcodeSwift}"
        echo "FSKit requires Xcode's Swift toolchain for FSKit.framework"
        exit 1
      fi

      # Ensure we use Xcode's toolchain
      unset SDKROOT DEVELOPER_DIR
      export SDKROOT="${xcodeSdk}"

      echo "Building OxVaultFFI..."
      cd crates/oxidized-fskit-legacy-ffi/swift
      ${xcodeSwift} build

      echo "Building OxVaultFSExtension..."
      cd ../../oxidized-fskit-ffi/extension
      ${xcodeSwift} build

      echo "Swift packages built successfully!"
    '';

    # Full FSKit build (Rust + sync + Swift)
    fskit-build.exec = ''
      set -e
      echo "=== Building FSKit Swift Extension ==="
      fskit-build-rust
      fskit-sync-bindings
      fskit-build-swift
      echo "=== FSKit build complete ==="
    '';

    # Clean Swift build artifacts
    fskit-clean.exec = ''
      echo "Cleaning Swift build artifacts..."
      rm -rf crates/oxidized-fskit-legacy-ffi/swift/.build
      rm -rf crates/oxidized-fskit-ffi/extension/.build
      echo "Clean complete"
    '';
  };
}
