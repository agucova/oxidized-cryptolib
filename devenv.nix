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
  # Required for oxidized-fskit (FSKit-based vault mounting on macOS 15.4+)
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
in
{
  languages.rust = {
    enable = true;
    channel = "nightly";
    components = [ "rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" "rust-src" "llvm-tools" ];
  };

  packages = with pkgs; [
    cargo-edit
    cargo-outdated
    cargo-audit
    cargo-fuzz
    cargo-nextest
    act  # Run GitHub Actions locally
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

    # Auto-detect podman and set DOCKER_HOST for act
    if command -v podman &> /dev/null && ! test -S /var/run/docker.sock; then
      PODMAN_SOCKET=$(podman machine inspect --format '{{.ConnectionInfo.PodmanSocket.Path}}' 2>/dev/null || true)
      if [[ -n "$PODMAN_SOCKET" ]] && [[ -S "$PODMAN_SOCKET" ]]; then
        export DOCKER_HOST="unix://$PODMAN_SOCKET"
      fi
    fi
  '';
}
