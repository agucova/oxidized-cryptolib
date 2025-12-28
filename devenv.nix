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
  ]
  # Add pjdfstest on Linux (requires FUSE which is native there)
  ++ lib.optionals stdenv.isLinux [
    pjdfstest
    fuse3
  ]
  # On macOS, add macfuse build dependencies (macfuse itself must be installed via brew)
  ++ lib.optionals stdenv.isDarwin [
    pjdfstest  # Can still build pjdfstest, just needs macFUSE at runtime
  ];

  env = {
    RUST_BACKTRACE = "1";
  } // lib.optionalAttrs pkgs.stdenv.isDarwin {
    PKG_CONFIG_PATH = "/usr/local/lib/pkgconfig";
  };

  enterShell = ''
    echo "oxidized-cryptolib dev environment"
    echo "Rust: $(rustc --version)"

    # Install cargo-llvm-cov if not present (nixpkgs version is broken)
    if ! command -v cargo-llvm-cov &> /dev/null; then
      echo "Installing cargo-llvm-cov..."
      cargo install cargo-llvm-cov --quiet
    fi
  '';
}
