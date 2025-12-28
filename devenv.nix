{ pkgs, lib, ... }:

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
