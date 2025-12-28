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
  ];

  env = {
    RUST_BACKTRACE = "1";
  };

  enterShell = ''
    echo "oxidized-cryptolib dev environment"
    echo "Rust: $(rustc --version)"
  '';
}
