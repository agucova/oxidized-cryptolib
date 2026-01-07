#!/bin/bash
set -euo pipefail

# Navigate to crate root (one level up from extension/)
cd "$(dirname "$0")/.."

# Parse configuration argument (Debug or Release, default Debug)
CONFIGURATION="${1:-Debug}"
if [[ "$CONFIGURATION" != "Debug" && "$CONFIGURATION" != "Release" ]]; then
  echo "Error: Invalid configuration '$CONFIGURATION'"
  echo "Usage: $0 [Debug|Release]"
  exit 1
fi

echo "=== Building oxcrypt-fileprovider ($CONFIGURATION) ==="
echo ""

# Step 1: Build Rust library
echo "[1/4] Building Rust library..."
if [[ "$CONFIGURATION" == "Release" ]]; then
  cargo build --release --lib
  echo "✓ Rust library built: target/release/liboxcrypt_fileprovider.a"
else
  cargo build --lib
  echo "✓ Rust library built: target/debug/liboxcrypt_fileprovider.a"
fi
echo ""

# Step 2: Verify Swift bridge code was generated
echo "[2/4] Verifying Swift bridge code..."
if [[ ! -f "extension/Shared/generated/SwiftBridgeCore.swift" ]]; then
  echo "Error: Swift bridge code not generated. build.rs may have failed."
  echo "Try running: cargo build --release --lib"
  exit 1
fi
echo "✓ Swift bridge code found: extension/Shared/generated/"
echo ""

# Step 3: Generate Xcode project from project.yml
echo "[3/4] Generating Xcode project..."
cd extension

# Check if xcodegen is available
if ! command -v xcodegen &> /dev/null; then
  echo "Error: xcodegen not found."
  echo ""
  echo "Install with: brew install xcodegen"
  echo "Or use devenv if available"
  exit 1
fi

xcodegen generate
echo "✓ Xcode project generated: OxCryptFileProvider.xcodeproj/"
echo ""

# Step 4: Build File Provider extension with xcodebuild
echo "[4/4] Building File Provider extension..."

# Determine signing configuration based on build configuration
if [[ "$CONFIGURATION" == "Release" ]]; then
  # Release: Use automatic signing with available certificates
  # Note: For Developer ID distribution, use notarize.sh after building
  echo "Release build: Automatic signing"

  # Try to auto-detect team ID from any available certificate
  TEAM_ID="${APPLE_TEAM_ID:-}"
  if [[ -z "$TEAM_ID" ]]; then
    # Try Apple Development first, then Developer ID Application
    TEAM_ID=$(security find-certificate -c "Apple Development" -p 2>/dev/null | \
              openssl x509 -noout -subject 2>/dev/null | \
              sed -n 's/.*OU=\([^/,]*\).*/\1/p' | head -1 || echo "")
    if [[ -z "$TEAM_ID" ]]; then
      TEAM_ID=$(security find-certificate -c "Developer ID Application" -p 2>/dev/null | \
                openssl x509 -noout -subject 2>/dev/null | \
                sed -n 's/.*OU=\([^/,]*\).*/\1/p' | head -1 || echo "")
    fi
  fi

  if [[ -z "$TEAM_ID" ]]; then
    echo "Warning: Could not detect team ID"
  else
    echo "Team ID: $TEAM_ID"
  fi

  # Let Xcode handle signing automatically
  if [[ -n "$TEAM_ID" ]]; then
    EXTRA_FLAGS=(
      "DEVELOPMENT_TEAM=$TEAM_ID"
      "-allowProvisioningUpdates"
    )
  else
    EXTRA_FLAGS=(
      "-allowProvisioningUpdates"
    )
  fi
else
  # Debug: Automatic signing with Apple Development
  echo "Debug build: Automatic signing with Apple Development"

  # Try to extract team ID from development certificate
  TEAM_ID=$(security find-certificate -c "Apple Development" -p 2>/dev/null | \
            openssl x509 -noout -subject 2>/dev/null | \
            sed -n 's/.*OU=\([^/,]*\).*/\1/p' | head -1 || echo "")

  if [[ -z "$TEAM_ID" ]]; then
    # Fallback: check for APPLE_TEAM_ID environment variable
    TEAM_ID="${APPLE_TEAM_ID:-}"
  fi

  if [[ -z "$TEAM_ID" ]]; then
    echo "Warning: Could not auto-detect Apple Team ID"
    echo "Set APPLE_TEAM_ID environment variable or install a development certificate"
    echo ""
    echo "Attempting build with automatic provisioning..."
    EXTRA_FLAGS=(
      "-allowProvisioningUpdates"
    )
  else
    echo "Detected Team ID: $TEAM_ID"
    EXTRA_FLAGS=(
      "DEVELOPMENT_TEAM=$TEAM_ID"
      "-allowProvisioningUpdates"
    )
  fi
fi

echo ""

# Clean environment for Xcode (avoid Nix interference)
# Build xcodebuild command
XCODEBUILD_CMD=(
  env -i
  HOME="$HOME"
  PATH="/usr/bin:/bin:/usr/sbin:/sbin:/Applications/Xcode.app/Contents/Developer/usr/bin"
  DEVELOPER_DIR="/Applications/Xcode.app/Contents/Developer"
  xcodebuild
  -project OxCryptFileProvider.xcodeproj
  -scheme OxCryptFileProvider
  -configuration "$CONFIGURATION"
  -derivedDataPath build
)

# Add extra flags if any
if [ ${#EXTRA_FLAGS[@]} -gt 0 ]; then
  XCODEBUILD_CMD+=("${EXTRA_FLAGS[@]}")
fi

XCODEBUILD_CMD+=(build)

# Execute the command
"${XCODEBUILD_CMD[@]}"

echo ""

# Step 5: Copy to expected location
echo "Copying extension bundle to build directory..."
rm -rf build/OxCryptFileProvider.app
cp -R "build/Build/Products/$CONFIGURATION/OxCryptFileProvider.app" \
      build/OxCryptFileProvider.app

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ Extension built successfully ($CONFIGURATION)!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "Location: extension/build/OxCryptFileProvider.app"
echo ""
if [[ "$CONFIGURATION" == "Release" ]]; then
  echo "Next steps:"
  echo "  • Notarize: ./extension/notarize.sh"
  echo "  • Or use devenv: fileprovider-notarize"
else
  echo "Next steps:"
  echo "  • Build Rust crate: cargo build -p oxcrypt-fileprovider"
  echo "  • Or build Release: ./build.sh Release"
fi
echo ""
