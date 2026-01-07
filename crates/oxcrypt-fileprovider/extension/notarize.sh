#!/bin/bash
set -euo pipefail

APP_PATH="build/OxCryptFileProvider.app"
BUNDLE_ID="com.agucova.oxcrypt.fileprovider"
ZIP_PATH="build/OxCryptFileProvider.zip"

cd "$(dirname "$0")"

echo "=== Notarizing File Provider Extension ==="
echo ""

# Step 1: Verify app exists
if [[ ! -d "$APP_PATH" ]]; then
  echo "Error: $APP_PATH not found."
  echo "Run ./build.sh Release first to build the extension."
  exit 1
fi
echo "[1/6] Found app bundle: $APP_PATH"
echo ""

# Step 2: Re-sign with Developer ID Application
echo "[2/6] Re-signing with Developer ID Application..."

# Find Developer ID Application certificate (use SHA-1 to avoid ambiguity)
DEVID_SHA1=$(security find-identity -v -p codesigning | grep "Developer ID Application" | head -1 | awk '{print $2}')
DEVID_NAME=$(security find-identity -v -p codesigning | grep "Developer ID Application" | head -1 | sed -n 's/.*"\(.*\)"/\1/p')

if [[ -z "$DEVID_SHA1" ]]; then
  echo "Error: No Developer ID Application certificate found in keychain"
  echo ""
  echo "Install a Developer ID Application certificate from developer.apple.com"
  exit 1
fi

echo "Using identity: $DEVID_NAME"
echo "Certificate: $DEVID_SHA1"
echo ""

# Deep sign with hardened runtime and secure timestamp
# Sign extension first, then the host app
echo "Signing extension..."
codesign --force --deep --sign "$DEVID_SHA1" \
  --options runtime \
  --timestamp \
  --entitlements OxCryptFileProviderExtension-Release.entitlements \
  "$APP_PATH/Contents/PlugIns/OxCryptFileProviderExtension.appex"

echo "Signing host app..."
codesign --force --deep --sign "$DEVID_SHA1" \
  --options runtime \
  --timestamp \
  --entitlements OxCryptFileProvider-Release.entitlements \
  "$APP_PATH"

# Verify signature
if ! codesign --verify --deep --strict "$APP_PATH" 2>/dev/null; then
  echo "Error: Code signature verification failed after re-signing"
  exit 1
fi

echo "✓ Re-signed with Developer ID Application"
echo ""

# Step 3: Check for required credentials
echo "[3/6] Checking credentials..."

if [[ -z "${APPLE_ID:-}" ]]; then
  echo "Error: APPLE_ID environment variable not set"
  echo ""
  echo "Set your Apple ID email:"
  echo "  export APPLE_ID='your@email.com'"
  exit 1
fi

if [[ -z "${APPLE_TEAM_ID:-}" ]]; then
  echo "Error: APPLE_TEAM_ID environment variable not set"
  echo ""
  echo "Set your team ID (find at developer.apple.com):"
  echo "  export APPLE_TEAM_ID='ABC123DEF4'"
  exit 1
fi

if [[ -z "${APPLE_APP_PASSWORD:-}" ]]; then
  echo "Error: APPLE_APP_PASSWORD environment variable not set"
  echo ""
  echo "Create an app-specific password at appleid.apple.com:"
  echo "  1. Go to https://appleid.apple.com"
  echo "  2. Sign In → App-Specific Passwords → Generate Password"
  echo "  3. Set: export APPLE_APP_PASSWORD='xxxx-xxxx-xxxx-xxxx'"
  exit 1
fi

echo "✓ Apple ID: $APPLE_ID"
echo "✓ Team ID: $APPLE_TEAM_ID"
echo "✓ App-specific password: ****-****-****-****"
echo ""

# Step 4: Create ZIP archive for notarization
echo "[4/6] Creating ZIP archive..."
rm -f "$ZIP_PATH"
ditto -c -k --keepParent "$APP_PATH" "$ZIP_PATH"
ZIP_SIZE=$(du -h "$ZIP_PATH" | cut -f1)
echo "✓ Archive created: $ZIP_PATH ($ZIP_SIZE)"
echo ""

# Step 5: Submit for notarization
echo "[5/6] Submitting to Apple for notarization..."
echo "This may take several minutes..."
echo ""

xcrun notarytool submit "$ZIP_PATH" \
  --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" \
  --password "$APPLE_APP_PASSWORD" \
  --wait

NOTARIZE_EXIT=$?

if [[ $NOTARIZE_EXIT -ne 0 ]]; then
  echo ""
  echo "❌ Notarization failed!"
  echo ""
  echo "To see detailed logs:"
  echo "  xcrun notarytool log <submission-id> --apple-id $APPLE_ID --team-id $APPLE_TEAM_ID --password \$APPLE_APP_PASSWORD"
  exit 1
fi

echo ""
echo "✓ Notarization successful!"
echo ""

# Step 6: Staple the notarization ticket
echo "[6/6] Stapling notarization ticket..."
xcrun stapler staple "$APP_PATH"
echo "✓ Ticket stapled to app bundle"
echo ""

# Verify the stapled ticket
echo "Verifying notarization..."
spctl -a -vvv -t install "$APP_PATH" 2>&1 | head -5
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✓ Notarization complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "The extension is now notarized and ready for distribution."
echo "Location: $APP_PATH"
echo ""
