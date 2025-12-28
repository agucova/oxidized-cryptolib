#!/usr/bin/env bash
# Setup script for nextest: sets KDF parameters based on profile
#
# - Default/quick profiles: use fast KDF (N=1024) for faster tests
# - CI profile: use production KDF (N=32768) for thorough security testing

if [ -z "$NEXTEST_ENV" ]; then
    echo "Error: NEXTEST_ENV not set (not running under nextest)" >&2
    exit 1
fi

# Check which profile is being used
# NEXTEST_PROFILE is set by nextest to the current profile name
if [ "$NEXTEST_PROFILE" = "ci" ]; then
    echo "OXCRYPT_FAST_KDF=0" >> "$NEXTEST_ENV"
else
    # Default, quick, or any other profile uses fast KDF
    echo "OXCRYPT_FAST_KDF=1" >> "$NEXTEST_ENV"
fi
