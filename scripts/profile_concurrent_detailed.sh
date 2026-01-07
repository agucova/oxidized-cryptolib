#!/bin/bash
#
# Comprehensive profiling of concurrent workload with multiple data collection methods
#

set -e

VAULT_PATH="test_vault"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PROFILE_DIR="profiles/concurrent_${TIMESTAMP}"
mkdir -p "$PROFILE_DIR"

echo "=========================================="
echo "Concurrent Workload Profiling"
echo "=========================================="
echo "Profile directory: $PROFILE_DIR"
echo ""

# Clean up any stale processes
echo "Cleaning up stale processes..."
pkill -f "oxbench|oxmount" || true
timeout 10 diskutil unmount force /tmp/oxbench/fuse 2>/dev/null || true
sleep 2

# Build with profiling support
echo "Building release binary..."
PKG_CONFIG_PATH=/usr/local/lib/pkgconfig cargo build --release -p oxcrypt-bench 2>&1 | tail -5

echo ""
echo "=========================================="
echo "Run 1: Baseline with VaultStats metrics"
echo "=========================================="
echo "Collecting operation metrics during execution..."

# Run with stats collection
OXCRYPT_FAST_KDF=1 timeout 120 ./target/release/oxbench test_vault fuse \
  --password 123456789 \
  --workload concurrent \
  --iterations 2 \
  2>&1 | tee "$PROFILE_DIR/concurrent_baseline.log"

echo ""
echo "=========================================="
echo "Run 2: With detailed debug logging"
echo "=========================================="
echo "Collecting trace logs to understand operation patterns..."

# Clean up for next run
pkill -f "oxbench|oxmount" || true
timeout 10 diskutil unmount force /tmp/oxbench/fuse 2>/dev/null || true
sleep 2

# Run with debug logging to see operation patterns
OXCRYPT_FAST_KDF=1 RUST_LOG=oxcrypt_bench::bench::workloads=info,oxcrypt_fuse=warn timeout 120 \
  ./target/release/oxbench test_vault fuse \
  --password 123456789 \
  --workload concurrent \
  --iterations 1 \
  2>&1 | tee "$PROFILE_DIR/concurrent_debug.log"

echo ""
echo "=========================================="
echo "Run 3: Detailed latency breakdown"
echo "=========================================="
echo "Running with verbose operation logging..."

# Clean up
pkill -f "oxbench|oxmount" || true
timeout 10 diskutil unmount force /tmp/oxbench/fuse 2>/dev/null || true
sleep 2

# Run with verbose output
OXCRYPT_FAST_KDF=1 timeout 120 ./target/release/oxbench test_vault fuse \
  --password 123456789 \
  --workload concurrent \
  --iterations 1 \
  --verbose \
  2>&1 | tee "$PROFILE_DIR/concurrent_verbose.log"

echo ""
echo "=========================================="
echo "Analysis"
echo "=========================================="

# Extract key metrics from baseline
echo "Extracting metrics from baseline run..."
python3 << 'PYTHON_SCRIPT'
import re
import sys

log_file = "profiles/concurrent_" + [d for d in __import__('os').listdir('profiles') if d.startswith('concurrent_')][-1] + "/concurrent_baseline.log"

try:
    with open(log_file, 'r') as f:
        content = f.read()

    # Remove ANSI escape codes
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean = ansi_escape.sub('', content)

    # Look for timing info
    timing_match = re.search(r'Time \(mean ± σ\):\s+([^\n]+)', clean)
    if timing_match:
        print(f"Timing: {timing_match.group(1)}")

    # Look for operation rates
    lines = clean.split('\n')
    for i, line in enumerate(lines):
        if 'ops/sec' in line or 'operations' in line or 'latency' in line.lower():
            print(f"  {line.strip()}")

except Exception as e:
    print(f"Error parsing: {e}", file=sys.stderr)
PYTHON_SCRIPT

echo ""
echo "Profile data saved to: $PROFILE_DIR"
echo ""
echo "To analyze further:"
echo "  1. Review operation patterns: cat $PROFILE_DIR/concurrent_debug.log | grep -E 'read|write|meta'"
echo "  2. Check latency distribution: grep -i latency $PROFILE_DIR/concurrent_baseline.log"
echo "  3. Look for performance cliffs: tail -100 $PROFILE_DIR/concurrent_verbose.log"
