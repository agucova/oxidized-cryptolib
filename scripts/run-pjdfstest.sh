#!/bin/bash
# run-pjdfstest.sh - Run pjdfstest POSIX compliance tests against oxidized-fuse
#
# Usage: ./scripts/run-pjdfstest.sh [OPTIONS]
#
# Options:
#   --vault PATH       Path to Cryptomator vault (default: ./test_vault)
#   --mount PATH       Mount point (default: /tmp/oxidized-fuse-test)
#   --pjdfstest PATH   Path to pjdfstest directory (default: ./pjdfstest)
#   --password PASS    Vault password (default: test-password-123)
#   --quick            Run only a subset of tests
#   --help             Show this help message
#
# Requirements:
#   - Root access (sudo)
#   - FUSE installed (fuse3 on Linux)
#   - pjdfstest built (see https://github.com/pjd/pjdfstest)
#   - oxidized-fuse built (cargo build --release -p oxidized-fuse)

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
VAULT_PATH="./test_vault"
MOUNT_POINT="/tmp/oxidized-fuse-test"
PJDFSTEST_BIN=""  # Will be auto-detected
PJDFSTEST_TESTS=""  # Path to pjdfstest tests directory
VAULT_PASSWORD="123456789"
QUICK_MODE=false
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --vault)
            VAULT_PATH="$2"
            shift 2
            ;;
        --mount)
            MOUNT_POINT="$2"
            shift 2
            ;;
        --pjdfstest-bin)
            PJDFSTEST_BIN="$2"
            shift 2
            ;;
        --pjdfstest-tests)
            PJDFSTEST_TESTS="$2"
            shift 2
            ;;
        --password)
            VAULT_PASSWORD="$2"
            shift 2
            ;;
        --quick)
            QUICK_MODE=true
            shift
            ;;
        --help)
            head -20 "$0" | tail -18
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Logging functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check for root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (for FUSE mounting and pjdfstest)"
        exit 1
    fi

    # Check for FUSE
    if [[ ! -e /dev/fuse ]]; then
        log_error "FUSE not available (/dev/fuse not found)"
        exit 1
    fi

    # Check for oxmount binary
    OXMOUNT="$PROJECT_ROOT/target/release/oxmount"
    if [[ ! -x "$OXMOUNT" ]]; then
        log_warn "oxmount not found at $OXMOUNT, building..."
        (cd "$PROJECT_ROOT" && cargo build --release -p oxidized-fuse)
    fi

    # Check for vault
    if [[ ! -d "$VAULT_PATH" ]]; then
        log_error "Vault not found at $VAULT_PATH"
        exit 1
    fi

    # Check for pjdfstest
    PJDFSTEST_BIN="$PJDFSTEST_PATH/pjdfstest"
    if [[ ! -x "$PJDFSTEST_BIN" ]]; then
        log_error "pjdfstest not found at $PJDFSTEST_BIN"
        log_info "To build pjdfstest:"
        log_info "  git clone https://github.com/pjd/pjdfstest"
        log_info "  cd pjdfstest && autoreconf -ifs && ./configure && make"
        exit 1
    fi

    log_info "All prerequisites satisfied"
}

# Cleanup function
cleanup() {
    log_info "Cleaning up..."

    # Unmount if mounted
    if mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
        log_info "Unmounting $MOUNT_POINT..."
        umount "$MOUNT_POINT" 2>/dev/null || fusermount -u "$MOUNT_POINT" 2>/dev/null || true
        sleep 1
    fi

    # Kill oxmount if running
    if [[ -n "${OXMOUNT_PID:-}" ]]; then
        kill "$OXMOUNT_PID" 2>/dev/null || true
        wait "$OXMOUNT_PID" 2>/dev/null || true
    fi

    # Remove mount point if we created it
    if [[ -d "$MOUNT_POINT" ]] && [[ -z "$(ls -A "$MOUNT_POINT")" ]]; then
        rmdir "$MOUNT_POINT" 2>/dev/null || true
    fi
}

# Set up trap for cleanup
trap cleanup EXIT

# Mount the vault
mount_vault() {
    log_info "Mounting vault at $MOUNT_POINT..."

    # Create mount point
    mkdir -p "$MOUNT_POINT"

    # Mount using oxmount
    VAULT_PASSWORD="$VAULT_PASSWORD" "$OXMOUNT" "$VAULT_PATH" "$MOUNT_POINT" &
    OXMOUNT_PID=$!

    # Wait for mount to be ready
    local timeout=10
    local count=0
    while ! mountpoint -q "$MOUNT_POINT" 2>/dev/null; do
        sleep 0.5
        count=$((count + 1))
        if [[ $count -ge $((timeout * 2)) ]]; then
            log_error "Timed out waiting for mount"
            exit 1
        fi
    done

    log_info "Vault mounted successfully (PID: $OXMOUNT_PID)"
}

# Run pjdfstest
run_pjdfstest() {
    log_info "Running pjdfstest..."

    cd "$MOUNT_POINT"

    # Tests to run (skip unsupported operations)
    # Skip: mkfifo (not supported), mknod (not supported), chflags (BSD-specific)
    local test_dirs=(
        "chmod"
        "chown"
        "link"
        "mkdir"
        "open"
        "rename"
        "rmdir"
        "symlink"
        "truncate"
        "unlink"
    )

    if $QUICK_MODE; then
        # Quick mode: run just a few key tests
        test_dirs=("mkdir" "open" "rename" "unlink")
        log_info "Quick mode: running subset of tests"
    fi

    local failed=0
    local passed=0

    for test_dir in "${test_dirs[@]}"; do
        local test_path="$PJDFSTEST_PATH/tests/$test_dir"
        if [[ -d "$test_path" ]]; then
            log_info "Running $test_dir tests..."
            if prove -r "$test_path" 2>&1; then
                passed=$((passed + 1))
            else
                failed=$((failed + 1))
                log_warn "$test_dir tests had failures"
            fi
        else
            log_warn "Test directory not found: $test_path"
        fi
    done

    echo ""
    log_info "======================================"
    log_info "Test Summary"
    log_info "======================================"
    log_info "Passed: $passed"
    if [[ $failed -gt 0 ]]; then
        log_error "Failed: $failed"
    else
        log_info "Failed: $failed"
    fi
    log_info "======================================"

    return $failed
}

# Main
main() {
    log_info "oxidized-fuse pjdfstest runner"
    log_info "======================================"

    check_prerequisites
    mount_vault

    # Give mount time to stabilize
    sleep 1

    if run_pjdfstest; then
        log_info "All tests passed!"
        exit 0
    else
        log_error "Some tests failed"
        exit 1
    fi
}

main "$@"
