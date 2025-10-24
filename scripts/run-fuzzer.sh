#!/usr/bin/env bash
# Cross‑platform fuzzer runner with dependency checks
# Compatible with macOS and Linux

# Environment variables:
#   - FUZZ_TIME: (optional) fuzzer execution time

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

#---------------------------------------
# Detect platform
#---------------------------------------
OS="$(uname -s)"
IS_DARWIN=false
IS_LINUX=false

if [[ "$OS" == "Darwin" ]]; then
    IS_DARWIN=true
elif [[ "$OS" == "Linux" ]]; then
    IS_LINUX=true
else
    echo "Unsupported OS: $OS"
    exit 1
fi

#---------------------------------------
# Helper: check for a command
#---------------------------------------
check_command() {
    local cmd="$1"
    local install_hint="$2"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "❌ Missing required command: $cmd"
        echo "➡️  Install using:"
        echo "   $install_hint"
        exit 1
    fi
}

#---------------------------------------
# Verify required tools
#---------------------------------------

# Check if "cargo ziggy" subcommand exists
if ! cargo ziggy --help >/dev/null 2>&1; then
    echo "❌ Missing required cargo subcommand: ziggy"
    echo "➡️  Install using:"
    echo "   cargo install ziggy cargo-afl honggfuzz grcov"
    exit 1
fi

if $IS_LINUX; then
    check_command timeout "sudo apt install coreutils"
elif $IS_DARWIN; then
    check_command gtimeout "brew install coreutils"
fi

FUZZ_TIME="${FUZZ_TIME:-"5m"}"

#---------------------------------------
# Run fuzz test
#---------------------------------------
cd ./test/subspace-test-fuzzer

echo "🚀 Running Ziggy fuzzing for $FUZZ_TIME..."
if $IS_DARWIN; then
    gtimeout --preserve-status "$FUZZ_TIME" cargo ziggy fuzz --release --no-honggfuzz
else
    timeout --preserve-status "$FUZZ_TIME" cargo ziggy fuzz --release --no-honggfuzz
fi

echo "✅ Fuzzing complete."
