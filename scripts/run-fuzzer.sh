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

FUZZ_TIME="${FUZZ_TIME:-"10m"}"

#---------------------------------------
# Run fuzz test
#---------------------------------------
cd ./test/subspace-test-fuzzer

# remove existing afl output so that previous run is not continued
rm -rf output

# build binary
cargo ziggy build --release --no-honggfuzz

BINARY="./target/afl/release/subspace-test-fuzzer"

echo "🚀 Running Ziggy fuzzing for $FUZZ_TIME..."

# run behind a timeout since ziggy by itself one
# TODO: https://github.com/srlabs/ziggy/issues/115
if $IS_DARWIN; then
    set +e
    gtimeout --preserve-status "$FUZZ_TIME" cargo ziggy fuzz -b ${BINARY}
    FUZZ_EXIT_CODE=$?
    set -e
else
    set +e
    timeout --preserve-status "$FUZZ_TIME" cargo ziggy fuzz -b ${BINARY}
    FUZZ_EXIT_CODE=$?
    set -e
fi

echo "✅ Fuzzing completed with exit code: ${FUZZ_EXIT_CODE}."

#---------------------------------------
# Check for crashes
# We need to do this since ziggy does not exit if it encounters any crash
# Hopefully this PR should fix it: https://github.com/srlabs/ziggy/pull/113
#---------------------------------------
CRASH_DIR="./output/target/afl/release/subspace-test-fuzzer/crashes"

if [[ -d "$CRASH_DIR" ]]; then
    CRASH_COUNT=$(find "$CRASH_DIR" -type f | wc -l | tr -d ' ')
    if [[ "$CRASH_COUNT" -gt 0 ]]; then
        echo "⚠️  Found $CRASH_COUNT crashes from this fuzzing run."
        echo "🧩 Replaying crashes to print stack traces..."
        find "$CRASH_DIR" -type f -exec "$BINARY" {} \;
        exit 1
    else
        echo "✅ No crashes detected."
        exit 0
    fi
else
    echo "❌ Crash directory not found: $CRASH_DIR"
    echo "    (Fuzzer output structure may have changed or fuzzing failed)"
    exit 2
fi
