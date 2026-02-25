#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IDASDK="${IDASDK:-$SCRIPT_DIR/idasdk/src}"
BUILD_DIR="$SCRIPT_DIR/build"
JOBS="$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

echo "=== Building tests ==="
cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR/tests" -DBUILD_PLUGIN=OFF -DBUILD_TESTS=ON
cmake --build "$BUILD_DIR/tests" -j"$JOBS"

echo ""
echo "=== Running tests ==="
"$BUILD_DIR/tests/ida_mcp_tests"

echo ""
echo "=== Building plugin (IDASDK=$IDASDK) ==="
cmake -S "$SCRIPT_DIR" -B "$BUILD_DIR/plugin" -DBUILD_PLUGIN=ON -DBUILD_TESTS=OFF -DIDASDK="$IDASDK"
cmake --build "$BUILD_DIR/plugin" -j"$JOBS"

PLUGINS_DIR="$HOME/ida-free-9.3/plugins"
echo ""
echo "=== Installing plugin to $PLUGINS_DIR ==="
cp "$BUILD_DIR/plugin/ida_mcp.so" "$PLUGINS_DIR/ida_mcp.so"

echo ""
echo "=== Done ==="
echo "Plugin: $PLUGINS_DIR/ida_mcp.so"
