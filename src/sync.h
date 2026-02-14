#pragma once

#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <stdexcept>

using json = nlohmann::json;

namespace idasync {

// ═══════════════════════════════════════════════════════════════════
// Error Types
// ═══════════════════════════════════════════════════════════════════

/// IDA-specific tool error (maps to JSON-RPC -32000)
class IDAError : public std::runtime_error {
public:
    explicit IDAError(const std::string& msg) : std::runtime_error(msg) {}
};

/// Sync/timeout error (maps to JSON-RPC -32603)
class IDASyncError : public std::runtime_error {
public:
    explicit IDASyncError(const std::string& msg) : std::runtime_error(msg) {}
};

// ═══════════════════════════════════════════════════════════════════
// Main Thread Execution
// ═══════════════════════════════════════════════════════════════════

/// Get the default tool timeout in seconds (from IDA_MCP_TOOL_TIMEOUT_SEC env).
double get_tool_timeout_seconds();

/// Execute a function on IDA's main thread using execute_sync(MFF_WRITE).
/// Blocks until completion or timeout.
/// cancel_flag: if non-null and set to true, throws CancelledError.
json execute_on_main_thread(
    std::function<json()> func,
    std::shared_ptr<std::atomic<bool>> cancel_flag = nullptr,
    double timeout_sec = -1.0 // -1 means use default
);

} // namespace idasync
